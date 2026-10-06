//! Polling event intake and per-tick maintenance.

use super::*;

impl Client {
    /// Apply a background event. Terminal and GUI share the same semantics: here we only change data and notifications.
    pub fn apply_event(&mut self, event: PollingEvent) {
        match event {
            PollingEvent::RoomsUpdated(rooms) => self.apply_room_snapshot(rooms),
            PollingEvent::SentRequestsUpdated(requests) => {
                self.announce_declined(&requests);
                self.sent_requests = requests;
            }
            PollingEvent::PendingRequestsUpdated(requests) => {
                self.apply_requests(requests);
            }
            PollingEvent::MessageSent(message) => self.absorb_message(message),
            PollingEvent::IncomingMessage(message) => {
                let room_id = message.room_id.clone();
                let sender_id = message.sender_id.clone();
                let is_own = Some(&message.sender_id) == self.current_user_id.as_ref();
                let sender_name = self.sender_display_name(&message.sender_id);
                let preview = message.content.clone();
                self.absorb_message(message);
                if Some(room_id.as_str()) == self.current_room_id().as_deref() {
                    self.unread_counts.remove(&room_id);
                } else if !self.muted_room_ids.contains(&room_id) {
                    *self.unread_counts.entry(room_id.clone()).or_insert(0) += 1;
                }
                // Pop a desktop notification for other people's messages (same trigger point as the terminal version):
                // Messages not in the current room also pop; if the room has do-not-disturb on, don't pop (unread count still increments)
                if !is_own && !self.muted_room_ids.contains(&room_id) {
                    let title = self.text("notification_new_message");
                    let body = format!("{sender_name}: {preview}");
                    self.notify_in_app(&title, &body);
                    crate::desktop_notice::send(self.sound_enabled, &title, &body);
                }
                if !sender_id.is_empty() {
                    self.presence_by_user.insert(sender_id, true);
                }
            }
            PollingEvent::EncryptInvitation(handshake) => {
                self.handle_invitation(handshake);
            }
            PollingEvent::EncryptAccepted(handshake) => self.handle_accepted(handshake),
            PollingEvent::EncryptSessionReady(room_id) => self.handle_session_ready(room_id),
            PollingEvent::EncryptedMessage(incoming) => {
                self.decrypt_message(incoming);
            }
            PollingEvent::EncryptedMessageSent(_message_id) => {}
            PollingEvent::QuitCleanupFinished => {
                // Background cleanup (logout of private chat session) complete; the interface can exit
                self.quit_requested = true;
            }
            PollingEvent::EncryptSessionEnded((room_id, reason)) => {
                self.crypto.sessions.remove(&room_id);
                // The mapping from the wire reason to a wording key is given centrally by the seam according to the version.
                let reason_text =
                    self.text(self.connector.version().session_end_reason_key(&reason));
                // The server ends the session but keeps the room; soft-close it locally, exactly like the terminal version,
                // so the private chat leaves the room list instead of staying behind as an unusable one-person shell.
                self.close_local_room(&room_id);
                self.notify(
                    self.text("notification_room_removed")
                        .replace("{reason}", &reason_text),
                );
            }
            PollingEvent::MemberTyping((room_id, user_id, username)) => {
                if Some(&user_id) == self.current_user_id.as_ref() {
                    return;
                }
                self.sender_names.insert(user_id, username.clone());
                if Some(&room_id) == self.current_room_id().as_ref() {
                    self.typing_members
                        .push((room_id, username, Instant::now()));
                }
            }
            PollingEvent::PresenceChanged((user_id, username, online)) => {
                if !user_id.is_empty() {
                    self.presence_by_user.insert(user_id.clone(), online);
                    if !username.is_empty() {
                        self.sender_names.insert(user_id, username);
                    }
                }
            }
            PollingEvent::WebSocketConnected => {
                self.websocket_connected_at = Instant::now();
            }
            PollingEvent::WebSocketState(key) => {
                // Connection jitters are only logged; the greet probe is the sole basis for "can we connect"
                config::debug_log(&format!("WebSocket state: {key}"));
            }
            PollingEvent::ReachabilityChanged(online) => self.update_connection(online),
            PollingEvent::AvatarLoaded((user_id, bytes)) => match bytes {
                Some(bytes) => {
                    config::debug_log(&format!(
                        "Avatar fetched for {user_id}: {} bytes",
                        bytes.len()
                    ));
                    self.avatar_images.insert(user_id, Some(bytes));
                }
                None => {
                    self.avatar_images.insert(user_id, None);
                }
            },
            PollingEvent::AvatarFileChosen(Some(path)) => self.apply_local_avatar(&path),
            PollingEvent::AvatarFileChosen(None) => {}
            PollingEvent::RegisteredUsersUpdated(users) => {
                for user in &users {
                    self.sender_names
                        .insert(user.id.clone(), user.username.clone());
                }
                self.registered_users = Some(users);
            }
            PollingEvent::UpdateAvailable(package) => {
                // The prompt is drawn by the interface from this state; nothing is fetched yet
                self.pending_update = Some((package, UpdateStage::AwaitingAnswer));
            }
            PollingEvent::UpdateUpToDate(version) => {
                self.notify(
                    self.text("update_up_to_date")
                        .replace("{version}", &version),
                );
            }
            PollingEvent::UpdateReady((version, package_path)) => {
                let matched = match self.pending_update.take() {
                    Some((package, _)) if package.version == version => {
                        self.pending_update = Some((package, UpdateStage::Package(package_path)));
                        true
                    }
                    other => {
                        self.pending_update = other;
                        false
                    }
                };
                if matched && self.start_update_install() {
                    return;
                }
                if matched {
                    self.notify_error(self.text("error_update_start_failed"));
                }
            }
            PollingEvent::Error(message) => {
                if message.contains(crate::auth_expired_marker()) {
                    self.session_expired();
                } else {
                    self.notify_error(message);
                }
            }
        }
    }

    /// Two-stage notice expiry: a lone line vanishes quietly while its popup stays
    /// open; when the last live line goes the whole popup starts gliding out and is
    /// dropped only once that glide finished.
    fn sweep_notices(&mut self, now: Instant) {
        let glide = Duration::from_secs_f32(crate::app::layout::notice_glide_seconds());
        for kind in NoticeKind::all() {
            let live = self
                .notices
                .iter()
                .filter(|notice| {
                    notice.kind == kind && notice.closing_at.is_none() && notice.expires_at > now
                })
                .count();
            self.notices.retain(|notice| {
                if notice.kind != kind {
                    return true;
                }
                match notice.closing_at {
                    Some(started) => now.duration_since(started) < glide,
                    None => notice.expires_at > now || live == 0,
                }
            });
            if live == 0 {
                for notice in self.notices.iter_mut() {
                    if notice.kind == kind && notice.closing_at.is_none() {
                        notice.closing_at = Some(now);
                    }
                }
            }
        }
    }

    /// Periodic maintenance: notification expiry, input state decay, handshake resend, cache batch writeback
    pub fn tick(&mut self) {
        let now = Instant::now();
        self.sweep_notices(now);
        self.typing_members
            .retain(|(_room_id, _name, seen_at)| seen_at.elapsed() < Duration::from_secs(2));
        self.resend_handshakes();
        self.flush_cache_if_due();
        if now.duration_since(self.websocket_connected_at)
            >= self.connector.version().subscription_refresh_interval()
        {
            self.restart_websocket();
        }
    }

    // ==================== Rooms and Messages ====================

    /// Room snapshots fall into the local view state: new rooms need to reconnect to get subscriptions; removed group chats need accurate prompts
    pub(crate) fn apply_room_snapshot(&mut self, rooms: Vec<RoomInfo>) {
        let previous_ids: HashSet<String> = self.rooms.iter().map(|room| room.id.clone()).collect();
        let current_ids: HashSet<String> = rooms.iter().map(|room| room.id.clone()).collect();
        let had_rooms = !self.rooms.is_empty();
        for gone in previous_ids.difference(&current_ids) {
            if !self.left_room_ids.remove(gone) && self.room_was_encrypted(gone) {
                self.crypto.sessions.remove(gone);
            }
        }
        let added = current_ids.iter().any(|id| !previous_ids.contains(id));
        // A locally closed private chat stays hidden, and so does a leftover
        // one-person shell; filtering here keeps the list order equal to `self.rooms`.
        let previous_selection = self.current_room_id();
        self.rooms = rooms
            .into_iter()
            .filter(|room| {
                !self.closed_room_ids.contains(&room.id)
                    && (room.is_group || room.members.len() >= 2)
            })
            .collect();
        // Keep the same room while it still exists; nothing is ever selected on its
        // own, so opening a room is always the person's own click.
        self.selected_room_index = previous_selection
            .as_deref()
            .and_then(|room_id| self.rooms.iter().position(|room| room.id == room_id));
        // The selection really moved (the open room vanished, or the list re-ordered under a
        // still-open room): the text in the box belongs to the room that was open, so it goes
        // into that room's own draft cache and empties the box, and the room now open receives
        // its own cached draft. Nothing typed ever lands in a different chat this way.
        let now_selection = self.current_room_id();
        if now_selection != previous_selection {
            self.stash_room_draft(previous_selection.as_deref());
            self.restore_room_draft(now_selection.as_deref());
        }
        if added && had_rooms {
            self.restart_websocket();
        }
        self.refresh_room_avatars();
        match self.selected_room_index {
            Some(index) => {
                let room_id = self.rooms[index].id.clone();
                self.load_room_messages(&room_id);
            }
            None => {
                // No room left: the message area must not keep showing the room that just disappeared.
                self.messages.clear();
                self.older_cursor = None;
                self.has_more_older = false;
            }
        }
    }
}
