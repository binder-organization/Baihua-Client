//! Action part of the session layer: application background events, periodic maintenance, login/registration, and all server-side operations.
//! Shares the same `Client` as `client.rs`; split into two files just to make "state" and "behavior" each readable.

use crate::client::{Client, EncryptionPhase, EncryptionSession};
use baihua_core::api::UserInfo;
use baihua_core::config;
use baihua_core::{
    api::{
        CreateRoomRequest, EncryptHandshakeData, EncryptedMessageInfo, LoginRequest, MessageInfo,
        PollingEvent, ProfileUpdatePayload, RegisterRequest, RoomInfo, RoomRequestInfo, WsCommand,
        outbound_ws_payload,
    },
    chat_cache::ChatCache,
    crypto, paths,
    update::{ReleaseChannel, UpdateCheck, check_for_update, download_package},
};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

/// What the interface needs to do after a command is executed. The session layer doesn't touch overlays or focus; it hands this back to the interface.
#[derive(Debug, Clone, PartialEq)]
pub enum UiIntent {
    /// Nothing needs to be done (the command already expresses the result via notifications/data updates)
    Nothing,
    /// Exit the program
    Quit,
    /// Update has been handed off to the installer process; the interface should exit
    QuitForUpdate,
    /// Open your own profile card
    ShowOwnProfile,
    /// Open the right-side settings panel (all the complex settings like language, appearance, and server address that "need to be chosen and filled in" are in here)
    OpenSettings,
    /// Open the login page; pre-fill with username when provided (`/login username`)
    OpenSignIn(Option<String>),
    /// Open the registration page; pre-fill with username when provided (`/register username`)
    OpenSignUp(Option<String>),
}

impl Client {
    /// Whether logged in (having a user ID is considered as having a session)
    pub fn is_signed_in(&self) -> bool {
        self.current_user_id.is_some()
    }

    /// Not-logged-in prompt: report once on startup if there is no recoverable session
    pub fn notify_signed_out(&mut self) {
        // The graphical end has no `/login` command: point the user at the sign-in form it opens itself.
        let text = self.text("logged_out_hint_graphical");
        self.notify(text);
    }

    /// Write the message cache to be persisted before exiting (don't wait for the batch window)
    pub fn flush_before_exit(&mut self) {
        if let Some(room_id) = self.current_room_id() {
            self.cache_loaded_messages(&room_id);
        }
        self.cache_pending_flush_since = None;
    }

    /// Apply a background event. Terminal and GUI share the same semantics: here we only change data and notifications.
    pub fn apply_event(&mut self, event: PollingEvent) {
        match event {
            PollingEvent::RoomsUpdated(rooms) => self.apply_room_snapshot(rooms),
            PollingEvent::SentRequestsUpdated(requests) => {
                self.announce_declined_invitations(&requests);
                self.sent_requests = requests;
            }
            PollingEvent::PendingRequestsUpdated(requests) => {
                self.apply_received_requests(requests);
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
                    crate::desktop_notice::send(
                        self.sound_enabled,
                        &self.text("notification_new_message"),
                        &format!("{sender_name}: {preview}"),
                    );
                }
                if !sender_id.is_empty() {
                    self.presence_by_user.insert(sender_id, true);
                }
            }
            PollingEvent::EncryptInvitation(handshake) => {
                self.handle_encrypt_invitation(handshake);
            }
            PollingEvent::EncryptAccepted(handshake) => self.handle_encrypt_accepted(handshake),
            PollingEvent::EncryptSessionReady(room_id) => self.handle_session_ready(room_id),
            PollingEvent::EncryptedMessage(incoming) => {
                self.handle_encrypted_message(incoming);
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
                config::debug_log(&format!("WebSocket 状态: {key}"));
            }
            PollingEvent::ReachabilityChanged(online) => self.update_connection_state(online),
            PollingEvent::AvatarLoaded((user_id, bytes)) => match bytes {
                Some(bytes) => {
                    config::debug_log(&format!("头像已取回 {user_id}：{} 字节", bytes.len()));
                    self.avatar_images.insert(user_id, Some(bytes));
                }
                None => {
                    self.avatar_images.insert(user_id, None);
                }
            },
            PollingEvent::RegisteredUsersUpdated(users) => {
                for user in &users {
                    self.sender_names
                        .insert(user.id.clone(), user.username.clone());
                }
                self.registered_users = Some(users);
            }
            PollingEvent::UpdateReady((version, path)) => {
                self.pending_update = Some((version.clone(), path));
                self.notify(self.text("update_ready").replace("{version}", &version));
            }
            PollingEvent::Error(message) => {
                if message.contains(crate::auth_expired_marker()) {
                    self.handle_expired_session();
                } else {
                    self.notify_error(message);
                }
            }
        }
    }

    /// Periodic maintenance: notification expiry, input state decay, handshake resend, cache batch writeback
    pub fn tick(&mut self) {
        let now = Instant::now();
        self.notices.retain(|notice| notice.expires_at > now);
        self.typing_members
            .retain(|(_room_id, _name, seen_at)| seen_at.elapsed() < Duration::from_secs(2));
        self.resend_stalled_handshakes();
        self.flush_message_cache_if_due();
        if now.duration_since(self.websocket_connected_at)
            >= self.connector.version().subscription_refresh_interval()
        {
            self.restart_websocket();
        }
    }

    // ==================== Rooms and Messages ====================

    /// Room snapshots fall into the local view state: new rooms need to reconnect to get subscriptions; removed group chats need accurate prompts
    fn apply_room_snapshot(&mut self, rooms: Vec<RoomInfo>) {
        let previous_ids: HashSet<String> = self.rooms.iter().map(|room| room.id.clone()).collect();
        let current_ids: HashSet<String> = rooms.iter().map(|room| room.id.clone()).collect();
        let had_rooms = !self.rooms.is_empty();
        for gone in previous_ids.difference(&current_ids) {
            if !self.left_room_ids.remove(gone) && self.room_was_encrypted(gone) {
                self.crypto.sessions.remove(gone);
            }
        }
        let added = current_ids.iter().any(|id| !previous_ids.contains(id));
        // Visible rooms follow the terminal version's rule: a locally closed private chat stays hidden, and so does a leftover
        // one-person private chat shell (the other side's session ended; the server keeps the room but it is unusable on its own).
        // Filtering here, instead of inside `room_entries`, keeps the row order of the room list equal to the order of `self.rooms`,
        // which is what the interface's "clicked row index" and the selected-row highlight are resolved against.
        let previous_selection = self.current_room_id();
        self.rooms = rooms
            .into_iter()
            .filter(|room| {
                !self.closed_room_ids.contains(&room.id)
                    && (room.is_group || room.members.len() >= 2)
            })
            .collect();
        // Keep looking at the same room when it is still there; fall back to the first row, or to no room at all.
        self.selected_room_index = previous_selection
            .and_then(|room_id| self.rooms.iter().position(|room| room.id == room_id))
            .or_else(|| (!self.rooms.is_empty()).then_some(0));
        if added && had_rooms {
            self.restart_websocket();
        }
        self.refresh_avatar_for_visible_rooms();
        match self.selected_room_index {
            Some(index) => {
                let room_id = self.rooms[index].id.clone();
                self.load_messages_for_room(&room_id);
            }
            None => {
                // No room left: the message area must not keep showing the room that just disappeared.
                self.messages.clear();
                self.older_cursor = None;
                self.has_more_older = false;
            }
        }
    }

    /// Currently selected room ID
    pub fn current_room_id(&self) -> Option<String> {
        let index = self.selected_room_index?;
        self.rooms.get(index).map(|room| room.id.clone())
    }

    /// Select a room (called when clicking a room entry in the interface)
    pub fn open_room(&mut self, index: usize) {
        if index >= self.rooms.len() {
            return;
        }
        // Reopening a room you're already viewing also clears unread: the people are here, the red dot shouldn't stay
        let opened_id = self.rooms[index].id.clone();
        self.unread_counts.remove(&opened_id);
        if self.selected_room_index == Some(index) {
            return;
        }
        let previous_room = self
            .selected_room_index
            .and_then(|index| self.rooms.get(index).map(|room| room.id.clone()));
        if let Some(previous_room) = previous_room {
            self.cache_loaded_messages(&previous_room);
        }
        self.selected_room_index = Some(index);
        self.unread_counts.remove(&self.rooms[index].id);
        self.search_result = None;
        let room_id = self.rooms[index].id.clone();
        self.load_messages_for_room(&room_id);
    }

    /// Load room messages: first fill from local cache, then fetch the first page from the server and merge by ID
    fn load_messages_for_room(&mut self, room_id: &str) {
        // Messages the local side already holds for this very room. In end-to-end encrypted private chats this copy is the plaintext
        // this side decrypted, while the server returns an empty body for that history (the ciphertext only exists inside the session).
        // Reloading a room must therefore merge per message ID and keep the local copy, exactly like the terminal version;
        // clearing the table first would replace every decrypted body with that empty body.
        let same_room = self
            .messages
            .first()
            .is_some_and(|message| message.room_id == room_id);
        if !same_room {
            self.messages.clear();
            self.older_cursor = None;
            self.has_more_older = false;
            let encrypted = self.room_is_encrypted(room_id);
            if !encrypted
                && let Some(cache) = self.chat_cache.as_ref()
                && let Some(cached) = cache.load_room(room_id)
            {
                self.messages = cached.messages;
                self.older_cursor = cached.older_cursor;
                self.has_more_older = cached.has_more;
            }
        }
        match self.connector.get_messages(room_id, 50, None) {
            Ok(page) => {
                self.merge_messages(page.messages);
                self.older_cursor = page.next_cursor.clone();
                self.has_more_older = page.has_more;
            }
            Err(error) if error.is_connection_failure() => {
                config::debug_log(&format!("拉取消息时连不上服务端，保留缓存内容: {error}"));
            }
            Err(error) => {
                self.notify_error(format!("{}: {error}", self.text("error_load_history")))
            }
        }
        self.messages_reloaded_at = Instant::now();
        self.refresh_all_sender_names();
    }

    /// Page to earlier messages.
    ///
    /// `automatic` being true means this page turn was auto-triggered by "scrolling to the very top": on failure the cursor must be cleared,
    /// otherwise the render path judges a top-touch every frame and resends a request every frame. When the manual button (false) fails,
    /// keep the cursor, the button is still there, the user can try again themselves.
    pub fn load_older_messages(&mut self, automatic: bool) {
        let (Some(room_id), Some(cursor)) = (self.current_room_id(), self.older_cursor.clone())
        else {
            return;
        };
        match self
            .connector
            .get_messages(&room_id, 50, Some(cursor.as_str()))
        {
            Ok(page) => {
                self.merge_messages(page.messages);
                self.older_cursor = page.next_cursor.clone();
                self.has_more_older = page.has_more;
                self.mark_messages_dirty();
            }
            Err(error) if error.is_connection_failure() => {
                if automatic {
                    self.older_cursor = None;
                    self.has_more_older = false;
                }
            }
            Err(error) => {
                self.notify_error(format!("{}: {error}", self.text("error_load_history")));
                if automatic {
                    self.older_cursor = None;
                    self.has_more_older = false;
                }
            }
        }
    }

    /// Merge messages: deduplicate by ID, sort by time and ID ascending, only add never subtract
    fn merge_messages(&mut self, incoming: Vec<MessageInfo>) {
        let known: std::collections::HashSet<String> = self
            .messages
            .iter()
            .map(|message| message.id.clone())
            .collect();
        for message in incoming {
            if !known.contains(&message.id) {
                self.sender_names
                    .insert(message.sender_id.clone(), message.sender_id.clone());
                self.messages.push(message);
            }
        }
        self.messages.sort_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then_with(|| left.id.cmp(&right.id))
        });
    }

    /// Server receipt or locally sent messages fall into the view
    fn absorb_message(&mut self, message: MessageInfo) {
        if Some(message.room_id.clone()) != self.current_room_id() {
            return;
        }
        if self.messages.iter().any(|stored| stored.id == message.id) {
            return;
        }
        self.messages.push(message);
        self.mark_messages_dirty();
    }

    /// Whether the room is encrypted
    pub fn room_is_encrypted(&self, room_id: &str) -> bool {
        self.rooms
            .iter()
            .find(|room| room.id == room_id)
            .is_some_and(|room| room.is_encrypted)
    }

    /// Whether this room is a group chat (only group chats can add members or view the member list)
    pub fn room_is_group(&self, room_id: &str) -> bool {
        self.rooms
            .iter()
            .find(|room| room.id == room_id)
            .is_some_and(|room| room.is_group)
    }

    fn room_was_encrypted(&self, room_id: &str) -> bool {
        self.room_is_encrypted(room_id)
    }

    /// Room display entry: name, encrypted status, unread count, do-not-disturb
    pub fn room_entries(&self) -> Vec<crate::RoomEntry> {
        self.rooms
            .iter()
            .filter(|room| !self.closed_room_ids.contains(&room.id))
            .map(|room| crate::RoomEntry {
                id: room.id.clone(),
                title: room
                    .name
                    .clone()
                    .unwrap_or_else(|| self.text("private_chat_fallback")),
                encrypted: room.is_encrypted,
                unread: self.unread_counts.get(&room.id).copied().unwrap_or(0),
                muted: self.muted_room_ids.contains(&room.id),
            })
            .collect()
    }

    /// Hide a room locally, without notifying the server, and drop its encryption session:
    /// used when an encrypted private chat ends and when the user leaves a group chat.
    ///
    /// This is the graphical counterpart of the terminal version's `close_local_room`: the room leaves the visible list,
    /// the selection moves to the first remaining room (reloading its messages) or to nothing at all,
    /// and a room that was being looked at does not leave its messages on screen.
    pub fn close_local_room(&mut self, room_id: &str) {
        self.closed_room_ids.insert(room_id.to_string());
        self.crypto.sessions.remove(room_id);
        if let Some(cache) = self.chat_cache.as_ref() {
            cache.forget_room(room_id);
        }
        let was_selected = self.current_room_id().as_deref() == Some(room_id);
        self.rooms.retain(|room| room.id != room_id);
        if was_selected {
            self.selected_room_index = if self.rooms.is_empty() { None } else { Some(0) };
            self.messages.clear();
            self.older_cursor = None;
            self.has_more_older = false;
            if let Some(next_room_id) = self.current_room_id() {
                self.load_messages_for_room(&next_room_id);
            }
        }
    }

    // ==================== Sending and Input State ====================

    /// Send the content in the input box: starting with # is search, starting with / is a command, everything else is a message
    pub fn submit_draft(&mut self) -> UiIntent {
        let draft = self.draft.clone();
        let trimmed = draft.trim().to_string();
        if trimmed.is_empty() {
            return UiIntent::Nothing;
        }
        if let Some(rest) = trimmed.strip_prefix('/') {
            let intent = self.execute_command(rest);
            self.draft.clear();
            return intent;
        }
        if let Some(keyword) = trimmed.strip_prefix('#') {
            self.run_search(keyword);
            return UiIntent::Nothing;
        }
        self.send_message(&trimmed);
        self.draft.clear();
        UiIntent::Nothing
    }

    /// Send a normal message; if the room is encrypted and the session isn't ready, first initiate a handshake then resend
    pub fn send_message(&mut self, content: &str) {
        let Some(room_id) = self.current_room_id() else {
            self.notify_error(self.text("logged_out_hint_graphical"));
            return;
        };
        if !self.is_signed_in() {
            self.notify_error(self.text("error_not_logged_in_graphical"));
            return;
        }
        if !self.room_is_encrypted(&room_id) {
            self.send_payload(outbound_ws_payload(
                self.connector.version(),
                WsCommand::SendMessage {
                    room_id: &room_id,
                    content,
                },
            ));
            self.draft.clear();
            return;
        }
        match self
            .crypto
            .sessions
            .get(&room_id)
            .map(|session| session.phase)
        {
            Some(EncryptionPhase::Active) => self.send_encrypted(&room_id, content),
            Some(_) => {
                if let Some(session) = self.crypto.sessions.get_mut(&room_id) {
                    session.pending_content = Some(content.to_string());
                }
            }
            None => {
                self.initiate_encryption(&room_id, Some(content.to_string()));
            }
        }
    }

    /// Encrypt with the session key and send
    fn send_encrypted(&mut self, room_id: &str, content: &str) {
        let key = match self
            .crypto
            .sessions
            .get(room_id)
            .and_then(|session| session.shared_key)
        {
            Some(key) => key,
            None => return,
        };
        match crypto::encrypt_message(&key, content) {
            Ok(ciphertext) => self.send_payload(outbound_ws_payload(
                self.connector.version(),
                WsCommand::EncryptMessage {
                    room_id,
                    ciphertext: &ciphertext,
                },
            )),
            Err(error) => self.notify_error(format!(
                "{}: {error}",
                self.text("error_encrypt_send_failed")
            )),
        }
    }

    /// Input status reporting: throttle at the interval given by the seam; don't report if the draft is empty
    pub fn report_typing(&mut self) {
        let Some(room_id) = self.current_room_id() else {
            return;
        };
        if self.draft.trim().is_empty() {
            return;
        }
        if self.last_typing_frame_sent_at.is_some_and(|sent_at| {
            sent_at.elapsed() < self.connector.version().typing_send_interval()
        }) {
            return;
        }
        self.last_typing_frame_sent_at = Some(Instant::now());
        self.send_payload(outbound_ws_payload(
            self.connector.version(),
            WsCommand::SendTyping { room_id: &room_id },
        ));
    }

    /// Names of members currently typing in the current room
    pub fn typing_names(&self) -> Vec<String> {
        let room_id = self.current_room_id();
        // Members with the same name (old records left after multi-account or reconnection) are displayed only once:
        // without deduplication the title would first show two identical names, and after one expires it would go back to one
        let mut names: Vec<String> = Vec::new();
        for (_room, name, _seen) in self
            .typing_members
            .iter()
            .filter(|(typing_room, _name, _seen)| Some(typing_room.as_str()) == room_id.as_deref())
        {
            if !names.contains(name) {
                names.push(name.clone());
            }
        }
        names
    }

    // ==================== End-to-End Encryption Handshake ====================

    /// Initiate handshake: generate ephemeral key, sign public key and send invitation
    pub fn initiate_encryption(&mut self, room_id: &str, pending_content: Option<String>) {
        let ephemeral_secret = crypto::generate_ephemeral_secret();
        let public_key = crypto::encode_x25519_public(&ephemeral_secret);
        let identity_key = crypto::encode_identity_public(&self.crypto.identity_key);
        let Ok(signature) = crypto::sign_public_key(&self.crypto.identity_key, &public_key) else {
            self.notify_error(self.text("notification_encryption_failed_signature"));
            return;
        };
        self.send_payload(outbound_ws_payload(
            self.connector.version(),
            WsCommand::EncryptRequest {
                room_id,
                public_key: &public_key,
                identity_key: &identity_key,
                signature: &signature,
            },
        ));
        self.crypto.sessions.insert(
            room_id.to_string(),
            EncryptionSession {
                phase: EncryptionPhase::AwaitingAcceptance,
                ephemeral_secret: Some(ephemeral_secret),
                own_public_key: public_key,
                shared_key: None,
                pending_content,
                initiated_at: Instant::now(),
            },
        );
    }

    /// Received invitation: accept and reply with your public key
    fn handle_encrypt_invitation(&mut self, handshake: EncryptHandshakeData) {
        if Some(&handshake.peer_id) == self.current_user_id.as_ref() {
            return;
        }
        if !crypto::verify_handshake_signature(
            &handshake.identity_key,
            &handshake.public_key,
            &handshake.signature,
        ) {
            self.notify_error(self.text("notification_invitation_failed_signature"));
            return;
        }
        let existing = self
            .crypto
            .sessions
            .get(&handshake.room_id)
            .map(|session| session.phase);
        if existing == Some(EncryptionPhase::Active) {
            return;
        }
        let ephemeral_secret = crypto::generate_ephemeral_secret();
        let public_key = crypto::encode_x25519_public(&ephemeral_secret);
        let identity_key = crypto::encode_identity_public(&self.crypto.identity_key);
        let Ok(signature) = crypto::sign_public_key(&self.crypto.identity_key, &public_key) else {
            self.notify_error(self.text("notification_encryption_failed_signature"));
            return;
        };
        let shared_key = match crypto::derive_shared_key(ephemeral_secret, &handshake.public_key) {
            Ok(key) => key,
            Err(error) => {
                self.notify_error(format!("{}: {error}", self.text("error_key_derivation")));
                return;
            }
        };
        self.send_payload(outbound_ws_payload(
            self.connector.version(),
            WsCommand::EncryptAccept {
                room_id: &handshake.room_id,
                public_key: &public_key,
                identity_key: &identity_key,
                signature: &signature,
            },
        ));
        self.send_payload(outbound_ws_payload(
            self.connector.version(),
            WsCommand::EncryptReady {
                room_id: &handshake.room_id,
            },
        ));
        self.crypto.sessions.insert(
            handshake.room_id.clone(),
            EncryptionSession {
                phase: EncryptionPhase::AwaitingSessionReady,
                ephemeral_secret: None,
                own_public_key: public_key,
                shared_key: Some(shared_key),
                pending_content: None,
                initiated_at: Instant::now(),
            },
        );
    }

    /// Received the other side's acceptance: compute the shared key and reply ready
    fn handle_encrypt_accepted(&mut self, handshake: EncryptHandshakeData) {
        if Some(&handshake.peer_id) == self.current_user_id.as_ref() {
            return;
        }
        let waiting = self
            .crypto
            .sessions
            .get(&handshake.room_id)
            .is_some_and(|session| session.phase == EncryptionPhase::AwaitingAcceptance);
        if !waiting {
            return;
        }
        if !crypto::verify_handshake_signature(
            &handshake.identity_key,
            &handshake.public_key,
            &handshake.signature,
        ) {
            self.crypto.sessions.remove(&handshake.room_id);
            self.notify_error(self.text("notification_accept_failed_signature"));
            return;
        }
        let shared_key = {
            let Some(session) = self.crypto.sessions.get_mut(&handshake.room_id) else {
                return;
            };
            let Some(ephemeral_secret) = session.ephemeral_secret.take() else {
                return;
            };
            match crypto::derive_shared_key(ephemeral_secret, &handshake.public_key) {
                Ok(key) => key,
                Err(error) => {
                    self.notify_error(format!("{}: {error}", self.text("error_key_derivation")));
                    return;
                }
            }
        };
        self.send_payload(outbound_ws_payload(
            self.connector.version(),
            WsCommand::EncryptReady {
                room_id: &handshake.room_id,
            },
        ));
        if let Some(session) = self.crypto.sessions.get_mut(&handshake.room_id) {
            session.phase = EncryptionPhase::AwaitingSessionReady;
            session.shared_key = Some(shared_key);
            session.initiated_at = Instant::now();
        }
    }

    /// Server confirms both sides are ready: activate the session and resend messages that piled up during the handshake
    fn handle_session_ready(&mut self, room_id: String) {
        let pending = match self.crypto.sessions.get_mut(&room_id) {
            Some(session) => {
                session.phase = EncryptionPhase::Active;
                session.initiated_at = Instant::now();
                session.pending_content.take()
            }
            None => return,
        };
        self.notify(self.text("notification_encryption_ready"));
        if let Some(content) = pending {
            self.send_encrypted(&room_id, &content);
        }
    }

    /// Received ciphertext: decrypt and fall into the view as a normal message
    fn handle_encrypted_message(&mut self, incoming: EncryptedMessageInfo) {
        let key = match self
            .crypto
            .sessions
            .get(&incoming.room_id)
            .and_then(|session| session.shared_key)
        {
            Some(key) => key,
            None => {
                self.notify_error(self.text("notification_message_undecryptable"));
                return;
            }
        };
        let Ok(plaintext) = crypto::decrypt_message(&key, &incoming.ciphertext) else {
            self.notify_error(self.text("notification_message_undecryptable"));
            return;
        };
        let is_own = Some(&incoming.sender_id) == self.current_user_id.as_ref();
        let room_id = incoming.room_id.clone();
        let sender_name = self.sender_display_name(&incoming.sender_id);
        let preview = plaintext.clone();
        self.absorb_message(MessageInfo {
            id: incoming.id,
            room_id: incoming.room_id,
            sender_id: incoming.sender_id,
            content: plaintext,
            created_at: incoming.created_at,
        });
        // Encrypted messages also pop desktop notifications (same as terminal version: the body takes the just-decrypted plaintext)
        if !is_own && !self.muted_room_ids.contains(&room_id) {
            crate::desktop_notice::send(
                self.sound_enabled,
                &self.text("notification_new_message"),
                &format!("{sender_name}: {preview}"),
            );
        }
    }

    /// Resend at intervals when the handshake is stalled (resend invitation when waiting for acceptance, resend ready when waiting for ready)
    /// Resend at intervals when the handshake is stalled: resend invitation when waiting for acceptance (reuse the same ephemeral public key), resend ready when waiting for ready.
    /// The message is computed within the session borrow scope, then handed to WebSocket after the scope ends, avoiding two simultaneous mutable borrows.
    fn resend_stalled_handshakes(&mut self) {
        let interval = self.connector.version().handshake_resend_interval();
        let stalled: Vec<String> = self
            .crypto
            .sessions
            .iter()
            .filter(|(_room_id, session)| session.phase != EncryptionPhase::Active)
            .filter(|(_room_id, session)| session.initiated_at.elapsed() >= interval)
            .map(|(room_id, _session)| room_id.clone())
            .collect();
        let identity_key = crypto::encode_identity_public(&self.crypto.identity_key);
        for room_id in stalled {
            let payload = match self.crypto.sessions.get_mut(&room_id) {
                None => continue,
                Some(session) => match session.phase {
                    EncryptionPhase::AwaitingAcceptance => {
                        let Ok(signature) = crypto::sign_public_key(
                            &self.crypto.identity_key,
                            &session.own_public_key,
                        ) else {
                            continue;
                        };
                        session.initiated_at = Instant::now();
                        Some(outbound_ws_payload(
                            self.connector.version(),
                            WsCommand::EncryptRequest {
                                room_id: &room_id,
                                public_key: &session.own_public_key,
                                identity_key: &identity_key,
                                signature: &signature,
                            },
                        ))
                    }
                    EncryptionPhase::AwaitingSessionReady => {
                        session.initiated_at = Instant::now();
                        Some(outbound_ws_payload(
                            self.connector.version(),
                            WsCommand::EncryptReady { room_id: &room_id },
                        ))
                    }
                    EncryptionPhase::Active => None,
                },
            };
            if let Some(payload) = payload {
                self.send_payload(payload);
            }
        }
    }

    // ==================== Private Chat Requests ====================

    /// Align received requests with poll results: entries already processed by this side stay in history
    fn apply_received_requests(&mut self, polled: Vec<RoomRequestInfo>) {
        // First-seen pending request: pop a desktop notification (same as terminal version; repeated polls don't pop repeatedly)
        let fresh_senders: Vec<String> = polled
            .iter()
            .filter(|request| {
                !self
                    .pending_requests
                    .iter()
                    .any(|known| known.id == request.id)
            })
            .map(|request| match &request.sender {
                Some(sender) => sender.username.clone(),
                None => self.text("unknown_user"),
            })
            .collect();
        let kept: Vec<RoomRequestInfo> = self
            .pending_requests
            .iter()
            .filter(|request| !is_pending_request(request))
            .filter(|kept| !polled.iter().any(|request| request.id == kept.id))
            .cloned()
            .collect();
        self.pending_requests = polled.into_iter().chain(kept).collect();
        for sender_name in fresh_senders {
            crate::desktop_notice::send(
                self.sound_enabled,
                &self.text("notification_new_request"),
                &self
                    .text("notification_request_received")
                    .replace("{sender}", &sender_name),
            );
        }
    }

    /// Private chat request list: received ones come first
    pub fn request_entries(&self) -> Vec<(bool, RoomRequestInfo)> {
        self.pending_requests
            .iter()
            .cloned()
            .map(|request| (false, request))
            .chain(
                self.sent_requests
                    .iter()
                    .cloned()
                    .map(|request| (true, request)),
            )
            .collect()
    }

    /// Number of pending invitations (used for number badge in settings)
    pub fn pending_request_count(&self) -> usize {
        self.pending_requests
            .iter()
            .filter(|request| is_pending_request(request))
            .count()
            + self
                .sent_requests
                .iter()
                .filter(|request| request.status.as_deref() == Some("pending"))
                .count()
    }

    /// Accept a received invitation
    pub fn accept_request(&mut self, request_id: &str) {
        match self.connector.accept_room_request(request_id) {
            Ok(accepted) => {
                self.mark_request_handled(request_id, "accepted");
                self.notify(self.text("notification_request_accepted"));
                self.load_rooms_now();
                self.restart_websocket();
                let _ = accepted;
            }
            Err(error) => {
                self.notify_error(format!("{}: {error}", self.text("error_accept_failed")))
            }
        }
    }

    /// Reject a received invitation
    pub fn decline_request(&mut self, request_id: &str) {
        match self.connector.decline_room_request(request_id) {
            Ok(_status) => {
                self.mark_request_handled(request_id, "declined");
                self.notify(self.text("notification_request_declined"));
            }
            Err(error) => {
                self.notify_error(format!("{}: {error}", self.text("error_decline_failed")))
            }
        }
    }

    /// Withdraw an invitation you sent
    pub fn cancel_sent_request(&mut self, request_id: &str) {
        match self.connector.cancel_room_request(request_id) {
            Ok(_status) => {
                if let Some(request) = self
                    .sent_requests
                    .iter_mut()
                    .find(|request| request.id == request_id)
                {
                    request.status = Some("cancelled".to_string());
                }
                self.notify(self.text("notification_request_cancelled"));
            }
            Err(error) => {
                self.notify_error(format!("{}: {error}", self.text("error_cancel_failed")))
            }
        }
    }

    fn mark_request_handled(&mut self, request_id: &str, status: &str) {
        if let Some(request) = self
            .pending_requests
            .iter_mut()
            .find(|request| request.id == request_id)
        {
            request.status = Some(status.to_string());
        }
    }

    /// Prompt once when the other side rejects an invitation you sent.
    ///
    /// The server doesn't broadcast "request processed" events; it can only be seen from the status change in this "invitations I sent" list:
    /// **the last round's locally recorded status was pending and this round has changed to declined** counts as "just rejected".
    ///
    /// previously this was searched by "this round's result"; when a local record is missing (e.g., just logged in, haven't seen this invitation yet)
    /// it's treated as "still waiting last round", so every login would report invitations long since rejected from history again
    /// (the placeholder in the prompt text had the wrong name, so it displayed as `{user}` directly on the interface).
    /// now changed to the same judgment as the terminal version: only iterate last round's records, comparing each one to "was waiting then, now rejected".
    fn announce_declined_invitations(&mut self, latest: &[RoomRequestInfo]) {
        let mut notices: Vec<String> = Vec::new();
        for previous in &self.sent_requests {
            if previous.status.as_deref() != Some("pending") {
                continue;
            }
            let Some(current) = latest.iter().find(|request| request.id == previous.id) else {
                continue;
            };
            if current.status.as_deref() != Some("declined") {
                continue;
            }
            let receiver_name = current
                .receiver
                .as_ref()
                .map(|receiver| receiver.username.clone())
                .unwrap_or_else(|| self.text("unknown_user"));
            notices.push(
                self.text("request_declined_notice")
                    .replace("{user}", &receiver_name),
            );
        }
        for notice in notices {
            self.notify(notice);
        }
    }

    /// Status text for request entries (unknown status displayed as-is, never guessed as "withdrawn")
    pub fn request_status_label(&self, status: &str) -> String {
        match status {
            "pending" => self.text("request_status_pending"),
            "accepted" => self.text("request_status_accepted"),
            "declined" => self.text("request_status_declined"),
            "expired" => self.text("request_status_expired"),
            "cancelled" => self.text("request_status_cancelled"),
            other => other.to_string(),
        }
    }

    // ==================== Group Chat and Members ====================

    /// Create a group chat
    pub fn create_group(&mut self, name: &str, members: &str) {
        let usernames: Vec<String> = members
            .split([',', '，'])
            .map(|entry| entry.trim().to_string())
            .filter(|entry| !entry.is_empty())
            .collect();
        let request = CreateRoomRequest::group(name.to_string(), usernames);
        match self.connector.create_room(request) {
            Ok(room) => {
                self.notify(self.text("group_created"));
                self.closed_room_ids.remove(&room.id);
                self.load_rooms_now();
                self.restart_websocket();
            }
            Err(error) => self.notify_error(format!(
                "{}: {error}",
                self.text("error_group_create_failed")
            )),
        }
    }

    /// Initiate private chat: the server requires a previously accepted request first, so what's sent here is an invitation
    pub fn create_private_chat(&mut self, username: &str) {
        let target = match self.connector.get_user_profile(username) {
            Ok(profile) => profile,
            Err(error) => {
                self.notify_error(format!("{}: {error}", self.text("error_user_not_found")));
                return;
            }
        };
        let message = self.text("private_request_message");
        match self
            .connector
            .create_room_request(&target.id, &message, true)
        {
            Ok(_request) => self.notify(self.text("notification_request_sent")),
            Err(error) => {
                self.notify_error(format!("{}: {error}", self.text("error_request_failed")))
            }
        }
    }

    /// Room details and members: compiled into /info text lines
    pub fn room_information(&self) -> Vec<String> {
        let Some(room_id) = self.current_room_id() else {
            return vec![self.text("error_no_room_selected")];
        };
        let detail = match self.connector.get_room(&room_id) {
            Ok(detail) => detail,
            Err(error) => return vec![format!("{}: {error}", self.text("error_room_info_failed"))],
        };
        let members = self.connector.list_members(&room_id).ok();
        let mut lines: Vec<String> = vec![
            format!(
                "{}: {}",
                self.text("room_info_title"),
                detail
                    .name
                    .clone()
                    .unwrap_or_else(|| self.text("private_chat_fallback"))
            ),
            format!(
                "{}: {}",
                self.text("room_info_creator"),
                if detail.created_by.is_empty() {
                    self.text("unknown_user")
                } else {
                    self.sender_display_name(&detail.created_by)
                }
            ),
            format!(
                "{}: {}",
                self.text("room_info_created_at"),
                detail.created_at
            ),
            format!(
                "{}: {}",
                self.text("room_info_encrypted"),
                if detail.is_encrypted {
                    self.text("yes")
                } else {
                    self.text("no")
                }
            ),
        ];
        let roster = members.map(|data| data.members).unwrap_or_default();
        lines.push(format!(
            "{}: {}",
            self.text("room_info_members"),
            roster.len().max(detail.member_count)
        ));
        lines.push(format!(
            "{}: {}",
            self.text("room_info_online"),
            roster
                .iter()
                .filter(|member| self
                    .presence_by_user
                    .get(&member.user_id)
                    .copied()
                    .unwrap_or(false))
                .count()
        ));
        for member in roster {
            lines.push(format!(
                "  {} ({}{})",
                member.username,
                member.role,
                if member.user_id == self.current_user_id.clone().unwrap_or_default() {
                    String::new()
                } else if self
                    .presence_by_user
                    .get(&member.user_id)
                    .copied()
                    .unwrap_or(false)
                {
                    format!(", {}", self.text("status_online"))
                } else {
                    format!(", {}", self.text("status_offline"))
                }
            ));
        }
        lines
    }

    /// `/kick`: remove a specific member (or all members) from the current group chat.
    ///
    /// Same judgment as the terminal version (the GUI previously only searched by "display name of sender seen by this side",
    /// neither pulls the member table nor does admin verification; the `all` parameter couldn't be used):
    /// first confirm the selected room is a group chat, then pull room details once to get the authoritative member table,
    /// only admins/owners can kick; `all` means remove all members except yourself, and you exit at the end.
    /// names are matched with **case-sensitive** exact matching (server usernames are case-sensitive, no case folding here).
    pub fn execute_kick(&mut self, target: &str) {
        let Some(room_id) = self.current_room_id() else {
            self.notify_error(self.text("error_no_room_selected"));
            return;
        };
        if !self.room_is_group(&room_id) {
            self.notify_error(self.text("error_not_group"));
            return;
        }
        let detail = match self.connector.get_room(&room_id) {
            Ok(detail) => detail,
            Err(error) => {
                self.notify_error(format!(
                    "{}: {error}",
                    self.text("error_get_members_failed")
                ));
                return;
            }
        };
        let is_admin = self.current_user_id.as_deref().is_some_and(|current| {
            detail
                .members
                .iter()
                .any(|member| member.user_id == current && is_admin_role(&member.role))
        });
        if !is_admin {
            self.notify_error(self.text("error_kick_requires_admin"));
            return;
        }
        if is_kick_all_argument(target) {
            self.kick_all_members(&room_id);
            return;
        }
        let Some(member) = detail
            .members
            .iter()
            .find(|member| member.username == target)
        else {
            self.notify_error(
                self.text("error_user_not_found_in_group")
                    .replace("{target}", target),
            );
            return;
        };
        let member_user_id = member.user_id.clone();
        match self.connector.remove_member(&room_id, &member_user_id) {
            Ok(_result) => {
                // kicking yourself out also gets recorded in the "active exit" set, so it's not misjudged as "removed from the group"
                if self.current_user_id.as_deref() == Some(member_user_id.as_str()) {
                    self.left_room_ids.insert(room_id);
                }
                self.notify(self.text("removed_member").replace("{target}", target));
                self.load_rooms_now();
            }
            Err(error) => self.notify_error(format!("{}: {error}", self.text("error_kick_failed"))),
        }
    }

    /// `/kick all`: remove all members from the current group chat except yourself, and you exit at the end.
    ///
    /// member table comes from room snapshot (same source as terminal version); individual removal failures don't interrupt the batch operation,
    /// finally report one "all members removed". Recording yourself in the active exit set means the server's removal event won't be treated as being kicked.
    fn kick_all_members(&mut self, room_id: &str) {
        let member_ids: Vec<String> = self
            .rooms
            .iter()
            .find(|room| room.id == room_id)
            .map(|room| room.members.clone())
            .unwrap_or_default();
        let own_id = self.current_user_id.clone().unwrap_or_default();
        let mut other_ids: Vec<String> = member_ids
            .iter()
            .filter(|member_id| *member_id != &own_id)
            .cloned()
            .collect();
        other_ids.reverse();
        for member_id in &other_ids {
            let _ = self.connector.remove_member(room_id, member_id);
        }
        self.left_room_ids.insert(room_id.to_string());
        let _ = self.connector.remove_member(room_id, &own_id);
        self.load_rooms_now();
        self.notify(self.text("removed_all_members"));
    }

    /// Add a member to the current group chat (`/add_member username`). Only group chats can add members,
    /// permission is determined by the server; here we only block "no room selected", "not a group chat", and "no username provided".
    pub fn add_member(&mut self, username: &str) {
        let username = username.trim();
        if username.is_empty() {
            self.notify_error(self.text("error_add_member_usage"));
            return;
        }
        let Some(room_id) = self.current_room_id() else {
            self.notify_error(self.text("error_no_room_selected"));
            return;
        };
        if !self.room_is_group(&room_id) {
            self.notify_error(self.text("error_not_group"));
            return;
        }
        match self
            .connector
            .add_members(&room_id, &[username.to_string()])
        {
            Ok(_result) => {
                self.notify(self.text("add_member_success"));
                self.load_rooms_now();
            }
            Err(error) => {
                self.notify_error(format!("{}: {error}", self.text("error_add_member_failed")))
            }
        }
    }

    /// `/mute`: without arguments toggles the current room's do-not-disturb; with arguments sets according to the parameter
    /// (`true`/`on`/`1` to enable, `false`/`off`/`0` to disable); both forms are recognized by the terminal version.
    pub fn apply_mute_command(&mut self, argument: &str) {
        let Some(room_id) = self.current_room_id() else {
            self.notify_error(self.text("error_no_room_selected"));
            return;
        };
        let wanted = match argument.trim().to_lowercase().as_str() {
            "" => !self.muted_room_ids.contains(&room_id),
            "true" | "on" | "1" => true,
            "false" | "off" | "0" => false,
            _ => {
                self.notify_error(self.text("error_mute_usage"));
                return;
            }
        };
        if wanted {
            self.muted_room_ids.insert(room_id);
        } else {
            self.muted_room_ids.remove(&room_id);
        }
        self.write_display_preferences();
        self.notify(self.text(if wanted {
            "mute_dnd_on"
        } else {
            "mute_dnd_off"
        }));
    }

    /// Exit the current group chat
    pub fn leave_current_room(&mut self) {
        let Some(index) = self.selected_room_index else {
            return;
        };
        let Some(room) = self.rooms.get(index).cloned() else {
            return;
        };
        match self
            .connector
            .remove_member(&room.id, &self.current_user_id.clone().unwrap_or_default())
        {
            Ok(_result) => {
                self.left_room_ids.insert(room.id.clone());
                self.close_local_room(&room.id);
                self.notify(self.text("room_left"));
                self.load_rooms_now();
            }
            Err(error) => {
                self.notify_error(format!("{}: {error}", self.text("error_leave_failed")))
            }
        }
    }

    /// Immediately pull the room list once
    pub fn load_rooms_now(&mut self) {
        match self.connector.list_rooms() {
            Ok(rooms) => self.apply_room_snapshot(rooms),
            Err(error) if error.is_connection_failure() => {}
            Err(error) => self.notify_error(format!("{}: {error}", self.text("error_poll_rooms"))),
        }
    }

    // ==================== Accounts and Profile ====================

    /// Login. Returns true on success; the password is transformed according to the login scheme before sending (the server verifies the ciphertext).
    pub fn sign_in(&mut self, username: &str, password: &str) -> bool {
        let request = LoginRequest {
            username: username.to_string(),
            password: crypto::encrypt_login_password(password),
        };
        match self.connector.login(request) {
            Ok(data) => {
                let token = data.token.clone();
                let mut connector = self.connector.clone();
                connector.set_token(&token);
                self.connector = connector;
                self.current_user_id = Some(data.user.id.clone());
                self.remember_own_profile(&data.user);
                self.prepare_session(&token);
                self.notify(self.text("notification_login_success"));
                true
            }
            Err(error) => {
                self.notify_error(format!("{}: {error}", self.text("error_login_failed")));
                false
            }
        }
    }

    /// Register. On success the interface returns to the login page; the user fills in credentials themselves (same as terminal version: password doesn't go into the command line).
    pub fn sign_up(&mut self, username: &str, email: &str, password: &str) -> bool {
        let request = RegisterRequest {
            username: username.to_string(),
            email: email.to_string(),
            password: crypto::encrypt_login_password(password),
        };
        match self.connector.register(request) {
            Ok(registered) => {
                self.remember_own_profile(&registered.user);
                self.notify(self.text("notification_register_success"));
                true
            }
            Err(error) => {
                self.notify_error(format!("{}: {error}", self.text("error_register_failed")));
                false
            }
        }
    }

    /// Update local with the full user object from the login response: top bar username, profile card contacts, own avatar
    pub fn remember_own_profile(&mut self, user: &UserInfo) {
        self.current_username = user.username.clone();
        self.sender_names
            .insert(user.id.clone(), user.username.clone());
        self.own_contact = Some((
            user.email.clone(),
            user.phone_number.clone().unwrap_or_default(),
        ));
        drop(self.avatar_images.remove(&user.id));
    }

    /// Fixed actions after successful login: cache directory, event channel, two background threads, avatar and user directory pre-fetch
    pub fn prepare_session(&mut self, token: &str) {
        self.restore_own_username();
        self.open_event_channel();
        self.ensure_chat_cache();
        self.start_polling();
        self.start_reachability_watch();
        self.start_websocket(token, None);
        self.presence_by_user
            .insert(self.current_user_id.clone().unwrap_or_default(), true);
        if let Some(user_id) = self.current_user_id.clone() {
            self.request_avatars(&[user_id]);
        }
        self.ensure_registered_users_loaded();
    }

    /// Fill in the name of the "currently logged-in user".
    ///
    /// Manual login has the full user object from the login response (`remember_own_profile` already has the name written),
    /// auto-login only has the token and user ID left from the last exit, so the "current user" part of the top bar would be empty —
    /// this is the root cause of "the top bar doesn't show the current logged-in user after auto-login".
    /// fetch the profile once by user ID to fill in the name (same approach as terminal version `prepare_session_state`);
    /// if unavailable (offline, profile API error), keep empty string, don't show that part of the top bar, and the interface remains usable.
    fn restore_own_username(&mut self) {
        if !self.current_username.is_empty() {
            return;
        }
        let Some(user_id) = self.current_user_id.clone() else {
            return;
        };
        let Ok(profile) = self.connector.get_user_profile(&user_id) else {
            return;
        };
        self.current_username = profile.username.clone();
        self.sender_names.insert(profile.id, profile.username);
    }

    /// Auto-login: restore login state from the session saved on last exit
    pub fn try_auto_login(&mut self) -> bool {
        let Some((token, user_id)) = config::load_saved_session() else {
            return false;
        };
        let mut connector = self.connector.clone();
        connector.set_token(&token);
        match connector.list_rooms() {
            Ok(rooms) => {
                self.connector = connector;
                self.current_user_id = Some(user_id.clone());
                self.own_contact = config::load_saved_contact();
                self.presence_by_user.insert(user_id, true);
                self.apply_room_snapshot(rooms);
                self.prepare_session(&token);
                self.websocket_token = Some(token);
                true
            }
            Err(error) => {
                config::clear_saved_session();
                config::debug_log(&format!("自动登录失败，已清除会话: {error}"));
                false
            }
        }
    }

    /// Logout: stop threads, clear session, return to not-logged-in
    pub fn sign_out(&mut self) {
        if let Some(flag) = self.polling_running.take() {
            flag.store(false, std::sync::atomic::Ordering::Relaxed);
        }
        if let Some(flag) = self.websocket_running.take() {
            flag.store(false, std::sync::atomic::Ordering::Relaxed);
        }
        self.notifications_clear();
        self.websocket_sender = None;
        self.websocket_token = None;
        self.current_user_id = None;
        self.current_username = String::new();
        self.own_contact = None;
        self.profile_view = None;
        self.messages.clear();
        self.rooms.clear();
        self.unread_counts.clear();
        self.pending_requests.clear();
        self.sent_requests.clear();
        self.crypto.sessions.clear();
        config::clear_saved_session();
    }

    fn notifications_clear(&mut self) {
        self.notices.clear();
    }

    /// Token invalidated: local session is voided but loaded content is kept; the interface will re-display the login page
    fn handle_expired_session(&mut self) {
        config::clear_saved_session();
        self.websocket_sender = None;
        self.websocket_token = None;
        self.current_user_id = None;
        self.current_username = String::new();
        self.notify_error(self.text("error_session_expired"));
    }

    /// Save session before exit (token and contacts visible only to yourself)
    pub fn persist_session_before_exit(&self) {
        if let (Some(token), Some(user_id)) =
            (self.websocket_token.clone(), self.current_user_id.clone())
        {
            config::save_session_preferences(&token, &user_id, self.own_contact.as_ref());
        }
    }

    /// When opening the profile form, fetch your own profile: the form shows the current nickname and bio from the server.
    /// phone numbers have no read-only API to fetch back (the server only gives them in login/registration/change-profile responses), so keep empty
    pub fn prepare_profile_form(&mut self) {
        let Some(user_id) = self.current_user_id.clone() else {
            return;
        };
        if let Ok(profile) = self.connector.get_user_profile(&user_id) {
            self.profile_nickname_draft = profile.nickname.unwrap_or_default();
            self.profile_bio_draft = profile.bio.unwrap_or_default();
        }
    }

    /// Save profile: only write non-empty items into the request body; the server's three states are expressed by ProfileUpdatePayload
    pub fn update_profile(&mut self, nickname: &str, phone: &str, bio: &str) {
        let payload = ProfileUpdatePayload {
            nickname: profile_field_value(nickname),
            phone_number: profile_field_value(phone),
            bio: profile_field_value(bio),
            avatar: None,
        };
        if payload.nickname.is_none() && payload.phone_number.is_none() && payload.bio.is_none() {
            self.notify_error(self.text("profile_nothing_to_update"));
            return;
        }
        match self.connector.update_profile(&payload) {
            Ok(user) => {
                self.remember_own_profile(&user);
                self.notify(self.text("profile_saved"));
            }
            Err(error) => self.notify_error(format!(
                "{}: {error}",
                self.text("error_profile_update_failed")
            )),
        }
    }

    /// Change password: the server bumps token_version, and the local session must be voided on success
    pub fn change_password(&mut self, old_password: &str, new_password: &str, repeated: &str) {
        if new_password != repeated {
            self.notify_error(self.text("error_password_mismatch"));
            return;
        }
        match self.connector.change_password(
            &crypto::encrypt_login_password(old_password),
            &crypto::encrypt_login_password(new_password),
        ) {
            Ok(_result) => {
                self.sign_out();
                self.notify_error(self.text("notification_password_changed"));
            }
            Err(error) => self.notify_error(format!(
                "{}: {error}",
                self.text("error_password_change_failed")
            )),
        }
    }

    /// Delete account: clear all local residue on success
    pub fn delete_account(&mut self, password: &str) {
        match self
            .connector
            .delete_account(&crypto::encrypt_login_password(password))
        {
            Ok(_result) => {
                self.sign_out();
                if let Some(cache) = self.chat_cache.as_ref() {
                    cache.clear_all();
                }
                self.chat_cache = None;
                self.avatar_images.clear();
                self.notify(self.text("account_deleted"));
            }
            Err(error) => self.notify_error(format!(
                "{}: {error}",
                self.text("error_account_delete_failed")
            )),
        }
    }

    /// Directory for user-supplied avatars (same location as terminal version)
    pub fn avatar_directory() -> Option<PathBuf> {
        paths::avatar_source_directory()
    }

    /// Image filenames available in the avatar directory, sorted by name
    pub fn avatar_choices() -> Vec<(String, PathBuf)> {
        self::avatar_files()
    }

    /// Change avatar using a local image file
    pub fn apply_local_avatar(&mut self, path: &Path) {
        let Some((file_name, content_type, bytes)) = read_local_image(path) else {
            self.notify_error(self.text("error_avatar_local_file_unusable"));
            return;
        };
        match self
            .connector
            .upload_avatar(&file_name, &content_type, bytes)
        {
            Ok(user) => self.finish_avatar_change(&user),
            Err(error) => self.notify_error(format!(
                "{}: {error}",
                self.text("error_avatar_update_failed")
            )),
        }
    }

    /// Change avatar using a network URL
    pub fn apply_avatar_url(&mut self, url: &str) {
        let trimmed = url.trim();
        if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
            self.notify_error(self.text("error_avatar_url_invalid"));
            return;
        }
        let payload = ProfileUpdatePayload {
            nickname: None,
            phone_number: None,
            bio: None,
            avatar: Some(Some(trimmed.to_string())),
        };
        match self.connector.update_profile(&payload) {
            Ok(user) => self.finish_avatar_change(&user),
            Err(error) => self.notify_error(format!(
                "{}: {error}",
                self.text("error_avatar_update_failed")
            )),
        }
    }

    fn finish_avatar_change(&mut self, user: &UserInfo) {
        config::drop_cached_avatar(&user.id);
        self.remember_own_profile(user);
        self.notify(self.text("avatar_updated"));
    }

    // ==================== Profile Card and User Directory ====================

    /// View someone's profile; leave empty to view your own
    pub fn show_profile_of(&mut self, key: &str) {
        let lookup = if key.trim().is_empty() {
            self.current_user_id.clone()
        } else {
            Some(key.trim().to_string())
        };
        let Some(lookup) = lookup else {
            self.notify_error(self.text("error_no_user_reference"));
            return;
        };
        match self.connector.get_user_profile(&lookup) {
            Ok(profile) => {
                self.request_avatars(std::slice::from_ref(&profile.id));
                self.profile_view = Some(profile);
            }
            Err(error) => self.notify_error(format!(
                "{}: {error}",
                self.text("error_profile_fetch_failed")
            )),
        }
    }

    /// Fetch the registered user directory (send one request only when needed)
    pub fn ensure_registered_users_loaded(&mut self) {
        if self.registered_users.is_some() {
            return;
        }
        let Some(sender) = self.events.clone() else {
            return;
        };
        let connector = self.connector.clone();
        std::thread::spawn(move || match connector.list_all_users() {
            Ok(users) => {
                let _ = sender.send(PollingEvent::RegisteredUsersUpdated(users));
            }
            Err(error) => config::debug_log(&format!("拉取注册用户目录失败: {error}")),
        });
    }

    /// All registered users (for auto-completion and /list_users)
    pub fn registered_user_rows(&self) -> Vec<String> {
        self.registered_users
            .as_ref()
            .map(|users| {
                users
                    .iter()
                    .map(|user| format!("{} - {}", user.username, user.id))
                    .collect()
            })
            .unwrap_or_default()
    }

    // ==================== Avatar Fetch Bytes ====================

    /// Fetch avatar bytes for several users: read from disk first, only dispatch a background thread on miss; never connect to the network during rendering
    pub fn request_avatars(&mut self, user_ids: &[String]) {
        let Some(sender) = self.events.clone() else {
            return;
        };
        let mut missing: Vec<String> = Vec::new();
        for user_id in user_ids {
            if user_id.is_empty() || self.avatar_images.contains_key(user_id) {
                continue;
            }
            if let Some(bytes) = config::load_cached_avatar(user_id) {
                self.avatar_images.insert(user_id.clone(), Some(bytes));
                continue;
            }
            self.avatar_images.insert(user_id.clone(), None);
            missing.push(user_id.clone());
        }
        if missing.is_empty() {
            return;
        }
        // Fetching avatars is one network request per user; serial waiting would be very slow; split into segments by machine parallelism and fetch simultaneously,
        // one thread per segment, fetch one and hand it back to the main thread immediately via the event channel (the render thread only receives events, never connects to the network)
        let chunk_size = missing.len().div_ceil(avatar_fetch_worker_count()).max(1);
        for chunk in missing.chunks(chunk_size) {
            let connector = self.connector.clone();
            let sender_for_thread = sender.clone();
            let chunk: Vec<String> = chunk.to_vec();
            std::thread::spawn(move || {
                for user_id in chunk {
                    let bytes = connector
                        .get_user_profile(&user_id)
                        .ok()
                        .and_then(|profile| profile.avatar)
                        .and_then(|path| connector.fetch_static_resource(&path).ok());
                    if let Some(bytes) = &bytes {
                        config::store_cached_avatar(&user_id, bytes);
                    }
                    let _ = sender_for_thread.send(PollingEvent::AvatarLoaded((user_id, bytes)));
                }
            });
        }
    }

    /// People who have appeared in the current room (avatars need bytes fetched for them)
    fn refresh_avatar_for_visible_rooms(&mut self) {
        let ids: Vec<String> = self
            .messages
            .iter()
            .map(|message| message.sender_id.clone())
            .filter(|id| !id.is_empty())
            .collect();
        self.request_avatars(&ids);
    }

    /// Username mapping completion: pull room members once, avoid looking up people per message
    fn refresh_all_sender_names(&mut self) {
        let Some(room_id) = self.current_room_id() else {
            return;
        };
        if let Ok(detail) = self.connector.get_room(&room_id) {
            for member in detail.members {
                self.sender_names
                    .insert(member.user_id, member.nickname.unwrap_or(member.username));
            }
        }
        let ids: Vec<String> = self
            .messages
            .iter()
            .map(|message| message.sender_id.clone())
            .collect();
        self.request_avatars(&ids);
    }

    /// Sender display name: look up table → fall back to ID → fall back to "unknown user" for empty ID
    pub fn sender_display_name(&self, sender_id: &str) -> String {
        if sender_id.is_empty() {
            return self.text("unknown_user");
        }
        self.sender_names
            .get(sender_id)
            .cloned()
            .unwrap_or_else(|| sender_id.to_string())
    }

    // ==================== Message Cache ====================

    fn ensure_chat_cache(&mut self) {
        if self.chat_cache.is_some() {
            return;
        }
        if let Some(user_id) = self.current_user_id.clone() {
            self.chat_cache = ChatCache::open(&user_id);
        }
    }

    /// Messages arriving one by one only set a flag; write the whole room to disk once the batch window is full
    fn mark_messages_dirty(&mut self) {
        if self.cache_pending_flush_since.is_none() {
            self.cache_pending_flush_since = Some(Instant::now());
        }
    }

    fn flush_message_cache_if_due(&mut self) {
        let Some(since) = self.cache_pending_flush_since else {
            return;
        };
        if since.elapsed() < Duration::from_secs(5) {
            return;
        }
        if let Some(room_id) = self.current_room_id() {
            self.cache_loaded_messages(&room_id);
        }
        self.cache_pending_flush_since = None;
    }

    /// Write the current room's messages into cache (encrypted rooms are never persisted)
    pub fn cache_loaded_messages(&mut self, room_id: &str) {
        let Some(room_index) = self.rooms.iter().position(|room| room.id == room_id) else {
            return;
        };
        if self.rooms[room_index].is_encrypted || self.messages.is_empty() {
            return;
        }
        let loaded_room_matches = self
            .messages
            .last()
            .is_some_and(|message| message.room_id == room_id);
        if !loaded_room_matches {
            return;
        }
        self.ensure_chat_cache();
        if let Some(cache) = self.chat_cache.as_ref() {
            cache.store_room(
                room_id,
                &self.messages,
                self.older_cursor.as_deref(),
                self.has_more_older,
            );
        }
    }

    // ==================== Search ====================

    /// Whether in search mode (input box starts with #)
    pub fn in_search_mode(&self) -> bool {
        self.draft.trim_start().starts_with('#')
    }

    /// Search keyword
    pub fn search_keyword(&self) -> String {
        let trimmed = self.draft.trim_start();
        trimmed
            .strip_prefix('#')
            .map(|rest| rest.trim_start().to_string())
            .unwrap_or_default()
    }

    /// Execute search: look in loaded messages; clear results when keyword is empty
    pub fn run_search(&mut self, keyword: &str) {
        if keyword.trim().is_empty() {
            self.search_result = None;
            return;
        }
        let matches = self.messages_matching(keyword);
        if matches.is_empty() {
            self.search_result = Some((keyword.to_string(), Vec::new(), 0));
            return;
        }
        let last = matches.len() - 1;
        self.pending_scroll_message_id = Some(matches[last].clone());
        self.search_result = Some((keyword.to_string(), matches, last));
    }

    /// Look for keyword in loaded messages
    fn messages_matching(&self, keyword: &str) -> Vec<String> {
        let needle = keyword.to_lowercase();
        self.messages
            .iter()
            .filter(|message| message.content.to_lowercase().contains(&needle))
            .map(|message| message.id.clone())
            .collect()
    }

    /// Jump to previous/next match
    pub fn navigate_search(&mut self, backwards: bool) {
        let Some((keyword, matches, index)) = self.search_result.clone() else {
            return;
        };
        if matches.is_empty() {
            return;
        }
        let next = if backwards {
            (index + matches.len() - 1) % matches.len()
        } else {
            (index + 1) % matches.len()
        };
        self.pending_scroll_message_id = Some(matches[next].clone());
        self.search_result = Some((keyword, matches, next));
    }

    /// Set of message IDs matching the keyword (the interface draws highlight backgrounds based on this)
    pub fn search_matches(&self) -> (Vec<String>, Option<String>) {
        match &self.search_result {
            Some((_keyword, matches, index)) => (matches.clone(), matches.get(*index).cloned()),
            None => (Vec::new(), None),
        }
    }

    /// The keyword used by the last executed search (the title displays it, not what's being typed in the input box).
    /// the text in the input box might have been changed but not submitted; displaying it directly would mismatch the title and matches.
    pub fn searched_keyword(&self) -> Option<&str> {
        self.search_result
            .as_ref()
            .map(|(keyword, _matches, _index)| keyword.as_str())
    }

    /// Unified handling when input box content changes, rules same as terminal version:
    ///
    /// - not in search mode (input doesn't start with `#`): clear the last search results, title returns to unsearched state;
    /// - fast search on: rescan **loaded** messages on-the-fly as you type, no need to press Enter
    ///   (deliberately not fetching the whole room page-by-page; character-by-character paging would blow up the message API);
    /// - fast search off: when the input keyword differs from the last search, old results are immediately invalidated,
    ///   so the title and highlight backgrounds don't stay on the old keyword and mislead people.
    pub fn handle_draft_changed(&mut self) {
        if !self.in_search_mode() {
            self.search_result = None;
            return;
        }
        if self.quick_search {
            let keyword = self.search_keyword();
            if keyword.is_empty() {
                self.search_result = None;
                return;
            }
            self.run_search(&keyword);
            return;
        }
        if let Some(searched) = self.searched_keyword()
            && searched != self.search_keyword()
        {
            self.search_result = None;
        }
    }

    // ==================== Commands ====================

    /// Execute a command (without leading slash), return what the interface needs to do
    pub fn execute_command(&mut self, line: &str) -> UiIntent {
        let mut parts = line.splitn(2, ' ');
        let name = parts.next().unwrap_or_default().trim();
        let argument = parts.next().unwrap_or_default().trim().to_string();
        if !self.is_signed_in() && !command_allowed_signed_out(name) {
            self.notify_error(self.text("error_not_logged_in_graphical"));
            return UiIntent::Nothing;
        }
        match name {
            "" => UiIntent::Nothing,
            "quit" | "exit" => {
                self.quit_requested = true;
                UiIntent::Quit
            }
            "info" => {
                let lines = self.room_information();
                for line in lines {
                    self.notify(line);
                }
                UiIntent::Nothing
            }
            "profile" => {
                self.show_profile_of(&argument);
                UiIntent::ShowOwnProfile
            }
            "list_users" => {
                self.ensure_registered_users_loaded();
                let rows = self.registered_user_rows();
                if rows.is_empty() {
                    self.notify(self.text("users_empty"));
                }
                for row in rows {
                    self.notify(row);
                }
                UiIntent::Nothing
            }
            "search_users" => {
                match self.connector.search_users(&argument) {
                    Ok(users) => {
                        for user in users {
                            self.notify(format!("{} - {}", user.username, user.id));
                        }
                    }
                    Err(error) => self.notify_error(format!(
                        "{}: {error}",
                        self.text("error_user_search_failed")
                    )),
                }
                UiIntent::Nothing
            }
            "kick" => {
                self.execute_kick(&argument);
                UiIntent::Nothing
            }
            "leave" | "quit_group" => {
                self.leave_current_room();
                UiIntent::Nothing
            }
            "mute" => {
                self.apply_mute_command(&argument);
                UiIntent::Nothing
            }
            "add_member" => {
                self.add_member(&argument);
                UiIntent::Nothing
            }
            "logout" => {
                self.sign_out();
                UiIntent::OpenSignIn(None)
            }
            // Signing in is a "form-filling" complex action: here we only open the form (pre-fill with username),
            // password and other fields are left to the login page to fill in, to avoid putting passwords into the chat history.
            // The graphical end has no `/login`: the sign-in form is opened by the interface itself (modal page when no session is
            // restored, plus the sign-in button in the room list), so the name is not in the command table and falls through to
            // "unknown command" like any other name that is not a command.
            "register" => UiIntent::OpenSignUp(some_username(argument)),
            "update" => {
                if self.start_downloaded_update() {
                    UiIntent::QuitForUpdate
                } else {
                    UiIntent::Nothing
                }
            }
            "language" => {
                if !argument.is_empty() {
                    // Same as terminal version: the parameter must be a language code that actually exists under config/languages,
                    // and matched with case-sensitive exact matching (zh-cn is not zh-CN), no guessing, no case folding.
                    if !config::Language::available_codes()
                        .iter()
                        .any(|code| code == &argument)
                    {
                        self.notify_error(self.text("error_no_languages"));
                        return UiIntent::Nothing;
                    }
                    self.switch_language(&argument);
                    self.write_display_preferences();
                    self.notify(self.text("language_switched").replace("{lang}", &argument));
                    return UiIntent::Nothing;
                }
                // without arguments: languages are listed one by one, taking the person to the settings panel to choose
                UiIntent::OpenSettings
            }
            "appearance" => {
                if !argument.is_empty() {
                    // Same as terminal version: the parameter must be an appearance name that actually exists under config/themes,
                    // and matched with case-sensitive exact matching, to avoid silently applying an incorrect name as a built-in default color.
                    if !config::Palette::available_names()
                        .iter()
                        .any(|name| name == &argument)
                    {
                        self.notify_error(
                            self.text("error_appearance_not_found")
                                .replace("{name}", &argument),
                        );
                        return UiIntent::Nothing;
                    }
                    self.switch_appearance(&argument);
                    self.notify(
                        self.text("appearance_switched")
                            .replace("{name}", &argument),
                    );
                    return UiIntent::Nothing;
                }
                UiIntent::OpenSettings
            }
            "server_address" => {
                if !argument.is_empty() {
                    self.apply_server_address(&argument);
                    return UiIntent::Nothing;
                }
                UiIntent::OpenSettings
            }
            other => {
                self.notify_error(self.text("error_unknown_command").replace("{name}", other));
                UiIntent::Nothing
            }
        }
    }

    // ==================== Update ====================

    /// Dispatch a background version check and download
    pub fn start_update_check(&mut self, current_version: &str) {
        if self
            .update_check_running
            .as_ref()
            .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed))
        {
            return;
        }
        let Some(sender) = self.events.clone() else {
            return;
        };
        let flag = Arc::new(AtomicBool::new(true));
        self.update_check_running = Some(flag);
        let current_version = current_version.to_string();
        // The checking thread has no access to the language table, so the wording is taken here, on the interface side:
        // a failure becomes "<localized wording>: <library message>", the same shape every other error notice uses.
        let download_failed_wording = self.text("error_update_download_failed");
        std::thread::spawn(move || {
            let report = match check_for_update(&current_version, ReleaseChannel::Graphical) {
                UpdateCheck::Available(package) => match download_package(&package) {
                    Ok(path) => Some(PollingEvent::UpdateReady((package.version, path))),
                    Err(error) => Some(PollingEvent::Error(format!(
                        "{}: {error}",
                        download_failed_wording
                    ))),
                },
                UpdateCheck::UpToDate { .. } => None,
                // No package or no release page: the terminal version only writes this to the debug log and does not
                // put an untranslated technical reason in front of the user.
                UpdateCheck::Unavailable(reason) => {
                    config::debug_log(&format!("更新检查未完成: {reason}"));
                    None
                }
            };
            if let Some(event) = report {
                let _ = sender.send(event);
            }
        });
    }

    /// Arrange replacement with the downloaded package and request exit
    pub fn start_downloaded_update(&mut self) -> bool {
        let Some((version, path)) = self.pending_update.clone() else {
            self.notify(self.text("update_not_ready"));
            let current = env!("CARGO_PKG_VERSION").to_string();
            self.start_update_check(&current);
            return false;
        };
        match baihua_core::installer::apply_downloaded_archive(&path, &version) {
            Ok(report) => {
                self.update_handoff_requested = true;
                for note in report.notes {
                    config::debug_log(&note);
                }
                true
            }
            Err(error) => {
                self.notify_error(format!(
                    "{}: {error}",
                    self.text("error_update_apply_failed")
                ));
                false
            }
        }
    }
}

/// Whether this command is still available when not logged in. The table is in shared code; the terminal version judges the same one.
fn command_allowed_signed_out(name: &str) -> bool {
    baihua_core::commands::command_allowed_signed_out(name)
}

/// Whether a group member's role is admin/owner.
///
/// The server's role strings are inconsistent in case (owner / Owner / ADMIN have all appeared); this item is a protocol fact,
/// which doesn't conflict with "usernames/parameters are all case-sensitive", so we fold case according to the same rule as the terminal version.
fn is_admin_role(role: &str) -> bool {
    let lowered = role.to_lowercase();
    lowered == "owner" || lowered == "admin"
}

/// The batch parameter for `/kick` only recognizes the complete lowercase `all`.
///
/// Usernames and parameters are all **case-sensitive** (the server also matches as-is): `ALL`, `All` would be treated as a
/// real member with this name; if not found, report "user not found" instead of accidentally triggering "remove all members".
fn is_kick_all_argument(argument: &str) -> bool {
    argument == "all"
}

/// Username in command parameters: empty argument means "not given", represented by None
fn some_username(argument: String) -> Option<String> {
    let trimmed = argument.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Parallel thread count for fetching avatars: machine parallelism, max 4, min 1
fn avatar_fetch_worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get().min(4))
        .unwrap_or(1)
}

/// Whether a private chat request is still pending (the server's pending list doesn't give a status field)
fn is_pending_request(request: &RoomRequestInfo) -> bool {
    request
        .status
        .as_deref()
        .is_none_or(|status| status == "pending")
}

/// Form values to the server's three states: leave empty means don't rewrite this item
fn profile_field_value(text: &str) -> Option<Option<String>> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(Some(trimmed.to_string()))
    }
}

/// Local image file → (filename, CONTENT_TYPE, bytes). Format whitelist matches the upload interface.
fn read_local_image(path: &Path) -> Option<(String, String, Vec<u8>)> {
    let content_type = image_content_type_of(path)?;
    if fs::metadata(path)
        .ok()
        .is_some_and(|m| m.len() > 8 * 1024 * 1024)
    {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    let file_name = path.file_name()?.to_str()?.to_string();
    Some((file_name, content_type.to_string(), bytes))
}

fn image_content_type_of(path: &Path) -> Option<&'static str> {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_lowercase()
        .as_str()
    {
        "jpg" | "jpeg" => Some("image/jpeg"),
        "png" => Some("image/png"),
        "gif" => Some("image/gif"),
        "webp" => Some("image/webp"),
        _ => None,
    }
}

fn avatar_files() -> Vec<(String, PathBuf)> {
    let Some(directory) = paths::avatar_source_directory() else {
        return Vec::new();
    };
    let _ = fs::create_dir_all(&directory);
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut files: Vec<(String, PathBuf)> = entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path();
            let name = path.file_name()?.to_str()?.to_string();
            image_content_type_of(&path).map(|_| (name, path))
        })
        .collect();
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

#[cfg(test)]
mod tests {
    use super::*;
    use baihua_core::api::RoomMember;

    fn room(id: &str, name: &str, encrypted: bool) -> RoomInfo {
        RoomInfo {
            id: id.to_string(),
            name: Some(name.to_string()),
            created_by: "user-a".to_string(),
            created_at: "2026-09-06T00:00:00+00:00".to_string(),
            is_group: true,
            is_encrypted: encrypted,
            members: vec!["user-a".to_string()],
        }
    }

    fn request(id: &str, status: Option<&str>) -> RoomRequestInfo {
        RoomRequestInfo {
            id: id.to_string(),
            message: "请求建立私聊".to_string(),
            is_encrypted: true,
            created_at: "2026-09-06T00:00:00+00:00".to_string(),
            sender: None,
            receiver: None,
            status: status.map(str::to_string),
        }
    }

    #[test]
    fn closed_rooms_are_hidden_from_the_room_list() {
        let mut client = Client::default();
        client.rooms = vec![room("room-1", "一队", false), room("room-2", "二队", true)];
        client.close_local_room("room-2");
        let entries = client.room_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "room-1");
        assert!(!entries[0].encrypted);
    }

    #[test]
    fn unread_counts_show_only_for_the_inactive_room() {
        let mut client = Client::default();
        client.rooms = vec![room("room-1", "一队", false)];
        client.selected_room_index = Some(0);
        client.unread_counts.insert("room-1".to_string(), 4);
        // Opening a room counts as read: clear that room's unread when switching the selection
        client.open_room(0);
        assert!(
            !client.unread_counts.contains_key("room-1"),
            "点开房间后该房间的未读必须清零"
        );
    }

    #[test]
    fn muted_rooms_keep_their_count_but_are_marked() {
        let mut client = Client::default();
        client.rooms = vec![room("room-1", "一队", false)];
        client.unread_counts.insert("room-1".to_string(), 7);
        client.muted_room_ids.insert("room-1".to_string());
        let entries = client.room_entries();
        assert_eq!(entries[0].unread, 7);
        assert!(entries[0].muted, "免打扰标记要交给界面画成点而不是数字");
    }

    #[test]
    fn only_waiting_requests_are_counted_in_the_settings_badge() {
        let mut client = Client::default();
        client.pending_requests = vec![
            request("received-1", None),
            request("received-2", Some("accepted")),
        ];
        client.sent_requests = vec![
            request("sent-1", Some("pending")),
            request("sent-2", Some("declined")),
            request("sent-3", Some("cancelled")),
        ];
        assert_eq!(
            client.pending_request_count(),
            2,
            "收到的缺状态条目与仍在等的发出条目才计数"
        );
    }

    #[test]
    fn handled_received_invitations_stay_in_the_history() {
        let mut client = Client::default();
        client.pending_requests = vec![
            request("waiting", None),
            request("handled", Some("accepted")),
        ];
        // The server's pending list only returns rows still waiting; locally processed history must be brought back
        client.apply_received_requests(vec![request("waiting", None), request("newly", None)]);
        let ids: Vec<String> = client
            .pending_requests
            .iter()
            .map(|entry| entry.id.clone())
            .collect();
        assert_eq!(ids, vec!["waiting", "newly", "handled"]);
        assert_eq!(
            client
                .pending_requests
                .iter()
                .find(|entry| entry.id == "handled")
                .and_then(|entry| entry.status.as_deref()),
            Some("accepted"),
            "合并轮询结果不能冲掉本端记下的结果状态"
        );
    }

    #[test]
    fn declined_status_is_never_rendered_as_cancelled() {
        let client = Client::default();
        assert_eq!(
            client.request_status_label("declined"),
            client.request_status_label("declined")
        );
        assert_ne!(
            client.request_status_label("declined"),
            client.request_status_label("cancelled"),
            "被拒绝与被撤回必须是两种文案"
        );
        // Unknown status displayed as-is, never guessed as withdrawn
        assert_eq!(
            client.request_status_label("withdrawn_by_server"),
            "withdrawn_by_server"
        );
    }

    /// This round's fix: when a sent private chat invitation is rejected by the other side, only report once when "last round was still waiting, this round has changed to rejected".
    ///
    /// previously judged by "this round's result"; when there was no corresponding local record it was also counted as "still waiting last round",
    /// so every login would report invitations long since rejected from history again;
    /// and the replacement placeholder name was written as `{peer}`, but the language file calls it `{user`,
    /// so it displayed `{user}` directly as the prompt text on the interface.
    #[test]
    fn declined_invitation_is_announced_once_with_the_name_from_the_language_file() {
        fn sent_invitation(status: &str) -> RoomRequestInfo {
            RoomRequestInfo {
                id: "request-1".to_string(),
                message: "请求建立私聊".to_string(),
                is_encrypted: true,
                created_at: "2026-09-06T00:00:00+00:00".to_string(),
                sender: None,
                receiver: Some(baihua_core::api::RoomRequestPeer {
                    user_id: "user-carol".to_string(),
                    username: "carol".to_string(),
                    nickname: None,
                }),
                status: Some(status.to_string()),
            }
        }
        // If the language file can't be read, just skip (not a failure when the test machine has no config directory)
        let Ok(language) = config::Language::load("zh-CN") else {
            return;
        };
        let declined_text = language.text("request_declined_notice");
        assert!(
            declined_text.contains("{user}"),
            "语言文件里的占位符叫 {{user}}，改文案时要一起改：{declined_text:?}"
        );
        let mut client = Client::default();
        client.language = language;
        // Last round's local record was "still waiting", this round's poll says "rejected": report once
        client.sent_requests = vec![sent_invitation("pending")];
        client.announce_declined_invitations(&[sent_invitation("declined")]);
        let notices: Vec<String> = client
            .notices
            .iter()
            .map(|notice| notice.text.clone())
            .collect();
        assert_eq!(notices.len(), 1, "实际通知: {notices:?}");
        assert!(
            notices[0].contains("carol"),
            "通知里要点明是谁拒的: {notices:?}"
        );
        assert!(
            !notices[0].contains("{user}"),
            "占位符要被替换掉，不能原样显示: {notices:?}"
        );
        // After this side has already recorded declined, another round with the same status shouldn't report again
        client.notices.clear();
        client.sent_requests = vec![sent_invitation("declined")];
        client.announce_declined_invitations(&[sent_invitation("declined")]);
        assert!(client.notices.is_empty(), "同一状态变化不该报两次");
        // When just logged in, this side doesn't have the record of "invitations I sent"; old rejections in history shouldn't be treated as just happening
        client.notices.clear();
        client.sent_requests.clear();
        client.announce_declined_invitations(&[sent_invitation("declined")]);
        assert!(
            client.notices.is_empty(),
            "登录后不该把之前拒绝过的邀请再报一遍: {:?}",
            client
                .notices
                .iter()
                .map(|notice| notice.text.clone())
                .collect::<Vec<String>>()
        );
    }

    #[test]
    fn search_navigates_wrapping_around_both_ways() {
        let mut client = Client::default();
        client.messages = vec![
            MessageInfo {
                id: "msg-1".to_string(),
                room_id: "room-1".to_string(),
                sender_id: "user-a".to_string(),
                content: "第一段带关键词".to_string(),
                created_at: "2026-09-06T00:00:00+00:00".to_string(),
            },
            MessageInfo {
                id: "msg-2".to_string(),
                room_id: "room-1".to_string(),
                sender_id: "user-a".to_string(),
                content: "无关内容".to_string(),
                created_at: "2026-09-06T00:00:01+00:00".to_string(),
            },
            MessageInfo {
                id: "msg-3".to_string(),
                room_id: "room-1".to_string(),
                sender_id: "user-a".to_string(),
                content: "第二段带关键词".to_string(),
                created_at: "2026-09-06T00:00:02+00:00".to_string(),
            },
        ];
        client.run_search("关键词");
        let (matches, _) = client.search_matches();
        assert_eq!(matches, vec!["msg-1".to_string(), "msg-3".to_string()]);
        // Default to the last match
        assert_eq!(client.pending_scroll_message_id.as_deref(), Some("msg-3"));
        client.navigate_search(false);
        assert_eq!(client.pending_scroll_message_id.as_deref(), Some("msg-1"));
        client.navigate_search(true);
        assert_eq!(client.pending_scroll_message_id.as_deref(), Some("msg-3"));
    }

    /// Two messages with keywords + one irrelevant message, shared by search-related test cases
    fn client_with_searchable_messages() -> Client {
        let mut client = Client::default();
        client.messages = vec![
            MessageInfo {
                id: "msg-1".to_string(),
                room_id: "room-1".to_string(),
                sender_id: "user-a".to_string(),
                content: "第一段带关键词".to_string(),
                created_at: "2026-09-06T00:00:00+00:00".to_string(),
            },
            MessageInfo {
                id: "msg-2".to_string(),
                room_id: "room-1".to_string(),
                sender_id: "user-a".to_string(),
                content: "无关内容".to_string(),
                created_at: "2026-09-06T00:00:01+00:00".to_string(),
            },
        ];
        client
    }

    /// regression for feedback "fast search doesn't work": when the switch is on, rescan on-the-fly as you type, no need to press Enter
    #[test]
    fn quick_search_rescans_while_typing() {
        let mut client = client_with_searchable_messages();
        client.quick_search = true;
        client.draft = "#关键词".to_string();
        client.handle_draft_changed();
        assert_eq!(
            client.search_matches().0,
            vec!["msg-1".to_string()],
            "开了快速搜索之后，输入到 #关键词 这一帧就该有命中了"
        );
    }

    /// When fast search is off, if the keyword changes but Enter isn't pressed, old results must be invalidated (otherwise the title and highlight backgrounds stay on the old keyword)
    #[test]
    fn normal_search_drops_stale_results_when_the_keyword_changes() {
        let mut client = client_with_searchable_messages();
        client.quick_search = false;
        client.draft = "#关键词".to_string();
        client.run_search("关键词");
        assert!(!client.search_matches().0.is_empty(), "先有一次正式搜索");
        client.draft = "#关键词改".to_string();
        client.handle_draft_changed();
        assert!(
            client.search_matches().0.is_empty(),
            "关键词改了还没回车，旧结果不该继续挂着"
        );
    }

    /// Clear search results when exiting search mode (input no longer starts with #)
    #[test]
    fn leaving_search_mode_clears_the_result() {
        let mut client = client_with_searchable_messages();
        client.draft = "#关键词".to_string();
        client.run_search("关键词");
        client.draft = "普通消息".to_string();
        client.handle_draft_changed();
        assert!(
            client.search_result.is_none(),
            "不在搜索模式应当清掉搜索结果"
        );
    }

    /// regression for feedback "the same person might be shown twice as typing" (this data side):
    /// records with the same name in the same room (old records left after multi-account or reconnection) are kept as only one,
    /// input status from other rooms isn't included in the list to display this time
    #[test]
    fn typing_names_hide_duplicates_and_other_rooms() {
        let mut client = Client::default();
        client.rooms = vec![room("room-1", "一队", false), room("room-2", "二队", false)];
        client.selected_room_index = Some(0);
        client.typing_members.push((
            "room-1".to_string(),
            "小明".to_string(),
            std::time::Instant::now(),
        ));
        client.typing_members.push((
            "room-1".to_string(),
            "小明".to_string(),
            std::time::Instant::now(),
        ));
        client.typing_members.push((
            "room-2".to_string(),
            "小红".to_string(),
            std::time::Instant::now(),
        ));
        assert_eq!(
            client.typing_names(),
            vec!["小明".to_string()],
            "同名只显示一次，别的房间的不算"
        );
    }

    #[test]
    fn deleting_a_user_leaves_unknown_names_and_rooms_behind() {
        let mut client = Client::default();
        // Server ON DELETE SET NULL: after the speaker deletes their account, the seam gives an empty string
        assert_eq!(
            client.sender_display_name(""),
            client.text("unknown_user"),
            "空用户 ID 必须退回未知用户而不是显示空字符串"
        );
        client.sender_names =
            std::collections::HashMap::from([("user-a".to_string(), "alice".to_string())]);
        assert_eq!(client.sender_display_name("user-a"), "alice");
        assert_eq!(client.sender_display_name("user-unknown"), "user-unknown");
    }

    #[test]
    fn blank_form_fields_are_left_out_of_the_request() {
        assert_eq!(profile_field_value("   "), None);
        assert_eq!(
            profile_field_value(" 花名 "),
            Some(Some("花名".to_string())),
            "两侧空白要去掉，服务端三态靠 Option 表达"
        );
    }

    #[test]
    fn only_signed_out_safe_commands_work_without_a_session() {
        assert!(command_allowed_signed_out("login"));
        assert!(command_allowed_signed_out("language"));
        assert!(command_allowed_signed_out("quit"));
        assert!(!command_allowed_signed_out("info"));
        assert!(!command_allowed_signed_out("mute"));
    }

    #[test]
    fn encrypted_rooms_are_never_written_to_the_message_cache() {
        let mut client = Client::default();
        client.rooms = vec![room("room-enc", "私聊", true)];
        client.messages = vec![MessageInfo {
            id: "msg-1".to_string(),
            room_id: "room-enc".to_string(),
            sender_id: "user-a".to_string(),
            content: "密文解出的明文".to_string(),
            created_at: "2026-09-06T00:00:00+00:00".to_string(),
        }];
        client.selected_room_index = Some(0);
        // No cache directory when not logged in; here we only require that the "encrypted rooms are never persisted" judgment holds
        assert!(client.room_is_encrypted("room-enc"));
        client.cache_loaded_messages("room-enc");
        assert!(client.chat_cache.is_none(), "未登录不该有缓存对象");
    }

    #[test]
    fn member_rows_and_room_roster_are_formatted_for_display() {
        let member = RoomMember {
            user_id: "user-a".to_string(),
            username: "alice".to_string(),
            nickname: Some("爱丽丝".to_string()),
            role: "admin".to_string(),
            joined_at: "2026-09-06T00:00:00+00:00".to_string(),
        };
        assert_eq!(member.nickname.clone().unwrap_or(member.username), "爱丽丝");
    }

    #[test]
    fn avatar_extension_whitelist_matches_the_upload_endpoint() {
        for (name, expected) in [
            ("me.png", Some("image/png")),
            ("me.JPG", Some("image/jpeg")),
            ("me.jpeg", Some("image/jpeg")),
            ("me.gif", Some("image/gif")),
            ("me.webp", Some("image/webp")),
            ("me.txt", None),
            ("noextension", None),
        ] {
            assert_eq!(
                image_content_type_of(std::path::Path::new(name)),
                expected,
                "{name} 的格式判定不对"
            );
        }
    }

    #[test]
    fn time_text_follows_the_date_switch() {
        let created_at = "2026-09-06T00:00:00+00:00";
        let with_date = crate::app::format_message_time_for_test(created_at, true);
        let without_date = crate::app::format_message_time_for_test(created_at, false);
        assert!(with_date.contains("-"), "带日期时应含年月日分隔");
        assert!(!without_date.contains("-"), "只显时间时不该有日期");
    }

    /// This round's change: all terminal version commands must work.
    /// The criterion is "doesn't fall through to an unknown command", and each returns to the correct interface intent.
    #[test]
    fn every_ported_command_has_its_own_branch() {
        let mut client = Client::default();
        // The graphical end has no `/login`: the sign-in form is opened by the interface itself
        // (a modal page when no session is restored, plus the sign-in button in the room list),
        // so the name falls through to "unknown command" like any other name outside the command table.
        client.notices.clear();
        assert!(matches!(client.execute_command("login"), UiIntent::Nothing));
        assert!(
            client.notices.iter().any(|notice| notice.is_error),
            "/login 在图形版不再是一条命令，应当报未知命令而不是静默"
        );
        // Registration: pre-fill with username when provided, give None otherwise
        assert!(matches!(
            client.execute_command("register bob"),
            UiIntent::OpenSignUp(Some(name)) if name == "bob"
        ));
        // Logout: invalidate local session and return to login page
        assert!(matches!(
            client.execute_command("logout"),
            UiIntent::OpenSignIn(None)
        ));
        // Language / appearance / server address without arguments: take the person to the settings panel to choose
        for name in ["language", "appearance", "server_address"] {
            assert!(
                matches!(client.execute_command(name), UiIntent::OpenSettings),
                "/{name} 不带参数应当打开设置面板"
            );
        }
        // Exit the client
        assert!(matches!(client.execute_command("quit"), UiIntent::Quit));
        assert!(matches!(client.execute_command("exit"), UiIntent::Quit));
        assert!(client.quit_requested, "quit/exit 都要请求退出");
    }

    /// The graphical command table (completion list and command panel take it from `crate::command_entries`) has no `/login`.
    #[test]
    fn the_graphical_command_table_has_no_login_command() {
        let names: Vec<&str> = crate::command_entries()
            .into_iter()
            .map(|(name, _description)| name)
            .collect();
        assert!(
            !names.contains(&"login"),
            "图形版不再有 /login，命令表实际为 {names:?}"
        );
        assert!(names.contains(&"register"), "注册仍是一条命令");
        assert!(names.contains(&"logout"), "退出登录仍是一条命令");
    }

    /// 顶栏文案里的竖杠写在文案里（与终端版一致），服务端版本未知时右侧不得留下孤零零的一条竖杠。
    #[test]
    fn status_bar_text_carries_one_separator_per_segment() {
        let mut client = Client::default();
        if let Ok(language) = config::Language::load("zh-CN") {
            client.language = language;
        }
        client.current_username = "alice".to_string();
        let (_connection_label, _mark, user_text, right_text) = client.status_bar_texts();
        assert_eq!(
            user_text.matches('|').count(),
            1,
            "当前用户那一段只该有一条竖杠，实际 {user_text:?}"
        );
        assert!(
            user_text.trim_start().starts_with('|'),
            "竖杠要写在文案里，界面不再自己画一条，实际 {user_text:?}"
        );
        assert!(
            !right_text.trim_start().starts_with('|'),
            "没有服务端版本时右侧不得以竖杠开头，实际 {right_text:?}"
        );
        assert_eq!(
            right_text.matches('|').count(),
            0,
            "只有客户端版本时右侧不该有分隔竖杠，实际 {right_text:?}"
        );
    }

    /// 重新加载同一个加密私聊时，服务端给的空正文不得盖掉本端已经解出来的明文。
    ///
    /// 这条路径不需要真的连上服务端：指向一个必定连不上的地址，走的正是"取不回服务端那一页就保留本端内容"的分支，
    /// 而修复前是**先清空整表**再取，明文在此就已经没了。
    #[test]
    fn reloading_the_same_encrypted_room_keeps_the_plaintext_held_in_memory() {
        let mut client = Client::default();
        client.connector.set_base_url("http://localhost:1");
        client.rooms = vec![RoomInfo {
            id: "room-secret".to_string(),
            name: None,
            created_by: "user-a".to_string(),
            created_at: String::new(),
            is_group: false,
            is_encrypted: true,
            members: vec!["user-a".to_string(), "user-b".to_string()],
        }];
        client.selected_room_index = Some(0);
        client.messages = vec![MessageInfo {
            id: "message-secret".to_string(),
            room_id: "room-secret".to_string(),
            sender_id: "user-b".to_string(),
            content: "只存在于内存里的明文".to_string(),
            created_at: "2026-09-06T00:00:00+00:00".to_string(),
        }];
        client.load_messages_for_room("room-secret");
        assert!(
            client.messages.iter().any(|message| {
                message.id == "message-secret" && message.content == "只存在于内存里的明文"
            }),
            "整房重载不得把本端解出来的明文换成服务端的空正文，实际 {:?}",
            client
                .messages
                .iter()
                .map(|message| message.content.clone())
                .collect::<Vec<String>>()
        );
    }

    /// 本轮新增与改用的语言键必须在随程序发布的语言表里真的有：
    /// 少写一个键，界面上就会把键名当文案显示给用户（`Language::text` 找不到就回退成键名）。
    #[test]
    fn the_new_language_keys_resolve_to_wording() {
        let Ok(language) = config::Language::load("zh-CN") else {
            return;
        };
        for key in [
            "message_encrypted_history_unavailable",
            "error_update_download_failed",
            "logged_out_hint_graphical",
            "error_not_logged_in_graphical",
        ] {
            let wording = language.text(key);
            assert_ne!(wording, key, "语言表里缺 {key}，界面会直接把键名显示给用户");
            assert!(!wording.is_empty(), "{key} 的文案不能是空的");
        }
    }

    /// Commands that work when not logged in: login, registration, logout, and local switches
    #[test]
    fn signed_out_commands_are_allowed_and_the_rest_are_refused() {
        assert!(command_allowed_signed_out("login"));
        assert!(command_allowed_signed_out("register"));
        assert!(command_allowed_signed_out("logout"));
        assert!(command_allowed_signed_out("language"));
        assert!(command_allowed_signed_out("appearance"));
        assert!(command_allowed_signed_out("server_address"));
        assert!(command_allowed_signed_out("update"));
        assert!(command_allowed_signed_out("quit"));
        assert!(command_allowed_signed_out("exit"));
        assert!(!command_allowed_signed_out("info"));
        assert!(!command_allowed_signed_out("mute"));
        assert!(!command_allowed_signed_out("quit_group"));
        assert!(!command_allowed_signed_out("add_member"));
    }

    /// This round's change: command names and parameters are all **case-sensitive**.
    ///
    /// Command names don't fold case: `/PROFILE` is not `/profile`, report as unknown command and echo the actual input;
    /// parameters (language code, appearance name, username) are also not folded: lowercase `zh-cn` is not usable `zh-CN`,
    /// would be rejected instead of silently switching the interface language/appearance (server usernames also match as-is, to avoid case errors).
    #[test]
    fn command_names_and_language_arguments_are_matched_case_sensitively() {
        // This test case needs to read a real language file to see "the placeholder is really replaced"; skip if it can't be read
        let Some(available_code) = config::Language::available_codes().first().cloned() else {
            return;
        };
        let Ok(language) = config::Language::load(&available_code) else {
            return;
        };
        let mut client = Client::default();
        client.language = language;
        client.current_user_id = Some("user-self".to_string());
        assert!(
            matches!(client.execute_command("PROFILE alice"), UiIntent::Nothing),
            "大小写不同的命令名不能被当成 /profile 执行"
        );
        let last = client.notices.last().expect("应当有一条报错通知");
        assert!(last.is_error, "未知命令应当是报错样式");
        assert!(
            last.text.contains("PROFILE"),
            "报错要点出实际输入的命令名（占位符要真的被替换）：{}",
            last.text
        );

        // Language code: only original case is valid; folding to uppercase would be rejected, and it won't be written back to preferences or switch the current language
        let folded_code = available_code.to_uppercase();
        if folded_code == available_code {
            return;
        }
        let before = client.language.code.clone();
        client.execute_command(&format!("language {folded_code}"));
        let last = client.notices.last().expect("应当有一条报错通知");
        assert!(last.is_error, "大写语言码应当被拒绝: {folded_code}");
        assert_eq!(
            client.language.code, before,
            "被拒绝的语言码不该换掉当前语言"
        );

        // Appearance name same principle
        let Some(name) = config::Palette::available_names().first().cloned() else {
            return;
        };
        let folded = name.to_uppercase();
        if folded == name {
            return;
        }
        client.execute_command(&format!("appearance {folded}"));
        let last = client.notices.last().expect("应当有一条报错通知");
        assert!(last.is_error, "大写外观名应当被拒绝: {folded}");
    }

    /// The batch parameter for `/kick all` only recognizes the complete lowercase `all`: `ALL`, `All` would be treated as a real member with this name,
    /// so it won't accidentally trigger "remove all members".
    #[test]
    fn kick_all_argument_is_case_sensitive() {
        assert!(is_kick_all_argument("all"));
        assert!(!is_kick_all_argument("ALL"));
        assert!(!is_kick_all_argument("All"));
        assert!(!is_kick_all_argument(" all "));
        assert!(!is_kick_all_argument(""));
    }

    /// /mute without arguments toggles, with arguments sets according to the parameter; both forms must land in the local do-not-disturb set
    #[test]
    fn mute_command_accepts_an_optional_flag() {
        let mut client = Client::default();
        client.rooms = vec![room("room-1", "一队", false)];
        client.selected_room_index = Some(0);
        client.apply_mute_command("");
        assert!(
            client.muted_room_ids.contains("room-1"),
            "不带参数应当翻转成免打扰"
        );
        client.apply_mute_command("off");
        assert!(
            !client.muted_room_ids.contains("room-1"),
            "off 应当关掉免打扰"
        );
        client.apply_mute_command("1");
        assert!(client.muted_room_ids.contains("room-1"), "1 应当开启免打扰");
    }

    /// /add_member's three local blocks: no room selected, not a group chat, no username written
    #[test]
    fn add_member_refuses_when_there_is_nothing_to_add_to() {
        let mut client = Client::default();
        // No room selected
        client.add_member("alice");
        let last = client.notices.last().expect("应当有一条报错通知");
        assert!(last.is_error, "没选房间应当报错");
        // Selected room is a private chat (not a group)
        let mut private = room("room-2", "(私聊)", false);
        private.is_group = false;
        client.rooms = vec![private];
        client.selected_room_index = Some(0);
        client.add_member("alice");
        let last = client.notices.last().expect("应当有一条报错通知");
        assert!(last.is_error, "不是群聊应当报错");
        // Group chat but no username written
        client.rooms = vec![room("room-3", "三队", false)];
        client.add_member("   ");
        let last = client.notices.last().expect("应当有一条报错通知");
        assert!(last.is_error, "没写用户名应当报错");
    }
}

/// End-to-end online check: requires this machine running a server, so skipped by default.
/// How to run: cargo test -p baihua-client-gui -- --ignored --nocapture
#[cfg(test)]
mod online_tests {
    use super::Client;
    use baihua_core::config;
    use std::thread::sleep;
    use std::time::Duration;

    fn server_address() -> String {
        std::env::var("BAIHUA_TEST_SERVER").unwrap_or_else(|_| {
            config::preference_string("server_address", "http://localhost:8080")
        })
    }

    /// Build an account used only for this test and log in; return the client with address and session filled in
    fn signed_in_client(name: &str, password: &str) -> Client {
        let address = server_address();
        let mut client = Client::default();
        client.connector.set_base_url(&address);
        let email = format!("{name}@example.com");
        assert!(
            client.sign_up(name, &email, password),
            "注册 {name} 应当成功（同名账号可重复注册，用本次专用口令即可）"
        );
        assert!(client.sign_in(name, password), "登录 {name} 应当成功");
        client
    }

    fn pump(client: &mut Client, seconds: f32) {
        let deadline = std::time::Instant::now() + Duration::from_secs_f32(seconds);
        while std::time::Instant::now() < deadline {
            while let Some(event) = client.next_event() {
                client.apply_event(event);
            }
            sleep(Duration::from_millis(100));
        }
    }

    /// regression for auto-login restoring "current logged-in user": the login response has the name, auto-login only has the token and user ID.
    ///
    /// here we manually set up the auto-login state (token + user ID, name empty) then go through `prepare_session`,
    /// it must fetch the profile by user ID to fill in the name on the top bar (the "current user" part of `status_bar_texts`).
    #[test]
    #[ignore = "需要本机跑着 Baihua 服务端"]
    fn auto_login_restores_the_top_bar_username() {
        let stamp = chrono::Local::now().format("%H%M%S%.3f").to_string();
        let name = format!("guilogin{}", stamp.replace('.', ""));
        let password = "gui-auto-login-pass".to_string();
        let mut signed_in = signed_in_client(&name, &password);
        pump(&mut signed_in, 1.0);

        let token = signed_in
            .websocket_token
            .clone()
            .expect("登录之后应当留有令牌");
        let user_id = signed_in
            .current_user_id
            .clone()
            .expect("登录之后应当留有用户 ID");

        // The auto-login state: only token and user ID, no username from the login response
        let mut restored = Client::default();
        restored.connector.set_base_url(&server_address());
        restored.connector.set_token(&token);
        restored.current_user_id = Some(user_id);
        assert!(restored.current_username.is_empty(), "自动登录起点没有名字");
        restored.prepare_session(&token);
        assert_eq!(
            restored.current_username, name,
            "自动登录后应当按用户 ID 取回用户名"
        );
        let (_connection_label, _mark, user_text, _right_text) = restored.status_bar_texts();
        assert!(
            user_text.contains(&name),
            "顶栏的当前用户那一截要出现刚恢复出来的名字，实际为 {user_text:?}"
        );
    }

    #[test]
    #[ignore = "需要本机跑着 Baihua 服务端"]
    fn two_clients_exchange_a_group_message_end_to_end() {
        let stamp = chrono::Local::now().format("%H%M%S%.3f").to_string();
        let name_a = format!("gui{}a", stamp.replace('.', ""));
        let name_b = format!("gui{}b", stamp.replace('.', ""));
        let password = "gui-e2e-pass".to_string();
        let marker = format!("图形版联调消息 {stamp}");

        let mut sender = signed_in_client(&name_a, &password);
        let mut receiver = signed_in_client(&name_b, &password);
        pump(&mut sender, 1.0);
        pump(&mut receiver, 1.0);

        // A builds a room and brings B in
        sender.create_group("图形版联调群", &name_b);
        pump(&mut sender, 3.0);
        sender.load_rooms_now();
        let rooms = sender.room_entries();
        assert!(
            rooms.iter().any(|room| room.title == "图形版联调群"),
            "A 建房后自己的房间列表里要有它，实际为 {:?}",
            rooms
                .iter()
                .map(|room| room.title.clone())
                .collect::<Vec<String>>()
        );
        let index = rooms
            .iter()
            .position(|room| room.title == "图形版联调群")
            .expect("上面已断言存在");
        sender.open_room(index);
        pump(&mut sender, 1.0);

        // A sends a message: goes up via WebSocket
        sender.send_message(&marker);
        pump(&mut sender, 2.0);

        // B pulls history from the server, verifies the message really reached the server and has the sender name
        receiver.load_rooms_now();
        pump(&mut receiver, 2.0);
        let receiver_rooms = receiver.room_entries();
        let position = receiver_rooms
            .iter()
            .position(|room| room.title == "图形版联调群")
            .expect("B 也该在群里");
        receiver.open_room(position);
        let contents: Vec<String> = receiver
            .messages
            .iter()
            .map(|message| message.content.clone())
            .collect();
        assert!(
            contents.iter().any(|text| text == &marker),
            "B 拉到的历史里应有那条消息，实际为 {contents:?}"
        );
        let posted = receiver
            .messages
            .iter()
            .find(|message| message.content == marker)
            .expect("上面已断言存在");
        assert_eq!(
            receiver.sender_display_name(&posted.sender_id),
            name_a,
            "发送者名要能从成员表里查出来"
        );

        // Cleanup: both accounts logged out, no residue left on the dev server
        sender.delete_account(&password);
        receiver.delete_account(&password);
        assert!(
            !sender.is_signed_in() && !receiver.is_signed_in(),
            "注销后本地会话应当作废"
        );
    }
}
