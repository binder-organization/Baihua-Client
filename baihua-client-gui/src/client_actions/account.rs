//! Sign-in, sign-up, session restore/expire, and account removal.

use super::*;

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
            self.cache_messages(&room_id);
        }
        self.cache_pending_flush_since = None;
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
                // Store the fresh session right away: a recents-swipe kill can
                // arrive before any exit hook runs (see `persist_session`).
                self.persist_session();
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
        self.watch_reachability();
        self.start_websocket(token, None);
        self.presence_by_user
            .insert(self.current_user_id.clone().unwrap_or_default(), true);
        if let Some(user_id) = self.current_user_id.clone() {
            self.request_avatars(&[user_id]);
        }
        self.ensure_users_loaded();
    }

    /// Restore the top-bar name after auto-login (the saved session kept only a
    /// token and id): fetch the profile once; offline keeps the name empty.
    pub(crate) fn restore_own_username(&mut self) {
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
                config::debug_log(&format!("Automatic login failed, session cleared: {error}"));
                false
            }
        }
    }

    /// Fold the background startup pass into the live session on the interface
    /// thread, and report whether the client ended up signed in.
    pub fn apply_startup(&mut self, outcome: crate::client::StartupOutcome) -> bool {
        if let Some((version, raw)) = &outcome.probe {
            self.connector.adopt_probe_result(*version, raw);
        }
        self.update_connection(outcome.server_online);
        match outcome.session {
            Some((token, user_id, rooms)) => {
                self.connector.set_token(&token);
                self.current_user_id = Some(user_id.clone());
                self.own_contact = config::load_saved_contact();
                self.presence_by_user.insert(user_id, true);
                self.apply_room_snapshot(rooms);
                self.prepare_session(&token);
                self.websocket_token = Some(token);
                true
            }
            None => false,
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
        // Drafts belong to the previous account's rooms and must not outlive the session
        self.room_drafts.clear();
        self.draft.clear();
        self.pending_requests.clear();
        self.sent_requests.clear();
        self.crypto.sessions.clear();
        config::clear_saved_session();
    }

    pub(crate) fn notifications_clear(&mut self) {
        self.notices.clear();
    }

    /// Token invalidated: local session is voided but loaded content is kept; the interface will re-display the login page
    pub(crate) fn session_expired(&mut self) {
        config::clear_saved_session();
        self.websocket_sender = None;
        self.websocket_token = None;
        self.current_user_id = None;
        self.current_username = String::new();
        self.notify_error(self.text("error_session_expired"));
    }

    /// Write the live session to the saved preferences after every change, because
    /// Android kills a swiped-away process with no shutdown hook.
    pub fn persist_session(&self) {
        if let (Some(token), Some(user_id)) =
            (self.websocket_token.clone(), self.current_user_id.clone())
        {
            config::save_session_preferences(&token, &user_id, self.own_contact.as_ref());
        }
    }
}
