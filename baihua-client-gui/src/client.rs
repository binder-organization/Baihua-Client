//! The session layer for the GUI: connections, rooms, messages, private chat requests, end-to-end encryption, account operations, and background thread driving.
//!
//! No egui types appear here: what the interface gets is data (room entries, message rows, four segments of status bar text, notification queue),
//! the interface is only responsible for layout and mouse interaction. Protocol details all go through the one seam at `baihua_core::api`,
//! theme and language reading goes through `baihua_core::config`, sharing the same config file as the TUI.

use baihua_core::config::{self, Language, Palette};
use baihua_core::{
    api::{
        Connector, MessageInfo, PollingEvent, PublicProfile, RoomInfo, RoomRequestInfo,
        UserSearchResult, authorization_value, parse_websocket_event, websocket_auth_sentinel,
    },
    chat_cache::ChatCache,
    crypto,
};
use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::thread;
use std::time::{Duration, Instant};
use tungstenite::Message as WebSocketMessage;
use tungstenite::client::IntoClientRequest;
use tungstenite::http::HeaderValue;
use x25519_dalek::EphemeralSecret;

/// The phase an end-to-end encryption session is in. The server only forwards handshake messages; key material is entirely on the client sides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionPhase {
    /// Invitation sent, waiting for the other side to accept
    AwaitingAcceptance,
    /// Both sides' keys have been negotiated, waiting for the server to confirm ready
    AwaitingSessionReady,
    /// Session active, can send and receive encrypted messages
    Active,
}

/// Encryption session for a single room. The ephemeral private key can only be consumed once, so after taking it out with Option it becomes None.
pub struct EncryptionSession {
    pub phase: EncryptionPhase,
    pub ephemeral_secret: Option<EphemeralSecret>,
    /// Own ephemeral public key: resending an invitation must reuse the same one, otherwise the shared keys computed by both sides will not match
    pub own_public_key: String,
    pub shared_key: Option<[u8; 32]>,
    /// User already pressed send before the handshake was complete; send it immediately once ready
    pub pending_content: Option<String>,
    /// The moment this phase started: resend the handshake at intervals if waiting too long
    pub initiated_at: Instant,
}

impl std::fmt::Debug for EncryptionSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EncryptionSession")
            .field("phase", &self.phase)
            .field("own_public_key", &self.own_public_key)
            .finish_non_exhaustive()
    }
}

/// Client encryption identity and per-room sessions. Identity keys are regenerated each startup and not persisted (consistent with the server agreement).
pub struct ClientCrypto {
    pub identity_key: ed25519_dalek::SigningKey,
    pub sessions: HashMap<String, EncryptionSession>,
}

impl Default for ClientCrypto {
    fn default() -> Self {
        Self {
            identity_key: crypto::generate_identity_key(),
            sessions: HashMap::new(),
        }
    }
}

impl std::fmt::Debug for ClientCrypto {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientCrypto")
            .field("session_count", &self.sessions.len())
            .finish()
    }
}

/// A notification: text, whether it is an error style, and expiration time. The interface draws it based on remaining time, and `tick` cleans it up when expired.
pub struct Notice {
    pub text: String,
    pub is_error: bool,
    pub expires_at: Instant,
}

/// The session layer. Fields are split into two layers: the upper layer is user-controllable config (written to preferences.json), the lower layer is runtime state.
pub struct Client {
    // ==================== Upper layer: user-controllable configuration ====================
    /// The seam for communicating with the server, holding the token and version negotiation result
    pub connector: Connector,
    /// All text for the current language
    pub language: Language,
    /// The currently active theme (the interface takes colors from here for rendering)
    pub palette: Palette,
    /// Current theme name, "built_in" when no theme file
    pub appearance_name: String,
    /// Whether to show the sender's UID in messages
    pub show_uid: bool,
    /// Whether to show the date in timestamps
    pub time_with_date: bool,
    /// Whether to emit system sounds/notifications (window alert in the GUI)
    pub sound_enabled: bool,
    /// Set of muted room IDs
    pub muted_room_ids: HashSet<String>,
    /// Quick search: search loaded messages as you type, no need to press Enter
    pub quick_search: bool,

    // ==================== Lower layer: runtime state ====================
    /// Room snapshots (as the server has them, not filtered for locally closed rooms)
    pub rooms: Vec<RoomInfo>,
    /// Index of the currently selected room; the interface list selection syncs with this
    pub selected_room_index: Option<usize>,
    /// Messages in the current room (sorted by time ascending)
    pub messages: Vec<MessageInfo>,
    /// Pagination cursor for "older messages" in the current room; None means no more available
    pub older_cursor: Option<String>,
    /// Whether there are still older messages to fetch for the current room
    pub has_more_older: bool,
    /// Room ID → unread count
    pub unread_counts: HashMap<String, u32>,
    /// User ID → username (used for message sender display name and online marker)
    pub sender_names: HashMap<String, String>,
    pub current_user_id: Option<String>,
    pub current_username: String,
    /// Own email and phone number: the server only gives them in the full response for login/register/profile/avatar endpoints
    pub own_contact: Option<(String, String)>,
    /// The user currently displayed on the profile card
    pub profile_view: Option<PublicProfile>,
    /// Nickname draft in the profile form (pre-filled with the server's current value when the form is opened)
    pub profile_nickname_draft: String,
    /// Bio draft in the profile form
    pub profile_bio_draft: String,
    /// Received private chat requests (including historical entries already processed locally)
    pub pending_requests: Vec<RoomRequestInfo>,
    /// Private chat requests sent by self (the server gives all statuses)
    pub sent_requests: Vec<RoomRequestInfo>,
    /// Index of the selected private chat request (received ones come first)
    /// Registered users directory cache; None means never fetched
    pub registered_users: Option<Vec<UserSearchResult>>,
    /// User ID → whether online. The server only broadcasts when the connection count changes from 0↔1; there is no baseline roster
    pub presence_by_user: HashMap<String, bool>,
    /// Members who are typing: room ID, username, most recent typing frame timestamp
    pub typing_members: Vec<(String, String, Instant)>,
    /// The moment the most recent typing frame was sent upstream, used for throttling
    pub last_typing_frame_sent_at: Option<Instant>,
    /// Notification queue
    pub notices: Vec<Notice>,
    /// Server reachability: None means not probed yet
    pub connection_ready: Option<bool>,
    /// Local message cache (only caches plaintext rooms)
    pub chat_cache: Option<ChatCache>,
    /// Avatar raw bytes: user ID → bytes; None means confirmed to have no avatar or fetch failed
    pub avatar_images: HashMap<String, Option<Vec<u8>>>,
    /// Encryption identity and per-room sessions
    pub crypto: ClientCrypto,
    /// Event channel shared by background threads
    pub events: Option<Sender<PollingEvent>>,
    /// Event receiver end: the interface takes a batch of these events each frame before drawing
    event_receiver: Option<mpsc::Receiver<PollingEvent>>,
    /// WebSocket command channel (values are full JSON text)
    pub websocket_sender: Option<Sender<String>>,
    /// Token copy for reconnection use
    pub websocket_token: Option<String>,
    pub websocket_running: Option<Arc<AtomicBool>>,
    pub websocket_connected_at: Instant,
    pub polling_running: Option<Arc<AtomicBool>>,
    pub reachability_running: Option<Arc<AtomicBool>>,
    pub update_check_running: Option<Arc<AtomicBool>>,
    /// Search mode: keyword in the input box and match results (keyword, matched message IDs, current index)
    pub search_result: Option<(String, Vec<String>, usize)>,
    /// Message ID to scroll to; cleared after the interface scrolls into position
    pub pending_scroll_message_id: Option<String>,
    /// Input box draft (bound directly by TextEdit in the GUI; the session layer needs to read it to determine search/command mode)
    pub draft: String,
    /// Locally closed room IDs (only hidden, not notified to the server)
    pub closed_room_ids: HashSet<String>,
    /// IDs of group chats the user voluntarily left, used to distinguish "self-left" from "kicked"
    pub left_room_ids: HashSet<String>,
    /// The moment the full room was loaded: discard late scroll events within a short time
    pub messages_reloaded_at: Instant,
    /// Downloaded and verified update package (new version, package path)
    pub pending_update: Option<(String, PathBuf)>,
    /// Update has been handed off to a detached installer process; the interface should exit
    pub update_handoff_requested: bool,
    /// The moment when message cache is pending being flushed to disk
    pub cache_pending_flush_since: Option<Instant>,
    /// Needs to exit after the main thread takes it away
    pub quit_requested: bool,
}

impl Default for Client {
    fn default() -> Self {
        let connector = Connector::new("http://localhost:8080");
        Self {
            connector,
            language: Language::default(),
            palette: Palette::built_in(),
            appearance_name: "built_in".to_string(),
            show_uid: false,
            time_with_date: true,
            sound_enabled: true,
            muted_room_ids: HashSet::new(),
            quick_search: false,
            rooms: Vec::new(),
            selected_room_index: None,
            messages: Vec::new(),
            older_cursor: None,
            has_more_older: false,
            unread_counts: HashMap::new(),
            sender_names: HashMap::new(),
            current_user_id: None,
            current_username: String::new(),
            own_contact: None,
            profile_view: None,
            profile_nickname_draft: String::new(),
            profile_bio_draft: String::new(),
            pending_requests: Vec::new(),
            sent_requests: Vec::new(),
            registered_users: None,
            presence_by_user: HashMap::new(),
            typing_members: Vec::new(),
            last_typing_frame_sent_at: None,
            notices: Vec::new(),
            connection_ready: None,
            chat_cache: None,
            avatar_images: HashMap::new(),
            crypto: ClientCrypto::default(),
            events: None,
            event_receiver: None,
            websocket_sender: None,
            websocket_token: None,
            websocket_running: None,
            websocket_connected_at: Instant::now(),
            polling_running: None,
            reachability_running: None,
            update_check_running: None,
            search_result: None,
            pending_scroll_message_id: None,
            draft: String::new(),
            closed_room_ids: HashSet::new(),
            left_room_ids: HashSet::new(),
            messages_reloaded_at: Instant::now(),
            pending_update: None,
            update_handoff_requested: false,
            cache_pending_flush_since: None,
            quit_requested: false,
        }
    }
}

impl Client {
    /// Establish a session and read config: language, theme, display switches, and server address all come from the same preferences.json.
    /// Items that cannot be read keep their defaults; do not error here (same rule as the TUI).
    pub fn start() -> Self {
        let mut client = Self::default();
        let preferences = config::read_preferences();
        if let Some(address) = preferences
            .get("server_address")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
        {
            client.connector.set_base_url(address);
        }
        let code = config::preference_string("language", "zh-CN");
        match Language::load(&code) {
            Ok(language) => client.language = language,
            // No language file could be read at startup: the text table itself is empty here, so every wording
            // (including this one) can only fall back to its key name until a readable file is installed.
            Err(path) => client.notices.push(Notice {
                text: format!(
                    "{}: {}",
                    path.display(),
                    client.text("error_lang_file_read")
                ),
                is_error: true,
                expires_at: Instant::now() + Duration::from_secs(6),
            }),
        }
        client.show_uid = config::preference_bool("show_uid", false);
        client.time_with_date = config::preference_bool("time_with_date", true);
        client.sound_enabled = config::preference_bool("sound_enabled", true);
        client.quick_search = config::preference_bool("quick_search", false);
        client.muted_room_ids = preferences
            .get("muted_rooms")
            .and_then(serde_json::Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| entry.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let appearance_name = config::preference_string("appearance", "");
        if !appearance_name.is_empty() {
            client.apply_appearance(&appearance_name);
        }
        client
    }

    /// Get text by language key
    pub fn text(&self, key: &str) -> String {
        self.language.text(key)
    }

    /// Add a notification (hint style)
    pub fn notify(&mut self, text: String) {
        self.notices.push(Notice {
            text,
            is_error: false,
            expires_at: Instant::now() + Duration::from_secs(6),
        });
    }

    /// Add a notification (error style)
    pub fn notify_error(&mut self, text: String) {
        self.notices.push(Notice {
            text,
            is_error: true,
            expires_at: Instant::now() + Duration::from_secs(8),
        });
    }

    // ==================== Configuration writeback ====================

    /// Switch language: load the text table and write back to config
    pub fn switch_language(&mut self, code: &str) {
        match Language::load(code) {
            Ok(language) => self.language = language,
            // The core hands back the path of the file it could not read; the wording comes from the table
            // that is still loaded (the previous language), exactly like the terminal version reports it.
            Err(path) => self.notify_error(format!(
                "{}: {}",
                path.display(),
                self.text("error_lang_file_read")
            )),
        }
        config::write_preferences(&[("language", Some(serde_json::json!(code)))]);
    }

    /// Apply theme: read back the full color set at once; missing/extra fields are explicitly reported per the convention
    pub fn apply_appearance(&mut self, name: &str) {
        let theme: baihua_core::config::ThemeFile = Palette::load(name);
        self.palette = theme.palette;
        self.appearance_name = name.to_string();
        if theme.has_missing_field {
            self.notify_error(
                self.text("appearance_missing_fields")
                    .replace("{name}", name),
            );
        }
        if !theme.extra_fields.is_empty() {
            self.notify_error(
                self.text("appearance_extra_fields")
                    .replace("{name}", name)
                    .replace("{fields}", &theme.extra_fields.join(", ")),
            );
        }
    }

    /// User switches theme: apply and write back to config
    pub fn switch_appearance(&mut self, name: &str) {
        self.apply_appearance(name);
        self.write_display_preferences();
    }

    /// Write back all display-related config (new switches only change this one place)
    pub fn write_display_preferences(&self) {
        config::write_preferences(&[
            ("show_uid", Some(serde_json::json!(self.show_uid))),
            (
                "time_with_date",
                Some(serde_json::json!(self.time_with_date)),
            ),
            ("sound_enabled", Some(serde_json::json!(self.sound_enabled))),
            ("quick_search", Some(serde_json::json!(self.quick_search))),
            ("appearance", Some(serde_json::json!(&self.appearance_name))),
            (
                "muted_rooms",
                Some(serde_json::json!(
                    self.muted_room_ids.iter().cloned().collect::<Vec<String>>()
                )),
            ),
        ]);
    }

    /// Switch server address: immediately re-probe version and restart both background threads
    pub fn apply_server_address(&mut self, address: &str) {
        self.connector.set_base_url(address);
        config::write_preferences(&[("server_address", Some(serde_json::json!(address)))]);
        self.connection_ready = None;
        self.probe_server_at_startup();
        self.start_reachability_watch();
        if self.is_signed_in() {
            self.start_polling();
        }
    }

    // ==================== Session establishment ====================

    /// The four segments for the top bar: connection label, marker, current user segment, version segment.
    ///
    /// The vertical bars are part of the **text**, exactly like the terminal version: the separator between the current user and
    /// the connection state, and the one between the two version items, are both written into the segment.
    /// The interface must not draw an extra separator of its own (a `Separator` inside a horizontal row of a top panel is as tall
    /// as the whole panel area, which shows up as a stray vertical bar running down the window).
    pub fn status_bar_texts(&self) -> (String, String, String, String) {
        let connection_label = self.text("bar_connection");
        let mark = match self.connection_ready {
            Some(true) => "●",
            Some(false) | None => "○",
        };
        let user_text = if self.current_username.is_empty() {
            String::new()
        } else {
            format!(
                "  |  {} {}",
                self.text("bar_current_user"),
                self.current_username
            )
        };
        // Version segment: server version first when it is known, the client version always last;
        // joined with the same separator, never leaving a leading bar when the server version is missing.
        let mut version_parts: Vec<String> = Vec::new();
        if !self.connector.server_version_text().is_empty() {
            version_parts.push(format!(
                "{}: {}",
                self.text("bar_server_version"),
                self.connector.server_version_text()
            ));
        }
        version_parts.push(format!(
            "{}: {}",
            self.text("bar_client_version"),
            env!("CARGO_PKG_VERSION")
        ));
        (
            connection_label,
            mark.to_string(),
            user_text,
            version_parts.join("  |  "),
        )
    }

    /// Probe the server version (also determines the initial connection marker). Must probe even when not logged in, so the top bar can display the server version.
    pub fn probe_server_at_startup(&mut self) {
        match self.connector.probe_version() {
            Ok((_version, _text)) => self.update_connection_state(true),
            Err(error) => {
                self.connector.clear_server_version();
                config::debug_log(&format!("启动探测服务端失败: {error}"));
                self.update_connection_state(false);
            }
        }
    }

    /// The single write entry for connection state: only notify once on a transition
    pub fn update_connection_state(&mut self, online: bool) {
        if self.connection_ready == Some(online) {
            return;
        }
        let first_probe = self.connection_ready.is_none();
        self.connection_ready = Some(online);
        if online {
            if !first_probe {
                self.notify(self.text("connection_restored"));
            }
        } else if !first_probe {
            self.notify_error(self.text("error_server_unreachable"));
        }
    }

    /// Persistent reachability probe: every 5 seconds, only judge offline after two consecutive failures.
    /// Only this place writes the connection marker; polling and WebSocket jitter must not flip it.
    pub fn start_reachability_watch(&mut self) {
        if let Some(flag) = self.reachability_running.take() {
            flag.store(false, Ordering::Relaxed);
        }
        let Some(sender) = self.events.clone() else {
            return;
        };
        let connector = self.connector.clone();
        let flag = Arc::new(AtomicBool::new(true));
        self.reachability_running = Some(flag.clone());
        thread::spawn(move || {
            let mut failures = 0_u32;
            while flag.load(Ordering::Relaxed) {
                if connector.probe_reachable() {
                    failures = 0;
                    let _ = sender.send(PollingEvent::ReachabilityChanged(true));
                } else {
                    failures += 1;
                    if failures >= 2 {
                        let _ = sender.send(PollingEvent::ReachabilityChanged(false));
                    }
                }
                for _ in 0..50 {
                    if !flag.load(Ordering::Relaxed) {
                        return;
                    }
                    thread::sleep(Duration::from_millis(100));
                }
            }
        });
    }

    /// Establish the event channel (only once); the interface uses `take_events` to take the receiver end
    pub fn open_event_channel(&mut self) {
        if self.events.is_some() {
            return;
        }
        let (sender, receiver) = mpsc::channel();
        self.events = Some(sender);
        self.event_receiver = Some(receiver);
    }

    /// Take background events: the interface calls this once per frame
    pub fn next_event(&mut self) -> Option<PollingEvent> {
        self.event_receiver.as_ref()?.try_recv().ok()
    }

    /// Start the polling thread: room list every 2 seconds, private chat requests every 3 seconds, tick at 100ms
    pub fn start_polling(&mut self) {
        let Some(sender) = self.events.clone() else {
            return;
        };
        if let Some(flag) = self.polling_running.take() {
            flag.store(false, Ordering::Relaxed);
        }
        let connector = self.connector.clone();
        let language_map: HashMap<String, String> = self.language_texts_map();
        let flag = Arc::new(AtomicBool::new(true));
        self.polling_running = Some(flag.clone());
        thread::spawn(move || {
            let translate = move |key: &str| {
                language_map
                    .get(key)
                    .cloned()
                    .unwrap_or_else(|| key.to_string())
            };
            let mut last_rooms: Vec<RoomInfo> = Vec::new();
            let mut last_received: Vec<RoomRequestInfo> = Vec::new();
            let mut last_sent: Vec<RoomRequestInfo> = Vec::new();
            let mut rooms_counter = 0_u32;
            let mut requests_counter = 0_u32;
            while flag.load(Ordering::Relaxed) {
                if rooms_counter.is_multiple_of(20) {
                    match connector.list_rooms() {
                        Ok(rooms) => {
                            if rooms != last_rooms {
                                last_rooms = rooms.clone();
                                let _ = sender.send(PollingEvent::RoomsUpdated(rooms));
                            }
                        }
                        Err(error) if error.is_connection_failure() => {
                            config::debug_log(&format!("轮询房间列表时连不上服务端: {error}"));
                        }
                        Err(error) => {
                            let _ = sender.send(PollingEvent::Error(format!(
                                "{}: {error}",
                                translate("error_poll_rooms")
                            )));
                        }
                    }
                }
                if requests_counter.is_multiple_of(30) {
                    match connector.list_pending_requests() {
                        Ok(requests) => {
                            if requests != last_received {
                                last_received = requests.clone();
                                let _ = sender.send(PollingEvent::PendingRequestsUpdated(requests));
                            }
                        }
                        Err(error) => {
                            if !error.is_connection_failure() {
                                let _ = sender.send(PollingEvent::Error(format!(
                                    "{}: {error}",
                                    translate("error_poll_requests")
                                )));
                            }
                        }
                    }
                    match connector.list_sent_requests() {
                        Ok(requests) => {
                            if requests != last_sent {
                                last_sent = requests.clone();
                                let _ = sender.send(PollingEvent::SentRequestsUpdated(requests));
                            }
                        }
                        Err(error) => {
                            if !error.is_connection_failure() {
                                let _ = sender.send(PollingEvent::Error(format!(
                                    "{}: {error}",
                                    translate("error_poll_requests")
                                )));
                            }
                        }
                    }
                }
                rooms_counter = rooms_counter.wrapping_add(1);
                requests_counter = requests_counter.wrapping_add(1);
                thread::sleep(Duration::from_millis(100));
            }
        });
    }

    /// Start WebSocket thread: auto-reconnect on disconnect; optionally notify the caller when a connected receipt is received
    pub fn start_websocket(&mut self, token: &str, ready: Option<Sender<()>>) {
        if let Some(flag) = self.websocket_running.take() {
            flag.store(false, Ordering::Relaxed);
            thread::sleep(Duration::from_millis(150));
        }
        let Some(event_sender) = self.events.clone() else {
            return;
        };
        let (command_sender, command_receiver) = mpsc::channel::<String>();
        self.websocket_sender = Some(command_sender);
        self.websocket_token = Some(token.to_string());
        self.websocket_connected_at = Instant::now();

        let version = self.connector.version();
        let url = version.websocket_url(self.connector.base_url());
        let token = token.to_string();
        let language_map = self.language_texts_map();
        let heartbeat_frame = version.heartbeat_frame();
        let heartbeat_interval = version.application_heartbeat_interval();
        let flag = Arc::new(AtomicBool::new(true));
        self.websocket_running = Some(flag.clone());

        thread::spawn(move || {
            let translate = move |key: &str| {
                language_map
                    .get(key)
                    .cloned()
                    .unwrap_or_else(|| key.to_string())
            };
            while flag.load(Ordering::Relaxed) {
                let mut request = match url.as_str().into_client_request() {
                    Ok(request) => request,
                    Err(error) => {
                        config::debug_log(&format!("WS 请求构造失败: {error}"));
                        let _ = event_sender.send(PollingEvent::Error(format!(
                            "{}: {error}",
                            translate("error_ws_handshake")
                        )));
                        for _ in 0..20 {
                            if !flag.load(Ordering::Relaxed) {
                                return;
                            }
                            thread::sleep(Duration::from_millis(100));
                        }
                        continue;
                    }
                };
                match HeaderValue::from_str(&authorization_value(&token)) {
                    Ok(value) => {
                        request.headers_mut().insert("Authorization", value);
                    }
                    Err(error) => {
                        config::debug_log(&format!("WS 认证头构造失败: {error}"));
                        for _ in 0..20 {
                            if !flag.load(Ordering::Relaxed) {
                                return;
                            }
                            thread::sleep(Duration::from_millis(100));
                        }
                        continue;
                    }
                }
                let mut socket = match tungstenite::connect(request) {
                    Ok((socket, _response)) => socket,
                    Err(error) => {
                        let _ = event_sender.send(PollingEvent::WebSocketState(
                            "error_ws_connect_failed".to_string(),
                        ));
                        if version.is_auth_failure(&error.to_string()) {
                            let _ = event_sender
                                .send(PollingEvent::Error(websocket_auth_sentinel().to_string()));
                            return;
                        }
                        for _ in 0..20 {
                            if !flag.load(Ordering::Relaxed) {
                                return;
                            }
                            thread::sleep(Duration::from_millis(100));
                        }
                        continue;
                    }
                };
                if let tungstenite::stream::MaybeTlsStream::Plain(stream) = socket.get_ref() {
                    let _ = stream.set_nonblocking(true);
                }
                let mut signaled = false;
                let mut keepalive = Instant::now();
                loop {
                    if !flag.load(Ordering::Relaxed) {
                        return;
                    }
                    match socket.read() {
                        Ok(WebSocketMessage::Text(text)) => {
                            if let Some(event) = parse_websocket_event(text.as_ref(), &translate) {
                                if !signaled
                                    && let PollingEvent::WebSocketConnected = &event
                                    && let Some(sender) = ready.clone()
                                {
                                    let _ = sender.send(());
                                    signaled = true;
                                }
                                let _ = event_sender.send(event);
                            }
                        }
                        Ok(_) => {}
                        Err(tungstenite::Error::Io(error))
                            if error.kind() == ErrorKind::WouldBlock => {}
                        Err(error) => {
                            config::debug_log(&format!("WS 断开: {error}"));
                            let _ = event_sender.send(PollingEvent::WebSocketState(
                                "error_ws_disconnected_reconnect".to_string(),
                            ));
                            break;
                        }
                    }
                    while let Ok(payload) = command_receiver.try_recv() {
                        if socket.write(WebSocketMessage::text(payload)).is_err() {
                            let _ = event_sender.send(PollingEvent::WebSocketState(
                                "error_ws_send_failed".to_string(),
                            ));
                        }
                    }
                    if keepalive.elapsed() >= heartbeat_interval {
                        let _ = socket.write(WebSocketMessage::text(heartbeat_frame.clone()));
                        keepalive = Instant::now();
                    }
                    let _ = socket.flush();
                    thread::sleep(Duration::from_millis(50));
                }
                for _ in 0..10 {
                    if !flag.load(Ordering::Relaxed) {
                        return;
                    }
                    thread::sleep(Duration::from_millis(100));
                }
            }
        });
    }

    /// Rebuild WebSocket connection: the server only snapshots room subscriptions on connection; a new room appearing requires reconnection
    pub fn restart_websocket(&mut self) {
        if let Some(token) = self.websocket_token.clone() {
            self.start_websocket(&token, None);
        }
    }

    /// Send a serialized message to the WebSocket
    pub fn send_payload(&mut self, payload: serde_json::Value) {
        let Some(sender) = self.websocket_sender.clone() else {
            return;
        };
        let _ = sender.send(payload.to_string());
    }

    /// Snapshot of the language table, handed to the background thread for localization
    fn language_texts_map(&self) -> HashMap<String, String> {
        self.language.texts()
    }
}
