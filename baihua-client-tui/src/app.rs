use crate::avatar::{AvatarPixels, build_avatar_pixels, placeholder_color, placeholder_initial};
use baihua_core::{
    api::{
        ApiVersion, Connector, CreateRoomRequest, EncryptHandshakeData, EncryptedMessageInfo,
        LoginRequest, MessageInfo, PollingEvent, ProfileUpdatePayload, PublicProfile,
        RegisterRequest, RoomInfo, RoomRequestInfo, ServerSignal, UserInfo, UserSearchResult,
        WsCommand, authorization_value, outbound_ws_payload, parse_websocket_event,
        websocket_auth_sentinel,
    },
    chat_cache::ChatCache,
    config, crypto, installer, paths,
    update::{ReleaseChannel, UpdateCheck, check_for_update, download_package},
};
use chrono::{DateTime, Local};
use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers, MouseEventKind};
use ed25519_dalek::SigningKey;
use rat_text::HasScreenCursor;
use rat_text::TextPosition;
use rat_text::core::TextStore;
use rat_text::text_area;
use rat_text::text_area::{TextArea, TextAreaState};
use rat_text::text_input;
use rat_text::text_input::{TextInput, TextInputState};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Margin, Position, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{
        Block, Borders, Clear, List, ListItem, ListState, Paragraph, Scrollbar,
        ScrollbarOrientation, ScrollbarState, StatefulWidget,
    },
};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::thread;
use std::time::{Duration, Instant};
use tungstenite::Message as WebSocketMessage;
use tungstenite::client::IntoClientRequest;
use tungstenite::http::HeaderValue;
use x25519_dalek::EphemeralSecret;

/// Securely write a file: on Unix systems, create the file with 0600 permissions (readable and writable only by the owner),
/// preventing sensitive configuration files (such as preferences.json) from being read by other users.
/// Windows has no equivalent file permission mechanism, so standard writing is used directly.
fn secure_write(path: &std::path::Path, content: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(content.as_bytes())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, content)
    }
}

/// Debug diagnostics.
#[cfg(debug_assertions)]
fn debug_log(message: &str) {
    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(std::env::temp_dir().join("baihua_client_debug.log"))
    {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis())
            .unwrap_or(0);
        let _ = writeln!(file, "[{timestamp}] {message}");
    }
}

/// Debug diagnostics (no-op in release builds).
#[cfg(not(debug_assertions))]
fn debug_log(_message: &str) {}

/// Currently displayed overlay.
#[derive(Debug, Clone, PartialEq)]
pub enum DisplayingOverlay {
    Nothing,
    CreateGroup,
    CreatePrivate,
    PendingRequests,
    SettingsMenu,
    LanguageSelect,
    ServerAddress,
    // The login form overlay opened without arguments by the /login command (password field obscured)
    Login,
    // The registration form overlay opened without arguments by the /register command (password field obscured)
    Register,
    // The appearance selection overlay opened from the settings page or /appearance without arguments
    AppearanceSelect,
    // Profile card (opened via /profile): displays username, UID, nickname, bio, and avatar
    ProfileCard,
    // General form overlay (settings profile, change password, change avatar, delete account):
    // Specific fields and submit actions are in App::active_form; this variant only means "a form is currently displayed"
    Form,
    // Local avatar selection overlay: lists image files in `<client_dir>/config/avatars`,
    // Press Enter to upload that file as the avatar; press Ctrl+U in the overlay to switch to the form for entering a network link
    AvatarSelect,
}

/// A single input field in the form overlay.
#[derive(Debug, Clone)]
struct FormField {
    // Label text key (displayed line by line to the left of the input field in the form overlay)
    label_key: String,
    state: TextInputState,
    // Password-type input: displayed as obscured characters, and will not be copied by full-screen selection
    secret: bool,
}

impl FormField {
    fn new(label_key: &str, prefilled: &str, secret: bool) -> Self {
        let mut state = TextInputState::default();
        state.set_text(prefilled);
        Self {
            label_key: label_key.to_string(),
            state,
            secret,
        }
    }

    /// Current text of the input field (trimmed)
    fn text(&self) -> String {
        self.state.value.text().string().trim().to_string()
    }
}

/// The action to perform from the form overlay. Field values are taken from active_form in declaration order.
#[derive(Debug, Clone, PartialEq)]
enum FormAction {
    // Update profile: nickname, phone number, bio
    UpdateProfile,
    // Change password: old password, new password, confirm new password
    ChangePassword,
    // Change avatar: local image path or full URL accessible from the server
    ChangeAvatar,
    // Delete account: enter password again
    DeleteAccount,
}

/// Encryption session phase
#[derive(Debug, Clone, Copy, PartialEq)]
enum EncryptionPhase {
    // Invitation sent, waiting for peer to accept
    AwaitingAcceptance,
    // Key negotiated, waiting for server to confirm both sides are ready
    AwaitingSessionReady,
    // Session active, can send and receive encrypted messages
    Active,
}

/// Encryption session state for a single room; the ephemeral private key does not implement Debug/Clone, it is manually implemented by the outer code
struct EncryptionSession {
    phase: EncryptionPhase,
    ephemeral_secret: Option<EphemeralSecret>,
    // Our ephemeral public key (base64): re-sending an invitation must reuse the same one, otherwise the keys on both sides will not match
    own_public_key: String,
    shared_key: Option<[u8; 32]>,
    pending_content: Option<String>,
    // Start time of this phase: if acceptance is not received within the timeout, an invitation is automatically re-sent
    initiated_at: Instant,
}

/// Client encryption state: user identity key and per-room encryption sessions
struct ClientCrypto {
    identity_key: SigningKey,
    sessions: HashMap<String, EncryptionSession>,
}

impl fmt::Debug for ClientCrypto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientCrypto")
            .field("session_count", &self.sessions.len())
            .finish()
    }
}

/// All input field states managed centrally
#[derive(Default, Debug, Clone)]
pub struct InputCollector {
    // Login page
    pub login_name_state: TextInputState,
    pub login_password_state: TextInputState,
    // Registration page
    pub register_name_state: TextInputState,
    pub register_email_state: TextInputState,
    pub register_password_state: TextInputState,
    // Chat page
    pub message_input_state: TextAreaState,
    // Create group chat popup
    pub create_group_name_state: TextInputState,
    pub create_group_members_state: TextInputState,
    // Create private chat popup
    pub create_private_username_state: TextInputState,
    // Server address popup
    pub server_address_state: TextInputState,
    // Full-screen mouse selection copy: start point recorded on left mouse button press, endpoint updated while dragging, and used on release to copy text from the full-screen row snapshot
    // to copy text to clipboard and clear. When the start point is inside the message input box, these fields are not used,
    // the input control itself maintains the selection area (preserving in-control selection and cursor semantics).
    pub selection_start: Option<(u16, u16)>,
    pub selection_end: Option<(u16, u16)>,
}

/// Data carrier for the appearance system: centralized definition of all colorable slots in the client.
/// Each field corresponds to a same-named key in config/themes/{appearance_name}.json; the user-chosen name is persisted in
/// the appearance field of preferences.json; the interface takes colors from here for rendering, no longer scattering hardcoded colors.
#[derive(Debug, Clone, PartialEq)]
struct Appearance {
    // Overall application background color (overrides terminal default background, including popup areas)
    app_background: Color,
    // Message display area border color
    message_border: Color,
    // Group chat list border color
    room_border: Color,
    // Border color for all overlay windows (overlay style unified to this slot; can be adjusted separately in the theme)
    overlay_border: Color,
    // Message body text color
    message_text: Color,
    // Selected text color (room list items, settings menu items, command auto-completion items)
    selected_text: Color,
    // Other user's username text color
    other_username_text: Color,
    // Own username text color
    own_username_text: Color,
    // Message timestamp text color
    time_text: Color,
    // Keyboard shortcut hint text color
    hint_text: Color,
    // Border color when the tooltip is in hint state
    notice_hint_border: Color,
    // Border color when the tooltip is in error state
    notice_error_border: Color,
    // Message input box default state border color
    input_border: Color,
    // Message input box body text color
    input_text: Color,
    // Message input box command mode border color
    command_border: Color,
    // Message input box search mode border color
    search_border: Color,
    // Background color for text selected by mouse for copying
    selection_background: Color,
    // Background color for search mode matched fragments
    search_match_background: Color,
    // Background color for "the currently located match" in search mode (distinguished from other hits)
    search_current_match_background: Color,
    // Read/unread status text color below messages
    read_state_text: Color,
}

/// Color notation in theme files: supports hex "#rrggbb", terminal basic color names, and [red, green, blue] three-element arrays.
/// Return None when unrecognized; the caller handles it as "that slot is missing" and never guesses an approximate color.
fn parse_theme_color(value: &serde_json::Value) -> Option<Color> {
    if let Some(components) = value.as_array() {
        let mut bytes = [0u8; 3];
        for (index, component) in components.iter().take(3).enumerate() {
            bytes[index] = component.as_u64()?.try_into().ok()?;
        }
        if components.len() != 3 {
            return None;
        }
        return Some(Color::Rgb(bytes[0], bytes[1], bytes[2]));
    }
    let text = value.as_str()?.trim().to_lowercase();
    if let Some(hexadecimal) = text.strip_prefix('#') {
        if hexadecimal.len() != 6 {
            return None;
        }
        let red = u8::from_str_radix(&hexadecimal[0..2], 16).ok()?;
        let green = u8::from_str_radix(&hexadecimal[2..4], 16).ok()?;
        let blue = u8::from_str_radix(&hexadecimal[4..6], 16).ok()?;
        return Some(Color::Rgb(red, green, blue));
    }
    let named = match text.as_str() {
        "default" | "reset" => Color::Reset,
        "black" => Color::Black,
        "red" => Color::Red,
        "green" => Color::Green,
        "yellow" => Color::Yellow,
        "blue" => Color::Blue,
        "magenta" => Color::Magenta,
        "cyan" => Color::Cyan,
        "white" => Color::White,
        "dark_gray" | "dark-gray" | "bright_black" | "bright-black" => Color::DarkGray,
        "light_red" | "light-red" | "bright_red" | "bright-red" => Color::LightRed,
        "light_green" | "light-green" | "bright_green" | "bright-green" => Color::LightGreen,
        "light_yellow" | "light-yellow" | "bright_yellow" | "bright-yellow" => Color::LightYellow,
        "light_blue" | "light-blue" | "bright_blue" | "bright-blue" => Color::LightBlue,
        "light_magenta" | "light-magenta" | "bright_magenta" | "bright-magenta" => {
            Color::LightMagenta
        }
        "light_cyan" | "light-cyan" | "bright_cyan" | "bright-cyan" => Color::LightCyan,
        "gray" | "grey" => Color::Gray,
        "bright_white" | "bright-white" => Color::White,
        _ => return None,
    };
    Some(named)
}

/// Select a readable foreground color based on background brightness: dark background gets light text, light background gets dark text.
/// The theme only provides background colors for selection and search hits; if the body foreground color is used, the text and background may be the same darkness and hard to see,
/// so the foreground color is uniformly derived from this function; when the background is the terminal default color, it is treated as dark.
fn contrasting_foreground(background: Color) -> Color {
    let brightness: u32 = match background {
        Color::Rgb(red, green, blue) => {
            (red as u32 * 299 + green as u32 * 587 + blue as u32 * 114) / 1000
        }
        Color::Indexed(index) => match index {
            0..=7 => 40,
            8..=15 => 170,
            16..=231 => {
                let cube = index - 16;
                let red = (cube / 36) * 51;
                let green = ((cube / 6) % 6) * 51;
                let blue = (cube % 6) * 51;
                (red as u32 * 299 + green as u32 * 587 + blue as u32 * 114) / 1000
            }
            _ => 128,
        },
        Color::Black | Color::Blue | Color::Green | Color::Magenta | Color::Red | Color::Reset => {
            40
        }
        Color::Cyan
        | Color::DarkGray
        | Color::Gray
        | Color::LightBlue
        | Color::LightCyan
        | Color::LightGreen
        | Color::LightMagenta
        | Color::LightRed
        | Color::LightYellow
        | Color::White
        | Color::Yellow => 200,
    };
    if brightness >= 128 {
        Color::Black
    } else {
        Color::White
    }
}

impl Appearance {
    /// Built-in default appearance: identical to the hardcoded color scheme before the appearance system was introduced,
    /// and also serves as the fallback color when a theme file has missing slots, ensuring users without a configured theme see the original effect.
    fn built_in() -> Self {
        Self {
            app_background: Color::Reset,
            message_border: Color::Cyan,
            room_border: Color::Cyan,
            overlay_border: Color::Cyan,
            message_text: Color::White,
            selected_text: Color::Yellow,
            other_username_text: Color::Cyan,
            own_username_text: Color::Green,
            time_text: Color::DarkGray,
            hint_text: Color::DarkGray,
            notice_hint_border: Color::Blue,
            notice_error_border: Color::Red,
            input_border: Color::Cyan,
            input_text: Color::White,
            command_border: Color::Yellow,
            search_border: Color::Red,
            selection_background: Color::Yellow,
            search_match_background: Color::Red,
            search_current_match_background: Color::LightYellow,
            read_state_text: Color::Blue,
        }
    }

    // Read `<config_dir>/themes/{name}.json`, returning the complete appearance struct at once.
    // The second tuple element is the "missing field" flag: true if any slot is missing, following theme conventions the specific missing field is not listed;
    /// The third element is the list of unknown field names extra in the theme file.
    /// Returns the built-in default appearance when the file is unreadable or not valid JSON, with the missing field flag set to true.
    fn load(name: &str) -> (Self, bool, Vec<String>) {
        let mut appearance = Self::built_in();
        let path = paths::config_path(&format!("themes/{name}.json"));
        let Ok(content) = fs::read_to_string(&path) else {
            return (appearance, true, Vec::new());
        };
        let Ok(document) = serde_json::from_str::<serde_json::Value>(&content) else {
            return (appearance, true, Vec::new());
        };
        let slots: Vec<(&str, &mut Color)> = vec![
            ("app_background", &mut appearance.app_background),
            ("message_border", &mut appearance.message_border),
            ("room_border", &mut appearance.room_border),
            ("overlay_border", &mut appearance.overlay_border),
            ("message_text", &mut appearance.message_text),
            ("selected_text", &mut appearance.selected_text),
            ("other_username_text", &mut appearance.other_username_text),
            ("own_username_text", &mut appearance.own_username_text),
            ("time_text", &mut appearance.time_text),
            ("hint_text", &mut appearance.hint_text),
            ("notice_hint_border", &mut appearance.notice_hint_border),
            ("notice_error_border", &mut appearance.notice_error_border),
            ("input_border", &mut appearance.input_border),
            ("input_text", &mut appearance.input_text),
            ("command_border", &mut appearance.command_border),
            ("search_border", &mut appearance.search_border),
            ("selection_background", &mut appearance.selection_background),
            (
                "search_match_background",
                &mut appearance.search_match_background,
            ),
            (
                "search_current_match_background",
                &mut appearance.search_current_match_background,
            ),
            ("read_state_text", &mut appearance.read_state_text),
        ];
        let known_field_names: Vec<&str> = slots.iter().map(|(field, _)| *field).collect();
        let mut has_missing_field = false;
        for (field, slot) in slots {
            match document.get(field).and_then(parse_theme_color) {
                Some(color) => *slot = color,
                None => has_missing_field = true,
            }
        }
        let extra_fields = document
            .as_object()
            .map(|entries| {
                entries
                    .keys()
                    .filter(|entry| !known_field_names.contains(&entry.as_str()))
                    .cloned()
                    .collect::<Vec<String>>()
            })
            .unwrap_or_default();
        (appearance, has_missing_field, extra_fields)
    }

    /// Border color for boxed input fields in form overlays (change password, change avatar, settings profile, delete account):
    /// Always takes the unselected color; the current item is indicated by bold title and > marker on the arrow row, avoiding seeing selection color everywhere when the overlay opens.
    fn form_field_border(&self) -> Color {
        self.input_border
    }

    /// Border color for boxed input fields in the login overlay: focused items use the selected color, the overlay retains its original strong indication style.
    fn login_field_border(&self, focused: bool) -> Color {
        if focused {
            self.selected_text
        } else {
            self.input_border
        }
    }

    /// List all available appearance names under config/themes (removing .json suffix), sorted alphabetically
    fn available_names() -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(paths::config_directory().join("themes"))
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .map(|extension| extension == "json")
                    .unwrap_or(false)
            })
            .filter_map(|entry| {
                entry
                    .path()
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .map(|stem| stem.to_string())
            })
            .collect();
        names.sort();
        names
    }
}

#[derive(Debug)]
pub struct App {
    // ==================== Upper layer: user-controllable configuration (from preferences.json or interface/command settings)====================
    pub input_collector: InputCollector,
    pub connector: Connector,
    // Currently loaded language string mapping (key → localized text)
    language_strings: HashMap<String, String>,
    // Whether to display the sender's uid in messages (true shows username(uid))
    show_uid: bool,
    // Whether the time display includes the date (true shows date+time, false shows time only)
    time_with_date: bool,
    // Whether to enable system notifications (prompt when new messages/private chat requests arrive)
    sound_enabled: bool,
    // Set of room IDs with "message do not disturb" enabled (keyed by each room's unique id), persisted in preferences.json.
    // Muted rooms do not send system notifications/sounds when receiving new messages elsewhere; unread counts are shown as dots (·) instead of specific numbers.
    muted_room_ids: HashSet<String>,
    // Currently active appearance color scheme (loaded from the theme file pointed to by the appearance field of preferences.json)
    appearance: Appearance,
    // Current appearance name ("built_in" when no theme file), used for settings page and /appearance echo
    appearance_name: String,
    // Quick search: in search mode, results appear in loaded messages as you type, no need to press Enter.
    // Enter still retains the full semantics of "load all history for the whole room then search" (pressing every key would page-load the entire history and overwhelm the API).
    // Persisted by the quick_search field of preferences.json
    quick_search: bool,

    // ==================== Lower layer: temporary state maintained during program runtime (not written to config files)====================
    // Index of the currently focused input field
    focus_index: usize,
    // Top-right notification list, elements are (notification text, is error type, expiration time), auto-removed when expired
    notifications: Vec<(String, bool, Instant)>,
    // Chat page state.
    rooms: Vec<RoomInfo>,
    rooms_state: ListState,
    messages: Vec<MessageInfo>,
    // Room ID → unread message count, used to show message count in red after the non-selected group chat name
    unread_counts: HashMap<String, u32>,
    current_user_id: Option<String>,
    displaying_overlay: DisplayingOverlay,
    // sender_id → username mapping
    sender_names: HashMap<String, String>,
    // Background polling thread communication sender (shared by multiple background threads)
    polling_sender: Option<mpsc::Sender<PollingEvent>>,
    // Background WebSocket thread command channel (complete WS JSON payload)
    websocket_sender: Option<mpsc::Sender<String>>,
    // WebSocket thread authentication token copy, used to rebuild the connection when a new room is detected
    websocket_token: Option<String>,
    // WebSocket thread running flag, setting to false makes it exit
    websocket_running: Option<Arc<AtomicBool>>,
    // Moment of the most recent successful WebSocket connection, used to periodically refresh room subscriptions to prevent degradation
    websocket_connected_at: Instant,
    // Background polling thread running flag, setting to false makes it exit (used when logging out)
    polling_running: Option<Arc<AtomicBool>>,
    // Currently selected item in the command completion list
    command_list_state: ListState,
    // Client encryption state (identity key and per-room encryption sessions)
    crypto: ClientCrypto,
    // Pending chat request list
    pending_requests: Vec<RoomRequestInfo>,
    // Currently selected item in the pending request list
    request_list_state: ListState,
    // Currently selected item in the settings menu
    menu_list_state: ListState,
    // Scroll distance of the message display area from the bottom (0 means snap to bottom following latest messages), unit is rendered rows
    messages_scroll_from_bottom: u16,
    // Pagination cursor for "older messages" of the currently selected room (next_cursor from the last message fetch response,
    // i.e., the server ID of the oldest message in the loaded list). Some means the server indicates there are still earlier messages
    // can be fetched, None means no more or fetch failed and stopped; assigned by load_messages_for_selected_room
    // after each full room load, consumed and advanced by load_older_messages when render_messages detects the user has scrolled to the top
    messages_older_cursor: Option<String>,
    // Moment the most recent full room message load completed. Switching rooms loads synchronously and blocks the main thread for hundreds of milliseconds, during which the user
    // mouse events pile up in the system queue, and after loading completes they are processed one by one, "automatically" pushing the new room view up
    // and may accidentally trigger top-pull; discarding mouse events within a short window from this moment eliminates these late inputs
    messages_reloaded_at: Instant,
    // Encrypted private chat room IDs closed locally: hidden from the interface only, not notified to the server to avoid creating single-person rooms
    closed_room_ids: HashSet<String>,
    // Group chat room IDs that this client actively left (/quit, /quit_group, /kick),
    // Distinguishes "voluntary quit" from "removed from group" to avoid false kick reports
    left_room_ids: HashSet<String>,
    // /quit exit cleanup has completed in the background, the main loop should exit immediately upon detection
    quit_ready: bool,
    // Currently selected item in the language selection list
    language_list_state: ListState,
    // Currently selected item in the appearance selection list
    appearance_list_state: ListState,
    // Currently selected item in the local avatar selection list
    avatar_list_state: ListState,
    // Search mode results: (executed search keyword, list of hit message IDs, current match index).
    // None means no search has been executed in this search mode round (the input box title only shows "search mode").
    search_result: Option<(String, Vec<String>, usize)>,
    // Message ID to be positioned in search mode: written when switching matches, cleared after render_messages scrolls it into view
    pending_scroll_message_id: Option<String>,
    // Currently typing members: elements are (room ID, username, most recent typing frame timestamp).
    // The server only has typing:true and no "stop typing" signal, so it decays locally based on the 2-second window agreed in TODO,
    // entries beyond the window are neither displayed nor cleaned up in handle_tick
    typing_members: Vec<(String, String, Instant)>,
    // Moment the most recent typing frame was sent upstream, used to throttle at the interval given by the seam
    // (server inbound rate limit is 30/30 seconds, per-character reporting would immediately fill the quota)
    last_typing_frame_sent_at: Option<Instant>,
    // Member presence table: user ID → online status. Completely accumulated from server user_online / user_offline
    // jump broadcast accumulation (the server does not send a baseline online list when establishing a connection),
    // absence from the table means "unknown", the interface does not show a status marker, avoiding incorrectly displaying unknown as offline.
    presence_by_user: HashMap<String, bool>,
    // Previous frame's full-screen row text snapshot (restored for double-width characters spanning cells), used to extract text by row and column range when selection is released.
    // Must be collected after the overlay and notifications are drawn, so text can be copied from any position, not just the message area.
    screen_text_rows: Vec<String>,
    // Flag requesting the main loop to perform a full-screen repaint (full redraw the frame after terminal.clear).
    // Set by Ctrl+L: incidental auto-scroll on the terminal side causes the screen content to desync from ratatui's incremental buffer,
    // incremental rendering only rewrites "changed" cells so it cannot self-heal, a full redraw is the only reliable fix.
    full_repaint_requested: bool,
    // Rectangle of the message input box on screen, written every frame by render_message_input.
    // Dragging within this area is still handled by the input control itself (preserving in-control selection and cursor semantics),
    // only dragging outside this area triggers full-screen selection; the two selection types do not take effect simultaneously.
    message_input_area: Rect,
    // Server real-time connection status: None means not yet probed (status bar shows no marker to avoid false offline report at startup),
    // Some(true/false) causes the online or offline marker to be drawn. The status bar marker and the "server unreachable, prompt once" share this.
    connection_ready: Option<bool>,
    // Current logged-in username (shown as "current user" in the status bar; empty string when not logged in)
    current_username: String,
    // User profile currently displayed in the /profile overlay
    profile_view: Option<PublicProfile>,
    // Action and fields of the general form overlay (only have values when displaying_overlay == Form)
    active_form: Option<(FormAction, Vec<FormField>)>,
    // Own email and phone number. The server only provides these two items in the complete response of registration, login, profile, and avatar interfaces,
    // the public profile interface deliberately excludes them, so these two lines on the card show "none" when viewing others.
    own_contact: Option<(String, String)>,
    // List of chat requests sent by oneself (displayed together with received requests in the private chat management overlay)
    sent_requests: Vec<RoomRequestInfo>,
    // Registered user directory cache (server's full user list). None means not yet fetched, Some even if empty counts as fetched,
    // no repeated requests. /profile auto-completion reads it every frame, so fetching can only be triggered by key presses and completed in the background thread,
    // and must absolutely not appear in the render path
    registered_users: Option<Vec<UserSearchResult>>,
    // Local message cache (only caches unencrypted rooms). The directory is established by the current logged-in user ID, None when not logged in
    chat_cache: Option<ChatCache>,
    // Raw avatar bytes: user ID → image bytes, None means "confirmed no avatar or fetch failed".
    // an existing entry means no repeated requests, avoiding repeatedly connecting to the network for the same user every frame; bytes are fetched in the background thread and delivered via
    // PollingEvent::AvatarLoaded back to the main thread, only one decoding is done during rendering (see avatar_pixels)。
    avatar_images: HashMap<String, Option<Vec<u8>>>,
    // Decoded avatar pixel blocks at display size: key is (user ID, column count, row count).
    // the same size is only decoded once (message list uses small blocks, profile card uses large blocks), thereafter looked up directly in the table every frame.
    avatar_pixels: HashMap<(String, usize, usize), AvatarPixels>,
    // Downloaded and verified new version: (new version number, local package path). Consumed by /update and the settings item "update client"
    pending_update: Option<(String, PathBuf)>,
    // /update has arranged a background installation process waiting for this process to exit, the main loop exits immediately upon detecting this flag
    update_handoff_requested: bool,
    // Whether background version checking and downloading is in progress, to avoid spawning duplicate download threads
    update_check_running: Option<Arc<AtomicBool>>,
    // Running flag of the persistent reachability probe thread (stop old, start new when changing server address)
    reachability_running: Option<Arc<AtomicBool>>,
    // The moment when message cache is pending being flushed to disk: Some means "the current room's message list is newer than the disk".
    // Only set when messages arrive one by one, not written to disk; handle_tick accumulates enough of a batch window and writes the entire room at once,
    // avoiding triggering a full file rewrite for every message in an active group chat
    cache_pending_flush_since: Option<Instant>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            input_collector: InputCollector::default(),
            connector: Connector::default(),
            language_strings: HashMap::new(),
            show_uid: false,
            time_with_date: false,
            sound_enabled: true,
            muted_room_ids: HashSet::new(),
            appearance: Appearance::built_in(),
            appearance_name: "built_in".to_string(),
            quick_search: false,
            focus_index: 0,
            notifications: Vec::new(),
            rooms: Vec::new(),
            rooms_state: ListState::default(),
            messages: Vec::new(),
            unread_counts: HashMap::new(),
            current_user_id: None,
            displaying_overlay: DisplayingOverlay::Nothing,
            sender_names: HashMap::new(),
            polling_sender: None,
            websocket_sender: None,
            websocket_token: None,
            websocket_running: None,
            websocket_connected_at: Instant::now(),
            polling_running: None,
            command_list_state: ListState::default(),
            crypto: ClientCrypto {
                identity_key: crypto::generate_identity_key(),
                sessions: HashMap::new(),
            },
            pending_requests: Vec::new(),
            request_list_state: ListState::default(),
            menu_list_state: ListState::default(),
            messages_scroll_from_bottom: 0,
            messages_older_cursor: None,
            messages_reloaded_at: Instant::now(),
            closed_room_ids: HashSet::new(),
            left_room_ids: HashSet::new(),
            quit_ready: false,
            language_list_state: ListState::default(),
            appearance_list_state: ListState::default(),
            avatar_list_state: ListState::default(),
            search_result: None,
            pending_scroll_message_id: None,
            typing_members: Vec::new(),
            last_typing_frame_sent_at: None,
            presence_by_user: HashMap::new(),
            screen_text_rows: Vec::new(),
            message_input_area: Rect::default(),
            full_repaint_requested: false,
            connection_ready: None,
            current_username: String::new(),
            profile_view: None,
            active_form: None,
            own_contact: None,
            sent_requests: Vec::new(),
            registered_users: None,
            chat_cache: None,
            avatar_images: HashMap::new(),
            avatar_pixels: HashMap::new(),
            pending_update: None,
            update_handoff_requested: false,
            update_check_running: None,
            reachability_running: None,
            cache_pending_flush_since: None,
        }
    }
}

/// Calculate the area allowed for this frame: reduce the full-screen height by one, leaving the bottom row empty.
/// Reason: when writing to the last row of the screen (especially the bottom-right cell), some terminals trigger auto-wrap and scroll existing content up one row,
/// but ratatui's incremental buffer doesn't know about this scroll, and each subsequent frame only redraws "changed" cells,
/// the misalignment can never be fixed — manifesting as the entire interface being pushed up a section after entering a large block of text with a Chinese input method,
/// only operations that trigger a full redraw like switching groups can recover. Leaving the last row empty avoids scrolling at the root.
fn drawable_area(area: Rect) -> Rect {
    if area.height <= 1 {
        return area;
    }
    Rect {
        height: area.height - 1,
        ..area
    }
}

/// Fill the given area with a specified background color (each component only patches the styles it wrote, so painting the base first allows uniform inheritance).
fn paint_background(frame: &mut Frame, area: Rect, background: Color) {
    frame
        .buffer_mut()
        .set_style(area, Style::default().bg(background));
}

/// Restore the full-screen buffer to a text snapshot row by row (double-width characters advance across cells, no extra spaces inserted).
/// Collected after all elements are drawn each frame, so full-screen selection can cover any position including message area, room list, overlays, and notifications.
fn collect_screen_text_rows(buffer: &ratatui::buffer::Buffer, area: Rect) -> Vec<String> {
    let mut rows: Vec<String> = Vec::new();
    for row in area.top()..area.bottom() {
        let mut text = String::new();
        let mut column = area.left();
        while column < area.right() {
            let Some(cell) = buffer.cell((column, row)) else {
                break;
            };
            let symbol = cell.symbol();
            text.push_str(symbol);
            column += display_width(symbol).max(1);
        }
        rows.push(text);
    }
    rows
}

/// Extract text covered by the selection rectangle from the full-screen row text snapshot: concatenate by row, cut columns by display width,
/// remove trailing spaces from rows and rows that are entirely empty at the beginning/end. Start and end order doesn't matter, the end column itself is included in the selection.
fn extract_selected_screen_text(
    screen_text_rows: &[String],
    selection_start: (u16, u16),
    selection_end: (u16, u16),
) -> String {
    let first_row = selection_start.1.min(selection_end.1);
    let last_row = selection_start.1.max(selection_end.1);
    let first_column = selection_start.0.min(selection_end.0);
    // The end column includes the cell itself, so shift right by one when taking the right boundary
    let last_column = selection_start.0.max(selection_end.0) + 1;
    let mut selected_rows: Vec<String> = Vec::new();
    for row in first_row..=last_row {
        let Some(row_text) = screen_text_rows.get(row as usize) else {
            continue;
        };
        selected_rows.push(
            strip_decoration_characters(&slice_columns_by_display_width(
                row_text,
                first_column,
                last_column,
            ))
            .trim()
            .to_string(),
        );
    }
    while selected_rows.last().is_some_and(|row| row.is_empty()) {
        selected_rows.pop();
    }
    while selected_rows.first().is_some_and(|row| row.is_empty()) {
        selected_rows.remove(0);
    }
    selected_rows.join("\n")
}

/// Strip interface decorations from the selection result: box-drawing symbols, bullet points, and dots, and blanks used as background fill.
/// These cells belong to the outer frame and background rather than content text, and should not be copied when selection crosses panel edges.
fn strip_decoration_characters(row_text: &str) -> String {
    row_text
        .chars()
        .filter(|character| {
            !matches!(
                character,
                '─' | '│'
                    | '┌'
                    | '┐'
                    | '└'
                    | '┘'
                    | '├'
                    | '┤'
                    | '┬'
                    | '┴'
                    | '┼'
                    | '━'
                    | '┃'
                    | '┏'
                    | '┓'
                    | '┗'
                    | '┛'
                    | '═'
                    | '║'
                    | '╔'
                    | '╗'
                    | '╚'
                    | '╝'
                    | '╠'
                    | '╣'
                    | '╦'
                    | '╩'
                    | '╬'
                    | '►'
                    | '▶'
                    | '●'
                    | '○'
                    | '·'
            )
        })
        .collect()
}

/// Normalize pasted content: unify line endings and strip control characters except newlines and tabs.
/// When macOS Terminal.app pastes multi-line text, the line ending sent is \r\n,
/// splitting only by \n would insert the \r at the end of each line into the text buffer,
/// manifesting as a garbled cell between lines, which needs to be deleted with backspace to restore normal text.
fn normalize_pasted_text(pasted_text: &str) -> String {
    pasted_text
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\t'))
        .collect()
}

/// Determine if a cell contains "content text": blank fill and interface decorations (box lines, arrows, dots, etc.) are not included.
/// Selection should only fall on content text; blanks and outer frames should neither be highlighted nor copied.
fn is_content_character(character: char) -> bool {
    !character.is_whitespace() && !is_decoration_character(character)
}

/// Set of interface decoration characters: box-drawing lines, selection arrows, online status dots, project dots, half-character avatars, etc.
/// Selection copy and highlighting both exclude according to this list, avoiding treating interface graphics as chat content.
fn is_decoration_character(character: char) -> bool {
    matches!(
        character,
        '─' | '│'
            | '┌'
            | '┐'
            | '└'
            | '┘'
            | '├'
            | '┤'
            | '┬'
            | '┴'
            | '┼'
            | '━'
            | '┃'
            | '┏'
            | '┓'
            | '┗'
            | '┛'
            | '═'
            | '║'
            | '╔'
            | '╗'
            | '╚'
            | '╝'
            | '╠'
            | '╣'
            | '╦'
            | '╩'
            | '╬'
            | '►'
            | '▶'
            | '●'
            | '○'
            | '·'
            | '▀'
            | '▄'
    )
}

/// Highlight the full-screen selection rectangle with the appearance's selection background color (order of the two endpoints doesn't matter), clamped to the screen range.
fn paint_screen_selection(
    frame: &mut Frame,
    area: Rect,
    selection_start: (u16, u16),
    selection_end: (u16, u16),
    appearance: &Appearance,
) {
    let first_row = selection_start.1.min(selection_end.1);
    let last_row = selection_start.1.max(selection_end.1);
    let first_column = selection_start.0.min(selection_end.0);
    let last_column = selection_start.0.max(selection_end.0);
    if area.width == 0 || area.height == 0 {
        return;
    }
    let selection_style = Style::default()
        .fg(contrasting_foreground(appearance.selection_background))
        .bg(appearance.selection_background);
    let buffer = frame.buffer_mut();
    for row in first_row..=last_row.min(area.bottom().saturating_sub(1)) {
        for column in first_column..=last_column.min(area.right().saturating_sub(1)) {
            let Some(cell) = buffer.cell_mut((column, row)) else {
                continue;
            };
            // Only highlight content text cells: outer frames, decorations, and background blanks are not part of the selection display
            if cell
                .symbol()
                .chars()
                .next()
                .is_some_and(is_content_character)
            {
                cell.set_style(selection_style);
            }
        }
    }
}

impl App {
    // Set the background polling thread communication sender
    pub fn set_polling_sender(&mut self, sender: Option<mpsc::Sender<PollingEvent>>) {
        self.polling_sender = sender;
    }

    // Start the background polling thread to periodically fetch room lists, pending and sent chat requests from the server.
    // When fetching fails, categorize by error type: inability to reach the server only reports a reachability change (interface prompts once and marks the status bar),
    // business errors explicitly returned by the server are still popped as Error.
    pub fn start_polling_thread(&mut self) {
        let Some(sender) = self.polling_sender.clone() else {
            return;
        };

        let connector = self.connector.clone();
        let lang_map = self.language_strings.clone();

        // Notify the old polling thread to stop, avoiding multiple polling threads existing in scenarios like logging out
        if let Some(running_flag) = self.polling_running.take() {
            running_flag.store(false, Ordering::Relaxed);
        }
        let running_flag = Arc::new(AtomicBool::new(true));
        self.polling_running = Some(running_flag.clone());

        thread::spawn(move || {
            let tr = |key: &str| {
                lang_map
                    .get(key)
                    .cloned()
                    .unwrap_or_else(|| key.to_string())
            };
            let report_failure = |error: baihua_core::api::ConnectorError, label_key: &str| {
                if error.is_connection_failure() {
                    let _ = sender.send(PollingEvent::ReachabilityChanged(false));
                } else {
                    let _ = sender.send(PollingEvent::Error(format!("{}: {error}", tr(label_key))));
                }
            };
            let mut last_rooms: Vec<RoomInfo> = Vec::new();
            let mut last_requests: Vec<RoomRequestInfo> = Vec::new();
            let mut last_sent_requests: Vec<RoomRequestInfo> = Vec::new();
            let mut room_poll_counter: u32 = 0;
            let mut request_poll_counter: u32 = 0;

            while running_flag.load(Ordering::Relaxed) {
                // Poll the room list every 2 seconds. Inability to reach the server is uniformly reported by the persistent probe thread,
                // here transport-layer failures are not thrown as business errors, otherwise one network jitter would be a string of error popups
                if room_poll_counter.is_multiple_of(20) {
                    match connector.list_rooms() {
                        Ok(rooms) => {
                            if rooms != last_rooms {
                                last_rooms = rooms.clone();
                                let _ = sender.send(PollingEvent::RoomsUpdated(rooms));
                            }
                        }
                        Err(error) if error.is_connection_failure() => {
                            debug_log(&format!(
                                "Cannot reach the server when polling room list: {error}"
                            ));
                        }
                        Err(error) => {
                            let _ = sender.send(PollingEvent::Error(format!(
                                "{}: {error}",
                                tr("error_poll_rooms")
                            )));
                        }
                    }
                }

                // Poll received and sent chat requests every 3 seconds; request interface failure doesn't change the reachability conclusion,
                // the room list already bears the same connectivity judgment, here only business errors are reported
                if request_poll_counter.is_multiple_of(30) {
                    match connector.list_pending_requests() {
                        Ok(requests) => {
                            if requests != last_requests {
                                last_requests = requests.clone();
                                let _ = sender.send(PollingEvent::PendingRequestsUpdated(requests));
                            }
                        }
                        Err(error) => report_failure(error, "error_poll_requests"),
                    }
                    match connector.list_sent_requests() {
                        Ok(requests) => {
                            if requests != last_sent_requests {
                                last_sent_requests = requests.clone();
                                let _ = sender.send(PollingEvent::SentRequestsUpdated(requests));
                            }
                        }
                        Err(error) => report_failure(error, "error_poll_requests"),
                    }
                }

                room_poll_counter = room_poll_counter.wrapping_add(1);
                request_poll_counter = request_poll_counter.wrapping_add(1);

                thread::sleep(Duration::from_millis(100));
            }
        });
    }

    // Start the WebSocket thread responsible for real-time message sending and receiving
    // Start the WebSocket thread: auto-reconnects on disconnect, until replaced by restart_websocket_thread or the application exits
    // Optional connected_sender: sends a signal when the server's connected receipt is received, used for auto-login waiting for connection readiness
    pub fn start_websocket_thread(
        &mut self,
        token: &str,
        mut connected_sender: Option<Sender<()>>,
    ) {
        // Notify the old thread to stop and wait for it to fully exit: ensure the old socket is closed before establishing a new connection,
        // avoiding the server seeing two connections from the same user briefly and getting confused
        if let Some(running_flag) = self.websocket_running.take() {
            running_flag.store(false, Ordering::Relaxed);
            // Wait for the old thread to exit (its inner loop sleeps 50ms then checks the flag and returns)
            thread::sleep(Duration::from_millis(150));
        }
        let Some(event_sender) = self.polling_sender.clone() else {
            return;
        };
        let (command_sender, command_receiver) = mpsc::channel::<String>();
        self.websocket_sender = Some(command_sender);
        self.websocket_token = Some(token.to_string());
        self.websocket_connected_at = Instant::now();

        let running_flag = Arc::new(AtomicBool::new(true));
        self.websocket_running = Some(running_flag.clone());
        let thread_running = running_flag.clone();

        // WebSocket connection URL is derived by the seam based on the current version (scheme mapping + fixed path /websocket)
        let version = self.connector.version();
        let websocket_url = version.websocket_url(self.connector.base_url());
        let token = token.to_string();
        let lang_map = self.language_strings.clone();
        // Application-layer bidirectional heartbeat frame and interval (by version), for the background thread to send periodically to maintain client→server direction traffic
        let heartbeat_frame = version.heartbeat_frame();
        let heartbeat_interval = version.application_heartbeat_interval();

        thread::spawn(move || {
            let tr = |key: &str| {
                lang_map
                    .get(key)
                    .cloned()
                    .unwrap_or_else(|| key.to_string())
            };
            // The outer loop supports auto-reconnect on disconnect; after reconnecting, the server completes subscription based on the latest room list
            while thread_running.load(Ordering::Relaxed) {
                // The library auto-generates a complete handshake request conforming to RFC 6455 (including required headers like Sec-WebSocket-Key)
                let mut request = match websocket_url.as_str().into_client_request() {
                    Ok(request) => request,
                    Err(e) => {
                        debug_log(&format!("WS request construction failed: {e}"));
                        let _ = event_sender.send(PollingEvent::Error(format!(
                            "{}: {e}",
                            tr("error_ws_handshake")
                        )));
                        // Wait and retry after request construction failure
                        for _ in 0..20 {
                            if !thread_running.load(Ordering::Relaxed) {
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
                    Err(e) => {
                        debug_log(&format!("WS auth header construction failed: {e}"));
                        let _ = event_sender.send(PollingEvent::Error(format!(
                            "{}: {e}",
                            tr("error_construct_auth_failed")
                        )));
                        // Wait and retry after auth header construction failure
                        for _ in 0..20 {
                            if !thread_running.load(Ordering::Relaxed) {
                                return;
                            }
                            thread::sleep(Duration::from_millis(100));
                        }
                        continue;
                    }
                }

                let mut socket = match tungstenite::connect(request) {
                    Ok((socket, _)) => {
                        debug_log("WS connected");
                        socket
                    }
                    Err(e) => {
                        debug_log(&format!("WS connection failed: {e}"));
                        let err_msg = e.to_string();
                        let _ = event_sender.send(PollingEvent::WebSocketState(
                            "error_ws_connect_failed".to_string(),
                        ));
                        // Server handshake authentication failure (401/403/token expired, etc., the judgment marker is given by the seam based on version):
                        // Clear the session and notify the main thread, exit directly without retrying
                        if version.is_auth_failure(&err_msg) {
                            let _ = event_sender
                                .send(PollingEvent::Error(websocket_auth_sentinel().to_string()));
                            return;
                        }
                        // Wait and retry after connection failure
                        for _ in 0..20 {
                            if !thread_running.load(Ordering::Relaxed) {
                                return;
                            }
                            thread::sleep(Duration::from_millis(100));
                        }
                        continue;
                    }
                };
                // Set the underlying TCP stream to non-blocking mode so read operations return immediately when there's no data
                if let tungstenite::stream::MaybeTlsStream::Plain(stream) = socket.get_ref() {
                    let _ = stream.set_nonblocking(true);
                }

                let mut connected_signaled = false;
                // Application-layer bidirectional heartbeat: the server only sends protocol-level Ping frames (30 seconds), the client direction is completely silent
                // Will be judged by intermediate network devices (NAT/proxy/firewall) as one-directional no traffic and the connection mapping will be discarded.
                // {"type":"pong"} is the only message the server confirms to silently ignore (no reply), used to generate
                // client→server direction TCP traffic to keep the NAT mapping active.
                let mut keepalive = Instant::now();

                loop {
                    if !thread_running.load(Ordering::Relaxed) {
                        return;
                    }
                    match socket.read() {
                        Ok(WebSocketMessage::Text(text)) => {
                            if let Some(event) = parse_websocket_event(text.as_ref(), &tr) {
                                debug_log(&format!(
                                    "WS 收到类型: {}",
                                    text.chars().take(80).collect::<String>()
                                ));
                                // If it's a connected event and there's a connected_sender, send a signal to notify connection readiness
                                if !connected_signaled
                                    && let PollingEvent::WebSocketConnected = &event
                                {
                                    debug_log("WS connected receipt received, sending sync signal");
                                    if let Some(sender) = connected_sender.take() {
                                        let _ = sender.send(());
                                        connected_signaled = true;
                                    }
                                }
                                let _ = event_sender.send(event);
                            }
                        }
                        Ok(_) => {}
                        Err(tungstenite::Error::Io(ref error))
                            if error.kind() == ErrorKind::WouldBlock => {}
                        Err(e) => {
                            debug_log(&format!("WS disconnected: {e}"));
                            let _ = event_sender.send(PollingEvent::WebSocketState(
                                "error_ws_disconnected_reconnect".to_string(),
                            ));
                            break;
                        }
                    }

                    while let Ok(payload) = command_receiver.try_recv() {
                        debug_log(&format!("WS sent: {payload}"));
                        if socket.write(WebSocketMessage::text(payload)).is_err() {
                            let _ = event_sender.send(PollingEvent::WebSocketState(
                                "error_ws_send_failed".to_string(),
                            ));
                        }
                    }

                    // Periodically send application-layer heartbeat frames (frame content and interval are given by the seam based on version),
                    // Maintain client→server direction TCP traffic, avoiding intermediate devices discarding the connection mapping
                    if keepalive.elapsed() >= heartbeat_interval {
                        let _ = socket.write(WebSocketMessage::text(heartbeat_frame.clone()));
                        keepalive = Instant::now();
                    }

                    // Unconditional flush: Pong automatically queued by tungstenite (responding to server Ping)
                    // and heartbeat messages are all written to the TCP stream through this flush
                    let _ = socket.flush();

                    thread::sleep(Duration::from_millis(50));
                }

                // Wait briefly after disconnect then reconnect
                for _ in 0..10 {
                    if !thread_running.load(Ordering::Relaxed) {
                        return;
                    }
                    thread::sleep(Duration::from_millis(100));
                }
            }
        });
    }

    /// Rebuild the WebSocket connection: the server only snapshots room subscriptions when the connection is established,
    /// must reconnect to receive pushes for that room when a new room appears (like when a chat request is just accepted)
    fn restart_websocket_thread(&mut self) {
        if let Some(token) = self.websocket_token.clone() {
            self.start_websocket_thread(&token, None);
            self.websocket_connected_at = Instant::now();
        }
    }

    // Handle events sent by background threads
    pub fn handle_polling_event(&mut self, event: PollingEvent) {
        match event {
            PollingEvent::RoomsUpdated(rooms) => {
                self.apply_room_snapshot(rooms);
            }
            PollingEvent::SentRequestsUpdated(requests) => {
                self.announce_declined_invitations(&requests);
                self.sent_requests = requests;
            }
            PollingEvent::ReachabilityChanged(online) => {
                self.update_connection_state(online);
            }
            PollingEvent::AvatarLoaded((user_id, image_bytes)) => {
                self.avatar_images.insert(user_id, image_bytes);
            }
            PollingEvent::RegisteredUsersUpdated(users) => {
                self.registered_users = Some(users);
            }
            PollingEvent::UpdateReady((version, archive_path)) => {
                self.pending_update = Some((version.clone(), archive_path));
                self.push_notification(
                    self.t("update_ready")
                        .replace("{version}", &version)
                        .to_string(),
                );
            }
            PollingEvent::WebSocketConnected => {
                self.update_connection_state(true);
                // Connection (or reconnection) is ready: re-send all inactive handshakes with existing key material as-is.
                // Old invitations may be broadcast and lost during periods when nobody is subscribed; no-op when there are no inactive sessions
                let stale_room_ids: Vec<String> = self
                    .crypto
                    .sessions
                    .iter()
                    .filter(|(_, session)| session.phase != EncryptionPhase::Active)
                    .map(|(room_id, _)| room_id.clone())
                    .collect();
                for room_id in stale_room_ids {
                    self.resend_handshake_if_needed(&room_id);
                }
            }
            PollingEvent::MessageSent(message) => {
                // The server simultaneously sends back an acknowledgment and new message broadcast; deduplicate by id to avoid showing own messages twice
                if !self
                    .messages
                    .iter()
                    .any(|existing| existing.id == message.id)
                {
                    self.messages.push(message);
                    self.mark_messages_dirty();
                }
            }
            PollingEvent::IncomingMessage(message) => {
                debug_log(&format!(
                    "IncomingMessage: id={} room_id={} sender_id={} selected_room={:?}",
                    message.id,
                    message.room_id,
                    message.sender_id,
                    self.rooms_state
                        .selected()
                        .and_then(|i| self.rooms.get(i))
                        .map(|r| &r.id)
                ));
                // Check if it's our own message
                let is_own_message = self
                    .current_user_id
                    .as_ref()
                    .map(|uid| uid == &message.sender_id)
                    .unwrap_or(false);
                // Any message from others triggers a system notification (including sound), regardless of whether it's in the currently viewed room;
                // the room's do-not-disturb setting suppresses the notification (unread count still accumulates)
                if !is_own_message && !self.muted_room_ids.contains(&message.room_id) {
                    let sender_name = self.sender_display_name(&message.sender_id);
                    self.send_system_notification(
                        &self.t("notification_new_message"),
                        &format!("{}: {}", sender_name, message.content),
                    );
                }
                // If the message belongs to the currently selected room and is not a duplicate, append it to the message list
                let selected_room_id = self
                    .rooms_state
                    .selected()
                    .and_then(|index| self.rooms.get(index))
                    .map(|room| room.id.clone());
                let is_duplicate = self
                    .messages
                    .iter()
                    .any(|existing| existing.id == message.id);
                if selected_room_id.as_deref() == Some(message.room_id.as_str()) && !is_duplicate {
                    debug_log(&format!(
                        "append_incoming_msg room={} id={}",
                        message.room_id, message.id
                    ));
                    // Receiving a message from someone in real-time means they have an active connection now: use this to correct the presence status,
                    // avoiding long-term incorrect display as offline due to missing user_online transitions
                    if !is_own_message && !message.sender_id.is_empty() {
                        self.presence_by_user
                            .insert(message.sender_id.clone(), true);
                    }
                    let is_match = !message.content.is_empty()
                        && self.search_result.as_ref().is_some_and(|(keyword, _, _)| {
                            !find_keyword_positions(&message.content, keyword).is_empty()
                        });
                    self.messages.push(message);
                    self.mark_messages_dirty();
                    if is_match {
                        // A new hit message arrived during search: rescan the hit list to update "i/n" accordingly,
                        // but don't seize the view position (the user may be reading content near the current match)
                        self.refresh_search_matches();
                    }
                } else {
                    // Message belongs to a non-selected room: accumulate unread count, displayed as red (N) when rendering
                    if selected_room_id.as_deref() != Some(message.room_id.as_str())
                        && self.rooms.iter().any(|r| r.id == message.room_id)
                    {
                        *self
                            .unread_counts
                            .entry(message.room_id.clone())
                            .or_insert(0) += 1;
                    }
                    debug_log(&format!(
                        "skip_incoming_msg: selected_room_id={:?} msg_room_id={} match={}",
                        selected_room_id.as_deref(),
                        message.room_id,
                        selected_room_id.as_deref() == Some(message.room_id.as_str())
                    ));
                }
            }
            PollingEvent::PendingRequestsUpdated(requests) => {
                // Detect newly arrived requests and prompt, then update the list and selection
                for request in &requests {
                    let is_new = !self
                        .pending_requests
                        .iter()
                        .any(|existing| existing.id == request.id);
                    if is_new {
                        let sender_name = request
                            .sender
                            .as_ref()
                            .map(|sender| sender.username.clone())
                            .unwrap_or_else(|| self.t("unknown_user"));
                        self.push_notification(
                            self.t("notification_request_received")
                                .replace("{sender}", &sender_name)
                                .to_string(),
                        );
                        // Send system notification
                        self.send_system_notification(
                            &self.t("notification_new_request"),
                            &self
                                .t("notification_request_received")
                                .replace("{sender}", &sender_name),
                        );
                    }
                }
                self.apply_received_requests(requests);
                if self.request_list_state.selected().is_none() && !self.pending_requests.is_empty()
                {
                    self.request_list_state.select(Some(0));
                }
            }
            PollingEvent::EncryptInvitation(handshake) => {
                debug_log(&format!(
                    "Event EncryptInvitation room={} peer={}",
                    handshake.room_id, handshake.peer_id
                ));
                self.handle_encrypt_invitation(handshake);
            }
            PollingEvent::EncryptAccepted(handshake) => {
                debug_log(&format!(
                    "Event EncryptAccepted room={} peer={}",
                    handshake.room_id, handshake.peer_id
                ));
                self.handle_encrypt_accepted(handshake);
            }
            PollingEvent::EncryptSessionReady(room_id) => {
                debug_log(&format!("Event EncryptSessionReady room={room_id}"));
                if let Some(session) = self.crypto.sessions.get_mut(&room_id) {
                    session.phase = EncryptionPhase::Active;
                }
                self.push_notification(self.t("notification_session_active"));
                // Flush all messages queued during the handshake sequentially
                while self.flush_pending_encrypted_message(&room_id) {}
            }
            PollingEvent::EncryptedMessage(info) => {
                debug_log(&format!(
                    "Event EncryptedMessage room={} sender={}",
                    info.room_id, info.sender_id
                ));
                self.handle_encrypted_message(info);
            }
            PollingEvent::EncryptedMessageSent(_) => {}
            PollingEvent::EncryptSessionEnded((room_id, reason)) => {
                self.crypto.sessions.remove(&room_id);
                // The mapping of reason→text key name is given centrally by the seam based on version
                let reason_text = self.connector.version().session_end_reason_key(&reason);
                let reason_text = self.t(reason_text);
                // Server session reset clears messages but not the room; soft-close locally to avoid creating a solo room
                self.close_local_room(&room_id);
                self.push_notification(
                    self.t("notification_room_removed")
                        .replace("{reason}", &reason_text)
                        .to_string(),
                );
            }
            PollingEvent::WebSocketState(message_key) => {
                // Local WebSocket jitter self-heals (auto-reconnect + periodic subscription refresh); by default do not disturb the user;
                // Only genuinely undeliverable packets prompt; avoid the noise of "error then self-recovery"
                debug_log(&format!("WebSocket status event: {message_key}"));
                match message_key.as_str() {
                    "error_ws_send_failed" => self.push_error(self.t(&message_key)),
                    // Cannot connect to server: delegate to the top bar marker; only pop one error per frame while the fault persists
                    "error_ws_connect_failed" => {
                        // Just clear the version string; the connection flag delegates to the persistent probing thread, which is more reliable than single-link jitter
                        self.connector.clear_server_version();
                    }
                    _ => {}
                }
            }
            PollingEvent::MemberTyping((room_id, user_id, username)) => {
                // The server already filters echo of our own typing frames; this adds another layer to prevent self-display in multi-connection scenarios
                if Some(&user_id) == self.current_user_id.as_ref() || username.is_empty() {
                    return;
                }
                // Keep only the latest entry per member: remove the old record before inserting, avoiding duplicate names piling into the title
                self.typing_members
                    .retain(|(_, kept_user_id, _)| kept_user_id != &user_id);
                self.typing_members
                    .push((room_id, username, Instant::now()));
            }
            PollingEvent::PresenceChanged((user_id, username, is_online)) => {
                self.presence_by_user.insert(user_id.clone(), is_online);
                if !is_online {
                    // Only update online status and typing indicators; never clean up encrypted sessions here:
                    // The server will momentarily consider the user fully offline during local WebSocket reconnection (new room subscription refresh, 60-second periodic rebuild):
                    // broadcast user_offline; dismantling sessions based on this is exactly why "switching groups and back causes
                    // private chats to break." Session lifecycles are driven solely by authoritative server events
                    // (30-second grace period from encrypt_partner_disconnected, encrypt_session_ended /
                    // encrypt_session_expired); if the peer reconnects within the grace period the session remains usable.
                    self.typing_members
                        .retain(|(_, kept_user_id, _)| kept_user_id != &user_id);
                }
                // Online broadcasts include the username; also enrich the name mapping so new members display correctly before their first message
                if !username.is_empty() {
                    self.sender_names.insert(user_id, username);
                }
            }
            PollingEvent::QuitCleanupFinished => {
                self.quit_ready = true;
            }
            PollingEvent::Error(error) => {
                // Client-made auth failure sentinel (token expired/invalid): clear the session and return to the logged-out chat page.
                // Place before other categories to avoid being misreported as a displayable error.
                if error == websocket_auth_sentinel() {
                    debug_log("WebSocket 认证失败，清除保存的会话并回到未登录聊天页");
                    Self::clear_saved_session();
                    self.current_user_id = None;
                    self.focus_index = 0;
                    self.rooms.clear();
                    self.rooms_state = ListState::default();
                    self.messages.clear();
                    self.sender_names.clear();
                    self.crypto.sessions.clear();
                    self.closed_room_ids.clear();
                    self.left_room_ids.clear();
                    self.notifications.clear();
                    self.displaying_overlay = DisplayingOverlay::Nothing;
                    self.input_collector.login_name_state = TextInputState::default();
                    self.input_collector.login_password_state = TextInputState::default();
                    self.input_collector.register_name_state = TextInputState::default();
                    self.input_collector.register_email_state = TextInputState::default();
                    self.input_collector.register_password_state = TextInputState::default();
                    if let Some(running_flag) = self.websocket_running.take() {
                        running_flag.store(false, Ordering::Relaxed);
                    }
                    if let Some(running_flag) = self.polling_running.take() {
                        running_flag.store(false, Ordering::Relaxed);
                    }
                    self.websocket_sender = None;
                    self.websocket_token = None;
                    return;
                }
                // Remaining server error texts are categorized as domain signals by version; behavior is judged centrally, scattered literals have been absorbed into the seam
                match self.connector.version().classify_server_error(&error) {
                    // Hit a lingering active encrypted session on the server: send encrypt_leave to clear the field, and display the error to the user
                    ServerSignal::StuckEncryptedSession => {
                        self.recover_stuck_encryption_sessions();
                        self.push_error(error);
                    }
                    // Peer offline causing handshake rejection: clean up the zombie session waiting for accept locally, and return queued plaintext to the input box
                    ServerSignal::PartnerOfflineHandshakeRejected => {
                        self.discard_rejected_handshakes();
                    }
                    // /quit batch cleanup of leave for rooms without sessions: expected, silently ignored
                    ServerSignal::NoActiveEncryptedSession => {}
                    // Server reports "not a member" after leaving a private chat: expected, silently ignored
                    ServerSignal::NotRoomMember => {}
                    // Other genuine errors: display to the user
                    ServerSignal::Displayable => {
                        self.push_error(error);
                    }
                }
            }
        }
    }

    /// Send leave messages to all inactive encrypted sessions locally, prompting the server to clean up residual state
    fn recover_stuck_encryption_sessions(&mut self) {
        let stuck_room_ids: Vec<String> = self
            .crypto
            .sessions
            .iter()
            .filter(|(_, session)| session.phase != EncryptionPhase::Active)
            .map(|(room_id, _)| room_id.clone())
            .collect();
        for room_id in stuck_room_ids {
            self.send_ws_payload(outbound_ws_payload(
                self.connector.version(),
                WsCommand::EncryptLeave { room_id: &room_id },
            ));
        }
    }

    // Cleanup when peer offline causes handshake rejection: remove all sessions in "waiting for peer accept" state (they can no longer succeed):
    // and return the queued unsent plaintext to the message input box.
    /// The consequence of not returning is "message sent then immediately disappears": the session is deleted, queued content is discarded with the session, and the input box is already cleared,
    /// so the user neither sent it nor sees any trace. Return only the one in the currently selected room; discard the rest.
    fn discard_rejected_handshakes(&mut self) {
        let selected_room_id = self.selected_room_id();
        let stuck_room_ids: Vec<String> = self
            .crypto
            .sessions
            .iter()
            .filter(|(_, session)| session.phase == EncryptionPhase::AwaitingAcceptance)
            .map(|(room_id, _)| room_id.clone())
            .collect();
        let mut returned_content: Option<String> = None;
        for room_id in stuck_room_ids {
            if let Some(session) = self.crypto.sessions.remove(&room_id)
                && Some(room_id) == selected_room_id
            {
                returned_content = session.pending_content;
            }
        }
        self.push_notification(self.t("notification_partner_offline"));
        let Some(content) = returned_content else {
            return;
        };
        let typed = self.input_collector.message_input_state.text();
        // When the input box has been edited again, do not overwrite the user's new content; instead prepend the unsent content, keeping both
        let merged = if typed.is_empty() {
            content
        } else {
            format!("{content}\n{typed}")
        };
        self.input_collector.message_input_state.set_text(merged);
        self.push_notification(self.t("notification_message_returned"));
    }

    /// Handle encryption session invitation initiated by the peer: verify signature, negotiate key, reply with acceptance and readiness
    fn handle_encrypt_invitation(&mut self, handshake: EncryptHandshakeData) {
        // The server broadcasts the invitation to all room members, inviter_id equal to self is the echo of its own request
        if Some(&handshake.peer_id) == self.current_user_id.as_ref() {
            debug_log("invitation 早退：自身回声");
            return;
        }
        // When a valid peer invitation arrives, the old session on this side waiting for acceptance indicates both sides initiated simultaneously (role reversal),
        // discard the old session and take the acceptance flow; if already active or negotiating, ignore duplicate invitations
        if let Some(existing) = self.crypto.sessions.get(&handshake.room_id) {
            if existing.phase != EncryptionPhase::AwaitingAcceptance {
                debug_log("invitation 早退：已有非等待接受会话");
                return;
            }
            debug_log("invitation 角色反转：丢弃旧会话改走接受方");
            self.crypto.sessions.remove(&handshake.room_id);
        }
        if !crypto::verify_handshake_signature(
            &handshake.identity_key,
            &handshake.public_key,
            &handshake.signature,
        ) {
            debug_log("invitation 早退：签名校验失败");
            self.push_error(self.t("error_invitation_signature_invalid"));
            return;
        }
        // Negotiate shared key: our new ephemeral private key × peer's ephemeral public key
        let ephemeral_secret = crypto::generate_ephemeral_secret();
        let own_public_key = crypto::encode_x25519_public(&ephemeral_secret);
        let shared_key = match crypto::derive_shared_key(ephemeral_secret, &handshake.public_key) {
            Ok(key) => key,
            Err(e) => {
                self.push_error(format!(
                    "{}: {e}",
                    self.t("notification_encryption_failed_key")
                ));
                return;
            }
        };
        // The signing target is our ephemeral public key (per server documentation convention)
        let signature = match crypto::sign_public_key(&self.crypto.identity_key, &own_public_key) {
            Ok(signature) => signature,
            Err(e) => {
                self.push_error(format!(
                    "{}: {e}",
                    self.t("notification_encryption_failed_signature")
                ));
                return;
            }
        };
        let identity_key = crypto::encode_identity_public(&self.crypto.identity_key);
        self.send_ws_payload(outbound_ws_payload(
            self.connector.version(),
            WsCommand::EncryptAccept {
                room_id: &handshake.room_id,
                public_key: &own_public_key,
                identity_key: &identity_key,
                signature: &signature,
            },
        ));
        self.send_ws_payload(outbound_ws_payload(
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
                own_public_key,
                shared_key: Some(shared_key),
                pending_content: None,
                initiated_at: Instant::now(),
            },
        );
        self.push_notification(self.t("notification_session_accepted"));
    }

    /// Handle peer acceptance response: verify signature, complete key negotiation, and send readiness
    fn handle_encrypt_accepted(&mut self, handshake: EncryptHandshakeData) {
        // acceptor_id equal to self is the broadcast echo of its own accept
        if Some(&handshake.peer_id) == self.current_user_id.as_ref() {
            return;
        }
        let session_exists = self
            .crypto
            .sessions
            .get(&handshake.room_id)
            .is_some_and(|session| session.phase == EncryptionPhase::AwaitingAcceptance);
        if !session_exists {
            return;
        }
        if !crypto::verify_handshake_signature(
            &handshake.identity_key,
            &handshake.public_key,
            &handshake.signature,
        ) {
            self.crypto.sessions.remove(&handshake.room_id);
            self.push_error(self.t("notification_accept_failed_signature"));
            return;
        }
        let shared_key = {
            let session = self
                .crypto
                .sessions
                .get_mut(&handshake.room_id)
                .expect("会话存在性已在上方校验");
            let ephemeral_secret = session
                .ephemeral_secret
                .take()
                .expect("等待接受阶段的会话必然持有临时私钥");
            match crypto::derive_shared_key(ephemeral_secret, &handshake.public_key) {
                Ok(key) => key,
                Err(e) => {
                    self.push_error(format!(
                        "{}: {e}",
                        self.t("notification_encryption_failed_key")
                    ));
                    return;
                }
            }
        };
        let session = self
            .crypto
            .sessions
            .get_mut(&handshake.room_id)
            .expect("会话存在性已在上方校验");
        session.shared_key = Some(shared_key);
        session.phase = EncryptionPhase::AwaitingSessionReady;
        session.initiated_at = Instant::now();
        self.send_ws_payload(outbound_ws_payload(
            self.connector.version(),
            WsCommand::EncryptReady {
                room_id: &handshake.room_id,
            },
        ));
    }

    /// Handle received encrypted messages: display after decryption, deduplicated by current selected room and message id
    fn handle_encrypted_message(&mut self, info: EncryptedMessageInfo) {
        let selected_room_id = self.selected_room_id();
        let is_selected = selected_room_id.as_deref() == Some(info.room_id.as_str());
        let is_own = self
            .current_user_id
            .as_ref()
            .map(|uid| *uid == info.sender_id)
            .unwrap_or(false);
        let shared_key = self
            .crypto
            .sessions
            .get(&info.room_id)
            .and_then(|session| session.shared_key);
        // If decryption succeeds, take the plaintext for notification preview; if it fails, it doesn't affect unread statistics
        let plaintext =
            shared_key.and_then(|key| crypto::decrypt_message(&key, &info.ciphertext).ok());

        if !is_selected {
            // Fix for private chat missing notifications in other rooms: accumulate unread count and send desktop notifications even for non-currently-viewed rooms:
            // Suppress notifications when the room has do-not-disturb enabled (or it's our own echo)
            *self.unread_counts.entry(info.room_id.clone()).or_insert(0) += 1;
            if !is_own && !self.muted_room_ids.contains(&info.room_id) {
                let sender_name = self.sender_display_name(&info.sender_id);
                let preview = plaintext.unwrap_or_else(|| self.t("encrypted_mark"));
                self.send_system_notification(
                    &self.t("notification_new_message"),
                    &format!("{}: {}", sender_name, preview),
                );
            }
            return;
        }

        // Current viewing room: append for display after decryption
        match plaintext {
            Some(plaintext) => {
                if !self.messages.iter().any(|existing| existing.id == info.id) {
                    // Encrypted rooms don't persist to disk, marking dirty here is harmless: it will be blocked again by the room encryption flag before persisting
                    self.mark_messages_dirty();
                    self.messages.push(MessageInfo {
                        id: info.id,
                        room_id: info.room_id,
                        sender_id: info.sender_id,
                        content: self
                            .t("notification_encrypted_prefix")
                            .replace("{text}", &plaintext)
                            .to_string(),
                        created_at: info.created_at,
                    });
                }
            }
            None => {
                if shared_key.is_none() {
                    self.push_error(self.t("notification_decrypt_failed_no_key"));
                } else {
                    self.push_error(self.t("notification_decrypt_failed"));
                }
            }
        }
    }

    /// After the session is active, send a queued plaintext message (sent after encryption); returns whether any message was actually sent
    fn flush_pending_encrypted_message(&mut self, room_id: &str) -> bool {
        let payload = {
            let session = match self.crypto.sessions.get_mut(room_id) {
                Some(session) if session.phase == EncryptionPhase::Active => session,
                _ => return false,
            };
            let content = match session.pending_content.take() {
                Some(content) => content,
                None => return false,
            };
            let shared_key = match session.shared_key {
                Some(key) => key,
                None => return false,
            };
            match crypto::encrypt_message(&shared_key, &content) {
                Ok(ciphertext) => outbound_ws_payload(
                    self.connector.version(),
                    WsCommand::EncryptMessage {
                        room_id,
                        ciphertext: &ciphertext,
                    },
                ),
                Err(e) => {
                    self.push_error(format!("{}: {e}", self.t("error_encrypt_message_failed")));
                    return false;
                }
            }
        };
        self.send_ws_payload(payload);
        true
    }

    /// Initiate an encryption session handshake; if there's pending content, it's automatically sent after the session is ready
    fn initiate_encryption(&mut self, room_id: &str, pending_content: Option<String>) {
        let ephemeral_secret = crypto::generate_ephemeral_secret();
        let public_key = crypto::encode_x25519_public(&ephemeral_secret);
        let identity_key = crypto::encode_identity_public(&self.crypto.identity_key);
        let signature = match crypto::sign_public_key(&self.crypto.identity_key, &public_key) {
            Ok(signature) => signature,
            Err(e) => {
                self.push_error(format!(
                    "{}: {e}",
                    self.t("notification_encryption_failed_signature")
                ));
                return;
            }
        };
        debug_log(&format!(
            "initiate room={room_id} public_key前8={}",
            &public_key[..8.min(public_key.len())]
        ));
        self.send_encrypt_request(room_id, &public_key, &identity_key, &signature);
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

    /// Send encryption handshake invitation message
    fn send_encrypt_request(
        &mut self,
        room_id: &str,
        public_key: &str,
        identity_key: &str,
        signature: &str,
    ) {
        self.send_ws_payload(outbound_ws_payload(
            self.connector.version(),
            WsCommand::EncryptRequest {
                room_id,
                public_key,
                identity_key,
                signature,
            },
        ));
    }

    /// Resend handshake messages with existing key material from the session as-is:
    /// Resend invitation (same public key) when awaiting acceptance, resend ready (server is idempotent) when awaiting readiness
    fn resend_handshake_if_needed(&mut self, room_id: &str) {
        let payload = {
            let session = match self.crypto.sessions.get_mut(room_id) {
                Some(session) if session.phase != EncryptionPhase::Active => session,
                _ => return,
            };
            match session.phase {
                EncryptionPhase::AwaitingAcceptance => {
                    let identity_key = crypto::encode_identity_public(&self.crypto.identity_key);
                    // The signing object remains the same ephemeral public key, ensuring the peer can negotiate consistently regardless of which invitation they respond to
                    let signature = match crypto::sign_public_key(
                        &self.crypto.identity_key,
                        &session.own_public_key,
                    ) {
                        Ok(signature) => signature,
                        Err(_) => return,
                    };
                    session.initiated_at = Instant::now();
                    outbound_ws_payload(
                        self.connector.version(),
                        WsCommand::EncryptRequest {
                            room_id,
                            public_key: &session.own_public_key,
                            identity_key: &identity_key,
                            signature: &signature,
                        },
                    )
                }
                EncryptionPhase::AwaitingSessionReady => {
                    session.initiated_at = Instant::now();
                    outbound_ws_payload(
                        self.connector.version(),
                        WsCommand::EncryptReady { room_id },
                    )
                }
                EncryptionPhase::Active => return,
            }
        };
        self.send_ws_payload(payload);
    }

    // Called periodically by the main loop: 1) When the WebSocket connection exceeds 60 seconds, periodically rebuild and refresh room subscriptions;
    // 2) Resend expired inactive handshakes; 3) Clean up input state records beyond the decay window
    pub fn handle_tick(&mut self) {
        // Server subscription snapshot mechanism: subscribe_to_room is only executed once when the connection is established,
        // afterward new rooms can't be dynamically added. Periodic reconnection ensures subscriptions are always up to date.
        // The interval for periodic WebSocket rebuild to refresh room subscriptions, given by the seam based on the current server version
        let version = self.connector.version();
        if self.websocket_token.is_some()
            && self.websocket_connected_at.elapsed() >= version.subscription_refresh_interval()
        {
            debug_log("tick 触发定期 WebSocket 重连刷新房间订阅");
            self.restart_websocket_thread();
            self.websocket_connected_at = Instant::now();
        }

        let resend_interval = version.handshake_resend_interval();
        let stale_room_ids: Vec<String> = self
            .crypto
            .sessions
            .iter()
            .filter(|(_, session)| {
                session.phase != EncryptionPhase::Active
                    && session.initiated_at.elapsed() >= resend_interval
            })
            .map(|(room_id, _)| room_id.clone())
            .collect();
        for room_id in stale_room_ids {
            debug_log(&format!("tick 触发重发 room={room_id}"));
            self.resend_handshake_if_needed(&room_id);
        }

        // Accumulate message changes for the batch window and persist at once (only set dirty marks when messages arrive one by one)
        self.flush_pending_message_cache();

        // The server doesn't broadcast "stop typing", timeout means stopped: periodically remove expired records to prevent the list from growing indefinitely
        let display_window = version.typing_display_window();
        self.typing_members
            .retain(|(_, _, seen_at)| seen_at.elapsed() < display_window);
    }

    // Unified entry point for when the message input box content changes (normal keys, Ctrl+J, Ctrl+U, paste all go through here):
    // Report input status, and immediately invalidate old search results that don't match the current input.
    // In quick search mode, rescan loaded messages in-place as you type; in normal search mode, once the keyword changes (including using backspace to delete a segment,
    /// or delete the hash prefix to exit search mode), the previous result is no longer valid; the match list, current index, and position are all cleared,
    /// the title returns to "search not executed", arrow keys no longer jump to old results.
    fn handle_message_input_changed(&mut self) {
        self.notify_typing_if_needed();
        // Fetch all users from the server at the moment "/profile " is typed; the profile panel will have content in subsequent frames
        if self
            .input_collector
            .message_input_state
            .text()
            .starts_with("/profile ")
        {
            self.ensure_registered_users_loaded();
        }
        if !self.in_search_mode() {
            self.search_result = None;
            self.pending_scroll_message_id = None;
            return;
        }
        if self.quick_search {
            self.apply_quick_search();
        } else if self.active_search_keyword().is_none() {
            self.search_result = None;
            self.pending_scroll_message_id = None;
        }
    }

    // Report input status after the input box text changes (both additions and deletions count, matching the judgment "considered typing within 2 seconds").
    /// Only sent when logged in, WebSocket is ready, a room is selected, and ordinary text (not commands/search mode) is being typed,
    /// and throttled at the interval given by the seam — the server's inbound rate limit is 30/30 seconds, per-character reporting would immediately fill the quota.
    fn notify_typing_if_needed(&mut self) {
        if !self.is_logged_in() || self.websocket_sender.is_none() {
            return;
        }
        let Some(room_id) = self.selected_room_id() else {
            return;
        };
        let typed = self.input_collector.message_input_state.text();
        if typed.is_empty() || typed.starts_with('/') || typed.starts_with('#') {
            return;
        }
        if let Some(sent_at) = self.last_typing_frame_sent_at
            && sent_at.elapsed() < self.connector.version().typing_send_interval()
        {
            return;
        }
        let version = self.connector.version();
        self.last_typing_frame_sent_at = Some(Instant::now());
        self.send_ws_payload(outbound_ws_payload(
            version,
            WsCommand::SendTyping {
                room_id: room_id.as_str(),
            },
        ));
    }

    /// Send a complete WS JSON payload through the WebSocket command channel
    fn send_ws_payload(&self, payload: serde_json::Value) {
        if let Some(sender) = &self.websocket_sender {
            let _ = sender.send(payload.to_string());
        }
    }

    /// Append an information-type notification (title "Hint", blue border), lifetime calculated by text length (base 3 seconds, plus 1 second per 20 characters)
    fn push_notification(&mut self, message: String) {
        let lifetime = Duration::from_secs(3 + (message.chars().count() / 20) as u64);
        // New notifications are placed below existing ones, pushing the whole column down
        self.notifications
            .push((message, false, Instant::now() + lifetime));
    }

    /// Append an error-type notification (client validation or API error, title "Error", red border)
    fn push_error(&mut self, message: String) {
        let lifetime = Duration::from_secs(3 + (message.chars().count() / 20) as u64);
        self.notifications
            .push((message, true, Instant::now() + lifetime));
    }

    /// Remove notifications that have exceeded their expiration time
    fn remove_expired_notifications(&mut self) {
        let now = Instant::now();
        self.notifications
            .retain(|(_, _, deadline)| *deadline > now);
    }
}

impl App {
    // Load language strings from config/languages/{lang}.json into language_strings
    pub fn load_language(&mut self, lang: &str) {
        let path = paths::config_path(&format!("languages/{lang}.json"));
        match fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str::<HashMap<String, String>>(&content) {
                Ok(map) => {
                    self.language_strings = map;
                }
                Err(_) => {
                    self.push_error(format!(
                        "{path}: {message}",
                        path = path.display(),
                        message = self.t("error_lang_file_format"),
                    ));
                }
            },
            Err(_) => {
                self.push_error(format!(
                    "{path}: {message}",
                    path = path.display(),
                    message = self.t("error_lang_file_read"),
                ));
            }
        }
    }

    // Look up the corresponding localized text from language_strings by language key, return the key itself if not found
    pub fn t(&self, key: &str) -> String {
        self.language_strings
            .get(key)
            .cloned()
            .unwrap_or_else(|| key.to_string())
    }
    /// Return all available language codes under config/languages/ (removing .json suffix)
    fn get_available_languages() -> Vec<String> {
        let dir = paths::config_directory().join("languages");
        fs::read_dir(dir)
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .map(|ext| ext == "json")
                    .unwrap_or(false)
            })
            .filter_map(|entry| {
                entry
                    .path()
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .map(|s| s.to_string())
            })
            .collect()
    }

    // Get the current language code (read from preferences.json)
    pub fn current_language() -> String {
        let prefs_path = paths::readable_config_path("preferences.json");
        fs::read_to_string(&prefs_path)
            .ok()
            .and_then(|content| serde_json::from_str::<serde_json::Value>(&content).ok())
            .and_then(|v| v.get("language")?.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "zh-CN".to_string())
    }

    /// Save language settings to preferences.json
    fn save_language_preference(lang: &str) {
        let prefs_path = paths::writable_config_path("preferences.json");
        let content = fs::read_to_string(&prefs_path).unwrap_or_default();
        let mut prefs: serde_json::Value =
            serde_json::from_str(&content).unwrap_or(serde_json::json!({}));
        prefs["language"] = serde_json::json!(lang);
        if let Ok(pretty) = serde_json::to_string_pretty(&prefs) {
            let _ = secure_write(&prefs_path, &pretty);
        }
    }

    // Read display preferences from preferences.json (show_uid / time_with_date / server_address / sound_enabled /
    // appearance / read_state_manual), keep defaults when not found
    pub fn load_display_preferences(&mut self) {
        let prefs_path = paths::readable_config_path("preferences.json");
        if let Some(v) = fs::read_to_string(&prefs_path)
            .ok()
            .and_then(|content| serde_json::from_str::<serde_json::Value>(&content).ok())
        {
            self.show_uid = v
                .get("show_uid")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            self.time_with_date = v
                .get("time_with_date")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true);
            self.sound_enabled = v
                .get("sound_enabled")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true);
            self.quick_search = v
                .get("quick_search")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if let Some(addr) = v.get("server_address").and_then(serde_json::Value::as_str)
                && !addr.is_empty()
            {
                self.connector.set_base_url(addr);
            }
            // Read the list of room IDs with do-not-disturb enabled
            self.muted_room_ids = v
                .get("muted_rooms")
                .and_then(serde_json::Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|item| item.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            // Read the appearance name and load the theme (use built-in colors when unconfigured, to not disturb the user)
            if let Some(name) = v.get("appearance").and_then(serde_json::Value::as_str)
                && !name.is_empty()
            {
                self.apply_appearance(name);
            }
        }
    }

    // Apply the appearance theme named name: load config/themes/{name}.json and write the result to self.appearance.
    /// When the theme is missing fields or has extra fields, mark explicitly per TODO convention (missing fields only report "incomplete" without listing specifics, extra fields list names),
    /// Missing slots are covered by built-in default colors, ensuring the interface never runs out of available colors.
    fn apply_appearance(&mut self, name: &str) {
        let (appearance, has_missing_field, extra_fields) = Appearance::load(name);
        self.appearance = appearance;
        self.appearance_name = name.to_string();
        if has_missing_field {
            self.push_error(
                self.t("appearance_missing_fields")
                    .replace("{name}", name)
                    .to_string(),
            );
        }
        if !extra_fields.is_empty() {
            self.push_error(
                self.t("appearance_extra_fields")
                    .replace("{name}", name)
                    .replace("{fields}", &extra_fields.join(", "))
                    .to_string(),
            );
        }
    }

    /// Unified entry point for the user to actively switch appearance: apply theme, write back to preferences.json, give result prompt.
    /// The settings page overlay and /appearance command share this, ensuring both paths behave consistently.
    fn switch_appearance(&mut self, name: &str) {
        self.apply_appearance(name);
        self.save_appearance_preference();
        self.push_notification(
            self.t("appearance_switched")
                .replace("{name}", name)
                .to_string(),
        );
    }

    /// Write the appearance name to preferences.json (configuration item, same file and notation as display preferences)
    fn save_appearance_preference(&self) {
        let prefs_path = paths::writable_config_path("preferences.json");
        let read_path = paths::readable_config_path("preferences.json");
        let content = fs::read_to_string(&read_path).unwrap_or_default();
        let mut prefs: serde_json::Value =
            serde_json::from_str(&content).unwrap_or(serde_json::json!({}));
        prefs["appearance"] = serde_json::json!(self.appearance_name);
        if let Ok(pretty) = serde_json::to_string_pretty(&prefs) {
            let _ = secure_write(&prefs_path, &pretty);
        }
    }

    /// Write all display preferences to preferences.json (adding new display toggles only requires changing this one place)
    fn save_display_preferences(&self) {
        let prefs_path = paths::writable_config_path("preferences.json");
        let read_path = paths::readable_config_path("preferences.json");
        let content = fs::read_to_string(&read_path).unwrap_or_default();
        let mut prefs: serde_json::Value =
            serde_json::from_str(&content).unwrap_or(serde_json::json!({}));
        prefs["show_uid"] = serde_json::json!(self.show_uid);
        prefs["time_with_date"] = serde_json::json!(self.time_with_date);
        prefs["sound_enabled"] = serde_json::json!(self.sound_enabled);
        prefs["quick_search"] = serde_json::json!(self.quick_search);
        prefs["muted_rooms"] =
            serde_json::json!(self.muted_room_ids.iter().cloned().collect::<Vec<String>>());
        if let Ok(pretty) = serde_json::to_string_pretty(&prefs) {
            let _ = secure_write(&prefs_path, &pretty);
        }
    }

    /// Save the custom server address to preferences.json
    fn save_server_address(&self) {
        let prefs_path = paths::writable_config_path("preferences.json");
        let read_path = paths::readable_config_path("preferences.json");
        let content = fs::read_to_string(&read_path).unwrap_or_default();
        let mut prefs: serde_json::Value =
            serde_json::from_str(&content).unwrap_or(serde_json::json!({}));
        prefs["server_address"] = serde_json::json!(self.connector.base_url());
        if let Ok(pretty) = serde_json::to_string_pretty(&prefs) {
            let _ = secure_write(&prefs_path, &pretty);
        }
    }

    /// Send a system notification (if enabled)
    fn send_system_notification(&self, title: &str, body: &str) {
        if !self.sound_enabled {
            debug_log("系统通知已禁用 (sound_enabled=false)");
            return;
        }
        debug_log(&format!("发送系统通知: title={}, body={}", title, body));

        // Play the notification sound on a background thread to avoid blocking the main thread
        let sound_enabled = self.sound_enabled;
        std::thread::spawn(move || {
            if !sound_enabled {
                return;
            }
            // Play system sound using afplay on macOS
            #[cfg(target_os = "macos")]
            {
                // Use the most reliable system alert sound file
                const SOUND_FILE: &str = "/System/Library/Sounds/Ping.aiff";
                match std::process::Command::new("afplay")
                    .arg(SOUND_FILE)
                    .status()
                {
                    Ok(status) => {
                        if status.success() {
                            debug_log(&format!("afplay 播放成功: {}", SOUND_FILE));
                        } else {
                            debug_log(&format!("afplay 退出码非零: {:?}", status));
                            // Fall back to terminal bell
                            let _ = std::io::Write::write_all(&mut std::io::stderr(), b"\x07");
                            let _ = std::io::Write::flush(&mut std::io::stderr());
                        }
                    }
                    Err(e) => {
                        debug_log(&format!("afplay 启动失败: {:?}，回退到 terminal bell", e));
                        let _ = std::io::Write::write_all(&mut std::io::stderr(), b"\x07");
                        let _ = std::io::Write::flush(&mut std::io::stderr());
                    }
                }
            }
            // Try terminal bell on other systems
            #[cfg(not(target_os = "macos"))]
            {
                if let Err(e) = std::io::Write::write_all(&mut std::io::stderr(), b"\x07") {
                    debug_log(&format!("terminal bell 写入失败: {e}"));
                }
                if let Err(e) = std::io::Write::flush(&mut std::io::stderr()) {
                    debug_log(&format!("terminal bell 刷新失败: {e}"));
                }
            }
        });

        // Send desktop notification asynchronously: macOS uses osascript (notify-rust is often unavailable in terminal TUI),
        // other platforms still use notify-rust.
        let title = title.to_string();
        let body = body.to_string();
        std::thread::spawn(move || {
            #[cfg(target_os = "macos")]
            {
                let escape = |text: &str| text.replace('\\', "\\\\").replace('"', "\\\"");
                let script = format!(
                    "display notification \"{}\" with title \"{}\"",
                    escape(&body),
                    escape(&title)
                );
                match std::process::Command::new("osascript")
                    .arg("-e")
                    .arg(&script)
                    .status()
                {
                    Ok(status) if status.success() => debug_log("osascript 桌面通知已发送"),
                    Ok(status) => debug_log(&format!("osascript 通知失败，退出码 {:?}", status)),
                    Err(e) => debug_log(&format!("osascript 启动失败: {e}")),
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                if let Err(e) = notify_rust::Notification::new()
                    .summary(&title)
                    .body(&body)
                    .appname("Baihua Client")
                    .show()
                {
                    debug_log(&format!("桌面通知发送失败: {e}"));
                }
            }
        });
    }

    /// Save the login session (JWT and corporate user ID) to preferences.json for auto-login on next startup.
    /// Tokens are encrypted at rest before saving; plaintext passwords or usernames are not stored.
    fn save_session_preferences(token: &str, user_id: &str, contact: Option<&(String, String)>) {
        let prefs_path = paths::writable_config_path("preferences.json");
        let read_path = paths::readable_config_path("preferences.json");
        let content = fs::read_to_string(&read_path).unwrap_or_default();
        let mut prefs: serde_json::Value =
            serde_json::from_str(&content).unwrap_or(serde_json::json!({}));
        prefs["token"] = serde_json::json!(crypto::encrypt_at_rest(token));
        prefs["user_id"] = serde_json::json!(user_id);
        match contact {
            Some((email, phone_number)) => {
                prefs["email"] = serde_json::json!(crypto::encrypt_at_rest(email));
                prefs["phone_number"] = serde_json::json!(crypto::encrypt_at_rest(phone_number));
            }
            None => {
                if let Some(map) = prefs.as_object_mut() {
                    map.remove("email");
                    map.remove("phone_number");
                }
            }
        }
        if let Ok(pretty) = serde_json::to_string_pretty(&prefs) {
            let _ = secure_write(&prefs_path, &pretty);
        }
    }

    /// Read the email and phone number saved at last exit (the server has no "query my contact info" interface,
    /// auto-login path cannot get the login response, so it relies on local session records to restore these two lines of the profile card).
    fn load_saved_contact() -> Option<(String, String)> {
        let content = fs::read_to_string(paths::config_path("preferences.json")).ok()?;
        let prefs: serde_json::Value = serde_json::from_str(&content).ok()?;
        let email = crypto::decrypt_at_rest(prefs.get("email")?.as_str()?)?;
        let phone_number = crypto::decrypt_at_rest(prefs.get("phone_number")?.as_str()?)?;
        Some((email, phone_number))
    }

    /// Read the saved login session; the token is decrypted first, returns None if credentials are missing or decryption fails
    fn load_saved_session() -> Option<(String, String)> {
        let prefs_path = paths::readable_config_path("preferences.json");
        let content = fs::read_to_string(&prefs_path).ok()?;
        let v: serde_json::Value = serde_json::from_str(&content).ok()?;
        let token = crypto::decrypt_at_rest(v.get("token")?.as_str()?)?;
        let user_id = v.get("user_id")?.as_str()?;
        Some((token, user_id.to_string()))
    }

    /// Clear the saved login session (called when the token is invalid or auto-login is no longer needed)
    fn clear_saved_session() {
        let prefs_path = paths::writable_config_path("preferences.json");
        let read_path = paths::readable_config_path("preferences.json");
        let content = fs::read_to_string(&read_path).unwrap_or_default();
        let mut prefs: serde_json::Value =
            serde_json::from_str(&content).unwrap_or(serde_json::json!({}));
        if let Some(map) = prefs.as_object_mut() {
            map.remove("token");
            map.remove("user_id");
            map.remove("email");
            map.remove("phone_number");
        }
        if let Ok(pretty) = serde_json::to_string_pretty(&prefs) {
            let _ = secure_write(&prefs_path, &pretty);
        }
    }

    // Try to auto-login with the saved session: if the token is valid, enter the chat page and prepare background threads,
    // if invalid, clear the session and stay on the login page. Returns whether auto-login succeeded.
    pub fn try_auto_login(&mut self) -> bool {
        let Some((token, user_id)) = Self::load_saved_session() else {
            // No valid session (possibly leftover plaintext/corrupted token): clear stale session fields
            Self::clear_saved_session();
            return false;
        };
        debug_log(&format!(
            "=== JWT AUTO-LOGIN START: token前8={} ===",
            &token[..8.min(token.len())]
        ));
        self.connector.set_token(&token);
        if self.connector.list_rooms().is_err() {
            debug_log("JWT AUTO-LOGIN: list_rooms 失败，清除会话");
            Self::clear_saved_session();
            return false;
        }
        self.update_connection_state(true);
        debug_log("JWT AUTO-LOGIN: list_rooms 成功，设置用户状态");
        // Auto-login also probes the server version immediately (token is set), so subsequent online decisions match the real version
        self.detect_and_apply_api_version();
        self.current_user_id = Some(user_id.clone());
        // Auto-login has no login response, contact info uses the one saved at last exit
        self.own_contact = Self::load_saved_contact();
        // The server doesn't broadcast user_online to itself, so the local presence status needs to be registered by itself
        self.presence_by_user.insert(user_id, true);
        self.focus_index = 0;
        // Keep exactly the same flow as normal login: load the room list first, then start background threads
        self.load_rooms();
        self.start_polling_thread();
        self.start_websocket_thread(&token, None);
        self.prepare_session_state(None);
        self.push_notification(self.t("auto_login_notification"));
        debug_log("=== JWT AUTO-LOGIN COMPLETE ===");
        true
    }
}

/// Built-in chat command table, elements are (command name, description language key).
/// The table itself lives in shared code `baihua-core::commands`; the GUI reads the same one;
/// When adding a new command, just add one entry to each execution branch (terminal version here and GUI).
pub(crate) fn chat_commands() -> Vec<(&'static str, &'static str)> {
    baihua_core::commands::chat_commands()
}

/// Filter the command table entries that match the entered command prefix
fn command_completions(prefix: &str) -> Vec<(&'static str, &'static str)> {
    baihua_core::commands::command_completions(prefix)
}

/// Determine if a group member role is group admin or owner (server role strings are case-insensitive)
fn is_admin_role(role: &str) -> bool {
    let lowered = role.to_lowercase();
    lowered == "owner" || lowered == "admin"
}

/// Filter invisible rooms: locally closed encrypted private chats, and leftover private chat shells with fewer than two members
fn filter_visible_rooms(rooms: Vec<RoomInfo>, closed_room_ids: &HashSet<String>) -> Vec<RoomInfo> {
    rooms
        .into_iter()
        .filter(|room| {
            !closed_room_ids.contains(&room.id) && (room.is_group || room.members.len() >= 2)
        })
        .collect()
}

/// Estimate the display width of a string in the terminal, CJK and full-width characters count as two columns
fn display_width(text: &str) -> u16 {
    text.chars()
        .map(|character| {
            let code = character as u32;
            if (0x1100..=0x115F).contains(&code)
                || (0x2E80..=0xA4CF).contains(&code)
                || (0xAC00..=0xD7A3).contains(&code)
                || (0xF900..=0xFAFF).contains(&code)
                || (0xFE10..=0xFE19).contains(&code)
                || (0xFE30..=0xFE6F).contains(&code)
                || (0xFF00..=0xFF60).contains(&code)
                || (0xFFE0..=0xFFE6).contains(&code)
            {
                2
            } else {
                1
            }
        })
        .sum()
}

/// Merge two batches of messages by ID: earlier arrived ones (already local, possibly decrypted plaintext) are preserved first,
/// later ones only add new entries, finally sorted by creation time and server ID ascending.
fn merge_messages_by_id(
    existing: Vec<MessageInfo>,
    incoming: Vec<MessageInfo>,
) -> Vec<MessageInfo> {
    let mut merged = existing;
    let mut seen: HashSet<String> = merged.iter().map(|message| message.id.clone()).collect();
    for message in incoming {
        if seen.insert(message.id.clone()) {
            merged.push(message);
        }
    }
    merged.sort_by(|left, right| (&left.created_at, &left.id).cmp(&(&right.created_at, &right.id)));
    merged
}

/// Unified overlay window border: four borders plus top-left title, border color always takes the appearance's overlay_border.
/// All overlays (forms, lists, cards, input groups) take their window appearance from here:
/// Changing theme or style only affects this one place; no more will an overlay follow the message area border color.
fn overlay_frame_block(appearance: &Appearance, title: &str) -> Block<'static> {
    Block::default()
        .title(format!(" {title} "))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(appearance.overlay_border))
}

/// Borderless input field: forms in arrow row style use this; body text, cursor, and selection colors come from the same source as boxed input fields.
fn render_plain_field(
    appearance: &Appearance,
    frame: &mut Frame,
    area: Rect,
    secret: bool,
    state: &mut TextInputState,
) {
    let mut input = TextInput::new()
        .style(Style::default().fg(appearance.input_text))
        .block(Block::default())
        .cursor_style(Style::default().fg(appearance.own_username_text))
        .select_style(
            Style::default()
                .fg(contrasting_foreground(appearance.selection_background))
                .bg(appearance.selection_background),
        );
    if secret {
        input = input.passwd();
    }
    input.render(area, frame.buffer_mut(), state);
}

/// Unified "boxed input field": label is written on the border title, body text, cursor, and selection colors all come from the appearance.
/// Overlays with fewer than three input fields use this; three or more use the arrow row style (see render_form).
/// Taking the free function form allows the caller to hold both an immutable borrow of the appearance and a mutable borrow of the input state.
/// Border color and title style are both provided by the caller: login/register use the selected color border switched by focus state, form overlays uniformly use
/// the unselected color border (see Appearance::form_field_border), the current item is indicated by bold title,
/// consistent with the same indication in arrow row style.
fn render_box_field(
    appearance: &Appearance,
    frame: &mut Frame,
    area: Rect,
    title: Line<'static>,
    border_color: Color,
    secret: bool,
    state: &mut TextInputState,
) {
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));
    let mut input = TextInput::new()
        .style(Style::default().fg(appearance.input_text))
        .block(block)
        .cursor_style(Style::default().fg(appearance.own_username_text))
        .select_style(
            Style::default()
                .fg(contrasting_foreground(appearance.selection_background))
                .bg(appearance.selection_background),
        );
    if secret {
        input = input.passwd();
    }
    input.render(area, frame.buffer_mut(), state);
}

/// Unified style for hint text (keyboard shortcuts, status bar labels, form hint lines all use it)
fn hint_style(color: Color) -> Style {
    Style::default().fg(color)
}

/// Wrap "label: value" rows in the profile card to available width, continuation lines are indented to the start of the value column.
/// On narrow terminals, long single lines like UID, email, and avatar links thus wrap instead of being cut off by the panel right edge.
fn wrap_profile_fields(body: Text<'static>, available_width: u16) -> Text<'static> {
    if available_width == 0 {
        return body;
    }
    let mut lines: Vec<Line<'static>> = Vec::new();
    for line in body.lines {
        let plain = line
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();
        if (line.width() as u16) <= available_width {
            lines.push(line);
            continue;
        }
        let style = line
            .spans
            .last()
            .map(|span| span.style)
            .unwrap_or_else(Style::default);
        let separator = match plain.find(": ") {
            Some(position) => position,
            // Rows without a "label: " structure (like close prompts) are wrapped by width, no indentation alignment
            None => {
                for piece in wrap_by_display_width(&plain, available_width) {
                    lines.push(Line::from(Span::styled(piece, style)));
                }
                continue;
            }
        };
        // Slice by bytes: ": " is two ASCII characters, the cut point must fall on a character boundary;
        // the label itself might be multi-byte Chinese, so the character count can't be used to calculate the cut point
        let prefix = plain[..separator + 2].to_string();
        let value = plain[separator + 2..].to_string();
        let indent_columns = usize::from(display_width(&prefix));
        let value_width = available_width.saturating_sub(indent_columns as u16).max(1);
        for (index, piece) in wrap_by_display_width(&value, value_width)
            .into_iter()
            .enumerate()
        {
            let text = if index == 0 {
                format!("{prefix}{piece}")
            } else {
                format!("{}{piece}", " ".repeat(indent_columns))
            };
            lines.push(Line::from(Span::styled(text, style)));
        }
    }
    Text::from(lines)
}

/// Placeholder when the avatar hasn't been fetched or the user hasn't set one: draws the first character of the user ID with a stable color in the top-left of the avatar block.
/// Placeholder and real image share the same area; once the avatar arrives it just fills this area, and the text position does not jump.
fn paint_avatar_placeholder(
    frame: &mut Frame,
    area: Rect,
    username: &str,
    appearance: &Appearance,
    user_id: &str,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            placeholder_initial(username),
            Style::default()
                .fg(placeholder_color(user_id))
                .add_modifier(Modifier::BOLD),
        )))
        .style(Style::default().bg(appearance.app_background)),
        Rect::new(area.x, area.y, 1, 1),
    );
}

/// Display width of the widest line in multi-line text (the total width of the entire text cannot be used to set the panel width, as it would inflate multi-line hints)
fn longest_line_width(text: &str) -> u16 {
    text.lines().map(display_width).max().unwrap_or(0)
}

/// Estimate how many render lines the text will take at a given inner width: explicit newlines each count as one line, then each line is wrapped up by display width.
fn estimated_wrapped_line_count(text: &str, inner_width: u16) -> u16 {
    if inner_width == 0 {
        return 1;
    }
    text.lines()
        .map(|line| display_width(line).div_ceil(inner_width).max(1))
        .sum::<u16>()
        .max(1)
}

/// Calculate a centered panel rectangle within the given area (shared by all overlays, avoiding repeated offset calculations everywhere)
fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    )
}

/// Whether the received request is still waiting for you to handle it. The server's `GET /requests/pending` only returns rows that are still pending
/// and does not return a status field, so the default status means "still waiting"; entries handled locally are written with their result status in place.
/// The server always gives a status for the side that sent it, so just checking `== "pending"` literally works, this function is not shared.
fn received_request_is_pending(request: &RoomRequestInfo) -> bool {
    request
        .status
        .as_deref()
        .is_none_or(|status| status == "pending")
}

/// Unified layout for list overlays (settings menu, language, appearance, local avatar):
/// Panel width is set by "widest item + border + highlight symbol" but does not exceed the drawable area;
/// Returns (panel rect, item available width); the item width is passed to `wrapped_list_item` by the caller for wrapping.
fn overlay_list_panel(labels: &[String], area: Rect) -> (Rect, u16) {
    let longest = labels
        .iter()
        .map(|label| display_width(label))
        .max()
        .unwrap_or(0);
    // Border 2 cols + highlight symbol 2 cols + 1 col margin on each side; the panel itself is sized by content,
    // but neither left as a narrow slit nor full-screen, finally yielding to the screen width
    let wanted_width = (longest + 6).clamp(30, 60);
    let width_ceiling = area.width.saturating_sub(2).max(12);
    let panel_width = if wanted_width > width_ceiling {
        width_ceiling
    } else {
        wanted_width
    };
    // Items longer than "panel width − border − highlight symbol" are wrapped, preferring to take an extra row over being cut off at the right boundary
    let body_width = panel_width.saturating_sub(6).max(1);
    let line_count: u16 = labels
        .iter()
        .map(|label| display_width(label).div_ceil(body_width).max(1))
        .sum();
    let wanted_height = line_count + 4;
    let height_ceiling = area.height.saturating_sub(2).max(5);
    let panel_height = if wanted_height > height_ceiling {
        height_ceiling
    } else {
        wanted_height
    };
    (centered_rect(panel_width, panel_height, area), body_width)
}

/// Row set for completing one candidate in the panel: description and command name are placed on the same row if they fit, otherwise the description goes on a new row,
/// both parts are wrapped to the panel inner width. Returns the line count for the caller to calculate panel height.
fn completion_lines(
    label: &str,
    description: &str,
    label_style: Style,
    description_style: Style,
    body_width: u16,
) -> Vec<Line<'static>> {
    let same_row_fits = display_width(label) + display_width(description) + 2 <= body_width;
    let mut lines: Vec<Line> = wrap_preserving_words(label, body_width)
        .into_iter()
        .map(|piece| Line::from(Span::styled(piece, label_style)))
        .collect();
    if description.is_empty() {
        return lines;
    }
    if same_row_fits {
        if let Some(first) = lines.first_mut() {
            first.push_span(Span::styled(format!("  {description}"), description_style));
        }
        return lines;
    }
    lines.extend(
        wrap_preserving_words(description, body_width.saturating_sub(2).max(1))
            .into_iter()
            .map(|piece| Line::from(Span::styled(format!("  {piece}"), description_style))),
    );
    lines
}

/// Wrap a hint text into styled Text at available width. The wrap point is fixed by this function, rendering no longer lets
/// Paragraph wrap itself, so "reserved lines" and "actually occupied lines" are necessarily consistent (when handing to Paragraph to wrap by word boundaries,
/// mixed Chinese-English may take one more row than estimated, the panel just cuts off the last row).
/// Within a line, prefer breaking at spaces; English sentences are not cut from the middle of words; pure Chinese breaks by character.
fn wrapped_hint_text(hint: &str, style: Style, available_width: u16) -> Text<'static> {
    Text::from(
        wrap_preserving_words(hint, available_width)
            .into_iter()
            .map(|piece| Line::from(Span::styled(piece, style)))
            .collect::<Vec<Line>>(),
    )
}

/// Wrap by display width, preferably breaking at spaces: first fill a row character by character, then retreat to the last space in the row.
/// If no space is found (a whole Chinese sentence, or a single very long word), break hard by display width, guaranteeing no infinite loop.
fn wrap_preserving_words(text: &str, limit: u16) -> Vec<String> {
    let limit = limit.max(1) as usize;
    let mut lines: Vec<String> = Vec::new();
    for paragraph in text.lines() {
        let characters: Vec<char> = paragraph.chars().collect();
        let mut start = 0usize;
        while start < characters.len() {
            let mut end = start;
            let mut width = 0usize;
            let mut last_space: Option<usize> = None;
            while end < characters.len() {
                let character_width =
                    usize::from(display_width(&characters[end].to_string()).max(1));
                if width + character_width > limit && end > start {
                    break;
                }
                if characters[end] == ' ' {
                    last_space = Some(end);
                }
                width += character_width;
                end += 1;
            }
            let break_at = if end < characters.len() {
                last_space.unwrap_or(end)
            } else {
                end
            };
            let piece: String = characters[start..break_at].iter().collect();
            lines.push(piece.trim_end().to_string());
            start = if break_at > start { break_at } else { end };
            // When breaking at a space, skip the space itself so the next line doesn't start with a space
            while start < characters.len() && characters[start] == ' ' {
                start += 1;
            }
        }
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// A list label is wrapped into a ListItem: continuation lines are padded with two spaces, aligned with the highlight symbol "> " width,
/// so selected and unselected body text both start in the same column.
fn wrapped_list_item(label: &str, style: Style, body_width: u16) -> ListItem<'static> {
    ListItem::new(
        wrap_preserving_words(label, body_width)
            .into_iter()
            .enumerate()
            .map(|(index, piece)| {
                let text = if index == 0 {
                    piece
                } else {
                    format!("  {piece}")
                };
                Line::from(Span::styled(text, style))
            })
            .collect::<Vec<Line>>(),
    )
}

/// Hint text key for the bottom of the form overlay (states the server's restrictions on the form, to avoid the user getting a 400 after submitting)
fn form_hint_key(action: &FormAction) -> String {
    match action {
        FormAction::UpdateProfile => "form_profile_hint".to_string(),
        FormAction::ChangePassword => "form_password_hint".to_string(),
        FormAction::ChangeAvatar => "form_avatar_hint".to_string(),
        FormAction::DeleteAccount => "form_delete_hint".to_string(),
    }
}

/// The action for each setting menu item after Enter. Rendering and key dispatch share the same entry table,
/// When adding/removing menu items, there is no need to sync "which number" elsewhere.
#[derive(Debug, Clone, PartialEq)]
enum SettingsAction {
    // Open an existing overlay (create group, create private, private chat management, language, appearance, server address, login, register)
    OpenOverlay(DisplayingOverlay),
    // Open form overlay (set profile, change password, change avatar, delete account)
    OpenForm(FormAction),
    // Toggle "show user UID"
    ToggleShowUid,
    // Toggle "time display includes date"
    ToggleTimeWithDate,
    // Toggle "quick search"
    ToggleQuickSearch,
    // Toggle "sound notification"
    ToggleSound,
    // Immediately start updating with the downloaded and verified package
    UpdateClient,
    // Logout
    Logout,
}

impl SettingsAction {
    // Whether this item requires login to be meaningful: the four form items to change your own account, server operations requiring a token
    /// (building rooms, sending invitations, private chat request management) and logout count.
    /// When not logged in, selecting them only shows "not logged in", does not switch the overlay, avoiding discovering after entering that it can't be done.
    fn requires_login(&self) -> bool {
        match self {
            SettingsAction::OpenForm(_) | SettingsAction::Logout => true,
            SettingsAction::OpenOverlay(overlay) => matches!(
                overlay,
                DisplayingOverlay::CreateGroup
                    | DisplayingOverlay::CreatePrivate
                    | DisplayingOverlay::PendingRequests
                    | DisplayingOverlay::AvatarSelect
            ),
            SettingsAction::ToggleShowUid
            | SettingsAction::ToggleTimeWithDate
            | SettingsAction::ToggleQuickSearch
            | SettingsAction::ToggleSound
            | SettingsAction::UpdateClient => false,
        }
    }
}

/// Form overlay title and input field definitions: concentrate the four form types' text keys in one place,
/// opening the form and rendering the form both take from here, avoiding drift in two dictionaries.
fn form_definition(action: &FormAction) -> (String, Vec<(String, bool)>) {
    let (title_key, fields) = match action {
        FormAction::UpdateProfile => (
            "option_edit_profile",
            vec![
                ("profile_nickname_label".to_string(), false),
                ("profile_phone_label".to_string(), false),
                ("profile_bio_label".to_string(), false),
            ],
        ),
        FormAction::ChangePassword => (
            "option_change_password",
            vec![
                ("password_old_label".to_string(), true),
                ("password_new_label".to_string(), true),
                ("password_confirm_label".to_string(), true),
            ],
        ),
        FormAction::ChangeAvatar => (
            "option_change_avatar",
            vec![("avatar_input_label".to_string(), false)],
        ),
        FormAction::DeleteAccount => (
            "option_delete_account",
            vec![("delete_account_password_label".to_string(), true)],
        ),
    };
    (title_key.to_string(), fields)
}

/// Wrap by display width; advance at least one character to avoid infinite loop from an overly wide single character
fn wrap_by_display_width(text: &str, limit: u16) -> Vec<String> {
    if text.is_empty() {
        return vec![String::new()];
    }
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut current_width = 0u16;
    for character in text.chars() {
        let character_width = display_width(&character.to_string()).max(1);
        if current_width + character_width > limit && !current.is_empty() {
            lines.push(std::mem::take(&mut current));
            current_width = 0;
        }
        current.push(character);
        current_width += character_width;
    }
    lines.push(current);
    lines
}

/// Find all positions of a keyword in the text (case-insensitive), returning [start, end) intervals in character units.
/// After a hit, skip the entire segment, overlapping matches are not counted. Lowercase per character aligns with the original string indices,
/// so intervals can be directly used to split the original text containing CJK wide characters without misalignment.
fn find_keyword_positions(text: &str, keyword: &str) -> Vec<(usize, usize)> {
    let haystack: Vec<char> = text
        .chars()
        .map(|character| character.to_lowercase().next().unwrap_or(character))
        .collect();
    let needle: Vec<char> = keyword
        .chars()
        .map(|character| character.to_lowercase().next().unwrap_or(character))
        .collect();
    let mut positions: Vec<(usize, usize)> = Vec::new();
    if needle.is_empty() || needle.len() > haystack.len() {
        return positions;
    }
    let mut start = 0usize;
    while start + needle.len() <= haystack.len() {
        if haystack[start..start + needle.len()] == needle[..] {
            positions.push((start, start + needle.len()));
            start += needle.len();
        } else {
            start += 1;
        }
    }
    positions
}

/// Split a line of text into (text segment, segment style) sequences by keyword hit positions:
/// Hit segments use search hit style, the rest use body text style; no hits means the whole line is one segment.
fn split_line_by_keyword(
    line: &str,
    keyword: &str,
    body_style: Style,
    match_style: Style,
) -> Vec<(String, Style)> {
    let characters: Vec<char> = line.chars().collect();
    let mut segments: Vec<(String, Style)> = Vec::new();
    let mut cursor = 0usize;
    for (start, end) in find_keyword_positions(line, keyword) {
        if start > cursor {
            let plain: String = characters[cursor..start].iter().collect();
            segments.push((plain, body_style));
        }
        let matched: String = characters[start..end].iter().collect();
        segments.push((matched, match_style));
        cursor = end;
    }
    if cursor < characters.len() {
        let tail: String = characters[cursor..].iter().collect();
        segments.push((tail, body_style));
    }
    if segments.is_empty() {
        segments.push((String::new(), body_style));
    }
    segments
}

/// Wrap a set of styled segments by display width, returning a sequence of directly renderable lines.
/// Implementation: flatten segments into a (character, style) stream and accumulate character by character, consecutive same-style characters in a line are merged into one Span;
/// when wrapping falls inside a highlight interval, that interval is naturally cut and continued on the new line, the highlight is not lost.
fn wrap_styled_segments(segments: &[(String, Style)], limit: u16) -> Vec<Line<'static>> {
    let mut lines: Vec<Line> = Vec::new();
    let mut spans: Vec<Span> = Vec::new();
    let mut run = String::new();
    let mut run_style: Option<Style> = None;
    let mut width = 0u16;
    for (character, style) in segments
        .iter()
        .flat_map(|(text, style)| text.chars().map(move |character| (character, *style)))
    {
        let character_width = display_width(&character.to_string()).max(1);
        let need_new_line = width + character_width > limit && width > 0;
        // When style switches or this row lacks width, wrap up first: convert accumulated same-style text into a Span, and end the current row if necessary
        if run_style != Some(style) || need_new_line {
            if let Some(closed_style) = run_style.take() {
                spans.push(Span::styled(std::mem::take(&mut run), closed_style));
            }
            if need_new_line {
                lines.push(Line::from(std::mem::take(&mut spans)));
                width = 0;
            }
        }
        if run_style.is_none() {
            run_style = Some(style);
        }
        run.push(character);
        width += character_width;
    }
    if let Some(closed_style) = run_style.take() {
        spans.push(Span::styled(std::mem::take(&mut run), closed_style));
    }
    if !spans.is_empty() {
        lines.push(Line::from(spans));
    }
    if lines.is_empty() {
        lines.push(Line::from(""));
    }
    lines
}

/// Cut out [start column, end column) intervals from row text by display width: double-width characters with any overlap with the interval are included whole,
/// so selection will never copy only half a character cell of a Chinese character, and will never lose characters because the start point falls in the middle of a character.
fn slice_columns_by_display_width(row_text: &str, start_column: u16, end_column: u16) -> String {
    let mut text = String::new();
    let mut column = 0u16;
    for character in row_text.chars() {
        let character_width = display_width(&character.to_string()).max(1);
        if column >= end_column {
            break;
        }
        if column + character_width > start_column {
            text.push(character);
        }
        column += character_width;
    }
    text
}

/// Format the RFC3339 UTC timestamp from the server into a local time display string.
/// When with_date is true, include the date (MM-DD HH:MM), otherwise show only the time (HH:MM).
/// Returns None when parsing fails (don't render the time header).
fn format_message_time(created_at: &str, with_date: bool) -> Option<String> {
    let local = DateTime::parse_from_rfc3339(created_at)
        .ok()?
        .with_timezone(&Local);
    let text = if with_date {
        local.format("%m-%d %H:%M").to_string()
    } else {
        local.format("%H:%M").to_string()
    };
    Some(text)
}

impl App {
    fn max_focus_index(&self) -> usize {
        if matches!(self.displaying_overlay, DisplayingOverlay::Form) {
            // The number of focusable items in the form overlay is determined by the field count
            self.active_form
                .as_ref()
                .map(|(_, fields)| fields.len().saturating_sub(1))
                .unwrap_or(0)
        } else if matches!(self.displaying_overlay, DisplayingOverlay::CreateGroup)
            || matches!(self.displaying_overlay, DisplayingOverlay::Login)
        {
            1
        } else if matches!(self.displaying_overlay, DisplayingOverlay::Register) {
            2
        } else {
            0
        }
    }

    fn get_focused_state(&mut self) -> Option<&mut TextInputState> {
        if matches!(self.displaying_overlay, DisplayingOverlay::CreateGroup) {
            match self.focus_index {
                0 => Some(&mut self.input_collector.create_group_name_state),
                1 => Some(&mut self.input_collector.create_group_members_state),
                _ => None,
            }
        } else if matches!(self.displaying_overlay, DisplayingOverlay::CreatePrivate) {
            match self.focus_index {
                0 => Some(&mut self.input_collector.create_private_username_state),
                _ => None,
            }
        } else if matches!(self.displaying_overlay, DisplayingOverlay::Login) {
            match self.focus_index {
                0 => Some(&mut self.input_collector.login_name_state),
                1 => Some(&mut self.input_collector.login_password_state),
                _ => None,
            }
        } else if matches!(self.displaying_overlay, DisplayingOverlay::Register) {
            match self.focus_index {
                0 => Some(&mut self.input_collector.register_name_state),
                1 => Some(&mut self.input_collector.register_email_state),
                2 => Some(&mut self.input_collector.register_password_state),
                _ => None,
            }
        } else if matches!(self.displaying_overlay, DisplayingOverlay::ServerAddress) {
            Some(&mut self.input_collector.server_address_state)
        } else if matches!(self.displaying_overlay, DisplayingOverlay::Form) {
            // General form overlay: the number of fields varies by form type, the focus position falls directly on the corresponding input item
            match &mut self.active_form {
                Some((_, fields)) => fields
                    .get_mut(self.focus_index)
                    .map(|field| &mut field.state),
                None => None,
            }
        } else if matches!(
            self.displaying_overlay,
            DisplayingOverlay::PendingRequests
                | DisplayingOverlay::SettingsMenu
                | DisplayingOverlay::ProfileCard
        ) {
            // List, menu, and read-only card popups don't focus any input field
            None
        } else {
            // When on the chat page with no popup, focus the multi-line message input box, handled separately by dispatch_focused_input_event
            None
        }
    }

    /// Dispatch keyboard/mouse events to the currently focused input field:
    /// When on the chat page with no popup, forward to the multi-line message input box; for other pages/popups, forward to the single-line input box
    fn dispatch_focused_input_event(&mut self, focus: bool, event: &Event) {
        if self.displaying_overlay == DisplayingOverlay::Nothing {
            let _ = text_area::handle_events(
                &mut self.input_collector.message_input_state,
                focus,
                event,
            );
        } else if let Some(state) = self.get_focused_state() {
            let _ = text_input::handle_events(state, focus, event);
        }
    }

    fn get_field_areas(&self, layout: &[Rect]) -> Vec<Rect> {
        if matches!(self.displaying_overlay, DisplayingOverlay::CreateGroup) {
            vec![]
        } else {
            vec![layout[8]]
        }
    }

    // Detect and apply the server API version: called after login success, auto-login startup, and switching server address.
    /// Detection failure is not fatal (uses current/default version); prompts the user to check compatibility when the version is unrecognized.
    /// The detection result determines all online behaviors matched by version in the API seam (success codes, messages, event names, etc.).
    fn detect_and_apply_api_version(&mut self) {
        match self.connector.probe_version() {
            Ok((version, raw)) => {
                debug_log(&format!("探测服务端版本: raw={raw} parsed={version:?}"));
                if version == ApiVersion::Unknown {
                    self.push_notification(format!("{}: {raw}", self.t("api_version_unknown")));
                }
            }
            Err(e) => {
                debug_log(&format!("版本探测失败(保留当前版本): {e}"));
            }
        }
    }

    /// Form overlay login submit: read the two login form fields and perform login.
    fn do_login(&mut self) {
        let username = self.input_collector.login_name_state.value.text().string();
        let password = self
            .input_collector
            .login_password_state
            .value
            .text()
            .string();
        self.perform_login(username, password);
    }

    /// Execute the core login flow, shared by the login overlay and the `/login <username> <password>` command.
    /// Password is transmitted after client deterministic encryption; on success, start polling and WebSocket threads and close the login overlay.
    fn perform_login(&mut self, username: String, password: String) {
        if username.is_empty() || password.is_empty() {
            self.push_error(self.t("error_empty_credentials"));
            return;
        }
        let encrypted_password = crypto::encrypt_login_password(&password);
        let req = LoginRequest {
            username,
            password: encrypted_password,
        };
        match self.connector.login(req) {
            Ok(data) => {
                debug_log(&format!(
                    "=== LOGIN START: user={} token前8={} ===",
                    data.user.id,
                    &data.token[..8.min(data.token.len())]
                ));
                self.current_user_id = Some(data.user.id.clone());
                // The server doesn't broadcast user_online to itself, so the local presence status needs to be registered by itself
                self.presence_by_user.insert(data.user.id.clone(), true);
                self.connector.set_token(&data.token);
                let logged_username = data.user.username.clone();
                // Probe the server version immediately after login, so all subsequent online decisions match the real version
                self.detect_and_apply_api_version();
                self.focus_index = 0;
                self.displaying_overlay = DisplayingOverlay::Nothing;
                self.load_rooms();
                self.start_polling_thread();
                self.start_websocket_thread(&data.token, None);
                self.prepare_session_state(Some(logged_username));
                // The complete user object in the login response is the only place to see own email and phone number, needed for the profile card
                self.remember_own_profile(&data.user);
                // Clear the form to avoid credentials remaining in the input box
                self.input_collector.login_name_state = TextInputState::default();
                self.input_collector.login_password_state = TextInputState::default();
                self.push_notification(self.t("login_success"));
            }
            Err(e) => {
                self.push_error(format!("{e}"));
            }
        }
    }

    /// Form overlay registration submit: read the three registration form fields and perform registration.
    fn do_register(&mut self) {
        let username = self
            .input_collector
            .register_name_state
            .value
            .text()
            .string();
        let email = self
            .input_collector
            .register_email_state
            .value
            .text()
            .string();
        let password = self
            .input_collector
            .register_password_state
            .value
            .text()
            .string();
        self.perform_register(username, email, password);
    }

    /// Execute the core registration flow, shared by the registration overlay and the `/register <username> <password> <email>` command.
    /// Uses the same deterministic encryption transformation as login; on success, gives a prompt and (in overlay scenario) switches to the login overlay.
    fn perform_register(&mut self, username: String, email: String, password: String) {
        if username.is_empty() || email.is_empty() || password.is_empty() {
            self.push_error(self.t("error_empty_fields"));
            return;
        }
        let encrypted_password = crypto::encrypt_login_password(&password);
        let req = RegisterRequest {
            username,
            email,
            password: encrypted_password,
        };
        match self.connector.register(req) {
            Ok(_) => {
                self.input_collector.register_name_state = TextInputState::default();
                self.input_collector.register_email_state = TextInputState::default();
                self.input_collector.register_password_state = TextInputState::default();
                // If initiated from the registration overlay, guide the user to the login overlay after successful registration; for direct command registration just prompt
                if self.displaying_overlay == DisplayingOverlay::Register {
                    self.displaying_overlay = DisplayingOverlay::Login;
                    self.focus_index = 0;
                }
                self.push_notification(self.t("register_success"));
            }
            Err(e) => {
                self.push_error(format!("{e}"));
            }
        }
    }

    /// Directly refresh the room list (called by UI operations or accepting requests that bypass polling), sharing snapshot logic with polling events.
    fn load_rooms(&mut self) {
        match self.connector.list_rooms() {
            Ok(rooms) => self.apply_room_snapshot(rooms),
            Err(e) => {
                self.push_error(format!("{e}"));
            }
        }
    }

    // Apply a latest room snapshot: detect being kicked from a group, filter by visibility, restore/fallback the selected room and reload messages
    /// messages, trigger WebSocket reconnection and member name refresh for newly appeared rooms. load_rooms and polling events
    /// RoomsUpdated share this single entry point, ensuring both paths behave exactly identically.
    fn apply_room_snapshot(&mut self, rooms: Vec<RoomInfo>) {
        // Detect rooms newly appeared relative to the current list: this connection isn't subscribed to it, must reconnect to receive pushes.
        // Single-person zombie rooms don't count as new rooms, avoiding triggering unnecessary reconnections
        let known_room_ids: HashSet<&str> =
            self.rooms.iter().map(|room| room.id.as_str()).collect();
        let has_new_room = rooms.iter().any(|room| {
            !known_room_ids.contains(room.id.as_str()) && (room.is_group || room.members.len() >= 2)
        });
        // Record room IDs newly appeared relative to the old list (holding ownership for post-reassignment judgment of "auto-switch to new private chat")
        let new_room_ids: HashSet<String> = rooms
            .iter()
            .filter(|room| !known_room_ids.contains(room.id.as_str()))
            .map(|room| room.id.clone())
            .collect();
        let previous_selected_id = self.selected_room_id();
        // Record currently visible group chats: if a group chat disappears and it wasn't actively left by this client, it's judged as kicked from the group
        let previous_groups: HashMap<String, String> = self
            .rooms
            .iter()
            .filter(|room| room.is_group)
            .map(|room| (room.id.clone(), room.name.clone().unwrap_or_default()))
            .collect();
        let new_group_ids: HashSet<String> = rooms
            .iter()
            .filter(|room| room.is_group)
            .map(|room| room.id.clone())
            .collect();
        let kicked_groups: Vec<(String, String)> = previous_groups
            .iter()
            .filter(|(id, _)| {
                !new_group_ids.contains(*id)
                    && !self.left_room_ids.contains(*id)
                    && !self.closed_room_ids.contains(*id)
            })
            .map(|(id, name)| (id.clone(), name.clone()))
            .collect();
        self.rooms = filter_visible_rooms(rooms, &self.closed_room_ids);
        if self.rooms.is_empty() {
            self.rooms_state.select(None);
            self.messages.clear();
        } else {
            let restored_index = previous_selected_id
                .and_then(|id| self.rooms.iter().position(|room| room.id == id));
            // Whenever a new private chat room appears (by accepting a request to create, or by polling after the peer accepts), automatically switch to it
            let new_private_index = self
                .rooms
                .iter()
                .position(|room| !room.is_group && new_room_ids.contains(&room.id));
            let selected_index = new_private_index.or(restored_index).unwrap_or(0);
            self.rooms_state.select(Some(selected_index));
            // Neither retaining the original selected room nor switching to a new private chat means the original selected room disappeared and fell back to 0, need to clear old messages to prevent remnants
            if new_private_index.is_none() && restored_index.is_none() {
                self.messages.clear();
            }
            self.load_messages_for_selected_room();
        }
        if has_new_room {
            // The new room isn't subscribed by this connection, needs reconnection for the server to re-snapshot the subscription; handshake resend is unified at WebSocketConnected
            self.restart_websocket_thread();
            self.refresh_all_sender_names();
        }
        for (group_id, name) in kicked_groups {
            self.announce_kicked_from_group(&group_id, &name);
        }
    }

    /// Fetch member lists of all visible rooms and populate the sender name mapping, ensuring member names display correctly when joining a group chat
    fn refresh_all_sender_names(&mut self) {
        let room_ids: Vec<String> = self.rooms.iter().map(|room| room.id.clone()).collect();
        for room_id in room_ids {
            if let Ok(room_detail) = self.connector.get_room(&room_id) {
                for member in &room_detail.members {
                    self.sender_names
                        .insert(member.user_id.clone(), member.username.clone());
                }
            }
        }
    }

    /// Prompt user that they were removed from a group: prefer the group name captured by polling; fall back to group ID if missing
    fn announce_kicked_from_group(&mut self, group_id: &str, known_name: &str) {
        let name = if known_name.is_empty() {
            group_id.to_string()
        } else {
            known_name.to_string()
        };
        self.push_notification(self.t("kicked_from_group").replace("{name}", &name));
    }

    fn load_messages_for_selected_room(&mut self) {
        // Take a room snapshot first before proceeding: the latter half of this method needs to mutably borrow self multiple times (merge messages, write cache):
        // Holding a reference to self.rooms throughout would make these writes impossible
        let Some(room) = self
            .rooms_state
            .selected()
            .and_then(|index| self.rooms.get(index))
            .cloned()
        else {
            return;
        };
        {
            // Full room (re)load always resets scroll position to the bottom and rewrites the message list below:
            // Every path in this method replaces self.messages with the latest messages in the entire table; the old "offset from bottom" for the new list
            // is meaningless — if a large offset remains, it would be clamped to the top and accidentally trigger auto-pull, stopping at a high position.
            // Therefore switching group chats and refreshing the same room uniformly reset to bottom; the user needs to actively scroll up before the offset accumulates again
            self.messages_scroll_from_bottom = 0;
            debug_log(&format!("整房加载 room={} 滚动偏移归零", room.id));
            // The user is viewing this room, reset its unread message count to zero
            self.unread_counts.remove(&room.id);
            // Messages the local side already holds for this very room. In end-to-end encrypted private chats this copy is the plaintext
            // this side decrypted, while the server returns an empty body for that history (the ciphertext only exists inside the session).
            // The merge below keeps the local copy per message ID, so the plaintext is not replaced by the empty body;
            // when the room changed (held messages belong elsewhere) they are dropped as before, so the previous room leaves nothing behind.
            let mut local_messages: Vec<MessageInfo> = std::mem::take(&mut self.messages);
            if local_messages
                .first()
                .is_none_or(|message| message.room_id != room.id)
            {
                local_messages.clear();
            }
            // First lay the history already viewed from the local cache on the screen: the server's first page only has 50 items,
            // the cache might have hundreds, show the cache first then merge, switching rooms won't make "history suddenly appear shorter"
            // End-to-end encrypted rooms don't cache; if the cache is unavailable, it's empty
            let cached_messages = if room.is_encrypted {
                None
            } else {
                self.chat_cache
                    .as_ref()
                    .and_then(|cache| cache.load_room(&room.id))
            };
            let base_messages: Vec<MessageInfo> = match cached_messages.clone() {
                Some(cached) => merge_messages_by_id(cached.messages, local_messages),
                None => local_messages,
            };
            self.messages = base_messages.clone();
            if let Some(cached) = cached_messages.clone() {
                self.messages_older_cursor = cached.older_cursor;
            }
            // Fetch room details
            match self.connector.get_room(&room.id) {
                Ok(room_detail) => {
                    for member in &room_detail.members {
                        self.sender_names
                            .insert(member.user_id.clone(), member.username.clone());
                    }
                    // Add the current user
                    if let Some(ref user_id) = self.current_user_id {
                        self.sender_names
                            .insert(user_id.clone(), self.t("self_name"));
                    }
                }
                Err(e) => {
                    self.push_error(format!("{}: {e}", self.t("error_get_room_failed")));
                    self.messages_reloaded_at = Instant::now();
                    return;
                }
            };
            match self.connector.get_messages(&room.id, 50, None) {
                Ok(data) => {
                    // The API returns latest first, reversed to old messages on top and new at the bottom, consistent with the real-time append direction
                    let mut loaded = data.messages;
                    loaded.reverse();
                    // Merge with the server's page by message ID instead of replacing the entire table: the local cache might have items not on this page
                    // older messages; replacing would lose them; merging preserves local items and also keeps in encrypted private chats
                    // the decrypted plaintext from being overwritten by the empty history body returned from the server
                    self.messages = merge_messages_by_id(base_messages, loaded);
                    // Record the older message pagination cursor (returns None when the server has no more), for auto-paging when scrolled to the top;
                    // when the cache already has earlier messages, use the cache's cursor; paging continues from the locally known position going backward
                    self.messages_older_cursor = cached_messages
                        .as_ref()
                        .and_then(|cached| cached.older_cursor.clone())
                        .or(data.next_cursor);
                }
                Err(e) => {
                    self.push_error(format!("{}: {e}", self.t("error_get_messages_failed")));
                    // When fetching fails, keep existing content (from cache or memory); this is precisely the meaning of local caching:
                    // You can still browse history even when the server is temporarily unreachable
                    if cached_messages.is_none() && self.messages.is_empty() {
                        self.messages_older_cursor = None;
                    }
                }
            }
            self.messages_reloaded_at = Instant::now();
            // After replacing the entire table, old hit message IDs might no longer be in the list; rescanning ensures search jumps remain valid
            self.refresh_search_matches();
            let loaded_room_id = room.id.clone();
            self.cache_loaded_messages(&loaded_room_id);
        }
    }

    // Auto-page up when the user scrolls to the top of the message display area: fetch a batch (50 items) by messages_older_cursor
    // earlier messages and insert at the head of the message list. An empty cursor means no earlier messages or the last fetch failed, return directly;
    /// on success the cursor is updated to the response's next_cursor (None when no more, paging naturally stops);
    /// on failure clear the cursor and show an error, avoiding retry every frame and overwhelming the server
    fn load_older_messages(&mut self) {
        let Some(cursor) = self.messages_older_cursor.clone() else {
            return;
        };
        let Some(room) = self
            .rooms_state
            .selected()
            .and_then(|index| self.rooms.get(index))
            .cloned()
        else {
            return;
        };
        match self.connector.get_messages(&room.id, 50, Some(&cursor)) {
            Ok(data) => {
                // The API returns newest-first; after reversing, insert the whole batch at the front; under the "offset from bottom" scroll model
                // offset unchanged while total rows increase, the viewport stays on the original content, the user can continue scrolling up to enter newly pulled history
                let mut older = data.messages;
                older.reverse();
                debug_log(&format!(
                    "更早消息前插 room={} 数量={} 新游标={:?}",
                    room.id,
                    older.len(),
                    data.next_cursor
                ));
                self.messages.splice(0..0, older);
                self.messages_older_cursor = data.next_cursor;
                let room_id = room.id.clone();
                self.cache_loaded_messages(&room_id);
            }
            Err(e) => {
                self.push_error(format!("{}: {e}", self.t("error_get_messages_failed")));
                self.messages_older_cursor = None;
            }
        }
    }

    // Whether currently logged in (holding user identity). After login/registration changed to command-based, this replaces the existence judgment of a separate login page.
    pub fn is_logged_in(&self) -> bool {
        self.current_user_id.is_some()
    }

    /// Unified entry point for login-protected operations: pops a prompt and returns false when not logged in, the caller aborts accordingly.
    fn require_login(&mut self) -> bool {
        if self.is_logged_in() {
            return true;
        }
        self.push_notification(self.t("error_not_logged_in"));
        false
    }

    // When not logged in at startup (no valid session), pop a prompt once guiding the user to /login or /register;
    // the chat window displays normally, not covered.
    pub fn notify_signed_out(&mut self) {
        self.push_notification(self.t("logged_out_hint"));
    }

    fn send_message(&mut self) {
        if !self.require_login() {
            return;
        }
        let content = self.input_collector.message_input_state.text();
        if content.is_empty() {
            return;
        }

        let Some(room) = self
            .rooms_state
            .selected()
            .and_then(|index| self.rooms.get(index))
            .cloned()
        else {
            return;
        };

        // Private chats always use end-to-end encryption (encryption is mandatory when the request is created)
        if !room.is_group {
            self.send_encrypted_message(&room.id, content);
            return;
        }

        if self.websocket_sender.is_none() {
            self.push_error(self.t("error_ws_not_ready"));
            return;
        }
        // Messages are sent via the WebSocket thread; after server confirmation, they are deduplicated and displayed via echo events
        self.send_ws_payload(outbound_ws_payload(
            self.connector.version(),
            WsCommand::SendMessage {
                room_id: &room.id,
                content: &content,
            },
        ));
        self.input_collector.message_input_state.set_text("");
    }

    /// Send via encryption: if the session is active, encrypt and send; if in handshake, queue and wait to send automatically after ready
    fn send_encrypted_message(&mut self, room_id: &str, content: String) {
        let session_phase = self
            .crypto
            .sessions
            .get(room_id)
            .map(|session| session.phase);
        match session_phase {
            Some(EncryptionPhase::Active) => {
                let shared_key = self
                    .crypto
                    .sessions
                    .get(room_id)
                    .and_then(|session| session.shared_key);
                let Some(shared_key) = shared_key else {
                    self.push_error(self.t("error_session_key_missing"));
                    return;
                };
                match crypto::encrypt_message(&shared_key, &content) {
                    Ok(ciphertext) => {
                        self.send_ws_payload(outbound_ws_payload(
                            self.connector.version(),
                            WsCommand::EncryptMessage {
                                room_id,
                                ciphertext: &ciphertext,
                            },
                        ));
                    }
                    Err(e) => {
                        self.push_error(format!("{}: {e}", self.t("error_encrypt_message_failed")));
                        return;
                    }
                }
            }
            Some(EncryptionPhase::AwaitingAcceptance)
            | Some(EncryptionPhase::AwaitingSessionReady) => {
                // New messages during an ongoing handshake are all queued and automatically sent in order when ready;
                // Do not perform any handshake reset here to avoid overwriting the in-progress key negotiation
                let session = self
                    .crypto
                    .sessions
                    .get_mut(room_id)
                    .expect("会话存在性已在上方确认");
                session.pending_content = Some(content);
                self.push_notification(self.t("error_session_establishing"));
            }
            None => {
                self.initiate_encryption(room_id, Some(content));
                self.push_notification(self.t("error_session_initiating"));
            }
        }
        self.input_collector.message_input_state.set_text("");
    }

    fn create_group(&mut self) {
        if !self.require_login() {
            return;
        }
        let name = self
            .input_collector
            .create_group_name_state
            .value
            .text()
            .string();
        let members_str = self
            .input_collector
            .create_group_members_state
            .value
            .text()
            .string();

        if name.is_empty() {
            self.push_error(self.t("error_group_name_empty"));
            return;
        }

        let usernames: Vec<String> = members_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let req = CreateRoomRequest::group(name, usernames);
        match self.connector.create_room(req) {
            Ok(_) => {
                self.displaying_overlay = DisplayingOverlay::Nothing;
                self.input_collector.create_group_name_state.set_text("");
                self.input_collector.create_group_members_state.set_text("");
                self.load_rooms();
            }
            Err(e) => {
                self.push_error(format!("{}: {e}", self.t("error_create_group_failed")));
            }
        }
    }

    /// Initiate a private chat: search for the target user to get their ID, then send a chat request; the room appears automatically after the peer accepts
    fn create_private_chat(&mut self) {
        if !self.require_login() {
            return;
        }
        let username = self
            .input_collector
            .create_private_username_state
            .value
            .text()
            .string();

        if username.is_empty() {
            self.push_error(self.t("error_username_empty"));
            return;
        }

        let search_result = match self.connector.search_users(&username) {
            Ok(users) => users,
            Err(e) => {
                self.push_error(format!("{}: {e}", self.t("error_search_user_failed")));
                return;
            }
        };
        // Prioritize exact username match, then take the first search result
        let target = search_result
            .iter()
            .find(|user| user.username == username)
            .or_else(|| search_result.first());
        let Some(target) = target else {
            self.push_error(self.t("error_user_not_found"));
            return;
        };
        if Some(&target.id) == self.current_user_id.as_ref() {
            self.push_error(self.t("error_cannot_send_to_self"));
            return;
        }

        // Private chats are always established as encrypted rooms, no runtime toggle needed
        let request_message = self.t("private_request_message");
        match self
            .connector
            .create_room_request(&target.id, &request_message, true)
        {
            Ok(_) => {
                self.displaying_overlay = DisplayingOverlay::Nothing;
                self.input_collector
                    .create_private_username_state
                    .set_text("");
                self.push_notification(self.t("notification_request_sent"));
            }
            Err(e) => {
                self.push_error(format!("{}: {e}", self.t("error_send_request_failed")));
            }
        }
    }

    /// Accept the selected pending chat request, refreshing the room list and request list on success
    fn accept_selected_request(&mut self) {
        let Some(request_id) = self.selected_request_id() else {
            return;
        };
        match self.connector.accept_room_request(&request_id) {
            Ok(_) => {
                self.push_notification(self.t("notification_request_accepted"));
                self.load_rooms();
                self.mark_pending_request_handled(&request_id, "accepted");
            }
            Err(e) => {
                self.push_error(format!("{}: {e}", self.t("error_accept_request_failed")));
            }
        }
    }

    /// Decline the selected pending chat request
    fn decline_selected_request(&mut self) {
        let Some(request_id) = self.selected_request_id() else {
            return;
        };
        match self.connector.decline_room_request(&request_id) {
            Ok(_) => {
                self.push_notification(self.t("notification_request_declined"));
                self.mark_pending_request_handled(&request_id, "declined");
            }
            Err(e) => {
                self.push_error(format!("{}: {e}", self.t("error_decline_request_failed")));
            }
        }
    }

    // After locally handling a received request, write the result status in place, the entry stays in the "received" area.
    // Can't remove: the server's `GET /requests/pending` only returns rows that are still pending, removing them means
    /// permanently losing this history (the sender side doesn't have this problem because `/requests/sent` returns all statuses).
    /// Also no extra list request is sent — two sources writing the same list in sequence would overwrite each other.
    fn mark_pending_request_handled(&mut self, request_id: &str, status: &str) {
        if let Some(request) = self
            .pending_requests
            .iter_mut()
            .find(|request| request.id == request_id)
        {
            request.status = Some(status.to_string());
        }
    }

    /// Align the "received requests" brought back by polling with the server: the server's list has no rows for already-processed items,
    /// so the entries the local side has recorded with results are reattached to the end of the list, so history isn't cleared after being processed once.
    fn apply_received_requests(&mut self, polled: Vec<RoomRequestInfo>) {
        let handled: Vec<RoomRequestInfo> = self
            .pending_requests
            .iter()
            .filter(|request| !received_request_is_pending(request))
            .filter(|kept| !polled.iter().any(|request| request.id == kept.id))
            .cloned()
            .collect();
        self.pending_requests = polled.into_iter().chain(handled).collect();
    }

    /// Mark sent requests as cancelled in place, also waiting for polling confirmation
    fn mark_sent_request_cancelled(&mut self, request_id: &str) {
        if let Some(request) = self
            .sent_requests
            .iter_mut()
            .find(|request| request.id == request_id)
        {
            request.status = Some("cancelled".to_string());
        }
    }

    fn selected_request_id(&self) -> Option<String> {
        self.request_list_state
            .selected()
            .and_then(|index| self.pending_requests.get(index))
            .map(|request| request.id.clone())
    }

    // Handle terminal events; returns true indicating the application requests exit (triggered by chat commands or exit shortcuts)
    pub fn handle_event(&mut self, event: &Event) -> bool {
        // Bracketed paste is handled first: the overlay branch returns early for any event, if placed later it wouldn't receive the pasted content.
        // When bracketed paste is not enabled, paste is split into per-character key events, where the newline is equivalent to pressing Enter,
        // so "copying multiple lines of text then pasting" would send multiple single-line messages in sequence.
        if let Event::Paste(pasted_text) = event {
            self.handle_pasted_text(pasted_text);
            return false;
        }

        // Full-screen selection is handled before overlay dispatch: text above overlays, notifications, and the status bar can also be selected and copied.
        // Drag and release are exclusive to selection (returning true means the event is fully consumed); pressing only records the start point and continues
        // following the original click-focus dispatch, not competing with the input box's own selection logic
        if let Event::Mouse(mouse) = event
            && self.handle_screen_selection_mouse(*mouse)
        {
            return false;
        }

        match self.displaying_overlay {
            DisplayingOverlay::CreateGroup => {
                if let Event::Key(key) = event
                    && key.kind == KeyEventKind::Press
                {
                    match key.code {
                        KeyCode::Esc => {
                            // Move focus up level by level; when at the first input box, fall back to the settings menu
                            if self.focus_index == 1 {
                                self.focus_index = 0;
                            } else {
                                self.dismiss_overlay_back();
                                self.input_collector.create_group_name_state.set_text("");
                                self.input_collector.create_group_members_state.set_text("");
                            }
                            return false;
                        }
                        KeyCode::Enter => {
                            if self.focus_index == 1 {
                                self.focus_index = 0;
                                self.create_group();
                                return false;
                            } else {
                                self.focus_index = 1;
                            }
                        }
                        KeyCode::Tab => {
                            self.focus_index = (self.focus_index + 1) % 2;
                            return false;
                        }
                        _ => {}
                    }
                    if let Some(state) = self.get_create_group_focused_state() {
                        let _ = text_input::handle_events(state, true, event);
                    }
                }
                return false;
            }

            DisplayingOverlay::CreatePrivate => {
                if let Event::Key(key) = event
                    && key.kind == KeyEventKind::Press
                {
                    match key.code {
                        KeyCode::Esc => {
                            self.dismiss_overlay_back();
                            self.input_collector
                                .create_private_username_state
                                .set_text("");
                            self.focus_index = 0;
                            return false;
                        }
                        KeyCode::Enter => {
                            self.create_private_chat();
                            return false;
                        }
                        _ => {}
                    }
                    if let Some(state) = self.get_create_private_focused_state() {
                        let _ = text_input::handle_events(state, true, event);
                    }
                }
                return false;
            }

            DisplayingOverlay::PendingRequests => {
                if let Event::Key(key) = event
                    && key.kind == KeyEventKind::Press
                {
                    // Received and sent requests are concatenated into a flat sequence, arrow keys move continuously across areas,
                    // therefore wrap around by total entry count instead of a single list length
                    let entries = self.request_entries();
                    match key.code {
                        KeyCode::Esc => {
                            self.dismiss_overlay_back();
                            return false;
                        }
                        KeyCode::Up | KeyCode::Down => {
                            if !entries.is_empty() {
                                let count = entries.len();
                                let current = self.request_list_state.selected().unwrap_or(0);
                                let next = if key.code == KeyCode::Up {
                                    (current + count - 1) % count
                                } else {
                                    (current + 1) % count
                                };
                                self.request_list_state.select(Some(next));
                            }
                            return false;
                        }
                        KeyCode::Enter => {
                            // Acceptance only makes sense for received requests still waiting: sent items and processed history do nothing
                            if matches!(
                                self.request_list_state
                                    .selected()
                                    .and_then(|index| entries.get(index)),
                                Some((false, request))
                                if received_request_is_pending(request)
                            ) {
                                self.accept_selected_request();
                            }
                            if self.pending_requests.is_empty() && self.sent_requests.is_empty() {
                                self.dismiss_overlay_back();
                            }
                            return false;
                        }
                        KeyCode::Char('d') => {
                            // The same key has different semantics in the two areas: "decline" and "cancel"
                            match self
                                .request_list_state
                                .selected()
                                .and_then(|index| entries.get(index))
                            {
                                Some((false, request)) if received_request_is_pending(request) => {
                                    self.decline_selected_request();
                                }
                                // Ended invitations can't be recalled, nothing is done here (no longer prompting "can it be recalled")
                                Some((true, request))
                                    if request.status.as_deref() == Some("pending") =>
                                {
                                    self.cancel_sent_request(&request.id);
                                }
                                _ => {}
                            }
                            if self.pending_requests.is_empty() && self.sent_requests.is_empty() {
                                self.dismiss_overlay_back();
                            }
                            return false;
                        }
                        _ => {}
                    }
                }
                return false;
            }

            DisplayingOverlay::AvatarSelect => {
                if let Event::Key(key) = event
                    && key.kind == KeyEventKind::Press
                {
                    // The list only opens when there are images in the local directory, the entry count is re-read from disk here
                    let count = local_avatar_files().len();
                    match key.code {
                        KeyCode::Esc => {
                            self.dismiss_overlay_back();
                            return false;
                        }
                        KeyCode::Up | KeyCode::Down if count > 0 => {
                            let current = self.avatar_list_state.selected().unwrap_or(0);
                            let next = if key.code == KeyCode::Up {
                                (current + count - 1) % count
                            } else {
                                (current + 1) % count
                            };
                            self.avatar_list_state.select(Some(next));
                            return false;
                        }
                        KeyCode::Enter if count > 0 => {
                            self.apply_local_avatar();
                            return false;
                        }
                        // Only in this overlay does Ctrl+U switch to "enter a network link"; in the message input box it still deletes the entire line
                        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            self.open_declared_form(&FormAction::ChangeAvatar);
                            return false;
                        }
                        _ => {}
                    }
                }
                return false;
            }

            DisplayingOverlay::Form => {
                if let Event::Key(key) = event
                    && key.kind == KeyEventKind::Press
                {
                    // Arrow keys switch the current input item like Tab: going through items one by one in a long form via Tab is too cumbersome
                    if matches!(key.code, KeyCode::Up | KeyCode::Down) {
                        self.cycle_form_focus(key.code == KeyCode::Up);
                        return false;
                    }
                    match key.code {
                        KeyCode::Esc => {
                            self.active_form = None;
                            self.focus_index = 0;
                            self.dismiss_overlay_back();
                            return false;
                        }
                        KeyCode::Tab => {
                            let field_count = self
                                .active_form
                                .as_ref()
                                .map(|(_, fields)| fields.len())
                                .unwrap_or(1);
                            self.focus_index = (self.focus_index + 1) % field_count.max(1);
                            return false;
                        }
                        KeyCode::Enter => {
                            self.submit_active_form();
                            return false;
                        }
                        _ => {}
                    }
                    if let Some(state) = self.get_focused_state() {
                        let _ = text_input::handle_events(state, true, event);
                    }
                }
                return false;
            }

            DisplayingOverlay::ProfileCard => {
                // Read-only card: Esc closes and returns to the chat page (it was opened by the /profile command, not part of the settings menu chain)
                if let Event::Key(key) = event
                    && key.kind == KeyEventKind::Press
                    && key.code == KeyCode::Esc
                {
                    self.profile_view = None;
                    self.displaying_overlay = DisplayingOverlay::Nothing;
                    self.restore_chat_focus();
                }
                return false;
            }

            DisplayingOverlay::SettingsMenu => {
                // Menu items and actions are defined in one place (settings_menu_entries); rendering and dispatch read the same table:
                // Adding/removing menu items does not require manually syncing "which number" again
                let entries = self.settings_menu_entries();
                let menu_count = entries.len().max(1);
                if let Event::Key(key) = event
                    && key.kind == KeyEventKind::Press
                {
                    match key.code {
                        KeyCode::Esc => {
                            self.dismiss_overlay_back();
                            return false;
                        }
                        KeyCode::Up | KeyCode::Down => {
                            let current = self.menu_list_state.selected().unwrap_or(0);
                            let next = if key.code == KeyCode::Up {
                                (current + menu_count - 1) % menu_count
                            } else {
                                (current + 1) % menu_count
                            };
                            self.menu_list_state.select(Some(next));
                            return false;
                        }
                        KeyCode::Enter => {
                            let selected = self.menu_list_state.selected().unwrap_or(0);
                            let Some((_, _, action)) = entries.get(selected) else {
                                return false;
                            };
                            let action = action.clone();
                            // Not logged in but wants to change account or perform server operations: show a prompt, keep the overlay on the settings menu
                            if action.requires_login() && !self.require_login() {
                                return false;
                            }
                            match action {
                                SettingsAction::ToggleShowUid => {
                                    self.show_uid = !self.show_uid;
                                    self.save_display_preferences();
                                }
                                SettingsAction::ToggleTimeWithDate => {
                                    self.time_with_date = !self.time_with_date;
                                    self.save_display_preferences();
                                }
                                SettingsAction::ToggleQuickSearch => {
                                    self.quick_search = !self.quick_search;
                                    self.save_display_preferences();
                                }
                                SettingsAction::ToggleSound => {
                                    self.sound_enabled = !self.sound_enabled;
                                    self.save_display_preferences();
                                }
                                SettingsAction::Logout => {
                                    self.logout();
                                    self.displaying_overlay = DisplayingOverlay::Nothing;
                                    self.restore_chat_focus();
                                }
                                SettingsAction::UpdateClient => {
                                    // Successful update suspends the installation process and exits via the main loop; on failure stay in the settings menu to see the prompt
                                    self.start_downloaded_update();
                                }
                                SettingsAction::OpenForm(form_action) => {
                                    self.open_declared_form(&form_action);
                                }
                                SettingsAction::OpenOverlay(overlay) => {
                                    self.open_overlay(overlay);
                                }
                            }
                            return false;
                        }
                        _ => {}
                    }
                }
                return false;
            }

            DisplayingOverlay::AppearanceSelect => {
                if let Event::Key(key) = event
                    && key.kind == KeyEventKind::Press
                {
                    let names = Appearance::available_names();
                    match key.code {
                        KeyCode::Esc => {
                            self.dismiss_overlay_back();
                            return false;
                        }
                        KeyCode::Up | KeyCode::Down => {
                            let count = names.len();
                            if count == 0 {
                                return false;
                            }
                            let current = self.appearance_list_state.selected().unwrap_or(0);
                            let next = if key.code == KeyCode::Up {
                                (current + count - 1) % count
                            } else {
                                (current + 1) % count
                            };
                            self.appearance_list_state.select(Some(next));
                            return false;
                        }
                        KeyCode::Enter => {
                            if let Some(index) = self.appearance_list_state.selected()
                                && let Some(name) = names.get(index)
                            {
                                self.switch_appearance(name);
                            }
                            self.displaying_overlay = DisplayingOverlay::SettingsMenu;
                            return false;
                        }
                        _ => {}
                    }
                }
                return false;
            }

            DisplayingOverlay::LanguageSelect => {
                if let Event::Key(key) = event
                    && key.kind == KeyEventKind::Press
                {
                    let languages = Self::get_available_languages();
                    match key.code {
                        KeyCode::Esc => {
                            self.dismiss_overlay_back();
                            return false;
                        }
                        KeyCode::Up | KeyCode::Down => {
                            let count = languages.len();
                            if count == 0 {
                                return false;
                            }
                            let current = self.language_list_state.selected().unwrap_or(0);
                            let next = if key.code == KeyCode::Up {
                                (current + count - 1) % count
                            } else {
                                (current + 1) % count
                            };
                            self.language_list_state.select(Some(next));
                            return false;
                        }
                        KeyCode::Enter => {
                            if let Some(idx) = self.language_list_state.selected()
                                && let Some(lang) = languages.get(idx)
                            {
                                Self::save_language_preference(lang);
                                self.load_language(lang);
                                self.push_notification(
                                    self.t("language_switched")
                                        .replace("{lang}", lang)
                                        .to_string(),
                                );
                            }
                            self.displaying_overlay = DisplayingOverlay::SettingsMenu;
                            return false;
                        }
                        _ => {}
                    }
                }
                return false;
            }

            DisplayingOverlay::ServerAddress => {
                if let Event::Key(key) = event
                    && key.kind == KeyEventKind::Press
                {
                    match key.code {
                        KeyCode::Esc => {
                            self.dismiss_overlay_back();
                            return false;
                        }
                        KeyCode::Enter => {
                            let new_addr = self
                                .input_collector
                                .server_address_state
                                .text()
                                .trim()
                                .to_string();
                            if new_addr.is_empty() {
                                self.push_notification(self.t("error_server_address_empty"));
                                return false;
                            }
                            // Test connectivity
                            let test_connector = Connector::new(&new_addr);
                            match test_connector.greet() {
                                Ok(_) => {
                                    self.connector.set_base_url(&new_addr);
                                    self.save_server_address();
                                    // After switching server, re-probe the version so online decisions match the new server
                                    self.detect_and_apply_api_version();
                                    // Connectivity probing should also target the new address
                                    self.start_reachability_watch();
                                    self.push_notification(self.t("server_address_saved"));
                                    self.displaying_overlay = DisplayingOverlay::SettingsMenu;
                                }
                                Err(_) => {
                                    self.push_notification(self.t("error_server_connect_failed"));
                                }
                            }
                            return false;
                        }
                        _ => {
                            let _ = text_input::handle_events(
                                &mut self.input_collector.server_address_state,
                                true,
                                event,
                            );
                            return false;
                        }
                    }
                }
                return false;
            }

            DisplayingOverlay::Login | DisplayingOverlay::Register => {
                if let Event::Key(key) = event
                    && key.kind == KeyEventKind::Press
                {
                    let max_index = self.max_focus_index();
                    match key.code {
                        KeyCode::Esc => {
                            // Consistent with creating a group: first move focus up level by level, close the overlay when at the first input field
                            if self.focus_index > 0 {
                                self.focus_index -= 1;
                            } else {
                                self.dismiss_overlay_back();
                            }
                            return false;
                        }
                        KeyCode::Tab => {
                            if max_index > 0 {
                                self.focus_index = (self.focus_index + 1) % (max_index + 1);
                            }
                        }
                        KeyCode::BackTab => {
                            if self.focus_index > 0 {
                                self.focus_index -= 1;
                            }
                        }
                        KeyCode::Enter => {
                            if self.focus_index == max_index {
                                if matches!(self.displaying_overlay, DisplayingOverlay::Login) {
                                    self.do_login();
                                } else {
                                    self.do_register();
                                }
                            } else if max_index > 0 {
                                self.focus_index += 1;
                            }
                        }
                        _ => {
                            self.dispatch_focused_input_event(true, event);
                        }
                    }
                }
                return false;
            }
            DisplayingOverlay::Nothing => {}
        }

        match event {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                // In search mode, the up/down key semantics are fully taken over: they no longer move the input box cursor or switch rooms,
                // always switch matches. Placed before the modifier key branches and matched with "any modifier",
                // because different terminals report Ctrl/Ctrl+Shift+arrow keys very differently (Terminal.app doesn't even distinguish),
                // only recognizing one combination key would manifest as pressing and having no reaction, only the input box cursor moving.
                if matches!(key.code, KeyCode::Up | KeyCode::Down) && self.in_search_mode() {
                    debug_log(&format!("搜索切换匹配项: {key:?}"));
                    self.navigate_search_result(key.code == KeyCode::Up);
                    return false;
                }
                // Ctrl+L requests full screen repaint (executed by the main loop via terminal.clear, used to fix the misalignment caused by terminal-side scrolling)
                if matches!(key.code, KeyCode::Char('l') | KeyCode::Char('L'))
                    && key.modifiers.contains(KeyModifiers::CONTROL)
                {
                    self.full_repaint_requested = true;
                    debug_log("Ctrl+L 请求整屏重绘");
                    return false;
                }
                if key.modifiers.contains(KeyModifiers::CONTROL) {
                    // Ctrl+P on the chat page opens the settings menu (entry for create group/private chat and pending requests)
                    if let KeyCode::Char('p') = key.code {
                        self.displaying_overlay = DisplayingOverlay::SettingsMenu;
                        self.menu_list_state.select(Some(0));
                        return false;
                    }
                }

                match key.code {
                    KeyCode::Up | KeyCode::Down => {
                        let input_text = self.input_collector.message_input_state.text();
                        if let Some(command_prefix) = input_text.strip_prefix('/') {
                            // When the completion list is on, arrow keys select commands, room switching is disabled
                            let candidate_count = self.completion_candidates(command_prefix).len();
                            if candidate_count > 0 {
                                let current = self.command_list_state.selected().unwrap_or(0);
                                let next = if key.code == KeyCode::Up {
                                    (current + candidate_count - 1) % candidate_count
                                } else {
                                    (current + 1) % candidate_count
                                };
                                self.command_list_state.select(Some(next));
                            }
                        } else {
                            // When multi-line text, arrow keys move the cursor, switch rooms only when reaching the first/last row
                            let state = &mut self.input_collector.message_input_state;
                            let before = state.cursor();
                            if key.code == KeyCode::Up {
                                state.move_up(1, false);
                            } else {
                                state.move_down(1, false);
                            }
                            let after = state.cursor();
                            // If the cursor didn't move, it's already at the boundary, execute room switching;
                            // Ctrl-combined keys are not used for room switching, to avoid confusion with search and other key combinations
                            if before == after
                                && !self.rooms.is_empty()
                                && !key.modifiers.contains(KeyModifiers::CONTROL)
                            {
                                let selected = self.rooms_state.selected().unwrap_or(0);
                                if key.code == KeyCode::Up {
                                    if selected > 0 {
                                        self.rooms_state.select(Some(selected - 1));
                                        self.load_messages_for_selected_room();
                                    }
                                } else if selected + 1 < self.rooms.len() {
                                    self.rooms_state.select(Some(selected + 1));
                                    self.load_messages_for_selected_room();
                                }
                            }
                        }
                    }
                    KeyCode::Esc => {
                        let input_text = self.input_collector.message_input_state.text();
                        if input_text.starts_with('/') {
                            // Clearing the prefix exits command mode
                            self.input_collector.message_input_state.set_text("");
                            return false;
                        }
                        if input_text.starts_with('#') {
                            // Search mode also uses prefix clearing as the exit condition, and clears highlighting and positioning together
                            self.exit_search_mode();
                            return false;
                        }
                        self.dispatch_focused_input_event(true, event);
                    }
                    KeyCode::Enter => {
                        // Enter sends the message
                        return self.handle_chat_submit();
                    }
                    KeyCode::Char('j') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        // Ctrl+J inserts a newline
                        self.input_collector.message_input_state.insert_newline();
                        self.handle_message_input_changed();
                    }
                    KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        // Ctrl+U deletes the entire line where the cursor is
                        self.input_collector.message_input_state.delete_line();
                        self.handle_message_input_changed();
                    }
                    _ => {
                        self.dispatch_focused_input_event(true, event);
                        // After input changes, the command selection returns to the first item; the component itself completes the insertion to maintain cursor position
                        let input_text = self.input_collector.message_input_state.text();
                        if input_text.starts_with('/') {
                            self.command_list_state.select(Some(0));
                        }
                        // Text addition/deletion is considered typing status, report input status as needed (internally throttled);
                        // also let old search results that don't match the current input become invalid (quick search rescan in-place)
                        self.handle_message_input_changed();
                    }
                }
            }
            Event::Mouse(mouse) => {
                // When on the chat page with no popup, the scroll wheel controls the message display area scroll; other interfaces ignore the scroll wheel
                if matches!(
                    mouse.kind,
                    MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
                ) {
                    if self.displaying_overlay == DisplayingOverlay::Nothing {
                        // Mouse events generated during synchronous blocking of the main thread for full room loading (switching groups/same room refresh) will
                        // pile up in the system queue, after loading completes they're processed late, pushing the new room view "automatically" up and
                        // may accidentally trigger top-pull; within the quiet window after loading completes, mouse events are all discarded to eliminate these late inputs
                        if self.messages_reloaded_at.elapsed() < Duration::from_millis(500) {
                            debug_log("整房加载后静默窗口内丢弃迟到的滚轮事件");
                            return false;
                        }
                        let scroll_step = 3u16;
                        if mouse.kind == MouseEventKind::ScrollUp {
                            self.messages_scroll_from_bottom =
                                self.messages_scroll_from_bottom.saturating_add(scroll_step);
                        } else {
                            self.messages_scroll_from_bottom =
                                self.messages_scroll_from_bottom.saturating_sub(scroll_step);
                        }
                        debug_log(&format!(
                            "滚轮 {:?} 后 offset={}",
                            mouse.kind, self.messages_scroll_from_bottom
                        ));
                    }
                    return false;
                }
                // Full-screen selection is already mentioned at the start of handle_event (can also be selected above overlays);
                // here only the selection area maintained by the control itself within the input box is retained
                // Selection within the input box is still maintained by the control itself, copying the control's selection text on release
                if self.displaying_overlay == DisplayingOverlay::Nothing
                    && mouse.kind == MouseEventKind::Up(crossterm::event::MouseButton::Left)
                {
                    self.copy_message_selection();
                }
                if mouse.kind == MouseEventKind::Down(crossterm::event::MouseButton::Left) {
                    let areas = self.get_field_areas(&[
                        Rect::default(),
                        Rect::default(),
                        Rect::default(),
                        Rect::default(),
                        Rect::default(),
                        Rect::default(),
                        Rect::default(),
                        Rect::default(),
                        Rect::default(),
                        Rect::default(),
                    ]);
                    for (i, area) in areas.iter().enumerate() {
                        if area.contains(ratatui::layout::Position::new(mouse.column, mouse.row)) {
                            self.focus_index = i;
                            break;
                        }
                    }
                    self.dispatch_focused_input_event(true, event);
                } else {
                    self.dispatch_focused_input_event(true, event);
                }
            }
            _ => {
                self.dispatch_focused_input_event(true, event);
            }
        }
        false
    }

    // Calculate the completion candidates for command input, returning (text to insert into the input box, list display text, description text).
    /// When /kick is followed by a space, list current group members (only for group chats where the current user is admin/owner);
    /// when /language is followed by a space, list available languages; otherwise it's command name completion.
    fn completion_candidates(
        &self,
        raw_command_after_slash: &str,
    ) -> Vec<(String, String, String)> {
        if raw_command_after_slash.starts_with("kick ") {
            let room_id = self.selected_room_id();
            let room_is_group = room_id
                .as_ref()
                .and_then(|id| self.rooms.iter().find(|room| room.id == *id))
                .map(|room| room.is_group)
                .unwrap_or(false);
            if !room_is_group {
                return Vec::new();
            }
            let Ok(detail) = self
                .connector
                .get_room(room_id.as_deref().unwrap_or_default())
            else {
                return Vec::new();
            };
            let is_admin = self.current_user_id.as_deref().is_some_and(|uid| {
                detail
                    .members
                    .iter()
                    .any(|member| member.user_id == uid && is_admin_role(&member.role))
            });
            if !is_admin {
                return Vec::new();
            }
            // Extract the input after the space for filtering
            let filter_text = raw_command_after_slash.strip_prefix("kick ").unwrap_or("");
            return detail
                .members
                .iter()
                .filter(|member| member.username.starts_with(filter_text))
                .map(|member| {
                    (
                        format!("/kick {}", member.username),
                        member.username.clone(),
                        String::new(),
                    )
                })
                .collect();
        }
        if raw_command_after_slash.starts_with("language ") {
            // Extract the input after the space for filtering
            let filter_text = raw_command_after_slash
                .strip_prefix("language ")
                .unwrap_or("");
            return Self::get_available_languages()
                .into_iter()
                .filter(|lang| lang.starts_with(filter_text))
                .map(|lang| (format!("/language {lang}"), lang.clone(), String::new()))
                .collect();
        }
        if raw_command_after_slash.starts_with("appearance ") {
            // When a space is entered after /appearance, list all available appearances under config/themes, can continue typing a prefix to filter
            let filter_text = raw_command_after_slash
                .strip_prefix("appearance ")
                .unwrap_or("");
            return Appearance::available_names()
                .into_iter()
                .filter(|name| name.starts_with(filter_text))
                .map(|name| (format!("/appearance {name}"), name.clone(), String::new()))
                .collect();
        }
        if raw_command_after_slash.starts_with("profile ") {
            // When a space is entered after /profile, list all registered users; entry text is displayed as "<username> - <UID>",
            // the username is inserted into the input box on Enter (the server's profile interface recognizes both username and UID)
            let filter_text = raw_command_after_slash
                .strip_prefix("profile ")
                .unwrap_or("");
            return self
                .registered_users
                .iter()
                .flatten()
                .filter(|user| {
                    user.username.starts_with(filter_text) || user.id.starts_with(filter_text)
                })
                .map(|user| {
                    (
                        format!("/profile {}", user.username),
                        format!("{} - {}", user.username, user.id),
                        user.nickname.clone().unwrap_or_default(),
                    )
                })
                .collect();
        }
        if raw_command_after_slash.starts_with("server_address ") {
            let current = self.connector.base_url();
            return vec![(
                format!("/server_address {current}"),
                current.to_string(),
                self.t("server_address_current"),
            )];
        }
        if raw_command_after_slash.starts_with("add_member ") {
            // The /add_member command only needs to prompt for a username, no specific completion
            return vec![(
                "/add_member <username>".to_string(),
                "<username>".to_string(),
                self.t("add_member_hint"),
            )];
        }
        if raw_command_after_slash.starts_with("mute ") {
            // /mute <bool> completes to true/false
            let filter_text = raw_command_after_slash.strip_prefix("mute ").unwrap_or("");
            return ["true", "false"]
                .into_iter()
                .filter(|value| value.starts_with(filter_text))
                .map(|value| (format!("/mute {value}"), value.to_string(), String::new()))
                .collect();
        }
        command_completions(raw_command_after_slash.trim())
            .into_iter()
            .map(|(name, description)| {
                (format!("/{name}"), format!("/{name}"), self.t(description))
            })
            .collect()
    }

    /// Handle chat page Enter submission; returns true indicating the application requests exit
    fn handle_chat_submit(&mut self) -> bool {
        let input_text = self.input_collector.message_input_state.text();
        // Search mode: Enter executes/re-executes the search, never sends "#keyword" as a message
        if input_text.starts_with('#') {
            self.execute_message_search();
            return false;
        }
        if !input_text.starts_with('/') {
            self.send_message();
            return false;
        }
        let trimmed = input_text.trim();
        let name = trimmed
            .strip_prefix('/')
            .and_then(|rest| rest.split_whitespace().next())
            .unwrap_or("");
        // /kick all are built-in batch operations (not member names), so they do not participate in member completion and go straight to command execution
        let kick_argument = trimmed.split_whitespace().nth(1).unwrap_or("");
        let is_kick_all = name == "kick" && kick_argument.eq_ignore_ascii_case("all");
        // When a command is followed by a space, enter argument completion: list group members, languages, appearance, server address, registered users,
        // press Enter to insert the selected item into the input box, press Enter again (when it's now a complete command) to execute
        let argument_completion_commands = [
            "kick",
            "language",
            "mute",
            "appearance",
            "server_address",
            "profile",
        ];
        if argument_completion_commands.contains(&name) && input_text.contains(' ') && !is_kick_all
        {
            let raw_prefix = input_text.strip_prefix('/').unwrap_or("");
            let candidates = self.completion_candidates(raw_prefix);
            // Check if the current input already exactly matches a completion candidate, and execute directly if so
            let exact_match = candidates
                .iter()
                .any(|(insert_text, _, _)| insert_text == &input_text);
            if !exact_match {
                // Current input is not a complete command; try inserting the selected completion
                if let Some(selected_index) = self.command_list_state.selected()
                    && let Some((insert_text, _, _)) =
                        candidates.get(selected_index.min(candidates.len().saturating_sub(1)))
                {
                    self.input_collector
                        .message_input_state
                        .set_text(insert_text);
                    self.input_collector.message_input_state.set_cursor(
                        TextPosition::new(insert_text.chars().count().try_into().unwrap(), 0),
                        false,
                    );
                    self.command_list_state.select(Some(0));
                }
                return false;
            }
            // If it is an exact match, continue to execute the command
        }
        // Login and registration don't accept any form of arguments: passwords shouldn't be left in the command line and scrollback history.
        // here neither executes nor clears the input box, letting the user delete the arguments themselves or switch to an overlay
        if matches!(name, "login" | "register")
            && !trimmed
                .strip_prefix(&format!("/{name}"))
                .unwrap_or("")
                .trim()
                .is_empty()
        {
            return false;
        }
        // When the command name is already a complete known command, execute directly (including /kick name, /language code with parameters)
        let is_known = chat_commands().iter().any(|(known, _)| *known == name);
        if is_known {
            let should_exit = self.execute_chat_command(trimmed);
            if !should_exit {
                self.input_collector.message_input_state.set_text("");
            }
            return should_exit;
        }
        // When the command name hasn't been completed to a full command, press Enter to complete the selected command into the input box, press Enter again to execute
        let candidates = self.completion_candidates(name);
        if !candidates.is_empty() {
            let selected = self.command_list_state.selected().unwrap_or(0);
            let index = selected.min(candidates.len() - 1);
            if let Some((insert_text, _, _)) = candidates.get(index) {
                let full = insert_text.clone();
                self.input_collector.message_input_state.set_text(&full);
                // Move the cursor to the end of the completion text, making it convenient for the user to add parameters or press Enter to execute
                self.input_collector.message_input_state.set_cursor(
                    TextPosition::new(full.chars().count().try_into().unwrap(), 0),
                    false,
                );
                self.command_list_state.select(Some(0));
            }
        }
        false
    }

    /// Execute chat commands starting with /; returns true indicating the application requests exit.
    /// To add a new command: append an entry to the chat_commands table and add a dispatch branch in the match here.
    fn execute_chat_command(&mut self, command_line: &str) -> bool {
        let Some(name) = command_line
            .strip_prefix('/')
            .and_then(|rest| rest.split_whitespace().next())
        else {
            let usage = chat_commands()
                .iter()
                .map(|(name, _)| format!("/{name}"))
                .collect::<Vec<_>>()
                .join(" ");
            self.push_error(format!("{}: {usage}", self.t("error_available_commands")));
            return false;
        };
        if !chat_commands().iter().any(|(known, _)| *known == name) {
            self.push_error(
                self.t("error_unknown_command")
                    .replace("{name}", name)
                    .to_string(),
            );
            return false;
        }
        // When not logged in, only allow login/register/exit/quit/language/appearance/server_address; other chat operations first show a prompt and reject
        let allowed_signed_out = matches!(
            name,
            "login"
                | "register"
                | "logout"
                | "quit"
                | "exit"
                | "update"
                | "language"
                | "appearance"
                | "server_address"
        );
        if !allowed_signed_out && !self.is_logged_in() {
            self.push_notification(self.t("error_not_logged_in"));
            return false;
        }
        match name {
            "quit" | "exit" => {
                self.begin_quit_cleanup();
                false
            }
            "quit_group" => {
                self.quit_current_group();
                false
            }
            "mute" => {
                // /mute <bool>: turn message do-not-disturb on/off for the currently selected room and persist in preferences.json
                let argument = command_line
                    .strip_prefix("/mute")
                    .unwrap_or("")
                    .trim()
                    .to_lowercase();
                let enable_mute = match argument.as_str() {
                    "true" | "on" | "1" => true,
                    "false" | "off" | "0" => false,
                    _ => {
                        self.push_notification(self.t("error_mute_usage"));
                        return false;
                    }
                };
                let Some(selected_room) = self
                    .rooms_state
                    .selected()
                    .and_then(|index| self.rooms.get(index))
                    .cloned()
                else {
                    self.push_error(self.t("error_no_room_selected"));
                    return false;
                };
                if enable_mute {
                    self.muted_room_ids.insert(selected_room.id.clone());
                } else {
                    self.muted_room_ids.remove(&selected_room.id);
                }
                self.save_display_preferences();
                let state_text = if enable_mute {
                    self.t("mute_dnd_on")
                } else {
                    self.t("mute_dnd_off")
                };
                let room_name = selected_room
                    .name
                    .unwrap_or_else(|| self.t("private_chat_fallback"));
                self.push_notification(format!("{}: {}", room_name, state_text));
                false
            }
            "kick" => {
                let argument = command_line.strip_prefix("/kick").unwrap_or("!").trim();
                self.execute_kick(argument);
                false
            }
            "info" => {
                self.show_room_info();
                false
            }
            "language" => {
                // /language without arguments → open the language selection overlay; /language <language code> → switch directly
                let argument = command_line
                    .strip_prefix("/language")
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if argument.is_empty() {
                    self.displaying_overlay = DisplayingOverlay::LanguageSelect;
                    self.language_list_state.select(Some(0));
                    return false;
                }
                let languages = Self::get_available_languages();
                if !languages.iter().any(|language| language == &argument) {
                    self.push_error(self.t("error_no_languages"));
                    return false;
                }
                Self::save_language_preference(&argument);
                self.load_language(&argument);
                self.push_notification(
                    self.t("language_switched")
                        .replace("{lang}", &argument)
                        .to_string(),
                );
                false
            }
            "logout" => {
                self.logout();
                false
            }
            "server_address" => {
                let argument = command_line
                    .strip_prefix("/server_address")
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if argument.is_empty() {
                    // No parameter → open the server address settings overlay, pre-filling the current address for editing
                    self.input_collector
                        .server_address_state
                        .set_text(self.connector.base_url());
                    self.focus_index = 0;
                    self.displaying_overlay = DisplayingOverlay::ServerAddress;
                    return false;
                }
                // With a parameter, test and save directly
                let test_connector = Connector::new(&argument);
                match test_connector.greet() {
                    Ok(_) => {
                        self.connector.set_base_url(&argument);
                        self.save_server_address();
                        // After switching server, re-probe the version so online decisions match the new server
                        self.detect_and_apply_api_version();
                        self.push_notification(self.t("server_address_saved"));
                    }
                    Err(_) => {
                        self.push_notification(self.t("error_server_connect_failed"));
                    }
                }
                false
            }
            "add_member" => {
                let argument = command_line
                    .strip_prefix("/add_member")
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if argument.is_empty() {
                    self.push_notification(self.t("error_add_member_usage"));
                    return false;
                }
                // Get the currently selected room
                let Some(room_id) = self.selected_room_id() else {
                    self.push_error(self.t("error_no_room_selected"));
                    return false;
                };
                // Check if it is a group chat
                let room_is_group = self
                    .rooms
                    .iter()
                    .find(|room| room.id == room_id)
                    .map(|room| room.is_group)
                    .unwrap_or(false);
                if !room_is_group {
                    self.push_error(self.t("error_not_group"));
                    return false;
                }
                // Call the API to add a member
                let usernames = vec![argument];
                match self.connector.add_members(&room_id, &usernames) {
                    Ok(_) => {
                        self.push_notification(self.t("add_member_success"));
                    }
                    Err(e) => {
                        self.push_error(format!("{}: {e}", self.t("error_add_member_failed")));
                    }
                }
                false
            }
            "appearance" => {
                // /appearance without arguments → open the appearance selection overlay; /appearance <appearance name> → apply directly
                let argument = command_line
                    .strip_prefix("/appearance")
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if argument.is_empty() {
                    self.displaying_overlay = DisplayingOverlay::AppearanceSelect;
                    let names = Appearance::available_names();
                    if names.is_empty() {
                        self.push_error(self.t("error_no_appearances"));
                        self.displaying_overlay = DisplayingOverlay::Nothing;
                        return false;
                    }
                    let idx = names.iter().position(|name| name == &self.appearance_name);
                    self.appearance_list_state.select(idx.or(Some(0)));
                    return false;
                }
                if !Appearance::available_names()
                    .iter()
                    .any(|name| name == &argument)
                {
                    self.push_error(
                        self.t("error_appearance_not_found")
                            .replace("{name}", &argument)
                            .to_string(),
                    );
                    return false;
                }
                self.switch_appearance(&argument);
                false
            }
            "login" | "register" => {
                // Cases with arguments were already blocked at the submit entry (see handle_chat_submit), here only no-argument calls are received:
                // directly open the corresponding overlay for filling
                self.displaying_overlay = if name == "login" {
                    DisplayingOverlay::Login
                } else {
                    DisplayingOverlay::Register
                };
                self.focus_index = 0;
                false
            }
            "list_users" => {
                self.show_registered_users();
                false
            }
            "search_users" => {
                let argument = command_line
                    .strip_prefix("/search_users")
                    .unwrap_or("")
                    .trim()
                    .to_string();
                self.search_registered_users(&argument);
                false
            }
            "profile" => {
                // No argument shows yourself, with argument shows a specific user; the parameter can be a username or UID
                let argument = command_line
                    .strip_prefix("/profile")
                    .unwrap_or("")
                    .trim()
                    .to_string();
                self.show_profile_card(if argument.is_empty() {
                    None
                } else {
                    Some(&argument)
                });
                false
            }
            "update" => {
                self.start_downloaded_update();
                false
            }
            _ => false,
        }
    }

    /// Logout: stop background threads, clear persisted sessions and chat state, return to the login page to log in again
    fn logout(&mut self) {
        if let Some(running_flag) = self.websocket_running.take() {
            running_flag.store(false, Ordering::Relaxed);
        }
        if let Some(running_flag) = self.polling_running.take() {
            running_flag.store(false, Ordering::Relaxed);
        }
        self.websocket_sender = None;
        self.websocket_token = None;
        // Messages accumulated but not yet persisted are written out first; the cache is by user ID directory, can still be reused by next auto-login after logout
        if let Some(room_id) = self.selected_room_id() {
            let room_id = room_id.clone();
            self.cache_loaded_messages(&room_id);
        }
        self.cache_pending_flush_since = None;
        Self::clear_saved_session();
        self.current_user_id = None;
        self.current_username.clear();
        self.own_contact = None;
        self.sent_requests.clear();
        self.registered_users = None;
        self.profile_view = None;
        self.active_form = None;
        self.avatar_images.clear();
        self.avatar_pixels.clear();
        self.avatar_list_state = ListState::default();
        self.chat_cache = None;
        self.rooms.clear();
        self.rooms_state = ListState::default();
        self.messages.clear();
        self.sender_names.clear();
        self.crypto.sessions.clear();
        self.closed_room_ids.clear();
        self.left_room_ids.clear();
        self.typing_members.clear();
        self.last_typing_frame_sent_at = None;
        self.presence_by_user.clear();
        self.search_result = None;
        self.pending_scroll_message_id = None;
        self.notifications.clear();
        self.displaying_overlay = DisplayingOverlay::Nothing;
        self.focus_index = 0;
        // Clear the login/registration form and return to the logged-out chat page (showing the login prompt)
        self.input_collector.login_name_state = TextInputState::default();
        self.input_collector.login_password_state = TextInputState::default();
        self.input_collector.register_name_state = TextInputState::default();
        self.input_collector.register_email_state = TextInputState::default();
        self.input_collector.register_password_state = TextInputState::default();
    }

    // /quit exit cleanup: send encrypt_leave to all private chats first to prompt the server to clean up encryption sessions
    /// and let the online peer synchronize hiding the interface, wait 5 seconds then exit rooms one by one, notify exit via the event channel when done.
    /// The client cannot detect whether the peer is online, so it waits uniformly; when the peer is offline, it only manifests as a delayed exit.
    fn begin_quit_cleanup(&mut self) {
        if self.quit_ready {
            return;
        }
        // Before quitting, write the accumulated but not-yet-persisted messages into the local cache, avoiding content received in the last few seconds being lost in memory
        if let Some(room_id) = self.selected_room_id() {
            let room_id = room_id.clone();
            self.cache_loaded_messages(&room_id);
        }
        // Before quitting, persist the login session (JWT and corporate user ID, contact info only visible to oneself), for next auto-login
        if let (Some(token), Some(user_id)) =
            (self.websocket_token.clone(), self.current_user_id.clone())
        {
            Self::save_session_preferences(&token, &user_id, self.own_contact.as_ref());
        }
        let private_room_ids: Vec<String> = self
            .rooms
            .iter()
            .filter(|room| !room.is_group)
            .map(|room| room.id.clone())
            .collect();

        if private_room_ids.is_empty() {
            self.quit_ready = true;
            return;
        }

        // First request the server via WebSocket to clean up encryption sessions in each room (failure doesn't affect subsequent room exits)
        for room_id in &private_room_ids {
            self.send_ws_payload(outbound_ws_payload(
                self.connector.version(),
                WsCommand::EncryptLeave {
                    room_id: room_id.as_str(),
                },
            ));
        }
        self.push_notification(self.t("notification_cleanup_started"));

        let Some(event_sender) = self.polling_sender.clone() else {
            self.quit_ready = true;
            return;
        };
        let connector = self.connector.clone();
        let Some(user_id) = self.current_user_id.clone() else {
            self.quit_ready = true;
            return;
        };

        thread::spawn(move || {
            // Wait for the online peer to complete processing the end event and updating the interface
            thread::sleep(Duration::from_secs(5));
            for room_id in &private_room_ids {
                let _ = connector.remove_member(room_id, &user_id);
            }
            let _ = event_sender.send(PollingEvent::QuitCleanupFinished);
        });
    }

    // Main loop queries whether exit cleanup is complete
    // Take and reset the "full screen repaint" request: called once per frame by the main loop, when true executes terminal.clear().
    pub fn take_full_repaint_request(&mut self) -> bool {
        std::mem::take(&mut self.full_repaint_requested)
    }

    pub fn should_quit_now(&self) -> bool {
        self.quit_ready
    }

    /// Leave the currently selected chat (group or private): remove self, send encrypted goodbye and clean up local session
    fn quit_current_group(&mut self) {
        let Some(room_id) = self.selected_room_id() else {
            self.push_error(self.t("error_no_room_selected"));
            return;
        };
        let is_group = self
            .rooms_state
            .selected()
            .and_then(|index| self.rooms.get(index))
            .map(|room| room.is_group)
            .unwrap_or(false);
        if !is_group {
            // Before leaving a private chat, first request the server via WebSocket to clean up the encrypted session:
            // so the online peer receives the end event synchronously and closes the interface, then remove yourself to leave the room
            self.send_ws_payload(outbound_ws_payload(
                self.connector.version(),
                WsCommand::EncryptLeave {
                    room_id: room_id.as_str(),
                },
            ));
            self.crypto.sessions.remove(&room_id);
            self.closed_room_ids.insert(room_id.clone());
        }
        self.leave_room(&room_id);
    }

    /// Exit the specified room as the current user and refresh the room list; notify when identity is missing or request fails
    fn leave_room(&mut self, room_id: &str) {
        let Some(user_id) = self.current_user_id.clone() else {
            self.push_error(self.t("error_no_user_id"));
            return;
        };
        match self.connector.remove_member(room_id, &user_id) {
            Ok(_) => {
                // Record the voluntarily left room to avoid subsequent polling misreporting it as "removed from group"
                self.left_room_ids.insert(room_id.to_string());
                if self.selected_room_id().as_deref() == Some(room_id) {
                    self.messages.clear();
                }
                self.load_rooms();
                self.push_notification(self.t("left_chat"));
            }
            Err(e) => {
                // When the room has already been deleted by the server or the peer has left, no prompt is needed, silently complete the local refresh;
                // For private chat exits, sending encrypt_leave first has already prompted the server to remove the member, then remove_member will report "not a member"
                let error_text = format!("{e}");
                self.left_room_ids.insert(room_id.to_string());
                // The table of "room does not exist / not a member" expected-error judgments is given centrally by the seam by version
                let is_expected_gone = self
                    .connector
                    .version()
                    .is_ignorable_room_removal_error(&error_text);
                if !is_expected_gone {
                    self.push_error(format!("{}: {e}", self.t("exit_chat_failed")));
                }
                if self.selected_room_id().as_deref() == Some(room_id) {
                    self.messages.clear();
                }
                self.load_rooms();
            }
        }
    }

    /// Get the ID of the currently selected room
    fn selected_room_id(&self) -> Option<String> {
        self.rooms_state
            .selected()
            .and_then(|index| self.rooms.get(index))
            .map(|room| room.id.clone())
    }

    /// Get the user ID of the "other party" in a private chat room (the member who isn't yourself).
    /// Returns None for group chats which have no single peer, or when no other members exist in the room besides self; the caller doesn't display peer status accordingly.
    fn chat_peer_id_of(&self, room: &RoomInfo) -> Option<String> {
        if room.is_group {
            return None;
        }
        room.members
            .iter()
            .find(|member| Some(*member) != self.current_user_id.as_ref())
            .cloned()
    }

    // Unified fallback after overlay Esc/operation complete: all overlays enter from the settings menu,
    /// so all return to the settings menu, only the settings menu itself returns to the no-overlay state,
    /// ensuring Esc is a layered fallback rather than closing the entire interface at once.
    fn dismiss_overlay_back(&mut self) {
        self.displaying_overlay =
            if matches!(self.displaying_overlay, DisplayingOverlay::SettingsMenu) {
                DisplayingOverlay::Nothing
            } else {
                DisplayingOverlay::SettingsMenu
            };
        self.restore_chat_focus();
    }

    // Return focus to the message input box when returning to the chat page.
    /// During the overlay, focus_index refers to input items or list positions within the overlay,
    /// if not reset after closing the overlay, keyboard input would fall on a 0 that nobody holds, manifesting as "typing has no response".
    fn restore_chat_focus(&mut self) {
        if self.displaying_overlay == DisplayingOverlay::Nothing {
            self.focus_index = 8;
        }
    }

    /// Soft-close an encrypted private chat locally: only hide from the interface and clear the session,
    /// don't notify the server to exit the room, avoiding the peer seeing a single-person residual room after reconnecting
    fn close_local_room(&mut self, room_id: &str) {
        self.closed_room_ids.insert(room_id.to_string());
        self.crypto.sessions.remove(room_id);
        if let Some(cache) = &self.chat_cache {
            cache.forget_room(room_id);
        }
        let was_selected = self.selected_room_id().as_deref() == Some(room_id);
        self.rooms.retain(|room| room.id != room_id);
        if was_selected {
            self.messages.clear();
            if !self.rooms.is_empty() {
                self.rooms_state.select(Some(0));
                self.load_messages_for_selected_room();
            } else {
                self.rooms_state.select(None);
            }
        }
    }

    fn get_create_group_focused_state(&mut self) -> Option<&mut TextInputState> {
        match self.focus_index {
            0 => Some(&mut self.input_collector.create_group_name_state),
            1 => Some(&mut self.input_collector.create_group_members_state),
            _ => None,
        }
    }

    fn get_create_private_focused_state(&mut self) -> Option<&mut TextInputState> {
        match self.focus_index {
            0 => Some(&mut self.input_collector.create_private_username_state),
            _ => None,
        }
    }

    pub fn ui(&mut self, frame: &mut Frame) {
        // Leave the bottom row for the terminal to avoid any write triggering scroll (see drawable_area)
        let area = drawable_area(frame.area());

        // First paint a layer of appearance background color across the full screen: ratatui's components only "patch" their own styles
        // (Cell::set_style only writes Some fields), so painting the base first allows all not-explicitly-specified backgrounds to
        // text and blank areas uniformly inherit the application background color from the appearance.
        paint_background(frame, area, self.appearance.app_background);

        // The status bar is fixed at one row, the chat page, overlays, and notifications are drawn below it;
        // the row text snapshot is still collected from the full screen, text on the status bar can also be selected and copied
        let [bar_area, body_area] =
            Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(area);
        self.render_status_bar(frame, bar_area);

        // The application is always a single chat page: login/register becomes an overlay opened by command; when not logged in, the chat page shows a login prompt centered.
        self.render_chat_page(frame, body_area);

        match self.displaying_overlay {
            DisplayingOverlay::CreateGroup => self.render_create_group_modal(frame, body_area),
            DisplayingOverlay::CreatePrivate => self.render_create_private_modal(frame, body_area),
            DisplayingOverlay::PendingRequests => self.render_pending_requests(frame, body_area),
            DisplayingOverlay::SettingsMenu => self.render_settings_menu(frame, body_area),
            DisplayingOverlay::LanguageSelect => self.render_language_select(frame, body_area),
            DisplayingOverlay::ServerAddress => self.render_server_address(frame, body_area),
            DisplayingOverlay::Login => self.render_login_modal(frame, body_area),
            DisplayingOverlay::Register => self.render_register_modal(frame, body_area),
            DisplayingOverlay::AppearanceSelect => self.render_appearance_select(frame, body_area),
            DisplayingOverlay::ProfileCard => self.render_profile_card(frame, body_area),
            DisplayingOverlay::Form => self.render_form(frame, body_area),
            DisplayingOverlay::AvatarSelect => self.render_avatar_select(frame, body_area),
            DisplayingOverlay::Nothing => {}
        }

        // Before rendering, first remove expired notifications, then display remaining notifications in the top-right
        self.remove_expired_notifications();
        if !self.notifications.is_empty() {
            self.render_notifications(frame, body_area);
        }

        // After all elements are drawn, collect the full-screen row text snapshot, text can be copied from any position when selection is released
        self.screen_text_rows = collect_screen_text_rows(&*frame.buffer_mut(), area);

        // Draw the selection highlight last, ensuring it remains visible over overlays and notifications
        if let Some(selection_start) = self.input_collector.selection_start {
            let selection_end = self
                .input_collector
                .selection_end
                .unwrap_or(selection_start);
            paint_screen_selection(
                frame,
                area,
                selection_start,
                selection_end,
                &self.appearance,
            );
        }

        // Position the hardware cursor at the currently focused input field
        self.place_cursor(frame);
    }

    /// Position the terminal hardware cursor at the cursor of the currently focused input field;
    /// rat-text only returns a visible cursor position when the input field is marked as focused, so first set the focus flag
    fn place_cursor(&mut self, frame: &mut Frame) {
        let screen_area = drawable_area(frame.area());
        // Clamp to screen: once the cursor position falls outside the buffer (long text pushing caret past the last row, etc.):
        // the terminal will auto-scroll up one row due to out-of-bounds write, but the render buffer does not scroll with it, so the whole interface becomes misaligned and never recovers
        let clamp_position = |position: Position| {
            Position::new(
                position.x.min(screen_area.width.saturating_sub(1)),
                position.y.min(screen_area.height.saturating_sub(1)),
            )
        };
        // When on the chat page with no popup, focus the multi-line message input box, handled separately by TextAreaState
        if self.displaying_overlay == DisplayingOverlay::Nothing {
            self.input_collector.message_input_state.focus.set(true);
            if let Some((x, y)) = self.input_collector.message_input_state.screen_cursor() {
                frame.set_cursor_position(clamp_position(Position::new(x, y)));
            }
            return;
        }
        if let Some(state) = self.get_focused_state() {
            state.focus.set(true);
            if let Some((x, y)) = state.screen_cursor() {
                frame.set_cursor_position(clamp_position(Position::new(x, y)));
            }
        }
    }

    fn copy_message_selection(&mut self) {
        let cursor = self.input_collector.message_input_state.cursor();
        let selected = self.input_collector.message_input_state.selected_text();
        // only attempt to write to the system clipboard and show a prompt when actual non-empty text has been selected
        if !selected.is_empty()
            && let Ok(mut clipboard) = arboard::Clipboard::new()
            && clipboard.set_text(selected).is_ok()
        {
            self.push_notification(self.t("copied_to_clipboard"));
        }
        // cancel the selection after copying: move the anchor back to the cursor position, making the selection highlight disappear
        self.input_collector
            .message_input_state
            .set_cursor(cursor, false);
    }

    // Handle a bracketed paste: insert the entire text as-is into the currently focused input field,
    /// the message input box inserts by line (newlines stay as multi-line within the box, never trigger sending),
    /// other single-line input fields only take the first line of content.
    fn handle_pasted_text(&mut self, pasted_text: &str) {
        if pasted_text.is_empty() {
            return;
        }
        let pasted_text = normalize_pasted_text(pasted_text);
        if pasted_text.is_empty() {
            return;
        }
        let focus_on_message_box = self.displaying_overlay == DisplayingOverlay::Nothing;
        if focus_on_message_box {
            let mut lines = pasted_text.split('\n').peekable();
            while let Some(line) = lines.next() {
                self.input_collector.message_input_state.insert_str(line);
                if lines.peek().is_some() {
                    self.input_collector.message_input_state.insert_newline();
                }
            }
            self.handle_message_input_changed();
            return;
        }
        // Single-line input fields (login, register, create group, etc.) don't retain newlines, only take the first line of the pasted content and insert at the cursor
        let first_line = pasted_text.lines().next().unwrap_or_default();
        if let Some(state) = self.get_focused_state() {
            let insert_position = state.value.cursor();
            let _ = state.value.insert_str(insert_position, first_line);
        }
    }

    // Copy text from the full-screen selection rectangle to the system clipboard and clear the selection highlight.
    // Text is taken from the full-screen row text snapshot collected in the previous frame, so it can be copied from any position including overlays, notifications, room lists;
    // Split columns by display width, keep double-width characters as whole units; trailing spaces and fully-empty leading/trailing rows are removed.
    // Mouse handling for full-screen selection: start recording when the start point is outside the message input box, update the endpoint while dragging, copy on release.
    // Because this method is called before overlay dispatch, the room list, message area, status bar, any overlay and notification
    /// above them can all be selected and copied; the display area's border is not considered text (see `is_content_character`),
    /// neither highlighted nor enters the clipboard. Returning true means the event was consumed by the selection (drag and release).
    fn handle_screen_selection_mouse(&mut self, mouse: crossterm::event::MouseEvent) -> bool {
        let pointer = (mouse.column, mouse.row);
        match mouse.kind {
            MouseEventKind::Down(crossterm::event::MouseButton::Left)
                if !self
                    .message_input_area
                    .contains(ratatui::layout::Position::new(mouse.column, mouse.row)) =>
            {
                // Only record the starting point; the event continues with the original click-focus dispatch;
                // when start and end points coincide, it doesn't constitute a selection, releasing doesn't trigger copying
                self.input_collector.selection_start = Some(pointer);
                self.input_collector.selection_end = Some(pointer);
                false
            }
            MouseEventKind::Drag(crossterm::event::MouseButton::Left)
                if self.input_collector.selection_start.is_some() =>
            {
                self.input_collector.selection_end = Some(pointer);
                true
            }
            MouseEventKind::Up(crossterm::event::MouseButton::Left)
                if self.input_collector.selection_start.is_some() =>
            {
                let dragged = self
                    .input_collector
                    .selection_start
                    .is_some_and(|start| start != pointer);
                self.input_collector.selection_end = Some(pointer);
                if dragged {
                    self.copy_screen_selection();
                } else {
                    // pressed without dragging: only clear the selection start point, no copying, no prompt
                    self.input_collector.selection_start = None;
                    self.input_collector.selection_end = None;
                }
                true
            }
            _ => false,
        }
    }

    fn copy_screen_selection(&mut self) {
        let (selection_start, selection_end) = match (
            self.input_collector.selection_start,
            self.input_collector.selection_end,
        ) {
            (Some(start), Some(end)) => (start, end),
            _ => {
                self.input_collector.selection_start = None;
                self.input_collector.selection_end = None;
                return;
            }
        };
        let selected_text =
            extract_selected_screen_text(&self.screen_text_rows, selection_start, selection_end);

        self.input_collector.selection_start = None;
        self.input_collector.selection_end = None;
        if selected_text.is_empty() {
            return;
        }
        if let Ok(mut clipboard) = arboard::Clipboard::new()
            && clipboard.set_text(selected_text).is_ok()
        {
            self.push_notification(self.t("copied_to_clipboard"));
        }
    }

    /// Clear the overlay area and immediately repaint the application background color in that area.
    /// Clear resets the cell styles in the area, without this layer the inside of the overlay would show the terminal's default background color, inconsistent with the theme.
    fn clear_overlay_area(&self, frame: &mut Frame, area: Rect) {
        frame.render_widget(Clear, area);
        paint_background(frame, area, self.appearance.app_background);
    }

    // Render the status bar: connection status and current user on the left, server version and client version on the right.
    /// The connection marker also serves as a persistent prompt for "can't reach the server" (errors only pop once on status change),
    /// when not logged in the current user isn't shown, when the server isn't reached the server version isn't shown.
    fn render_status_bar(&self, frame: &mut Frame, area: Rect) {
        if area.width == 0 || area.height == 0 {
            return;
        }
        let online = self.connection_ready.unwrap_or(false);
        let (connection_label, mark, user_text, right_text) = self.status_bar_texts();
        // First concatenate the pure text of the left segment to measure width (the following split decides who yields based on the actual widths of both segments)
        let left_plain_text = format!("{connection_label} {mark}{user_text}");
        // The marker is placed right after "connection" and colored separately: if the username is long and pushes the dot to the end of the row,
        // it can't represent the connection state anymore, so here it's fixed to concatenate in the order of "label marker user_segment"
        let left_line = Line::from(vec![
            Span::styled(
                format!("{connection_label} "),
                hint_style(self.appearance.hint_text),
            ),
            Span::styled(
                mark,
                Style::default()
                    .fg(if online {
                        self.appearance.own_username_text
                    } else {
                        self.appearance.notice_error_border
                    })
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(user_text, hint_style(self.appearance.hint_text)),
        ]);
        let right_line = Line::from(Span::styled(
            right_text.clone(),
            hint_style(self.appearance.hint_text),
        ));
        // When one row can't fit both segments, prioritize the left side: the connection marker and "current user" represent whether it's usable now and
        // what identity it's using, version info is just a reference. Previously sizing by the right side would squeeze the entire username off on narrow terminals.
        let left_width = display_width(&left_plain_text);
        let right_width = display_width(&right_text) + 1;
        let left_reserve = if left_width + right_width <= area.width {
            area.width.saturating_sub(right_width)
        } else {
            left_width.min(area.width)
        };
        let [left_area, right_area] =
            Layout::horizontal([Constraint::Length(left_reserve), Constraint::Fill(1)]).areas(area);
        frame.render_widget(
            Paragraph::new(left_line).style(Style::default().bg(self.appearance.app_background)),
            left_area,
        );
        frame.render_widget(
            Paragraph::new(right_line)
                .alignment(Alignment::Right)
                .style(Style::default().bg(self.appearance.app_background)),
            right_area,
        );
    }

    // Four-segment status bar text: (connection label, connection marker, current user segment, right version info).
    // Splitting into four segments is to place the marker between "connection" and the username and color it separately,
    /// also makes it easy to assert display rules in the absence of a real server:
    /// when not logged in the username isn't shown, when not connected to the server the server version isn't shown, the client version is always shown.
    fn status_bar_texts(&self) -> (String, String, String, String) {
        let online = self.connection_ready.unwrap_or(false);
        let mark = if online { "●" } else { "○" };
        let mut user_text = String::new();
        if self.is_logged_in() && !self.current_username.is_empty() {
            user_text = format!(
                "  |  {} {}",
                self.t("bar_current_user"),
                self.current_username
            );
        }
        let server_version = self.connector.server_version_text();
        let mut right_parts: Vec<String> = Vec::new();
        if online && !server_version.is_empty() {
            right_parts.push(format!(
                "{}: {server_version}",
                self.t("bar_server_version")
            ));
        }
        right_parts.push(format!(
            "{}: {}",
            self.t("bar_client_version"),
            Self::client_version()
        ));
        (
            self.t("bar_connection"),
            mark.to_string(),
            user_text,
            right_parts.join("  |  "),
        )
    }

    // Render the general form overlay: one field per row in the title, label on the left, input box on the right, Enter on the last item to submit.
    // The four form types (profile, change password, change avatar, delete account) have different field counts,
    // panel height is calculated by field count, label column width is based on the widest label in the current language, avoiding horizontal scrolling or truncation.
    // Render the generic form overlay. The window style is consistent with other overlays (same overlay_border).
    /// When there are three or more input items, use the arrow row `> label content` (nickname/phone/bio, old password/new password/confirm);
    /// For one or two items (change avatar, delete account), keep the original box input.
    fn render_form(&mut self, frame: &mut Frame, area: Rect) {
        // First take the content that needs to read self as owned values, the render period needs mutable borrow of form field states
        let Some((action, fields)) = &self.active_form else {
            return;
        };
        let field_count = fields.len();
        let secret_flags: Vec<bool> = fields.iter().map(|field| field.secret).collect();
        let labels: Vec<String> = fields
            .iter()
            .map(|field| self.t(&field.label_key))
            .collect();
        let title = self.t(&form_definition(action).0);
        let hint = self.t(&form_hint_key(action));
        let appearance = self.appearance.clone();
        let focused = self.focus_index;
        // Three or more entries use the arrow row: one item per row, saving half the height compared to three boxes stacked
        let arrow_rows = field_count >= 3;
        // First fix the panel width (clamped to the screen), hint wrapping and panel height are both calculated based on this width
        let panel_width = 60u16
            .min(area.width.saturating_sub(2))
            .max(30)
            .min(area.width.max(1));
        let hint_text = wrapped_hint_text(
            &hint,
            hint_style(appearance.hint_text),
            panel_width.saturating_sub(4),
        );
        let hint_lines = hint_text.lines.len().max(1) as u16;
        let needed_height = if arrow_rows {
            field_count as u16 + 3 + hint_lines
        } else {
            field_count as u16 * 4 + 3 + hint_lines
        };
        let panel_height = needed_height
            .min(area.height.saturating_sub(2))
            .max(if arrow_rows { 6 } else { 8 });
        let panel_rect = centered_rect(panel_width, panel_height, area);
        self.clear_overlay_area(frame, panel_rect);
        frame.render_widget(overlay_frame_block(&appearance, &title), panel_rect);

        let inner = panel_rect.inner(Margin {
            vertical: 1,
            horizontal: 2,
        });
        if arrow_rows {
            self.render_arrow_form_rows(frame, &labels, &secret_flags, inner, hint_text);
            return;
        }
        // Box form: each input box takes three rows, one blank row between boxes, last row for the prompt
        let rows = Layout::vertical(
            (0..field_count)
                .map(|_| Constraint::Length(3))
                .chain(std::iter::once(Constraint::Length(hint_lines)))
                .chain(std::iter::once(Constraint::Min(0)))
                .collect::<Vec<Constraint>>(),
        )
        .split(inner);
        for index in 0..field_count {
            // Same caliber as arrow row style: current item uses body text color bold, the rest use hint color, neither touches the selection color
            let field_style = if index == focused {
                Style::default()
                    .fg(appearance.input_text)
                    .add_modifier(Modifier::BOLD)
            } else {
                hint_style(appearance.hint_text)
            };
            render_box_field(
                &appearance,
                frame,
                rows[index],
                Line::from(Span::styled(format!(" {} ", labels[index]), field_style)),
                appearance.form_field_border(),
                secret_flags[index],
                &mut self
                    .active_form
                    .as_mut()
                    .expect("表单浮层显示期间表单必定存在")
                    .1[index]
                    .state,
            );
        }
        if let Some(hint_row) = rows.get(field_count) {
            frame.render_widget(
                Paragraph::new(hint_text).style(Style::default().bg(appearance.app_background)),
                *hint_row,
            );
        }
    }

    /// Arrow-row form body: left side `> label` (current item bold in selection color, rest in prompt color),
    /// right side same row is the borderless input area. Up/down arrow keys and Tab are all used to switch the current item.
    fn render_arrow_form_rows(
        &mut self,
        frame: &mut Frame,
        labels: &[String],
        secret_flags: &[bool],
        inner: Rect,
        hint: Text<'static>,
    ) {
        let appearance = self.appearance.clone();
        let field_count = labels.len();
        let hint_lines = hint.lines.len().max(1) as u16;
        let rows = Layout::vertical(
            (0..field_count)
                .map(|_| Constraint::Length(1))
                .chain(std::iter::once(Constraint::Length(hint_lines)))
                .chain(std::iter::once(Constraint::Min(0)))
                .collect::<Vec<Constraint>>(),
        )
        .split(inner);
        let label_width = labels
            .iter()
            .map(|label| display_width(label))
            .max()
            .unwrap_or(0)
            .saturating_add(4)
            .min(inner.width.saturating_sub(6))
            .max(6);
        for index in 0..field_count {
            let [label_area, input_area] =
                Layout::horizontal([Constraint::Length(label_width), Constraint::Fill(1)])
                    .areas(rows[index]);
            let is_focused = self.focus_index == index;
            let marker = if is_focused { ">" } else { " " };
            // Current item bold in input text color, rest in prompt color; do not use "selected text color"
            let label_style = if is_focused {
                Style::default()
                    .fg(appearance.input_text)
                    .add_modifier(Modifier::BOLD)
            } else {
                hint_style(appearance.hint_text)
            };
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    format!("{marker} {}", labels[index]),
                    label_style,
                )))
                .style(Style::default().bg(appearance.app_background)),
                label_area,
            );
            render_plain_field(
                &appearance,
                frame,
                input_area,
                secret_flags[index],
                &mut self
                    .active_form
                    .as_mut()
                    .expect("表单浮层显示期间表单必定存在")
                    .1[index]
                    .state,
            );
        }
        if let Some(hint_row) = rows.get(field_count) {
            frame.render_widget(
                Paragraph::new(hint).style(Style::default().bg(appearance.app_background)),
                *hint_row,
            );
        }
    }

    // Render the profile card: left side avatar block (drawn in true color with half-character), right side sequentially is
    // real name, nickname (if none, the whole row is hidden), UID, online status, email, phone, bio, avatar;
    /// the last four show "none" when they have no value. If the avatar is a relative path obtained from server upload, display it as "Local" per spec.
    /// Email and phone only have values when looking at yourself and the login response provided them — other users' profile APIs do not return these two fields.
    fn render_profile_card(&mut self, frame: &mut Frame, area: Rect) {
        let Some(profile) = self.profile_view.clone() else {
            return;
        };
        let max_avatar_columns = profile_avatar_cells().0;
        let title = self.t("profile_title");
        let none_text = self.t("profile_none");
        let is_self = Some(profile.id.as_str()) == self.current_user_id.as_deref();
        let online_label = match self.presence_by_user.get(&profile.id).copied() {
            Some(true) => self.t("presence_online"),
            Some(false) => self.t("presence_offline"),
            None => self.t("presence_unknown"),
        };
        // Email and phone are only available when "looking at yourself and login response provided them"; all others are treated as "none"
        let (email, phone_number) = match (&self.own_contact, is_self) {
            (Some(contact), true) => (contact.0.clone(), contact.1.clone()),
            _ => (String::new(), String::new()),
        };
        let value_or_none = |value: String| {
            if value.is_empty() {
                none_text.clone()
            } else {
                value
            }
        };
        let avatar_text = match profile.avatar.clone() {
            None => none_text.clone(),
            Some(path) if path.is_empty() => none_text.clone(),
            // The server stores uploaded avatars as relative paths like /static/avatars/xxx.png
            Some(path) if path.starts_with('/') => self.t("profile_avatar_local"),
            Some(path) => path,
        };
        let mut body_lines = vec![Line::from(Span::styled(
            profile.username.clone(),
            Style::default()
                .fg(self.appearance.own_username_text)
                .add_modifier(Modifier::BOLD),
        ))];
        if let Some(nickname) = profile.nickname.clone().filter(|value| !value.is_empty()) {
            body_lines.push(Line::from(format!(
                "{}: {nickname}",
                self.t("profile_nickname_label")
            )));
        }
        for (label, value) in [
            (self.t("profile_uid"), profile.id.clone()),
            (self.t("presence_state"), online_label),
            (self.t("profile_email_label"), value_or_none(email)),
            (self.t("profile_phone_label"), value_or_none(phone_number)),
            (
                self.t("profile_bio_label"),
                value_or_none(profile.bio.clone().unwrap_or_default()),
            ),
            (self.t("profile_avatar_url"), avatar_text),
        ] {
            body_lines.push(Line::from(format!("{label}: {value}")));
        }
        body_lines.push(Line::from(""));
        body_lines.push(Line::from(Span::styled(
            self.t("profile_close_hint"),
            hint_style(self.appearance.hint_text),
        )));
        let body = Text::from(body_lines);

        // Panel width can only be compressed within the screen; then body text wraps by available width:
        // Previously a fixed 40-column minimum with no wrapping, so long single lines like UID, email, and avatar links were cut off by the right boundary on narrow terminals
        let appearance = self.appearance.clone();
        let screen_width = area.width.saturating_sub(2);
        // The panel width minimum must fit "full avatar + one column of text": otherwise if nickname/bio is short,
        // the panel gets narrower and the avatar is downgraded to a very small block (long text is unaffected)
        let text_minimum = 24u16;
        let width_floor = (max_avatar_columns as u16 + 5 + text_minimum + 4)
            .min(screen_width.max(1))
            .max(24u16.min(screen_width.max(1)));
        let panel_width = (body.width() as u16 + 4).clamp(width_floor, screen_width.max(1));
        // Avatar column takes at most half the panel, and must satisfy "columns = 2×rows": downgrade the whole thing on narrow panels, do not squash round faces into vertical strips
        let (avatar_columns, avatar_rows) = avatar_grid_within(
            (panel_width / 2).max(2),
            area.height.saturating_sub(4).max(1),
        );
        let avatar_columns = avatar_columns as usize;
        let pixels = self.avatar_pixels_at(&profile.id, avatar_columns, avatar_rows as usize);
        let body_text_width = panel_width.saturating_sub(avatar_columns as u16 + 5).max(8);
        let body = wrap_profile_fields(body, body_text_width);
        let body_height: u16 = body
            .lines
            .iter()
            .map(|line| (line.width() as u16).div_ceil(body_text_width).max(1))
            .sum();
        let panel_height = (body_height.max(avatar_rows) + 4)
            .min(area.height.saturating_sub(2))
            .max(8);
        let panel_rect = centered_rect(panel_width, panel_height, area);
        self.clear_overlay_area(frame, panel_rect);
        frame.render_widget(overlay_frame_block(&appearance, &title), panel_rect);
        let inner = panel_rect.inner(Margin {
            horizontal: 2,
            vertical: 1,
        });
        let [picture_area, text_area] = Layout::horizontal([
            Constraint::Length(avatar_columns as u16 + 1),
            Constraint::Fill(1),
        ])
        .areas(inner);
        // Draw the image according to the grid's own row count; extra height is left for below (filling inner would distort the ratio again)
        let picture_area = Rect::new(
            picture_area.x,
            picture_area.y,
            avatar_columns as u16,
            avatar_rows,
        );
        // Avatar placeholder and real image share the same area: once the image arrives it just fills this area, and the text position to the right does not move
        match pixels {
            Some(pixels) => pixels.paint(frame, picture_area, appearance.app_background),
            None => paint_avatar_placeholder(
                frame,
                picture_area,
                &profile.username,
                &appearance,
                &profile.id,
            ),
        }
        frame.render_widget(
            Paragraph::new(body).style(Style::default().bg(appearance.app_background)),
            text_area,
        );
    }

    /// Center-render the login overlay: username and password (masked with asterisks) input boxes.
    /// The overlay keeps only the input box and submit; Tab/Enter/Esc are universal keys, so per the shortcut prompt spec they no longer get their own prompt line.
    fn render_login_modal(&mut self, frame: &mut Frame, area: Rect) {
        let panel_rect = centered_rect(
            50u16.min(area.width.saturating_sub(4)).max(30),
            11u16.min(area.height.saturating_sub(4)).max(9),
            area,
        );
        self.clear_overlay_area(frame, panel_rect);
        let inner = panel_rect.inner(Margin {
            vertical: 1,
            horizontal: 2,
        });
        let name_rect = Rect::new(inner.x, inner.y, inner.width, 3);
        let password_rect = Rect::new(inner.x, inner.y + 4, inner.width, 3);
        let appearance = self.appearance.clone();
        render_box_field(
            &appearance,
            frame,
            name_rect,
            Line::from(Span::raw(self.t("label_username"))),
            appearance.login_field_border(self.focus_index == 0),
            false,
            &mut self.input_collector.login_name_state,
        );
        render_box_field(
            &appearance,
            frame,
            password_rect,
            Line::from(Span::raw(self.t("label_password"))),
            appearance.login_field_border(self.focus_index == 1),
            true,
            &mut self.input_collector.login_password_state,
        );
        let title = self.t("page_login");
        frame.render_widget(overlay_frame_block(&appearance, &title), panel_rect);
    }

    /// Center-render the registration overlay: username, email, password (masked with asterisks) input boxes.
    /// Same as login overlay, Tab/Enter/Esc are universal keys and need no prompt, so remove the bottom prompt line and narrow the panel.
    fn render_register_modal(&mut self, frame: &mut Frame, area: Rect) {
        let panel_rect = centered_rect(50, 14, area);
        self.clear_overlay_area(frame, panel_rect);

        // Input box body text color comes from the appearance
        let input_text_style = Style::default().fg(self.appearance.input_text);
        let block = Block::default()
            .title(format!(" {} ", self.t("page_register")))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.appearance.overlay_border));
        let inner = panel_rect.inner(ratatui::layout::Margin {
            vertical: 1,
            horizontal: 2,
        });

        let focus_style = Style::default()
            .fg(self.appearance.selected_text)
            .add_modifier(Modifier::BOLD);
        let selection_style = Style::default()
            .fg(contrasting_foreground(self.appearance.selection_background))
            .bg(self.appearance.selection_background);

        let name_block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" {} ", self.t("label_username")))
            .border_style(if self.focus_index == 0 {
                focus_style
            } else {
                Style::default().fg(self.appearance.input_border)
            });
        let email_block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" {} ", self.t("label_email")))
            .border_style(if self.focus_index == 1 {
                focus_style
            } else {
                Style::default().fg(self.appearance.input_border)
            });
        let pwd_block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" {} ", self.t("label_password")))
            .border_style(if self.focus_index == 2 {
                focus_style
            } else {
                Style::default().fg(self.appearance.input_border)
            });

        TextInput::new()
            .style(input_text_style)
            .block(name_block)
            .focus_style(focus_style)
            .select_style(selection_style)
            .render(
                Rect::new(inner.x, inner.y, inner.width, 3),
                frame.buffer_mut(),
                &mut self.input_collector.register_name_state,
            );
        TextInput::new()
            .style(input_text_style)
            .block(email_block)
            .focus_style(focus_style)
            .select_style(selection_style)
            .render(
                Rect::new(inner.x, inner.y + 4, inner.width, 3),
                frame.buffer_mut(),
                &mut self.input_collector.register_email_state,
            );
        TextInput::new()
            .style(input_text_style)
            .block(pwd_block)
            .focus_style(focus_style)
            .select_style(selection_style)
            .passwd()
            .render(
                Rect::new(inner.x, inner.y + 8, inner.width, 3),
                frame.buffer_mut(),
                &mut self.input_collector.register_password_state,
            );

        frame.render_widget(block, panel_rect);
    }

    fn render_chat_page(&mut self, frame: &mut Frame, area: Rect) {
        let chunks = Layout::horizontal([Constraint::Percentage(30), Constraint::Percentage(70)])
            .split(area);

        // When logged out, the chat window displays normally (not obscured), only prompting login/registration via a one-time popup:
        // and reject unauthenticated calls at all protected operation entry points.
        self.render_room_list(frame, chunks[0]);
        self.render_chat_area(frame, chunks[1]);
    }

    fn render_room_list(&mut self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .title(format!(" {} ", self.t("rooms")))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.appearance.room_border));

        let items: Vec<ListItem> = self
            .rooms
            .iter()
            .enumerate()
            .map(|(i, room)| {
                let name = room
                    .name
                    .clone()
                    .unwrap_or_else(|| self.t("private_chat_fallback"));
                let style = if self.rooms_state.selected() == Some(i) {
                    Style::default()
                        .fg(self.appearance.selected_text)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(self.appearance.message_text)
                };
                // If a non-selected room has unread messages, append red (count) after the name
                let unread = if self.rooms_state.selected() == Some(i) {
                    0
                } else {
                    self.unread_counts.get(&room.id).copied().unwrap_or(0)
                };
                let mut spans = vec![Span::styled(name, style)];
                // Private chat annotates the peer's online status after the name: solid dot = online, hollow dot = offline,
                // do not annotate when the server has never broadcast that member (no online roster baseline), to avoid displaying the unknown as offline
                if let Some(peer_id) = self.chat_peer_id_of(room) {
                    let presence_mark = match self.presence_by_user.get(&peer_id) {
                        Some(true) => {
                            Some(("●", Style::default().fg(self.appearance.own_username_text)))
                        }
                        Some(false) => Some(("○", Style::default().fg(self.appearance.hint_text))),
                        None => None,
                    };
                    if let Some((mark, mark_style)) = presence_mark {
                        spans.push(Span::styled(format!(" {mark}"), mark_style));
                    }
                }
                if unread > 0 {
                    // Do-not-disturb rooms always show unread count as a dot (·); all others show the specific count (99+ above 99)
                    let suffix = if self.muted_room_ids.contains(&room.id) {
                        "(·)".to_string()
                    } else if unread > 99 {
                        "(99+)".to_string()
                    } else {
                        format!("({})", unread)
                    };
                    spans.push(Span::styled(
                        suffix,
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ));
                }
                ListItem::new(Line::from(spans))
            })
            .collect();

        let list = List::new(items)
            .block(block)
            .highlight_style(
                Style::default()
                    .fg(self.appearance.selected_text)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("► ");

        frame.render_stateful_widget(list, area, &mut self.rooms_state);
    }

    fn render_chat_area(&mut self, frame: &mut Frame, area: Rect) {
        let chunks = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(5),
            Constraint::Length(3),
        ])
        .split(area);

        self.render_messages(frame, chunks[0]);
        self.render_message_input(frame, chunks[1]);

        // When input starts with /, show the command auto-completion panel above the input box
        let input_text = self.input_collector.message_input_state.text();
        if let Some(command_prefix) = input_text.strip_prefix('/') {
            self.render_command_completions(frame, chunks[1], command_prefix);
        }

        // Shortcut prompts switch with input mode: modifier combinations must be prompted; Tab/Enter/Esc as universal keys are no longer prompted
        let hint_key = if input_text.starts_with('#') {
            "search_hint"
        } else if input_text.starts_with('/') {
            "command_hint"
        } else {
            "message_hint"
        };
        let hint = Paragraph::new(Text::raw(self.t(hint_key)))
            .alignment(Alignment::Center)
            .style(Style::default().fg(self.appearance.hint_text));
        frame.render_widget(hint, chunks[2]);
    }

    /// Render the command completion list above the input box; arrow keys to select, Enter to insert the selected item
    fn render_command_completions(
        &mut self,
        frame: &mut Frame,
        input_area: Rect,
        raw_prefix: &str,
    ) {
        let candidates = self.completion_candidates(raw_prefix);
        if candidates.is_empty() {
            return;
        }
        if self
            .command_list_state
            .selected()
            .is_none_or(|index| index >= candidates.len())
        {
            self.command_list_state.select(Some(0));
        }
        // Parameter completion lists for members/languages/appearance may be long; allow taller panels; command name completion stays compact
        let max_height = if raw_prefix.starts_with("kick ")
            || raw_prefix.starts_with("language ")
            || raw_prefix.starts_with("appearance ")
            || raw_prefix.starts_with("profile ")
        {
            12
        } else {
            7
        };
        let popup_width = input_area.width.saturating_sub(2);
        // 2 columns for border + 2 columns for highlight symbol
        let body_width = popup_width.saturating_sub(6).max(1);
        let candidate_lines: Vec<Vec<Line<'static>>> = candidates
            .iter()
            .map(|(_, label, description)| {
                completion_lines(
                    label,
                    description,
                    Style::default().fg(self.appearance.selected_text),
                    Style::default().fg(self.appearance.hint_text),
                    body_width,
                )
            })
            .collect();
        let total_lines: u16 = candidate_lines.iter().map(|lines| lines.len() as u16).sum();
        let popup_height = (total_lines + 2).min(max_height);
        let popup_y = input_area.y.saturating_sub(popup_height);
        let popup_rect = Rect::new(input_area.x + 1, popup_y, popup_width, popup_height);

        let items: Vec<ListItem> = candidate_lines.into_iter().map(ListItem::new).collect();

        let title_key = if raw_prefix.starts_with("kick ") {
            "member_select_title"
        } else if raw_prefix.starts_with("language ") {
            "select_language_title"
        } else if raw_prefix.starts_with("appearance ") {
            "appearance_select_title"
        } else if raw_prefix.starts_with("profile ") || raw_prefix.starts_with("search_users ") {
            "user_select_title"
        } else {
            "command_list"
        };
        let popup_block = Block::default()
            .title(format!(" {} ", self.t(title_key)))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.appearance.command_border));
        let list = List::new(items)
            .highlight_style(
                Style::default()
                    .fg(self.appearance.selected_text)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("► ");
        // The buffer is layered rendering; first clear the panel area to prevent lower-layer text from showing through
        self.clear_overlay_area(frame, popup_rect);
        frame.render_widget(popup_block, popup_rect);
        frame.render_stateful_widget(
            list,
            popup_rect.inner(ratatui::layout::Margin {
                vertical: 1,
                horizontal: 1,
            }),
            &mut self.command_list_state,
        );
    }

    /// Render the message display area: pre-wrap by display width, scrollbar on the right, wheel-follow and stick-to-bottom driven by reverse scroll offset
    fn render_messages(&mut self, frame: &mut Frame, area: Rect) {
        let mut title_spans: Vec<Span> = match self
            .rooms_state
            .selected()
            .and_then(|index| self.rooms.get(index))
        {
            Some(room) => {
                let name = room
                    .name
                    .clone()
                    .unwrap_or_else(|| self.t("private_chat_fallback"));
                vec![Span::raw(format!(" {} ({}) ", name, room.members.len()))]
            }
            None => vec![Span::raw(format!(" {} ", self.t("chat_history")))],
        };
        // Typing indicator: append member names within the 2-second decay window of this room to the message area title bar,
        // Doesn't occupy a message line nor interrupt reading (the client only shows input status in this one place on the title bar)
        let selected_room_id = self.selected_room_id();
        let mut typing_names: Vec<String> = Vec::new();
        for (room_id, username, _) in &self.typing_members {
            if Some(room_id) != selected_room_id.as_ref() {
                continue;
            }
            // members with the same name (duplicate records from multiple accounts or reconnects) are shown only once,
            // otherwise the title would show two identical names first, then revert to one after one expires
            if !typing_names.contains(username) {
                typing_names.push(username.clone());
            }
        }
        if !typing_names.is_empty() {
            let typing_text = if typing_names.len() == 1 {
                self.t("typing_one").replace("{username}", &typing_names[0])
            } else {
                self.t("typing_multiple")
                    .replace("{names}", &typing_names.join(", "))
            };
            title_spans.push(Span::styled(
                typing_text,
                Style::default().fg(self.appearance.hint_text),
            ));
        }

        let block = Block::default()
            .title(Line::from(title_spans))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.appearance.message_border));

        let inner = area.inner(ratatui::layout::Margin {
            vertical: 1,
            horizontal: 1,
        });
        // Leave a column on the right for drawing the scrollbar
        let text_width = inner.width.saturating_sub(1).max(1);
        let scroll_area = Rect {
            x: inner.x + inner.width.saturating_sub(1),
            y: inner.y,
            width: 1,
            height: inner.height,
        };

        let (lines, message_first_lines) = self.build_message_lines(text_width);
        let total_lines = lines.len() as u16;
        let visible_height = inner.height.max(1);
        let max_scroll_y = total_lines.saturating_sub(visible_height);

        // When switching match items in search mode, scroll the matched message into view: align to top with one row of margin, then clamp to the scrollable range.
        // The index of a message in the list may change due to "earlier message" prepending, so locate by message ID rather than a cached index.
        let mut scrolled_to_match = false;
        if let Some(target_id) = self.pending_scroll_message_id.take() {
            let target_index = self
                .messages
                .iter()
                .position(|message| message.id == target_id);
            if let Some(Some(first_line)) =
                target_index.map(|index| message_first_lines.get(index).copied())
            {
                let desired_scroll_y =
                    (first_line.saturating_sub(1)).min(usize::from(max_scroll_y));
                self.messages_scroll_from_bottom = max_scroll_y - desired_scroll_y as u16;
                scrolled_to_match = true;
            }
        }
        // Clamp the reverse offset to the scrollable range and write back; 0 means stick to bottom following the latest message
        self.messages_scroll_from_bottom = self.messages_scroll_from_bottom.min(max_scroll_y);
        let scroll_y = max_scroll_y - self.messages_scroll_from_bottom;

        // When the user scrolls to the top of the message display area (offset leaves the bottom and has reached the maximum scrollable position) and the server still has earlier messages,
        // automatically fetch a batch; after prepending, the increased total row count moves scroll_y away from the top, naturally avoiding per-frame repeated fetching.
        // Guard: the message list must belong to the currently selected room (when room-switch loading is incomplete/failed, the list and selection may be misaligned):
        // preventing using the residual offset and cursor of an old room to erroneously fetch earlier history from another room; do not fetch when a match item was just positioned this frame,
        // otherwise prepending shifts all row numbers and the positioning result is washed out
        let selected_room_id = self.selected_room_id();
        let list_matches_room = self
            .messages
            .last()
            .is_some_and(|message| Some(&message.room_id) == selected_room_id.as_ref());
        if self.messages_scroll_from_bottom > 0
            && scroll_y == 0
            && list_matches_room
            && !scrolled_to_match
        {
            debug_log(&format!(
                "触顶自动拉取 room={selected_room_id:?} offset={}",
                self.messages_scroll_from_bottom
            ));
            self.load_older_messages();
        }

        let paragraph = Paragraph::new(Text::from(lines)).scroll((scroll_y, 0));
        let paragraph_area = Rect {
            width: inner.width.saturating_sub(1),
            ..inner
        };
        frame.render_widget(paragraph, paragraph_area);

        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            .track_symbol(None);
        let mut scrollbar_state =
            ScrollbarState::new(max_scroll_y as usize).position(scroll_y as usize);
        frame.render_stateful_widget(scrollbar, scroll_area, &mut scrollbar_state);

        frame.render_widget(block, area);
    }

    // Build the render rows for the message display area.
    // Returns (list of render rows, row index of first line for each message in the list); the message order of the two vectors corresponds one-to-one;
    /// The row indices are used by search mode to scroll matched messages into view (only here can the real row number after wrapping be computed).
    /// When in search mode and the keyword is active, matched fragments use the search-match background color from the appearance.
    fn build_message_lines(&self, text_width: u16) -> (Vec<Line<'static>>, Vec<usize>) {
        let current_user_id = self.current_user_id.as_deref().unwrap_or("");
        let keyword = self.active_search_keyword();
        // The currently positioned match item: the matched message uses another background color, distinguishing it from other matched areas
        let current_match_message_id: Option<String> = keyword.as_ref().and_then(|_| {
            self.search_result
                .as_ref()
                .and_then(|(_, matched, selected)| matched.get(*selected).cloned())
        });
        let body_style = Style::default().fg(self.appearance.message_text);
        let match_style = Style::default()
            .fg(contrasting_foreground(
                self.appearance.search_match_background,
            ))
            .bg(self.appearance.search_match_background);
        let current_match_style = Style::default()
            .fg(contrasting_foreground(
                self.appearance.search_current_match_background,
            ))
            .bg(self.appearance.search_current_match_background);
        let mut lines: Vec<Line> = Vec::new();
        let mut message_first_lines: Vec<usize> = Vec::new();
        let mut last_time_key: Option<String> = None;
        for message in &self.messages {
            // Time header: hide if same minute as the previous message; insert a centered time bar only when crossing a minute boundary
            if let Some(time_text) = format_message_time(&message.created_at, self.time_with_date)
                && last_time_key.as_deref() != Some(time_text.as_str())
            {
                lines.push(
                    Line::from(Span::styled(
                        time_text.clone(),
                        Style::default().fg(self.appearance.time_text),
                    ))
                    .alignment(Alignment::Center),
                );
                last_time_key = Some(time_text);
            }
            let is_own = message.sender_id == current_user_id;
            let sender_name = if is_own {
                self.t("self_name").to_string()
            } else {
                self.sender_display_name(&message.sender_id)
            };
            // A speaker whose account was deleted has no ID to display; only show "unknown user"
            let display_sender = if self.show_uid && !sender_name.is_empty() {
                format!("{} ({})", sender_name, message.sender_id)
            } else {
                sender_name
            };
            let name_style = if is_own {
                Style::default()
                    .fg(self.appearance.own_username_text)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(self.appearance.other_username_text)
            };
            let alignment = if is_own {
                Alignment::Right
            } else {
                Alignment::Left
            };
            // The row index vector records the first text line: copy selection and search positioning are divided by "text block",
            // including the username row would change their boundaries
            for piece in wrap_by_display_width(&display_sender, text_width) {
                lines.push(Line::from(Span::styled(piece, name_style)).alignment(alignment));
            }
            message_first_lines.push(lines.len());
            let message_match_style = if Some(&message.id) == current_match_message_id.as_ref() {
                current_match_style
            } else {
                match_style
            };
            // In an encrypted private chat the server has no body to give (the ciphertext only exists inside the session):
            // the seam reports "this history message has no readable body" as an empty string, and the interface fills in
            // the placeholder text from the language table.
            let body: String = if message.content.is_empty() {
                self.t("message_encrypted_history_unavailable")
            } else {
                message.content.clone()
            };
            for source_line in body.split('\n') {
                let segments = match keyword.as_deref() {
                    Some(keyword) => {
                        split_line_by_keyword(source_line, keyword, body_style, message_match_style)
                    }
                    None => vec![(source_line.to_string(), body_style)],
                };
                for line in wrap_styled_segments(&segments, text_width) {
                    lines.push(line.alignment(alignment));
                }
            }
        }
        (lines, message_first_lines)
    }

    // Currently active search keyword: only when the input box is in search mode (starts with #) and a search has been executed,
    /// Only return when the keyword in the input box matches the one just executed. When the user changes the keyword, old results immediately stop highlighting,
    /// to avoid residual highlighting that does not match the current input.
    fn active_search_keyword(&self) -> Option<String> {
        let typed = self.input_collector.message_input_state.text();
        let typed_keyword = typed.strip_prefix('#')?;
        let (executed_keyword, _, _) = self.search_result.as_ref()?;
        if executed_keyword != typed_keyword {
            return None;
        }
        Some(executed_keyword.clone())
    }

    /// Whether currently in search mode: the judgment method is the same as command mode — the input box content starts with #.
    fn in_search_mode(&self) -> bool {
        self.input_collector
            .message_input_state
            .text()
            .starts_with('#')
    }

    /// Exit search mode: clear the input box and all search result state (highlight, match list, positioning all reset)
    fn exit_search_mode(&mut self) {
        self.input_collector.message_input_state.set_text("");
        self.search_result = None;
        self.pending_scroll_message_id = None;
    }

    /// Scan currently loaded messages by keyword, returning a list of matched message IDs (keeping message display order, case-insensitive)
    fn messages_matching_keyword(&self, keyword: &str) -> Vec<String> {
        self.messages
            .iter()
            .filter(|message| {
                !keyword.is_empty() && !find_keyword_positions(&message.content, keyword).is_empty()
            })
            .map(|message| message.id.clone())
            .collect()
    }

    // Execute message search (triggered by Enter in search mode).
    // The server message API only has limit/before cursors, not keyword search parameters, so first pull the current room's history messages
    /// into local (load_full_room_history), then scan for keywords in the complete list.
    /// After matching, default to positioning at the last match (i.e., the most recent hit); when no match, the result list is empty and the title shows "not found".
    fn execute_message_search(&mut self) {
        let Some(typed) = self
            .input_collector
            .message_input_state
            .text()
            .strip_prefix('#')
            .map(|rest| rest.to_string())
        else {
            return;
        };
        let keyword = typed.trim().to_string();
        if keyword.is_empty() {
            self.exit_search_mode();
            return;
        }
        // Only fetch the whole room when the server still reports earlier messages; repeatedly pressing Enter does not repeatedly page
        if self.messages_older_cursor.is_some() {
            self.push_notification(self.t("search_loading_history"));
            self.load_full_room_history();
        }
        self.apply_search_keyword(&keyword);
    }

    // Quick search: in search mode, every text change instantly scans loaded messages, no Enter needed.
    /// Deliberately not doing whole-room page fetching — per-character paging would overwhelm the message API; the full history is still triggered by Enter.
    /// When the keyword is cleared, directly clear the results and the title returns to the unsearched state.
    fn apply_quick_search(&mut self) {
        let Some(typed) = self
            .input_collector
            .message_input_state
            .text()
            .strip_prefix('#')
            .map(|rest| rest.to_string())
        else {
            return;
        };
        let keyword = typed.trim().to_string();
        if keyword.is_empty() {
            self.search_result = None;
            self.pending_scroll_message_id = None;
            return;
        }
        self.apply_search_keyword(&keyword);
    }

    // Scan for matched items in loaded messages by keyword and write into search result state:
    /// Default to positioning at the last match (most recent hit); when no match, the match list is empty and the title shows "not found".
    /// Formal search and quick search share this; the only difference is whether the full history is pulled before calling.
    fn apply_search_keyword(&mut self, keyword: &str) {
        let matched = self.messages_matching_keyword(keyword);
        let selected = matched.len().saturating_sub(1);
        let target_id = matched.get(selected).cloned();
        self.search_result = Some((keyword.to_string(), matched, selected));
        self.pending_scroll_message_id = target_id;
    }

    // Pull all paginated history messages of the currently selected room into local, for full keyword search use.
    // Single request fetches 100 messages (the hard server limit of limit); continue only when the server returns has_more and the cursor advances;
    /// if the cursor does not advance, stop immediately to prevent infinite loops; messages already local are deduplicated and kept:
    /// plaintext entries already decrypted locally in encrypted private chats must not be overwritten by placeholder ciphertext returned by the server.
    fn load_full_room_history(&mut self) {
        let Some(room) = self
            .rooms_state
            .selected()
            .and_then(|index| self.rooms.get(index))
            .cloned()
        else {
            return;
        };
        let mut fetched: Vec<MessageInfo> = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let before = cursor.clone();
            match self
                .connector
                .get_messages(&room.id, 100, before.as_deref())
            {
                Ok(page) => {
                    let has_more = page.has_more;
                    let next_cursor = page.next_cursor;
                    fetched.extend(page.messages);
                    // A missing cursor or no advancement is treated as reaching the end; stop immediately to prevent looping and overwhelming the API when the server is abnormal
                    if !has_more
                        || next_cursor.is_none()
                        || next_cursor == cursor
                        || fetched.len() >= 5000
                    {
                        break;
                    }
                    cursor = next_cursor;
                }
                Err(e) => {
                    self.push_error(format!("{}: {e}", self.t("error_get_messages_failed")));
                    break;
                }
            }
        }
        if fetched.is_empty() {
            return;
        }
        // The API returns newest-first; reverse to oldest-on-top, newest-on-bottom, then merge
        fetched.reverse();
        let existing_ids: HashSet<String> = self
            .messages
            .iter()
            .map(|message| message.id.clone())
            .collect();
        let fresh: Vec<MessageInfo> = fetched
            .into_iter()
            .filter(|message| !existing_ids.contains(&message.id))
            .collect();
        if fresh.is_empty() {
            return;
        }
        debug_log(&format!(
            "全量历史合并 room={} 新增={} 总计={}",
            room.id,
            fresh.len(),
            self.messages.len() + fresh.len()
        ));
        self.messages.extend(fresh);
        let merged_room_id = room.id.clone();
        self.cache_loaded_messages(&merged_room_id);
        // RFC3339 timestamps' lexicographic order is time order; stable sort preserves the original relative order of messages at the same moment
        self.messages
            .sort_by(|left, right| left.created_at.cmp(&right.created_at));
        // No earlier messages left to fetch, so close the top-reached auto-paging to avoid pulling duplicate history again after searching
        self.messages_older_cursor = None;
    }

    // Re-verify search results after the message list changes overall (room switch reload, full fetch, earlier message prepend):
    /// Rescan for matches in the current list by the already-executed keyword, and clamp the current match index back into the valid range.
    /// Without rescanning, matched IDs would point to non-existent messages, and switching match items would appear "stuck".
    fn refresh_search_matches(&mut self) {
        let Some((keyword, _, selected)) = self.search_result.clone() else {
            return;
        };
        let refreshed = self.messages_matching_keyword(&keyword);
        let bounded = if refreshed.is_empty() {
            0
        } else {
            selected.min(refreshed.len() - 1)
        };
        self.search_result = Some((keyword, refreshed, bounded));
    }

    // Switch match items in search results: to_previous true means take the previous one (wrap to last when already at the first),
    /// otherwise take the next one (wrap to first when already at the last), and register the target message as pending positioning.
    /// Do nothing when there are 0 or 1 match items, to avoid meaningless jitter of the scroll position.
    fn navigate_search_result(&mut self, to_previous: bool) {
        let Some((keyword, matched, selected)) = self.search_result.clone() else {
            return;
        };
        if matched.is_empty() {
            return;
        }
        let next_index = if to_previous {
            if selected == 0 {
                matched.len() - 1
            } else {
                selected - 1
            }
        } else if selected + 1 >= matched.len() {
            0
        } else {
            selected + 1
        };
        self.pending_scroll_message_id = matched.get(next_index).cloned();
        self.search_result = Some((keyword, matched, next_index));
    }

    /// Message input box title text and border color: given by three states — command mode / search mode / normal mode.
    /// The search mode title should reflect three progress states: "unsearched", "match i/n", "not found"; the title is red when not found.
    fn message_input_title(&self) -> (Line<'static>, Color) {
        let input_text = self.input_collector.message_input_state.text();
        if self.in_search_mode() {
            // The keyword in the input box differs from the last executed one (including backspace edits); the last result is already invalid:
            // The title returns to "unexecuted search", no longer showing old match progress, to avoid looking like there are results when they have long since expired
            let title = match (self.active_search_keyword(), self.search_result.as_ref()) {
                (None, _) | (_, None) => {
                    Line::from(Span::raw(format!(" {} ", self.t("search_mode"))))
                }
                (_, Some((_, matched, _))) if matched.is_empty() => Line::from(Span::styled(
                    format!(" {} ", self.t("search_not_found")),
                    Style::default()
                        .fg(self.appearance.notice_error_border)
                        .add_modifier(Modifier::BOLD),
                )),
                (_, Some((_, matched, selected))) => Line::from(Span::raw(format!(
                    " {} ",
                    self.t("search_progress")
                        .replace("{current}", &(selected + 1).to_string())
                        .replace("{total}", &matched.len().to_string())
                ))),
            };
            return (title, self.appearance.search_border);
        }
        if input_text.starts_with('/') {
            return (
                Line::from(Span::raw(format!(" {} ", self.t("command_mode")))),
                self.appearance.command_border,
            );
        }
        (
            Line::from(Span::raw(format!(" {} ", self.t("message_input")))),
            self.appearance.input_border,
        )
    }

    fn render_message_input(&mut self, frame: &mut Frame, area: Rect) {
        // Record the input box position this frame: drags within it are delegated to the widget for text selection; drags outside start a full-screen box selection
        self.message_input_area = area;
        let cursor_style = Style::default().fg(self.appearance.own_username_text);
        let (title, border_color) = self.message_input_title();

        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(
                Style::default()
                    .fg(border_color)
                    .add_modifier(Modifier::BOLD),
            );

        let selection_style = Style::default()
            .fg(contrasting_foreground(self.appearance.selection_background))
            .bg(self.appearance.selection_background);
        TextArea::new()
            .block(block)
            .style(Style::default().fg(self.appearance.input_text))
            .cursor_style(cursor_style)
            .select_style(selection_style)
            .render(
                area,
                frame.buffer_mut(),
                &mut self.input_collector.message_input_state,
            );
    }

    fn render_create_group_modal(&mut self, frame: &mut Frame, area: Rect) {
        // Panel size first by content requirement, then clamp to the drawable area: on narrow terminals, the excess used to be cut off by the terminal column
        let panel_rect = centered_rect(60, 18, area);

        // Only clear and cover the popup's own area to avoid breaking the border of the underlying group list and chat records
        self.clear_overlay_area(frame, panel_rect);

        let focus_style = Style::default()
            .fg(self.appearance.selected_text)
            .add_modifier(Modifier::BOLD);
        let cursor_style = Style::default().fg(self.appearance.own_username_text);
        let unfocused_style = Style::default().fg(self.appearance.input_border);
        let selection_style = Style::default()
            .fg(contrasting_foreground(self.appearance.selection_background))
            .bg(self.appearance.selection_background);

        // Input box body text color comes from the appearance
        let input_text_style = Style::default().fg(self.appearance.input_text);
        let block = Block::default()
            .title(format!(" {} ", self.t("create_group_title")))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.appearance.overlay_border));

        let inner = panel_rect.inner(ratatui::layout::Margin {
            vertical: 1,
            horizontal: 2,
        });

        let layout = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Fill(1),
        ])
        .split(inner);

        let name_focused = self.focus_index == 0;
        let members_focused = self.focus_index == 1;

        let name_block = Block::default()
            .title(format!(" {} ", self.t("group_name_label")))
            .borders(Borders::ALL)
            .border_style(if name_focused {
                focus_style
            } else {
                unfocused_style
            });
        let members_block = Block::default()
            .title(format!(" {} ", self.t("members_hint_label")))
            .borders(Borders::ALL)
            .border_style(if members_focused {
                focus_style
            } else {
                unfocused_style
            });

        frame.render_widget(block.clone(), panel_rect);
        frame.render_widget(name_block.clone(), layout[2]);
        frame.render_widget(members_block.clone(), layout[4]);

        TextInput::new()
            .style(input_text_style)
            .block(name_block)
            .focus_style(focus_style)
            .select_style(selection_style)
            .cursor_style(cursor_style)
            .render(
                layout[2],
                frame.buffer_mut(),
                &mut self.input_collector.create_group_name_state,
            );

        TextInput::new()
            .style(input_text_style)
            .block(members_block)
            .focus_style(focus_style)
            .select_style(selection_style)
            .cursor_style(cursor_style)
            .render(
                layout[4],
                frame.buffer_mut(),
                &mut self.input_collector.create_group_members_state,
            );
    }

    fn render_create_private_modal(&mut self, frame: &mut Frame, area: Rect) {
        let panel_rect = centered_rect(50, 14, area);

        // Only clear and cover the popup's own area to avoid breaking the border of the underlying group list and chat records
        self.clear_overlay_area(frame, panel_rect);

        let focus_style = Style::default()
            .fg(self.appearance.selected_text)
            .add_modifier(Modifier::BOLD);
        let cursor_style = Style::default().fg(self.appearance.own_username_text);
        let unfocused_style = Style::default().fg(self.appearance.input_border);
        let selection_style = Style::default()
            .fg(contrasting_foreground(self.appearance.selection_background))
            .bg(self.appearance.selection_background);

        // Input box body text color comes from the appearance
        let input_text_style = Style::default().fg(self.appearance.input_text);
        let block = Block::default()
            .title(format!(" {} ", self.t("create_private_title")))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.appearance.overlay_border));

        let inner = panel_rect.inner(ratatui::layout::Margin {
            vertical: 1,
            horizontal: 2,
        });

        let layout = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Fill(1),
        ])
        .split(inner);

        let name_focused = self.focus_index == 0;

        let name_block = Block::default()
            .title(format!(" {} ", self.t("peer_username_label")))
            .borders(Borders::ALL)
            .border_style(if name_focused {
                focus_style
            } else {
                unfocused_style
            });
        frame.render_widget(block.clone(), panel_rect);

        frame.render_widget(name_block.clone(), layout[2]);

        TextInput::new()
            .style(input_text_style)
            .block(name_block)
            .focus_style(focus_style)
            .select_style(selection_style)
            .cursor_style(cursor_style)
            .render(
                layout[2],
                frame.buffer_mut(),
                &mut self.input_collector.create_private_username_state,
            );
    }

    fn execute_kick(&mut self, target: &str) {
        let selected_room_id = self.selected_room_id();
        let Some(room) =
            selected_room_id.and_then(|id| self.rooms.iter().find(|room| room.id == id))
        else {
            self.push_error(self.t("error_no_room_selected"));
            return;
        };
        if !room.is_group {
            self.push_error(self.t("error_not_group"));
            return;
        }
        let room_id = room.id.clone();
        // /kick only for group admins/owners; non-admins cannot use it to remove members even if the target is themselves
        let detail = match self.connector.get_room(&room_id) {
            Ok(detail) => detail,
            Err(error) => {
                self.push_error(format!("{}: {error}", self.t("error_get_members_failed")));
                return;
            }
        };
        let is_admin = self.current_user_id.as_deref().is_some_and(|uid| {
            detail
                .members
                .iter()
                .any(|member| member.user_id == uid && is_admin_role(&member.role))
        });
        if !is_admin {
            self.push_error(self.t("error_kick_requires_admin"));
            return;
        }
        if target.to_uppercase() == "ALL" {
            self.kick_all_members(&room_id);
            return;
        }
        let Some(target_member) = detail
            .members
            .iter()
            .find(|member| member.username == target)
        else {
            self.push_error(
                self.t("error_user_not_found_in_group")
                    .replace("{target}", target)
                    .to_string(),
            );
            return;
        };
        match self
            .connector
            .remove_member(&room_id, &target_member.user_id)
        {
            Ok(_) => {
                // If removing oneself, record in the voluntary exit set to avoid being misjudged as "removed from group"
                if self.current_user_id.as_deref() == Some(target_member.user_id.as_str()) {
                    self.left_room_ids.insert(room_id.clone());
                }
                self.push_notification(
                    self.t("removed_member")
                        .replace("{target}", target)
                        .to_string(),
                );
                self.load_rooms();
            }
            Err(error) => {
                self.push_error(format!(
                    "{}: {error}",
                    self.t("remove_member_failed").replace("{target}", target)
                ));
            }
        }
    }

    fn kick_all_members(&mut self, room_id: &str) {
        let Some(room) = self.rooms.iter().find(|room| room.id == room_id) else {
            return;
        };
        let member_ids: Vec<String> = room.members.clone();
        let own_id = self.current_user_id.clone().unwrap_or_default();
        let mut other_ids: Vec<String> = member_ids
            .iter()
            .filter(|id| *id != &own_id)
            .cloned()
            .collect();
        other_ids.reverse();
        for member_id in &other_ids {
            let _ = self.connector.remove_member(room_id, member_id);
        }
        // When removing yourself, record in the voluntary exit set to avoid being misjudged as "removed from group"
        self.left_room_ids.insert(room_id.to_string());
        let _ = self.connector.remove_member(room_id, &own_id);
        self.load_rooms();
        self.push_notification(self.t("removed_all_members"));
    }

    fn show_room_info(&mut self) {
        let Some(room) = self
            .selected_room_id()
            .and_then(|id| self.rooms.iter().find(|room| room.id == id))
        else {
            self.push_error(self.t("error_no_group_selected"));
            return;
        };
        if !room.is_group {
            self.push_error(self.t("error_info_not_group"));
            return;
        }
        let room_id = room.id.clone();
        let detail = match self.connector.get_room(&room_id) {
            Ok(detail) => detail,
            Err(error) => {
                self.push_error(format!("{}: {error}", self.t("error_get_room_info_failed")));
                return;
            }
        };
        // The member roster now uses the dedicated member API: the member array in room details is an incidental field,
        // the member API is the authoritative roster given by the server (with count and complete role/joined_at),
        // Both need to be obtained to form complete information; when the member interface fails, fall back to the detail version, not showing nothing at all
        let roster = self.connector.list_members(&room_id).ok();
        let room_name = detail
            .name
            .clone()
            .unwrap_or_else(|| self.t("private_chat_fallback"));
        let encrypted_label = if detail.is_encrypted {
            self.t("room_info_yes")
        } else {
            self.t("room_info_no")
        };
        let members_text: Vec<String> = roster
            .as_ref()
            .map(|fetched| &fetched.members[..])
            .unwrap_or(&detail.members)
            .iter()
            .map(|member| {
                // Members followed by an online marker (●/○ consistent with server broadcasts); unknown status shows no marker
                let presence_mark = match self.presence_by_user.get(&member.user_id) {
                    Some(true) => "●",
                    Some(false) => "○",
                    None => "",
                };
                let joined_at = format_message_time(&member.joined_at, true)
                    .map(|moment| format!(" ({moment})"))
                    .unwrap_or_default();
                format!(
                    "{} [{}]{}{}",
                    member.username, member.role, presence_mark, joined_at
                )
            })
            .collect();
        let member_total = roster
            .as_ref()
            .map(|fetched| fetched.count)
            .unwrap_or(detail.member_count as usize);
        let online_count = detail
            .members
            .iter()
            .filter(|member| self.presence_by_user.get(&member.user_id) == Some(&true))
            .count();
        let info = format!(
            "{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}/{}\n{}: {}",
            self.t("room_info_name"),
            room_name,
            self.t("room_info_id"),
            detail.id,
            self.t("room_info_creator"),
            if detail.created_by.is_empty() {
                self.t("unknown_user")
            } else {
                detail.created_by.clone()
            },
            self.t("room_info_created"),
            detail.created_at,
            self.t("room_info_encrypted"),
            encrypted_label,
            self.t("room_info_member_count"),
            member_total,
            self.t("room_info_online_count"),
            online_count,
            member_total,
            self.t("room_info_members"),
            members_text.join(", ")
        );
        self.push_notification(info);
    }

    // Display name of the sender: look up the username mapping first; fall back to user ID if not found.
    /// After account deletion, the server sets `messages.sender_id` to null (`ON DELETE SET NULL`),
    /// the seam collapses null into an empty string; at this point there is neither name nor ID, so uniformly display "unknown user" (unknown user).
    fn sender_display_name(&self, sender_id: &str) -> String {
        if sender_id.is_empty() {
            return self.t("unknown_user");
        }
        self.sender_names
            .get(sender_id)
            .cloned()
            .unwrap_or_else(|| sender_id.to_string())
    }

    // Settings menu entry table: (label, text color, enter action).
    /// Overlay rendering and key dispatch both read this table; adding/removing menu items only changes this one place.
    /// Account deletion is marked in red as per TODO; logging out is also a destructive operation so it is also in red.
    fn settings_menu_entries(&self) -> Vec<(String, Color, SettingsAction)> {
        // Switch state in the settings menu goes through the language table like every other wording:
        // a hardcoded "ON"/"OFF" would stay English inside a Chinese interface.
        let on_off = |enabled: bool| {
            if enabled {
                self.t("switch_on")
            } else {
                self.t("switch_off")
            }
        };
        let plain_text = self.appearance.message_text;
        let danger_text = self.appearance.notice_error_border;
        // The number only shows "pending" count: everything received is pending (the API only returns pending),
        // only your own that are still pending count; old invitations already accepted/rejected/expired do not count
        let request_count = self
            .pending_requests
            .iter()
            .filter(|request| received_request_is_pending(request))
            .count()
            + self
                .sent_requests
                .iter()
                .filter(|request| request.status.as_deref() == Some("pending"))
                .count();
        let update_suffix = match self.pending_update.as_ref() {
            Some((version, _)) => format!(" ({version})"),
            None => String::new(),
        };
        vec![
            (
                format!(" {}", self.t("option_create_group")),
                plain_text,
                SettingsAction::OpenOverlay(DisplayingOverlay::CreateGroup),
            ),
            (
                format!(" {}", self.t("option_create_private")),
                plain_text,
                SettingsAction::OpenOverlay(DisplayingOverlay::CreatePrivate),
            ),
            (
                format!(" {} ({})", self.t("option_pending_requests"), request_count),
                plain_text,
                SettingsAction::OpenOverlay(DisplayingOverlay::PendingRequests),
            ),
            (
                format!(
                    " {} ({})",
                    self.t("option_language"),
                    Self::current_language()
                ),
                plain_text,
                SettingsAction::OpenOverlay(DisplayingOverlay::LanguageSelect),
            ),
            (
                format!(
                    " {} ({})",
                    self.t("option_appearance"),
                    self.appearance_name
                ),
                plain_text,
                SettingsAction::OpenOverlay(DisplayingOverlay::AppearanceSelect),
            ),
            (
                format!(" {} [{}]", self.t("option_show_uid"), on_off(self.show_uid)),
                plain_text,
                SettingsAction::ToggleShowUid,
            ),
            (
                format!(
                    " {} [{}]",
                    self.t("option_time_format"),
                    on_off(self.time_with_date)
                ),
                plain_text,
                SettingsAction::ToggleTimeWithDate,
            ),
            (
                format!(
                    " {} [{}]",
                    self.t("option_quick_search"),
                    on_off(self.quick_search)
                ),
                plain_text,
                SettingsAction::ToggleQuickSearch,
            ),
            (
                format!(
                    " {} [{}]",
                    self.t("option_sound_enabled"),
                    on_off(self.sound_enabled)
                ),
                plain_text,
                SettingsAction::ToggleSound,
            ),
            (
                format!(" {}", self.t("option_edit_profile")),
                plain_text,
                SettingsAction::OpenForm(FormAction::UpdateProfile),
            ),
            (
                format!(" {}", self.t("option_change_password")),
                plain_text,
                SettingsAction::OpenForm(FormAction::ChangePassword),
            ),
            (
                format!(" {}", self.t("option_change_avatar")),
                plain_text,
                SettingsAction::OpenOverlay(DisplayingOverlay::AvatarSelect),
            ),
            (
                format!(" {}", self.t("option_server_address")),
                plain_text,
                SettingsAction::OpenOverlay(DisplayingOverlay::ServerAddress),
            ),
            (
                format!(" {}{update_suffix}", self.t("option_update_client")),
                plain_text,
                SettingsAction::UpdateClient,
            ),
            (
                format!(" {}", self.t("option_delete_account")),
                danger_text,
                SettingsAction::OpenForm(FormAction::DeleteAccount),
            ),
            (
                format!(" {}", self.t("option_logout")),
                danger_text,
                SettingsAction::Logout,
            ),
            (
                format!(" {}", self.t("option_login")),
                plain_text,
                SettingsAction::OpenOverlay(DisplayingOverlay::Login),
            ),
            (
                format!(" {}", self.t("option_register")),
                plain_text,
                SettingsAction::OpenOverlay(DisplayingOverlay::Register),
            ),
        ]
    }

    /// Open an existing overlay while completing the initialization each needs: list overlays set the selected item to the currently active entry,
    /// the server address overlay pre-fills the existing address, and form/input overlays return focus to the first item.
    fn open_overlay(&mut self, overlay: DisplayingOverlay) {
        self.focus_index = 0;
        match overlay {
            DisplayingOverlay::PendingRequests => {
                self.request_list_state
                    .select(if self.request_entries().is_empty() {
                        None
                    } else {
                        Some(0)
                    });
            }
            DisplayingOverlay::LanguageSelect => {
                let languages = Self::get_available_languages();
                let current = Self::current_language();
                self.language_list_state
                    .select(languages.iter().position(|language| language == &current));
            }
            DisplayingOverlay::AppearanceSelect => {
                let names = Appearance::available_names();
                self.appearance_list_state
                    .select(names.iter().position(|name| name == &self.appearance_name));
            }
            DisplayingOverlay::ServerAddress => {
                self.input_collector
                    .server_address_state
                    .set_text(self.connector.base_url());
            }
            DisplayingOverlay::AvatarSelect => {
                ensure_avatar_source_directory();
                if local_avatar_files().is_empty() {
                    // No images in the directory: do not show an empty panel; just give the original link input form
                    self.open_declared_form(&FormAction::ChangeAvatar);
                    return;
                }
                self.avatar_list_state.select(Some(0));
            }
            _ => {}
        }
        self.displaying_overlay = overlay;
    }

    /// Open the form overlay as declared by the form spec. The profile form additionally pre-fills nickname and bio from the current server values;
    /// phone numbers have no read-only interface to retrieve (not provided beyond the login response), so leave empty meaning "do not change this item".
    fn open_declared_form(&mut self, action: &FormAction) {
        let (_, declared) = form_definition(action);
        let mut prefilled: Vec<String> = Vec::new();
        if *action == FormAction::UpdateProfile {
            let loaded = self
                .current_user_id
                .as_ref()
                .and_then(|user_id| self.connector.get_user_profile(user_id).ok());
            prefilled = vec![
                loaded
                    .as_ref()
                    .and_then(|profile| profile.nickname.clone())
                    .unwrap_or_default(),
                String::new(),
                loaded
                    .as_ref()
                    .and_then(|profile| profile.bio.clone())
                    .unwrap_or_default(),
            ];
        }
        let fields: Vec<FormField> = declared
            .iter()
            .enumerate()
            .map(|(index, (label_key, secret))| {
                FormField::new(
                    label_key,
                    prefilled.get(index).map(String::as_str).unwrap_or_default(),
                    *secret,
                )
            })
            .collect();
        self.open_form(action.clone(), fields);
    }

    /// Render the settings menu overlay: entries, colors, and actions all come from settings_menu_entries,
    /// panel height is calculated by item count; when exceeding the screen, the list scrolls by the selected item itself.
    fn render_settings_menu(&mut self, frame: &mut Frame, area: Rect) {
        let entries = self.settings_menu_entries();
        let labels: Vec<String> = entries.iter().map(|(label, _, _)| label.clone()).collect();
        let colors: Vec<Color> = entries.iter().map(|(_, color, _)| *color).collect();
        let (panel_rect, body_width) = overlay_list_panel(&labels, area);
        self.clear_overlay_area(frame, panel_rect);
        let block = Block::default()
            .title(format!(" {} ", self.t("settings_title")))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.appearance.overlay_border));

        let menu_items: Vec<ListItem> = labels
            .iter()
            .zip(colors.iter())
            .map(|(label, color)| wrapped_list_item(label, Style::default().fg(*color), body_width))
            .collect();

        let list = List::new(menu_items)
            .block(block)
            .highlight_style(
                Style::default()
                    .fg(self.appearance.selected_text)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");
        frame.render_stateful_widget(list, panel_rect, &mut self.menu_list_state);
    }

    /// Render the language selection overlay: list all language files under config/languages, press Enter to switch and write back to preferences.json
    fn render_language_select(&mut self, frame: &mut Frame, area: Rect) {
        let languages = Self::get_available_languages();
        let current = Self::current_language();
        let labels: Vec<String> = languages
            .iter()
            .map(|name| {
                if name == &current {
                    format!(" {name} ✓")
                } else {
                    format!(" {name}")
                }
            })
            .collect();
        let (panel_rect, body_width) = overlay_list_panel(&labels, area);
        self.clear_overlay_area(frame, panel_rect);

        let block = Block::default()
            .title(format!(" {} ", self.t("select_language_title")))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.appearance.overlay_border));

        let items: Vec<ListItem> = labels
            .iter()
            .map(|label| {
                wrapped_list_item(
                    label,
                    Style::default().fg(self.appearance.message_text),
                    body_width,
                )
            })
            .collect();

        let list = List::new(items)
            .block(block)
            .highlight_style(
                Style::default()
                    .fg(self.appearance.selected_text)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");
        frame.render_stateful_widget(list, panel_rect, &mut self.language_list_state);
    }

    /// Render the appearance selection overlay: list all theme file names under config/themes (stripping .json suffix),
    /// press Enter to apply and write back to the appearance field of preferences.json.
    fn render_appearance_select(&mut self, frame: &mut Frame, area: Rect) {
        let names = Appearance::available_names();
        let labels: Vec<String> = names
            .iter()
            .map(|name| {
                if name == &self.appearance_name {
                    format!(" {name} ✓")
                } else {
                    format!(" {name}")
                }
            })
            .collect();
        let (panel_rect, body_width) = overlay_list_panel(&labels, area);
        self.clear_overlay_area(frame, panel_rect);

        let block = Block::default()
            .title(format!(" {} ", self.t("appearance_select_title")))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.appearance.overlay_border));

        let items: Vec<ListItem> = labels
            .iter()
            .map(|label| {
                wrapped_list_item(
                    label,
                    Style::default().fg(self.appearance.message_text),
                    body_width,
                )
            })
            .collect();

        let list = List::new(items)
            .block(block)
            .highlight_style(
                Style::default()
                    .fg(self.appearance.selected_text)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");
        frame.render_stateful_widget(list, panel_rect, &mut self.appearance_list_state);
    }

    /// Local avatar selection overlay: window, list, and highlight symbol are exactly the same as the language/appearance selection,
    /// the items are image file names in `<client directory>/config/avatars`.
    fn render_avatar_select(&mut self, frame: &mut Frame, area: Rect) {
        let files = local_avatar_files();
        let labels: Vec<String> = files.iter().map(|(name, _)| name.clone()).collect();
        let hint = self.t("hint_avatar_select");
        let (base_rect, body_width) = overlay_list_panel(&labels, area);
        // Prompts wrap at the same inner width per item; only increase the panel height when the row count exceeds the panel's built-in two-row margin
        let hint_block =
            wrapped_hint_text(&hint, hint_style(self.appearance.hint_text), body_width);
        let hint_rows = hint_block.lines.len().max(1) as u16;
        let panel_rect = centered_rect(
            base_rect.width,
            base_rect.height + hint_rows.saturating_sub(2),
            area,
        );
        self.clear_overlay_area(frame, panel_rect);
        frame.render_widget(
            overlay_frame_block(&self.appearance, &self.t("option_change_avatar")),
            panel_rect,
        );
        let items: Vec<ListItem> = labels
            .iter()
            .map(|label| {
                wrapped_list_item(
                    label,
                    Style::default().fg(self.appearance.message_text),
                    body_width,
                )
            })
            .collect();
        let list = List::new(items)
            .highlight_style(
                Style::default()
                    .fg(self.appearance.selected_text)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");
        let inner = panel_rect.inner(Margin {
            vertical: 1,
            horizontal: 1,
        });
        let [list_area, hint_area] =
            Layout::vertical([Constraint::Min(0), Constraint::Length(hint_rows)]).areas(inner);
        frame.render_stateful_widget(list, list_area, &mut self.avatar_list_state);
        frame.render_widget(
            Paragraph::new(hint_block).alignment(Alignment::Center),
            hint_area,
        );
    }

    /// Replace the avatar with the selected local image: the file name comes from the avatar directory.
    fn apply_local_avatar(&mut self) {
        let index = self.avatar_list_state.selected().unwrap_or(0);
        let files = local_avatar_files();
        let Some((_, path)) = files.get(index) else {
            return;
        };
        self.upload_local_avatar(path);
    }

    // Hand a local image to the server's multipart upload interface (two entry points share this: list selection and form path entry).
    /// When the server cannot store the file, display the error as-is: the storage directory is created by the server itself at startup,
    /// the client does not touch the server's data directory; to upload a link-based avatar use Ctrl+U in the overlay.
    fn upload_local_avatar(&mut self, path: &std::path::Path) {
        let Some((file_name, content_type, bytes)) = read_local_image(path) else {
            self.push_error(self.t("error_avatar_local_file_unusable"));
            return;
        };
        match self
            .connector
            .upload_avatar(&file_name, &content_type, bytes)
        {
            Ok(user) => self.finish_avatar_change(&user),
            Err(error) => {
                self.push_error(format!("{}: {error}", self.t("error_avatar_update_failed")))
            }
        }
    }

    /// Render the server address overlay: single input box, press Enter to test connectivity and save.
    fn render_server_address(&mut self, frame: &mut Frame, area: Rect) {
        // Both the prompt and input box need to fit: panel width is first clamped to the screen; the prompt wraps to the final inner width before determining height
        let panel_width = 50u16.min(area.width.max(1));
        let label = wrapped_hint_text(
            &self.t("server_address_label"),
            Style::default().fg(self.appearance.message_text),
            panel_width.saturating_sub(6),
        );
        let label_lines = label.lines.len().max(1) as u16;
        let panel_rect = centered_rect(panel_width, 5 + label_lines, area);

        self.clear_overlay_area(frame, panel_rect);

        // Input box body text color comes from the appearance
        let input_text_style = Style::default().fg(self.appearance.input_text);
        let block = Block::default()
            .title(format!(" {} ", self.t("server_address_title")))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.appearance.overlay_border));

        let inner = panel_rect.inner(ratatui::layout::Margin {
            vertical: 1,
            horizontal: 2,
        });

        frame.render_widget(
            Paragraph::new(label).style(Style::default().fg(self.appearance.message_text)),
            Rect::new(inner.x, inner.y, inner.width, label_lines),
        );

        let input_rect = Rect::new(inner.x, inner.y + label_lines, inner.width, 3);
        let input_state = &mut self.input_collector.server_address_state;
        input_state.focus.set(true);
        let selection_style = Style::default()
            .fg(contrasting_foreground(self.appearance.selection_background))
            .bg(self.appearance.selection_background);
        let input = TextInput::new()
            .style(input_text_style)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(self.appearance.input_border)),
            )
            .select_style(selection_style)
            .cursor_style(Style::default().fg(self.appearance.own_username_text));
        frame.render_stateful_widget(input, input_rect, input_state);

        frame.render_widget(block, panel_rect);
    }

    // Render the private chat management overlay: the upper half is requests others sent to you (accept/reject),
    // the lower half is requests you sent (revocable, showing the current status returned by the server).
    // The two areas are combined into a flat sequence navigated by the same selected index, so here each row is drawn manually,
    // only countable options are counted, the title row is not part of the selection.
    // Render the private chat management overlay: the upper half is requests others sent to you (accept/reject),
    // the lower half is requests you sent (revocable, showing the current status returned by the server).
    // The two areas are combined into a flat sequence navigated by the same selected index, the title row is not part of the selection,
    /// so here each row is drawn by hand and the scroll offset is computed manually. The invitation body is displayed in full wrapped by the panel width,
    /// and when longer than the panel it scrolls with the selected item, instead of showing just one row as before.
    fn render_pending_requests(&mut self, frame: &mut Frame, area: Rect) {
        let entries = self.request_entries();
        let received_count = self.pending_requests.len();
        let selected = self.request_list_state.selected().unwrap_or(0);
        let panel_width = area.width.saturating_sub(4).clamp(40, 88);
        // Body available width: minus border, selection marker, and indentation
        let body_width = panel_width.saturating_sub(8).max(20) as usize;
        let appearance = self.appearance.clone();
        let empty_text = self.t("no_pending_requests");
        let unknown_text = self.t("unknown_user");
        let encrypted_mark = self.t("encrypted_mark");
        let received_title = self.t("request_section_received");
        let sent_title = self.t("request_section_sent");
        let panel_title = self.t("pending_requests_title");
        let hint_text = self.t("hint_pending_requests");

        // First pass counts rows only: each item may span multiple lines (body wrapping); both panel height and scrolling need it
        let mut rows: Vec<(Option<usize>, Line)> = Vec::new();
        if entries.is_empty() {
            rows.push((
                None,
                Line::from(Span::styled(
                    empty_text.clone(),
                    hint_style(appearance.hint_text),
                ))
                .alignment(Alignment::Center),
            ));
        }
        for (index, (is_sent, request)) in entries.iter().enumerate() {
            let starts_section = *is_sent || (received_count > 0 && index == received_count);
            if starts_section {
                if index > 0 {
                    rows.push((None, Line::from("")));
                }

                rows.push((
                    None,
                    Line::from(Span::styled(
                        format!(
                            " {}",
                            if *is_sent {
                                &sent_title
                            } else {
                                &received_title
                            }
                        ),
                        Style::default()
                            .fg(appearance.time_text)
                            .add_modifier(Modifier::BOLD),
                    )),
                ));
            }
            let peer_name = if *is_sent {
                request.receiver.as_ref()
            } else {
                request.sender.as_ref()
            }
            .map(|peer| peer.username.clone())
            .unwrap_or_else(|| unknown_text.clone());
            // The sending side always has a status from the server; the receiving side only has status for the ones processed locally (history items),
            // received items still waiting have a default status, no suffix
            let status_suffix = match request.status.as_deref() {
                Some(status) if *is_sent || status != "pending" => {
                    format!(" [{}]", self.request_status_label(status))
                }
                _ => String::new(),
            };
            let encryption_mark = if request.is_encrypted {
                encrypted_mark.clone()
            } else {
                String::new()
            };
            let is_current = index == selected;
            let entry_color = if is_current {
                appearance.selected_text
            } else {
                appearance.other_username_text
            };
            let body_color = if is_current {
                appearance.selected_text
            } else {
                appearance.message_text
            };
            let message_lines = wrap_by_display_width(
                &format!("{}{encryption_mark}", request.message),
                body_width as u16,
            );
            // Names and status themselves may be wider than the body area: if it doesn't fit, let it take several rows alone first, the body continues on the next row,
            // Otherwise the entire invitation would be clipped and invisible
            let label_text = format!("{peer_name}{status_suffix}：");
            let label_width = usize::from(display_width(&label_text));
            let label_pieces: Vec<String> = if label_width > body_width {
                wrap_by_display_width(&label_text, body_width as u16)
            } else {
                Vec::new()
            };
            for (line_index, piece) in label_pieces.iter().enumerate() {
                rows.push((
                    (is_current && line_index == 0).then_some(index),
                    Line::from(vec![
                        Span::raw(if is_current && line_index == 0 {
                            "> "
                        } else {
                            "  "
                        }),
                        Span::styled(piece.clone(), Style::default().fg(entry_color)),
                    ]),
                ));
            }
            // When on the same row as the name, the body is indented by the name width; when the name is on its own row, the body is flush left
            let same_row_label = label_pieces.is_empty();
            let indentation = if same_row_label { label_width } else { 0 };
            for (line_index, message_line) in message_lines.iter().enumerate() {
                rows.push((
                    (is_current && same_row_label && line_index == 0).then_some(index),
                    Line::from(vec![
                        Span::raw(if is_current && same_row_label && line_index == 0 {
                            "> "
                        } else {
                            "  "
                        }),
                        Span::styled(
                            if line_index == 0 && same_row_label {
                                label_text.clone()
                            } else {
                                " ".repeat(indentation)
                            },
                            Style::default().fg(entry_color),
                        ),
                        Span::styled(message_line.clone(), Style::default().fg(body_color)),
                    ]),
                ));
            }
        }

        // The bottom prompt also wraps at the panel inner width, and the actual row count it occupies is counted into the panel height (it gets clipped when the English text is wider than the panel)
        let hint_block = wrapped_hint_text(
            &hint_text,
            hint_style(appearance.hint_text),
            panel_width.saturating_sub(4).max(1),
        );
        let hint_rows = hint_block.lines.len().max(1) as u16;
        let panel_height = (rows.len() as u16 + 3 + hint_rows)
            .min(area.height.saturating_sub(2))
            .max(7);
        let panel_rect = centered_rect(panel_width, panel_height, area);
        self.clear_overlay_area(frame, panel_rect);
        frame.render_widget(overlay_frame_block(&appearance, &panel_title), panel_rect);
        let inner = panel_rect.inner(Margin {
            vertical: 1,
            horizontal: 1,
        });
        let [list_area, hint_area] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(hint_rows)]).areas(inner);
        let visible_rows = usize::from(list_area.height.max(1));
        // When the selected item is not in the visible range, scroll it to the last row; the title row is not an item, so look up the item ownership by row
        let selected_row = rows
            .iter()
            .position(|(entry_index, _)| *entry_index == Some(selected));
        let scroll_offset = match selected_row {
            Some(row) if row >= visible_rows.saturating_sub(1) => {
                row - visible_rows.saturating_sub(1) + 1
            }
            _ => 0,
        };
        let list = Paragraph::new(Text::from(
            rows.into_iter()
                .map(|(_, line)| line)
                .collect::<Vec<Line>>(),
        ))
        .scroll((scroll_offset as u16, 0))
        .style(Style::default().bg(appearance.app_background));
        frame.render_widget(list, list_area);

        // Only prompt the non-universal key d (Enter/Esc are universal keys, no longer listed per the shortcut prompt spec)
        frame.render_widget(
            Paragraph::new(hint_block).alignment(Alignment::Center),
            hint_area,
        );
    }

    /// Localized text for request status: the server gives lowercase English status strings; unknown statuses are shown as-is.
    fn request_status_label(&self, status: &str) -> String {
        let key = match status {
            "pending" => "request_status_pending",
            "accepted" => "request_status_accepted",
            "declined" => "request_status_declined",
            "expired" => "request_status_expired",
            "cancelled" => "request_status_cancelled",
            other => return other.to_string(),
        };
        self.t(key)
    }

    /// Render the notification popup column in the top-right corner, each notification a small bordered panel stacked downward
    fn render_notifications(&self, frame: &mut Frame, area: Rect) {
        let margin_between = 1u16;
        // Column width is calculated by "the widest row among all prompts": previously it used the total width of the entire text
        // (multi-line prompts would inflate the width), and the cap is only half the screen, so long single-line text neither opens the panel wide enough,
        // nor is it tall enough due to the wrong height calculation, and on small screens the content is not visible.
        let longest_line = self
            .notifications
            .iter()
            .map(|(text, _, _)| longest_line_width(text))
            .max()
            .unwrap_or(0);
        // Allow up to two-thirds of screen width (at least 28 columns), narrow terminals also get at least one row of space
        let preferred_width = area.width.saturating_sub(2).clamp(28, 60);
        let column_width = (longest_line + 4).clamp(28u16.min(preferred_width), preferred_width);
        let inner_width = column_width.saturating_sub(2).max(1);
        let mut next_top = area.y + 1;

        for (text, is_error, _) in &self.notifications {
            // Count rows per line by display width: both explicit line breaks and wrapping must be counted, otherwise multi-line prompts would be clipped
            let line_count = estimated_wrapped_line_count(text, inner_width);
            // Reserve an extra row: word-boundary wrapping may break earlier than the column width limit
            let needed_height = line_count + 3;
            let available_height = (area.y + area.height).saturating_sub(next_top);
            if available_height < 3 {
                // If even the smallest bordered panel cannot fit, the remaining old prompts are not displayed this round (they will be automatically cleared when they expire)
                break;
            }
            let panel_height = needed_height.min(available_height);
            let panel_x = area.x + area.width.saturating_sub(column_width + 1);
            let panel_rect = Rect::new(panel_x, next_top, column_width, panel_height);

            // Error type border uses the appearance's error border color, info type uses the prompt border color; the title takes the color synchronously
            let (title_text, border_color) = if *is_error {
                (
                    format!(" {} ", self.t("error_title")),
                    self.appearance.notice_error_border,
                )
            } else {
                (
                    format!(" {} ", self.t("info_title")),
                    self.appearance.notice_hint_border,
                )
            };
            let panel_block = Block::default()
                .title(title_text)
                .title_style(
                    Style::default()
                        .fg(border_color)
                        .add_modifier(Modifier::BOLD),
                )
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color));

            let message = Paragraph::new(Text::raw(text.as_str()))
                .style(Style::default().fg(self.appearance.message_text))
                .wrap(ratatui::widgets::Wrap { trim: true });
            // The buffer is layered rendering; the panel area must be cleared first (and the theme background re-laid), otherwise lower-layer text will show through causing chaos
            self.clear_overlay_area(frame, panel_rect);
            frame.render_widget(panel_block, panel_rect);
            // Text must be confined within the top and bottom borders to avoid paragraph styles turning the border white
            frame.render_widget(
                message,
                panel_rect.inner(ratatui::layout::Margin {
                    vertical: 1,
                    horizontal: 1,
                }),
            );

            next_top += panel_height + margin_between;
        }
    }
}

// ==================== Top bar connection status, message cache, avatar, account info and updates ====================

// The four entry points for avatar byte cache (read, write, delete, path calculation) are all in the shared layer `baihua_core::config`:
// The path rule is `<client root directory>/cache/avatar/<user ID>.img` (path separators in user ID are replaced with underscores).
// The terminal edition previously copied this rule on its own, while the graphical edition uses the shared layer; having two separate implementations risks "the same person having avatars stored separately in two interfaces",
// Here we changed to use the same implementation as the graphical edition; "one cache shared by two interfaces" is structurally sound (see AGENTS.md's configuration and cache sharing notes).

/// Maximum size of the avatar grid (cell columns and rows). One cell holds two pixels top and bottom using the half-character `▀`,
/// and the terminal cell itself is approximately 1:2 aspect ratio, so the grid is square when columns = 2×rows:
/// columns × 16 rows = 32×32 pixels. The card is specifically for viewing people, so the size should be large enough to recognize face shape and color;
/// the message area no longer draws avatars, so this size only affects the card.
fn profile_avatar_cells() -> (usize, usize) {
    (32, 16)
}

/// Determine the avatar grid within the given available area: always guarantee "columns = 2×rows", only downgrade the whole thing without changing the ratio.
/// The source image is first cropped to a square then resampled to "columns × rows×2" pixels, so when columns ≠ 2×rows
/// the old way: when the panel narrows only the columns are cropped and rows stay at 16) round faces get squashed into vertical rectangles.
fn avatar_grid_within(columns_available: u16, rows_available: u16) -> (u16, u16) {
    let (wanted_columns, wanted_rows) = profile_avatar_cells();
    let wanted_columns = wanted_columns as u16;
    let wanted_rows = wanted_rows as u16;
    // One row of cells holds two pixels top and bottom, so "columns = rows × 2" corresponds to a square pixel block:
    // First clamp the row count with available width and height, then derive columns from rows; the ratio stays constant
    let rows = wanted_rows
        .min(wanted_columns.min(columns_available.max(2)) / 2)
        .min(rows_available.max(1))
        .max(1);
    (rows * 2, rows)
}

impl App {
    // Client version: at compile time taken from this package's Cargo.toml, the top bar and `--version` share the same source.
    pub fn client_version() -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    // Core library version: evolves independently of the client version; the top bar and `--version` both report it for easier problem location。
    pub fn core_version() -> String {
        baihua_core::core_version().to_string()
    }

    /// The top bar connection flag and the "server unreachable only prompt once" share this one state update:
    /// pop an error when it flips to disconnected, pop a recovery prompt when it goes from disconnected to connected; the persistent state is only reflected in the top bar, no repeated popups.
    fn update_connection_state(&mut self, online: bool) {
        let previous = self.connection_ready;
        if previous == Some(online) {
            return;
        }
        self.connection_ready = Some(online);
        if online {
            // Only report recovery when "previously explicitly disconnected"; first-time connectivity detection does not disturb the user (login has its own prompt)
            if previous == Some(false) {
                self.push_notification(self.t("connection_restored"));
            }
        } else {
            self.push_error(self.t("error_server_unreachable"));
        }
    }

    // Probe the server once at startup: both to get the server version string for the top bar (even when logged out),
    // and to give an initial flag for "can connect or not".
    pub fn probe_server_at_startup(&mut self) {
        match self.connector.probe_version() {
            Ok((version, raw_version)) => {
                if version == ApiVersion::Unknown {
                    self.push_notification(
                        self.t("api_version_unknown")
                            .replace("{version}", &raw_version),
                    );
                }
                self.update_connection_state(true);
            }
            Err(error) => {
                debug_log(&format!("启动探测失败: {error}"));
                self.connector.clear_server_version();
                self.update_connection_state(false);
            }
        }
    }

    // Start a persistent server reachability probing thread: independent of login state, it keeps working after logout,
    // so false positives like "disconnected right after logout" will no longer appear.
    // Two consecutive probing failures are needed to judge offline (a burst of requests at login instant, server just restarted can both cause
    // a single probe to time out); one success means recovery.
    pub fn start_reachability_watch(&mut self) {
        // After changing the server address, a new round must be started: the old thread probes the old address; keeping it would mix the two conclusions together
        if let Some(previous) = self.reachability_running.take() {
            previous.store(false, Ordering::Relaxed);
        }
        let Some(sender) = self.polling_sender.clone() else {
            return;
        };
        let connector = self.connector.clone();
        let running_flag = Arc::new(AtomicBool::new(true));
        self.reachability_running = Some(running_flag.clone());
        thread::spawn(move || {
            let mut failed_in_a_row = 0usize;
            while running_flag.load(Ordering::Relaxed) {
                let reachable = connector.probe_reachable();
                if reachable {
                    failed_in_a_row = 0;
                } else {
                    failed_in_a_row += 1;
                }
                // Report on first success and on the second consecutive failure; a single intermediate jitter does not disturb the interface
                if reachable || failed_in_a_row == 2 {
                    debug_log(&format!("服务端可达性探测: {reachable}"));
                    if sender
                        .send(PollingEvent::ReachabilityChanged(reachable))
                        .is_err()
                    {
                        return;
                    }
                }
                thread::sleep(Duration::from_secs(5));
            }
        });
    }

    // Background check for new versions: when a new version is found, download and verify; only pop a notification when the package is really retrieved locally —
    // the notification appearing means "now /update can be done immediately"; there will be no situation where a prompt appears but you still have to wait for download.
    // If the check fails (no network, release page redesigned, no package for this platform) just log a debug message, do not disturb the user.
    pub fn start_update_check_thread(&mut self, current_version: String) {
        let Some(sender) = self.polling_sender.clone() else {
            return;
        };
        // If already checking, do not start a second one: /update can be pressed again; two threads downloading the same package simultaneously makes no sense
        if self
            .update_check_running
            .as_ref()
            .is_some_and(|running| running.load(Ordering::Relaxed))
        {
            return;
        }
        let running_flag = Arc::new(AtomicBool::new(true));
        self.update_check_running = Some(running_flag.clone());
        thread::spawn(move || {
            match check_for_update(&current_version, ReleaseChannel::Terminal) {
                UpdateCheck::Available(package) => {
                    debug_log(&format!("发现新版本 {}，开始下载", package.version));
                    match download_package(&package) {
                        Ok(archive_path) => {
                            let _ = sender
                                .send(PollingEvent::UpdateReady((package.version, archive_path)));
                        }
                        Err(error) => debug_log(&format!("新版本下载或校验失败: {error}")),
                    }
                }
                UpdateCheck::UpToDate {
                    newest_tag,
                    newest_assets,
                } => debug_log(&format!(
                    "客户端已是最新版本（发布页最新标签 {newest_tag}，附件 {newest_assets:?}）"
                )),
                UpdateCheck::Unavailable(reason) => debug_log(&format!("版本检查未完成: {reason}")),
            }
            // Only set the flag when both check and download are complete; repeatedly pressing /update during this time will not spawn a second download thread
            running_flag.store(false, Ordering::Relaxed);
        });
    }

    // Common preparation after session establishment (both normal login and auto-login go through here):
    // top bar username, local message cache directory, own avatar. The user directory is not fetched here,
    /// it is only fetched when the user actually types "/profile ", and the login instant should not page for it.
    /// Username is based on the login response; for auto-login with only a token and no response, look up the profile by UID once more.
    fn prepare_session_state(&mut self, known_username: Option<String>) {
        let user_id = match self.current_user_id.clone() {
            Some(user_id) => user_id,
            None => return,
        };
        self.current_username = known_username.unwrap_or_default();
        if self.current_username.is_empty() {
            self.current_username = self
                .connector
                .get_user_profile(&user_id)
                .map(|profile| profile.username)
                .unwrap_or_default();
        }
        self.ensure_chat_cache();
        self.request_missing_avatars(std::slice::from_ref(&user_id));
        // Pre-fetch the registered user directory: /profile parameter completion needs it; waiting until the user types it would always be one frame late
        self.ensure_registered_users_loaded();
    }

    /// Establish a message cache directory for the current logged-in user (called after login success, auto-login; when not logged in, keep no cache).
    fn ensure_chat_cache(&mut self) {
        if self.chat_cache.is_some() {
            return;
        }
        let Some(user_id) = self.current_user_id.clone() else {
            return;
        };
        self.chat_cache = ChatCache::open(&user_id);
    }

    /// Get the encryption flag of the specified room: messages from encrypted rooms never enter local cache.
    fn room_is_encrypted(&self, room_id: &str) -> bool {
        self.rooms
            .iter()
            .any(|room| room.id == room_id && room.is_encrypted)
    }

    /// Write the whole room to cache (after room-switch loading, top-reached paging, full search). Encrypted rooms are skipped directly.
    fn cache_loaded_messages(&self, room_id: &str) {
        if room_id.is_empty() || self.room_is_encrypted(room_id) {
            return;
        }
        let Some(cache) = &self.chat_cache else {
            return;
        };
        // The in-memory list must truly be this room before writing to disk: at the moment of room switch messages might still be
        // The content of the previous room, choosing the wrong room would mix someone else's history into this file
        let belongs_to_room = self
            .messages
            .last()
            .is_some_and(|message| message.room_id == room_id);
        if !belongs_to_room {
            return;
        }
        cache.store_room(
            room_id,
            &self.messages,
            self.messages_older_cursor.as_deref(),
            self.messages_older_cursor.is_some(),
        );
    }

    /// Mark "current room message list is newer than disk", delegate to handle_tick for batch disk write.
    /// Writing the file once per message arrival would cause unnecessary full-file rewrites in active groups.
    fn mark_messages_dirty(&mut self) {
        if self.cache_pending_flush_since.is_none() {
            self.cache_pending_flush_since = Some(Instant::now());
        }
    }

    /// Write to disk after the dirty flag exceeds one batch window (the main loop calls this each round, it does not itself generate network requests).
    fn flush_pending_message_cache(&mut self) {
        let Some(dirty_since) = self.cache_pending_flush_since else {
            return;
        };
        if dirty_since.elapsed() < Duration::from_secs(5) {
            return;
        }
        self.cache_pending_flush_since = None;
        if let Some(room_id) = self.selected_room_id() {
            let room_id = room_id.clone();
            self.cache_loaded_messages(&room_id);
        }
    }

    // Complete avatars for this batch of users: skip those with existing conclusions (including "definitely no avatar"),
    /// The rest is delegated to the background thread to fetch image bytes via the profile API; after fetching, handed back to the main thread via AvatarLoaded.
    /// Absolutely no network requests during rendering; here only register pending fetches and dispatch work.
    fn request_missing_avatars(&mut self, user_ids: &[String]) {
        let Some(sender) = self.polling_sender.clone() else {
            return;
        };
        let mut missing: Vec<String> = Vec::new();
        for user_id in user_ids {
            if user_id.is_empty() || self.avatar_images.contains_key(user_id) {
                continue;
            }
            // Register the placeholder first to avoid the same batch of users being judged missing again next frame and sending duplicate requests
            self.avatar_images.insert(user_id.clone(), None);
            missing.push(user_id.clone());
        }
        if missing.is_empty() {
            return;
        }
        let connector = self.connector.clone();
        thread::spawn(move || {
            for user_id in missing {
                let image_bytes = config::load_cached_avatar(&user_id).or_else(|| {
                    let bytes = connector
                        .get_user_profile(&user_id)
                        .ok()
                        .and_then(|profile| profile.avatar)
                        .map(|avatar_path| avatar_path.trim().to_string())
                        .filter(|avatar_path| !avatar_path.is_empty())
                        .and_then(|avatar_path| {
                            connector.fetch_static_resource(&avatar_path).ok()
                        })?;
                    config::store_cached_avatar(&user_id, &bytes);
                    Some(bytes)
                });
                let _ = sender.send(PollingEvent::AvatarLoaded((user_id, image_bytes)));
            }
        });
    }

    /// Get the avatar pixel block for a user at a specified size (decoded once from the fetched bytes when that size is first needed).
    /// Return None when there is no avatar, or the bytes are not a decodable image; the caller falls back to placeholder display.
    fn avatar_pixels_at(
        &mut self,
        user_id: &str,
        columns: usize,
        rows: usize,
    ) -> Option<AvatarPixels> {
        let key = (user_id.to_string(), columns, rows);
        if let Some(cached) = self.avatar_pixels.get(&key) {
            return Some(cached.clone());
        }
        let image_bytes = self.avatar_images.get(user_id).cloned().flatten()?;
        let pixels = build_avatar_pixels(&image_bytes, columns, rows)?;
        self.avatar_pixels.insert(key, pixels.clone());
        Some(pixels)
    }

    /// Open the generic form overlay (shared rendering and key handling for set profile, change password, change avatar, delete account).
    fn open_form(&mut self, action: FormAction, fields: Vec<FormField>) {
        self.active_form = Some((action, fields));
        self.displaying_overlay = DisplayingOverlay::Form;
        self.focus_index = 0;
    }

    /// Submit the current form: dispatch the form action to the corresponding server interface, close the overlay on success.
    fn submit_active_form(&mut self) {
        let Some((action, fields)) = self.active_form.clone() else {
            return;
        };
        match action {
            FormAction::UpdateProfile => self.submit_profile_update(&fields),
            FormAction::ChangePassword => self.submit_password_change(&fields),
            FormAction::ChangeAvatar => self.submit_avatar_change(&fields),
            FormAction::DeleteAccount => self.submit_account_deletion(&fields),
        }
    }

    /// Cycle focus among the input items of the current form
    fn cycle_form_focus(&mut self, to_previous: bool) {
        let field_count = self
            .active_form
            .as_ref()
            .map(|(_, fields)| fields.len())
            .unwrap_or(0);
        if field_count == 0 {
            return;
        }
        self.focus_index = if to_previous {
            (self.focus_index + field_count - 1) % field_count
        } else {
            (self.focus_index + 1) % field_count
        };
    }

    /// Close the form overlay and return to the settings menu
    fn close_form(&mut self) {
        self.active_form = None;
        self.dismiss_overlay_back();
    }

    /// Update profile: nickname, phone number, bio. Leave the input box empty to mean clear this item (the server processes as explicit null),
    /// when unchanged, just submit the original value; the interface introduces no extra state for "whether it was changed".
    fn submit_profile_update(&mut self, fields: &[FormField]) {
        let text_of = |index: usize| fields.get(index).map(FormField::text).unwrap_or_default();
        let payload = ProfileUpdatePayload {
            nickname: profile_field_value(&text_of(0)),
            phone_number: profile_field_value(&text_of(1)),
            bio: profile_field_value(&text_of(2)),
            avatar: None,
        };
        if payload.nickname.is_none() && payload.phone_number.is_none() && payload.bio.is_none() {
            self.push_notification(self.t("profile_nothing_to_update"));
            return;
        }
        match self.connector.update_profile(&payload) {
            Ok(user) => {
                self.remember_own_profile(&user);
                self.close_form();
                self.push_notification(self.t("profile_updated"));
            }
            Err(error) => self.push_error(format!(
                "{}: {error}",
                self.t("error_profile_update_failed")
            )),
        }
    }

    /// Change password: old password, new password, confirm new password。
    /// The server password change invalidates all previously issued tokens, so after success the local session must be cleared and the user must re-login.
    fn submit_password_change(&mut self, fields: &[FormField]) {
        let text_of = |index: usize| fields.get(index).map(FormField::text).unwrap_or_default();
        let old_password = text_of(0);
        let new_password = text_of(1);
        if new_password != text_of(2) {
            self.push_error(self.t("error_password_mismatch"));
            return;
        }
        if old_password.is_empty() || new_password.is_empty() {
            self.push_error(self.t("error_empty_credentials"));
            return;
        }
        match self.connector.change_password(
            &crypto::encrypt_login_password(&old_password),
            &crypto::encrypt_login_password(&new_password),
        ) {
            Ok(_) => {
                self.active_form = None;
                self.logout();
                self.displaying_overlay = DisplayingOverlay::Login;
                self.focus_index = 0;
                self.push_notification(self.t("password_changed_relogin"));
            }
            Err(error) => self.push_error(format!(
                "{}: {error}",
                self.t("error_password_change_failed")
            )),
        }
    }

    /// Change avatar: full link goes to the profile API, local image path goes to the avatar upload API (the server only accepts
    /// JPEG/PNG/GIF/WebP; sizes limited by server configuration).
    fn submit_avatar_change(&mut self, fields: &[FormField]) {
        let Some(input) = fields.first().map(FormField::text) else {
            return;
        };
        let input = input.trim().to_string();
        if input.is_empty() {
            self.push_error(self.t("error_avatar_input_empty"));
            return;
        }
        // Full link goes to the profile API, the rest goes to the avatar upload API based on the local image file
        if input.starts_with("http://") || input.starts_with("https://") {
            let payload = ProfileUpdatePayload {
                avatar: Some(Some(input)),
                ..ProfileUpdatePayload::default()
            };
            match self.connector.update_profile(&payload) {
                Ok(user) => self.finish_avatar_change(&user),
                Err(error) => {
                    self.push_error(format!("{}: {error}", self.t("error_avatar_update_failed")))
                }
            }
            return;
        }
        // The path entered is local: follows the same upload route as list selection (the unreadable text is also shared)
        self.upload_local_avatar(&PathBuf::from(&input));
    }

    // Avatar replaced: first invalidate the old avatar bytes (memory and disk), then record the complete info returned by the server.
    /// The disk copy must be deleted: the `request_missing_avatars` background thread reads from disk first then requests,
    /// keeping it would always show the first cached one — same for URL avatars.
    fn finish_avatar_change(&mut self, user: &UserInfo) {
        config::drop_cached_avatar(&user.id);
        self.remember_own_profile(user);
        self.close_form();
        self.push_notification(self.t("avatar_updated"));
    }

    /// Delete account: enter password again. After success, clear all local residue (session, cache, avatar).
    fn submit_account_deletion(&mut self, fields: &[FormField]) {
        let Some(password) = fields.first().map(FormField::text) else {
            return;
        };
        if password.is_empty() {
            self.push_error(self.t("error_empty_credentials"));
            return;
        }
        match self
            .connector
            .delete_account(&crypto::encrypt_login_password(&password))
        {
            Ok(_) => {
                if let Some(cache) = &self.chat_cache {
                    cache.clear_all();
                }
                self.chat_cache = None;
                self.avatar_images.clear();
                self.avatar_pixels.clear();
                self.active_form = None;
                self.logout();
                self.displaying_overlay = DisplayingOverlay::Nothing;
                self.push_notification(self.t("account_deleted"));
            }
            Err(error) => self.push_error(format!(
                "{}: {error}",
                self.t("error_account_delete_failed")
            )),
        }
    }

    // The complete user object returned by the server lands locally; the top bar username and own avatar display both take from it.
    /// The avatar may have just been changed, so discard the old avatar result and refetch via the profile API,
    /// otherwise the interface would keep displaying the previous one.
    fn remember_own_profile(&mut self, user: &UserInfo) {
        self.current_username = user.username.clone();
        self.own_contact = Some((
            user.email.clone(),
            user.phone_number.clone().unwrap_or_default(),
        ));
        self.avatar_images.remove(&user.id);
        self.avatar_pixels
            .retain(|(cached_user_id, _, _), _| cached_user_id != &user.id);
        let own_user_id = user.id.clone();
        self.request_missing_avatars(std::slice::from_ref(&own_user_id));
    }

    /// /profile [username or UID]: no parameter shows yourself, parameter shows the specified user, displayed as a card overlay (with avatar).
    fn show_profile_card(&mut self, user_key: Option<&str>) {
        let lookup_key = match user_key {
            Some(key) if !key.is_empty() => key.to_string(),
            _ => match self.current_user_id.clone() {
                Some(user_id) => user_id,
                None => {
                    self.push_notification(self.t("error_not_logged_in"));
                    return;
                }
            },
        };
        match self.connector.get_user_profile(&lookup_key) {
            Ok(profile) => {
                // The avatar on the card is a large image; the size differs from the message area, so it needs a separate byte fetch and decoding at the large size
                self.avatar_images.remove(&profile.id);
                self.request_missing_avatars(std::slice::from_ref(&profile.id));
                self.profile_view = Some(profile);
                self.displaying_overlay = DisplayingOverlay::ProfileCard;
            }
            Err(error) => {
                self.push_error(format!("{}: {error}", self.t("error_profile_not_found")))
            }
        }
    }

    /// Ensure the user directory has been dispatched to fetch in the background: only dispatch when never fetched before; after that, do not repeat the request whether it succeeds or fails.
    /// Triggered by the keypress of typing "/profile " with a space; the profile panel first frame may still be empty, and it fills in automatically after the fetch.
    fn ensure_registered_users_loaded(&mut self) {
        if self.registered_users.is_some() {
            return;
        }
        // Place first then fetch, to avoid entering this method again after the same frame and re-spawning threads
        self.registered_users = Some(Vec::new());
        let Some(sender) = self.polling_sender.clone() else {
            return;
        };
        let connector = self.connector.clone();
        thread::spawn(move || match connector.list_all_users() {
            Ok(users) => {
                let _ = sender.send(PollingEvent::RegisteredUsersUpdated(users));
            }
            Err(error) => debug_log(&format!("拉取用户目录失败: {error}")),
        });
    }

    /// /list_users: list all registered users on the server (username and UID displayed on the same row).
    fn show_registered_users(&mut self) {
        match self.connector.list_all_users() {
            Ok(users) => {
                self.registered_users = Some(users.clone());
                if users.is_empty() {
                    self.push_notification(self.t("list_users_empty"));
                    return;
                }
                let lines: Vec<String> = users
                    .iter()
                    .map(|user| format!("{} - {}", user.username, user.id))
                    .collect();
                let title = self
                    .t("list_users_title")
                    .replace("{count}", &lines.len().to_string());
                self.push_notification(format!("{title}\n{}", lines.join("\n")));
            }
            Err(error) => {
                self.push_error(format!("{}: {error}", self.t("error_list_users_failed")))
            }
        }
    }

    /// /search_users <keyword>: search users by username substring or UID exact match.
    fn search_registered_users(&mut self, keyword: &str) {
        if keyword.is_empty() {
            self.push_notification(self.t("search_users_usage"));
            return;
        }
        match self.connector.search_users(keyword) {
            Ok(users) => {
                if users.is_empty() {
                    self.push_notification(
                        self.t("search_users_empty")
                            .replace("{keyword}", keyword)
                            .to_string(),
                    );
                    return;
                }
                let lines: Vec<String> = users
                    .iter()
                    .map(|user| format!("{} - {}", user.username, user.id))
                    .collect();
                let title = self
                    .t("search_users_title")
                    .replace("{keyword}", keyword)
                    .replace("{count}", &lines.len().to_string());
                self.push_notification(format!("{title}\n{}", lines.join("\n")));
            }
            Err(error) => {
                self.push_error(format!("{}: {error}", self.t("error_search_users_failed")))
            }
        }
    }

    /// All entries in the private chat management overlay: (is_self_sent, request_entry). Received first, sent second,
    /// Arrow keys move continuously between the two areas, so rendering and key handling both use the same flat sequence to locate the selection.
    fn request_entries(&self) -> Vec<(bool, RoomRequestInfo)> {
        let mut entries: Vec<(bool, RoomRequestInfo)> = self
            .pending_requests
            .iter()
            .map(|request| (false, request.clone()))
            .collect();
        entries.extend(
            self.sent_requests
                .iter()
                .map(|request| (true, request.clone())),
        );
        entries
    }

    /// The server does not broadcast an event for "request processed"; it can only be seen from the status change of "requests I sent":
    /// last round was pending, this round became rejected — give the sender an additional notification.
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
                .map(|peer| peer.username.clone())
                .unwrap_or_else(|| self.t("unknown_user"));
            notices.push(
                self.t("request_declined_notice")
                    .replace("{user}", &receiver_name),
            );
        }
        for notice in notices {
            self.push_notification(notice);
        }
    }

    /// Revoke a private chat request you sent: the server sets the request to cancelled, and the peer will no longer see it.
    fn cancel_sent_request(&mut self, request_id: &str) {
        match self.connector.cancel_room_request(request_id) {
            Ok(_) => {
                self.push_notification(self.t("request_cancelled"));
                self.mark_sent_request_cancelled(request_id);
                if let Some(index) = self.request_list_state.selected()
                    && index >= self.request_entries().len()
                {
                    self.request_list_state
                        .select(if self.request_entries().is_empty() {
                            None
                        } else {
                            Some(index.min(self.request_entries().len() - 1))
                        });
                }
            }
            Err(error) => self.push_error(format!(
                "{}: {error}",
                self.t("error_cancel_request_failed")
            )),
        }
    }

    // /update: for the settings item "update client", arrange replacement with the already-downloaded and verified update package, this process exits subsequently,
    // yielding to the installation process. The installation process waits for this process number to disappear before touching files, avoiding on Windows
    // "the executable file being occupied cannot be overwritten".
    /// Cannot do a synchronous download here while the package has not arrived — downloading would occupy the entire interface thread,
    /// so instead dispatch one more background check; after retrieval, pop the notification as normal and the user can execute later.
    fn start_downloaded_update(&mut self) -> bool {
        let Some((version, archive_path)) = self.pending_update.clone() else {
            self.start_update_check_thread(Self::client_version());
            self.push_notification(self.t("update_not_ready"));
            return false;
        };
        let staged_directory = match paths::update_directory() {
            Some(directory) => directory.join(format!("staged-{version}")),
            None => {
                self.push_error(self.t("error_update_directory_unavailable"));
                return false;
            }
        };
        if let Err(error) = installer::extract_archive(&archive_path, &staged_directory) {
            self.push_error(format!(
                "{}: {error}",
                self.t("error_update_extract_failed")
            ));
            return false;
        }
        let Some(prefix) = installer::current_prefix() else {
            self.push_error(self.t("error_update_prefix_unavailable"));
            return false;
        };
        let request = installer::InstallRequest {
            source_directory: staged_directory,
            prefix,
            wait_for_process: Some(std::process::id()),
        };
        match installer::spawn_detached_installer(&request) {
            Ok(()) => {
                self.update_handoff_requested = true;
                true
            }
            Err(error) => {
                self.push_error(format!("{}: {error}", self.t("error_update_start_failed")));
                false
            }
        }
    }

    // Main loop exit condition: /update has hung the installation process, this process must immediately yield
    pub fn should_exit_for_update(&self) -> bool {
        self.update_handoff_requested
    }
}

/// Profile field value: if there is content, write the new value; if empty, this item does not enter the request body (server semantics is "default = keep original value").
/// The form is pre-filled with the current server values when opened, so "unchanged" means "submit as-is"; no extra clearing logic is needed.
fn profile_field_value(text: &str) -> Option<Option<String>> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(Some(trimmed.to_string()))
    }
}

/// Read local image file for upload: only recognize the four formats the server accepts; return None for the rest, the caller prompts the user.
/// The server has its own size limit (default 2 MB, configurable); here only block obviously ridiculous sizes,
/// so the user does not accidentally read an entire multi-hundred-megabyte file into memory; the real limit is answered by the server.
fn read_local_image(path: &std::path::Path) -> Option<(String, String, Vec<u8>)> {
    let content_type = image_content_type_of(path)?;
    if fs::metadata(path)
        .map(|metadata| metadata.len() > 8 * 1024 * 1024)
        .unwrap_or(true)
    {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    let file_name = path.file_name()?.to_str()?.to_string();
    Some((file_name, content_type.to_string(), bytes))
}

/// The four image formats the server accepts → CONTENT_TYPE in multipart.
/// Directory listing and upload share this one judgment; anything listed as selectable can definitely be uploaded.
fn image_content_type_of(path: &std::path::Path) -> Option<&'static str> {
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

/// Directory for user-supplied avatars: create it if it does not exist; the user places images following this path.
/// Guaranteed once at startup and every time the avatar overlay is entered; the render path does not touch disk creation.
pub(crate) fn ensure_avatar_source_directory() {
    if let Some(directory) = baihua_core::paths::avatar_source_directory() {
        let _ = fs::create_dir_all(directory);
    }
}

/// Selectable images in the avatar directory; elements are (display file name, upload full path), sorted by file name.
/// Directory read fails or has no images: return an empty table, the caller falls back to the link input form.
fn local_avatar_files() -> Vec<(String, PathBuf)> {
    match baihua_core::paths::avatar_source_directory() {
        Some(directory) => avatar_files_in(&directory),
        None => Vec::new(),
    }
}

/// List uploadable images in the specified directory. Format judgment and upload share `image_content_type_of`,
/// files listed as selectable can definitely be uploaded; subdirectories and unreadable entries are skipped directly.
fn avatar_files_in(directory: &std::path::Path) -> Vec<(String, PathBuf)> {
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
    // The parent module's `use` is not visible to the submodule; the fake server in tests needs to import the read/write traits itself
    use std::io::{Read, Write};

    /// Restore the rows rendered from styled fragments to plain text, to assert wrapping and splitting results
    fn line_text(line: &Line) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    #[test]
    fn keyword_positions_are_case_insensitive_and_char_indexed() {
        assert_eq!(
            find_keyword_positions("Baihua chat", "bai"),
            vec![(0usize, 3usize)]
        );
        assert_eq!(
            find_keyword_positions("Baihua CHAT chat", "chat"),
            vec![(7usize, 11usize), (12usize, 16usize)]
        );
        // Chinese keywords return by character index, unaffected by UTF-8 byte length
        assert_eq!(
            find_keyword_positions("你好，世界。世界！", "世界"),
            vec![(3usize, 5usize), (6usize, 8usize)]
        );
        // Empty keywords and overly long keywords should not match, to avoid highlighting the whole screen
        assert!(find_keyword_positions("abc", "").is_empty());
        assert!(find_keyword_positions("ab", "abc").is_empty());
    }

    #[test]
    fn keyword_positions_skip_overlapping_matches() {
        // "aa" matches twice rather than three times in "aaaa": skip the whole segment after a match
        assert_eq!(
            find_keyword_positions("aaaa", "aa"),
            vec![(0usize, 2usize), (2usize, 4usize)]
        );
    }

    #[test]
    fn split_line_marks_only_matched_segments() {
        let matched_style = Style::default().bg(Color::Red);
        let body_style = Style::default().fg(Color::White);
        let segments = split_line_by_keyword("xxAAYY", "aa", body_style, matched_style);
        let texts: Vec<&str> = segments.iter().map(|(text, _)| text.as_str()).collect();
        assert_eq!(texts, vec!["xx", "AA", "YY"]);
        assert_eq!(segments[0].1, body_style);
        assert_eq!(segments[1].1, matched_style);
        assert_eq!(segments[2].1, body_style);
        // When no match, return the whole row as a single text fragment
        let untouched = split_line_by_keyword("nothing", "zz", body_style, matched_style);
        assert_eq!(untouched.len(), 1);
        assert_eq!(untouched[0].0, "nothing");
        assert_eq!(untouched[0].1, body_style);
    }

    #[test]
    fn wrapping_keeps_highlight_across_line_breaks() {
        let body_style = Style::default().fg(Color::White);
        let matched_style = Style::default().bg(Color::Red);
        // When the keyword lands exactly on a wrapping boundary, the highlight style must continue on the next line following the cut-back half
        let segments = split_line_by_keyword("aaaBB", "BB", body_style, matched_style);
        let lines = wrap_styled_segments(&segments, 4);
        assert_eq!(lines.len(), 2);
        assert_eq!(line_text(&lines[0]), "aaaB");
        assert_eq!(line_text(&lines[1]), "B");
        // The only fragment on the second row is the highlight style, indicating the highlight was not lost during wrapping
        assert_eq!(lines[1].spans.len(), 1);
        assert_eq!(lines[1].spans[0].style, matched_style);
        assert_eq!(lines[0].spans[0].style, body_style);
    }

    #[test]
    fn wrapping_respects_display_width_for_wide_characters() {
        let segments = vec![("你好世界".to_string(), Style::default())];
        // Each Chinese character takes two columns; width 4 can only fit two characters
        let lines = wrap_styled_segments(&segments, 4);
        assert_eq!(lines.len(), 2);
        assert_eq!(line_text(&lines[0]), "你好");
        assert_eq!(line_text(&lines[1]), "世界");
        // Empty input also produces a row, to avoid Paragraph having one fewer row and causing scroll position misalignment
        assert_eq!(wrap_styled_segments(&[], 10).len(), 1);
    }

    #[test]
    fn theme_colors_accept_hex_names_and_rgb_array() {
        assert_eq!(
            parse_theme_color(&serde_json::json!("#efebe2")),
            Some(Color::Rgb(239, 235, 226))
        );
        assert_eq!(
            parse_theme_color(&serde_json::json!("light-blue")),
            Some(Color::LightBlue)
        );
        assert_eq!(
            parse_theme_color(&serde_json::json!("default")),
            Some(Color::Reset)
        );
        assert_eq!(
            parse_theme_color(&serde_json::json!([24, 26, 31])),
            Some(Color::Rgb(24, 26, 31))
        );
        // Illegal formats all return None; the caller marks missing fields; never guess approximate colors
        assert_eq!(parse_theme_color(&serde_json::json!("#fff")), None);
        assert_eq!(parse_theme_color(&serde_json::json!("notacolor")), None);
        assert_eq!(parse_theme_color(&serde_json::json!(12)), None);
        assert_eq!(parse_theme_color(&serde_json::json!([1, 2])), None);
    }

    #[test]
    fn contrasting_foreground_stays_readable_on_both_light_and_dark_backgrounds() {
        assert_eq!(
            contrasting_foreground(Color::Rgb(239, 235, 226)),
            Color::Black
        );
        assert_eq!(contrasting_foreground(Color::Rgb(24, 26, 31)), Color::White);
        assert_eq!(contrasting_foreground(Color::Yellow), Color::Black);
        assert_eq!(contrasting_foreground(Color::Reset), Color::White);
    }

    #[test]
    fn every_shipped_theme_is_field_complete_and_well_formatted() {
        // Every theme file shipped with the repository must have complete fields and no extra keys, otherwise it indicates the theme spec is disconnected from the code
        let names = Appearance::available_names();
        assert!(!names.is_empty(), "config/themes 下应至少有一个外观文件");
        for name in names {
            let (_appearance, has_missing_field, extra_fields) = Appearance::load(&name);
            assert!(
                !has_missing_field,
                "config/themes/{name}.json 缺少外观槽位，需补齐或同步 Appearance 字段"
            );
            assert!(
                extra_fields.is_empty(),
                "config/themes/{name}.json 含未知字段: {extra_fields:?}"
            );
        }
        // default.json is a mirror of the built-in colors; the two must not drift
        let (default_appearance, _, _) = Appearance::load("default");
        assert_eq!(default_appearance, Appearance::built_in());
    }

    #[test]
    fn missing_theme_file_falls_back_to_built_in_and_is_flagged() {
        let (appearance, has_missing_field, extra_fields) =
            Appearance::load("this-theme-does-not-exist");
        assert!(has_missing_field);
        assert!(extra_fields.is_empty());
        assert_eq!(appearance.room_border, Appearance::built_in().room_border);
    }

    /// Construct a renderable chat page app: load the repository's real language files and specified appearance,
    /// write one group chat and two messages, and guarantee the render path does not trigger any network requests.
    fn chat_page_app_for_render(appearance_name: &str) -> App {
        let mut app = App::default();
        app.load_language("zh-CN");
        let (appearance, _, _) = Appearance::load(appearance_name);
        app.appearance = appearance;
        app.appearance_name = appearance_name.to_string();
        // Having a token counts as logged in; otherwise the message area would be entirely covered by the "not logged in" prompt, and message styles cannot be asserted
        app.connector.set_token("test-token");
        app.connector.set_base_url("http://localhost:1");
        app.current_user_id = Some("user-self".to_string());
        app.rooms = vec![RoomInfo {
            id: "room-one".to_string(),
            name: Some("群聊一号".to_string()),
            is_group: true,
            created_by: "user-self".to_string(),
            members: vec!["user-self".to_string(), "user-other".to_string()],
            is_encrypted: false,
            created_at: String::new(),
        }];
        app.rooms_state.select(Some(0));
        app.sender_names
            .insert("user-other".to_string(), "bob".to_string());
        app.messages = vec![
            MessageInfo {
                id: "message-1".to_string(),
                room_id: "room-one".to_string(),
                sender_id: "user-other".to_string(),
                content: "alpha hello world".to_string(),
                created_at: "2026-08-30T08:00:00+00:00".to_string(),
            },
            MessageInfo {
                id: "message-2".to_string(),
                room_id: "room-one".to_string(),
                sender_id: "user-self".to_string(),
                content: "second message".to_string(),
                created_at: "2026-08-30T08:01:00+00:00".to_string(),
            },
        ];
        app
    }

    #[test]
    fn status_bar_shows_connection_user_and_versions_with_documented_omissions() {
        let mut app = chat_page_app_for_render("default");
        // Connection status not probed: draw a hollow dot as offline, and do not show the server version
        let (connection_label, mark, user_text, right) = app.status_bar_texts();
        assert_eq!(mark, "○");
        assert_eq!(connection_label, app.t("bar_connection"));
        assert!(user_text.is_empty(), "未登录不该显示当前用户");
        assert!(!right.contains(&app.t("bar_server_version")));
        assert!(right.contains(&app.t("bar_client_version")));
        assert!(right.contains(&App::client_version()));

        // Connected but version string not probed: still do not show the server version
        app.connection_ready = Some(true);
        let (_, online_mark, _, right_without_version) = app.status_bar_texts();
        assert_eq!(online_mark, "●");
        assert!(!right_without_version.contains(&app.t("bar_server_version")));

        // After login, show the current username, and the marker is still between "connected" and the username (the top bar order is the semantic order)
        app.current_username = "alice".to_string();
        let (label, mark, user_text, _) = app.status_bar_texts();
        assert_eq!(label, app.t("bar_connection"));
        assert_eq!(mark, "●");
        assert!(user_text.contains("alice"));
        assert!(user_text.contains(&app.t("bar_current_user")));
        let assembled = format!("{label} {mark}{user_text}");
        assert!(
            assembled.find(&app.t("bar_connection")).unwrap() < assembled.find("●").unwrap(),
            "圆点必须紧跟在连接标签之后，不能被用户名推到行尾"
        );
        assert!(
            assembled.contains("●  |  当前用户 alice"),
            "实际拼接: {assembled}"
        );
    }

    #[test]
    fn editing_search_keyword_backwards_drops_the_previous_result_set() {
        let mut app = chat_page_app_for_render("default");
        app.input_collector.message_input_state.set_text("#hello");
        app.search_result = Some(("hello".to_string(), vec!["message-1".to_string()], 0));
        // Delete a letter with backspace: the result is no longer valid, the match list and positioning are both cleared
        app.input_collector.message_input_state.set_text("#hell");
        app.handle_message_input_changed();
        assert!(
            app.search_result.is_none(),
            "改动关键词后应丢弃上次搜索结果"
        );
        assert!(app.pending_scroll_message_id.is_none());
        // The title returns to "search mode", showing neither old progress nor "not found"
        let (title, _) = app.message_input_title();
        let rendered = title
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();
        assert!(rendered.contains(&app.t("search_mode")));
        assert!(!rendered.contains(&app.t("search_progress")));
    }

    #[test]
    fn quick_search_recomputes_instead_of_dropping_results() {
        let mut app = chat_page_app_for_render("default");
        app.quick_search = true;
        app.input_collector.message_input_state.set_text("#hel");
        app.handle_message_input_changed();
        let early = app.search_result.clone().expect("快速搜索应即时给出结果");
        assert_eq!(early.1, vec!["message-1".to_string()]);
        app.input_collector.message_input_state.set_text("#hello");
        app.handle_message_input_changed();
        let refined = app
            .search_result
            .clone()
            .expect("改关键词后应重扫而不是清空");
        assert_eq!(refined.0, "hello".to_string());
    }

    #[test]
    fn notification_panel_clips_to_screen_instead_of_vanishing() {
        let mut app = chat_page_app_for_render("default");
        // Ten items of 60-column text; on small screens the old algorithm would calculate a height exceeding the screen, causing the whole item to not be drawn
        let long_body = (0..10)
            .map(|index| format!("{index} 一六〇列宽的长文本占位。").repeat(4))
            .collect::<Vec<String>>()
            .join("\n");
        app.push_notification(long_body.clone());
        let buffer = render_snapshot(&mut app, 50, 12);
        let first_line = long_body.lines().next().unwrap_or_default();
        let visible_head: String = first_line.chars().take(6).collect();
        assert!(
            buffer_contains(&buffer, &visible_head),
            "提示框在小屏幕上被整体丢弃了，长文本没能自适应"
        );
    }

    #[test]
    fn settings_menu_covers_account_operations_and_marks_destructive_ones() {
        let app = chat_page_app_for_render("default");
        let entries = app.settings_menu_entries();
        let labels: Vec<String> = entries.iter().map(|(label, _, _)| label.clone()).collect();
        for key in [
            "option_edit_profile",
            "option_change_password",
            "option_change_avatar",
            "option_update_client",
            "option_delete_account",
        ] {
            assert!(
                labels.iter().any(|label| label.contains(&app.t(key))),
                "设置菜单缺少条目 {key}"
            );
        }
        let delete_entry = entries
            .iter()
            .find(|(label, _, _)| label.contains(&app.t("option_delete_account")))
            .expect("应有删除账户条目");
        assert_eq!(
            delete_entry.1, app.appearance.notice_error_border,
            "删除账户必须用报错色显示"
        );
        assert_eq!(
            delete_entry.2,
            SettingsAction::OpenForm(FormAction::DeleteAccount)
        );
        // Every item needs a label: dispatch reads directly from this table; there are no longer any index constants needing alignment
        assert!(
            entries.iter().all(|(label, _, _)| !label.trim().is_empty()),
            "菜单项标签不该为空"
        );
    }

    #[test]
    fn request_overlay_lists_sent_invitations_with_their_status() {
        let mut app = chat_page_app_for_render("default");
        app.pending_requests = vec![RoomRequestInfo {
            id: "request-in".to_string(),
            message: "加个好友".to_string(),
            is_encrypted: false,
            created_at: String::new(),
            sender: Some(baihua_core::api::RoomRequestPeer {
                user_id: "user-other".to_string(),
                username: "bob".to_string(),
                nickname: None,
            }),
            receiver: None,
            status: Some("pending".to_string()),
        }];
        app.sent_requests = vec![RoomRequestInfo {
            id: "request-out".to_string(),
            message: "你好".to_string(),
            is_encrypted: false,
            created_at: String::new(),
            sender: None,
            receiver: Some(baihua_core::api::RoomRequestPeer {
                user_id: "user-carol".to_string(),
                username: "carol".to_string(),
                nickname: None,
            }),
            status: Some("accepted".to_string()),
        }];
        app.displaying_overlay = DisplayingOverlay::PendingRequests;
        app.request_list_state.select(Some(0));
        let buffer = render_snapshot(&mut app, 100, 30);
        assert!(buffer_contains(&buffer, &app.t("request_section_received")));
        assert!(buffer_contains(&buffer, &app.t("request_section_sent")));
        assert!(buffer_contains(&buffer, "carol"));
        assert!(buffer_contains(&buffer, &app.t("request_status_accepted")));
        // The flat sequence places received first; revoke and reject are different actions based on their area
        let entries = app.request_entries();
        assert_eq!(entries.len(), 2);
        assert!(!entries[0].0);
        assert!(entries[1].0);
    }

    /// Construct a private chat request entry, status and send/receive direction can be filled per test case.
    fn invitation_with_status(id: &str, status: Option<&str>) -> RoomRequestInfo {
        RoomRequestInfo {
            id: id.to_string(),
            message: "加个好友".to_string(),
            is_encrypted: false,
            created_at: String::new(),
            sender: Some(baihua_core::api::RoomRequestPeer {
                user_id: "user-other".to_string(),
                username: "bob".to_string(),
                nickname: None,
            }),
            receiver: Some(baihua_core::api::RoomRequestPeer {
                user_id: "user-carol".to_string(),
                username: "carol".to_string(),
                nickname: None,
            }),
            status: status.map(str::to_string),
        }
    }

    #[test]
    fn settings_badge_counts_only_invitations_still_pending() {
        let mut app = chat_page_app_for_render("default");
        // Received items are only given as pending, all counted; those sent by self are filtered by status
        app.pending_requests = vec![
            invitation_with_status("received-1", Some("pending")),
            invitation_with_status("received-2", Some("pending")),
        ];
        app.sent_requests = vec![
            invitation_with_status("sent-pending", Some("pending")),
            invitation_with_status("sent-accepted", Some("accepted")),
            invitation_with_status("sent-declined", Some("declined")),
            invitation_with_status("sent-expired", Some("expired")),
            invitation_with_status("sent-cancelled", Some("cancelled")),
            invitation_with_status("sent-unknown", None),
        ];
        let label = app
            .settings_menu_entries()
            .iter()
            .find(|(label, _, _)| label.contains(&app.t("option_pending_requests")))
            .expect("设置菜单应有私聊请求管理条目")
            .0
            .clone();
        assert_eq!(
            label,
            format!(" {} (3)", app.t("option_pending_requests")),
            "数字提示只该算两条收到的加一条仍在等的"
        );
    }

    #[test]
    fn declined_sent_invitation_is_labelled_declined_and_never_cancelled() {
        let mut app = chat_page_app_for_render("default");
        app.sent_requests = vec![invitation_with_status("sent-declined", Some("declined"))];
        app.displaying_overlay = DisplayingOverlay::PendingRequests;
        app.request_list_state.select(Some(0));
        let buffer = render_snapshot(&mut app, 96, 30);
        assert!(buffer_contains(&buffer, &app.t("request_status_declined")));
        assert!(
            !buffer_contains(&buffer, &app.t("request_status_cancelled")),
            "被拒绝的邀请不能显示成已撤回"
        );
    }

    #[test]
    fn acting_on_an_invitation_keeps_it_in_the_received_history() {
        let mut app = chat_page_app_for_render("default");
        app.pending_requests = vec![
            // The server's "received requests" list does not give a status field; here leave None as the API returns it
            invitation_with_status("received-1", None),
            invitation_with_status("received-2", None),
        ];
        app.sent_requests = vec![invitation_with_status("sent-1", Some("pending"))];
        app.request_list_state.select(Some(0));
        // After processing, only do a local optimistic update (no longer re-send a list request and poll racing to write the same list),
        // and the entry must stay in the "received" area: the server won't be able to return it next time either
        app.mark_pending_request_handled("received-1", "accepted");
        assert_eq!(
            app.pending_requests.len(),
            2,
            "已处理的邀请不能从历史里消失"
        );
        assert_eq!(
            app.pending_requests[0].status.as_deref(),
            Some("accepted"),
            "结果状态要就地记上，否则看上去还是待处理"
        );
        assert_eq!(app.request_entries().len(), 3);
        app.mark_pending_request_handled("received-2", "declined");
        assert_eq!(app.pending_requests[1].status.as_deref(), Some("declined"));
        app.mark_sent_request_cancelled("sent-1");
        assert_eq!(
            app.sent_requests[0].status.as_deref(),
            Some("cancelled"),
            "撤回后本地状态就要变，否则列表里仍显示待处理"
        );
    }

    #[test]
    fn polled_received_requests_keep_locally_handled_history() {
        let mut app = chat_page_app_for_render("default");
        // Local history: one still waiting, one already accepted
        app.pending_requests = vec![
            invitation_with_status("waiting", None),
            invitation_with_status("handled", Some("accepted")),
        ];
        // The list brought back by polling will only be rows the server still has as pending (the processed one is not in it)
        app.apply_received_requests(vec![
            invitation_with_status("waiting", None),
            invitation_with_status("newly-arrived", None),
        ]);
        let ids: Vec<&str> = app
            .pending_requests
            .iter()
            .map(|request| request.id.as_str())
            .collect();
        assert_eq!(ids, vec!["waiting", "newly-arrived", "handled"]);
        assert_eq!(
            app.pending_requests
                .iter()
                .find(|request| request.id == "handled")
                .and_then(|request| request.status.as_deref()),
            Some("accepted"),
            "合并轮询结果时不能把本端记的结果状态冲掉"
        );
        // When the same entry appears in both sources, the server's version takes precedence; do not list it twice
        app.apply_received_requests(vec![invitation_with_status("handled", None)]);
        assert_eq!(app.pending_requests.len(), 1);
    }

    /// Only take the text inside the panel rectangle (removing border characters and whitespace) and concatenate row by row.
    /// The wrapped text spans multiple rows; only by restricting the range to the panel column interval can it be compared as a continuous segment.
    fn panel_body_text(buffer: &ratatui::buffer::Buffer, panel_rect: Rect) -> String {
        let border_characters = ['─', '│', '┌', '┐', '└', '┘', '├', '┤', '┬', '┴', '┼'];
        let mut text = String::new();
        for row in panel_rect.y..panel_rect.y + panel_rect.height {
            for column in panel_rect.x..panel_rect.x + panel_rect.width {
                let symbol = buffer[(column, row)].symbol();
                for character in symbol.chars() {
                    if !character.is_whitespace() && !border_characters.contains(&character) {
                        text.push(character);
                    }
                }
            }
        }
        text
    }

    #[test]
    fn narrow_settings_menu_wraps_entries_instead_of_clipping_them() {
        let mut app = chat_page_app_for_render("default");
        app.pending_requests = vec![invitation_with_status("received-1", None)];
        let labels: Vec<String> = app
            .settings_menu_entries()
            .iter()
            .map(|(label, _, _)| label.clone())
            .collect();
        app.displaying_overlay = DisplayingOverlay::SettingsMenu;
        app.menu_list_state.select(Some(0));
        let buffer = render_snapshot(&mut app, 26, 64);
        // The panel rectangle is calculated with the same algorithm as production code, so only the column interval within the panel can be taken:
        // Concatenating the whole row would mix in the chat page text from both sides of the panel, so wrapped entries can never match
        let (panel_rect, body_width) = overlay_list_panel(&labels, Rect::new(0, 1, 26, 63));
        assert!(panel_rect.width <= 26, "面板不该比屏幕还宽");
        let inside = panel_body_text(&buffer, panel_rect);
        for label in &labels {
            let compact: String = label
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect();
            assert!(inside.contains(&compact), "设置菜单条目被裁掉: {label}");
        }
        assert!(
            labels.iter().any(|label| display_width(label) > body_width),
            "这份数据本该窄到需要折行，否则测不到折行分支"
        );
    }

    /// Take several trailing characters of a text segment (after wrapping the tail row must be fully visible; what is clipped first is the tail)
    fn tail_of(text: &str, characters: usize) -> String {
        text.chars()
            .rev()
            .take(characters)
            .collect::<Vec<char>>()
            .iter()
            .rev()
            .collect::<String>()
    }

    #[test]
    fn english_requests_and_form_hints_wrap_on_a_narrow_panel() {
        let mut app = chat_page_app_for_render("default");
        // English text is much longer than Chinese; clipping on narrow panels only shows up in English, so this one uses en-US
        app.load_language("en-US");
        app.sent_requests = vec![invitation_with_status("sent-1", Some("accepted"))];
        app.displaying_overlay = DisplayingOverlay::PendingRequests;
        app.request_list_state.select(Some(0));
        let buffer = render_snapshot(&mut app, 56, 20);
        assert!(
            buffer_contains(&buffer, &tail_of(&app.t("hint_pending_requests"), 8)),
            "私聊请求浮层的底部提示被右边界裁掉了"
        );

        app.open_form(
            FormAction::ChangePassword,
            vec![
                FormField::new("password_old_label", "", true),
                FormField::new("password_new_label", "", true),
                FormField::new("password_confirm_label", "", true),
            ],
        );
        let narrow = render_snapshot(&mut app, 40, 20);
        assert!(
            buffer_contains(&narrow, &tail_of(&app.t("form_password_hint"), 8)),
            "改密表单的底部提示在 40 列面板里被裁掉了"
        );
    }

    #[test]
    fn narrow_status_bar_keeps_the_connection_mark_and_user() {
        let mut app = chat_page_app_for_render("default");
        app.connection_ready = Some(true);
        app.current_username = "buitest13".to_string();
        // Version info is secondary: when one row does not fit, let it be clipped first; the connection marker and current user must stay
        let buffer = render_snapshot(&mut app, 56, 20);
        assert!(buffer_contains(&buffer, "连接 ●"), "窄屏把连接标记挤掉了");
        assert!(
            buffer_contains(&buffer, &format!("当前用户 {}", app.current_username)),
            "窄屏把当前用户挤掉了"
        );
        // On wide screens both fit, version info remains complete (server version was never probed, so it does not display anyway)
        let wide = render_snapshot(&mut app, 120, 20);
        assert!(buffer_contains(&wide, &app.t("bar_client_version")));
        assert!(buffer_contains(&wide, &App::client_version()));
        assert!(buffer_contains(&wide, "当前用户 buitest13"));
    }

    #[test]
    fn wrapped_hint_text_keeps_every_character_and_stays_within_width() {
        // The height reserved for the form overlay is the number of rows of this function, so "no lost characters + no line exceeds width" is equivalent to no clipping
        let app = chat_page_app_for_render("default");
        let hint = app.t("form_profile_hint");
        let wrapped = wrapped_hint_text(&hint, Style::default(), 34);
        assert!(wrapped.lines.len() >= 2, "窄面板里提示应该折行");
        let joined: String = wrapped
            .lines
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>()
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        let original: String = hint
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        assert_eq!(joined, original, "折行丢了字");
        for line in &wrapped.lines {
            let plain: String = line
                .spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect();
            assert!(display_width(&plain) <= 34, "折出来的行仍超宽: {plain}");
        }
    }

    #[test]
    fn account_settings_refuse_a_signed_out_user_without_leaving_the_menu() {
        let mut app = chat_page_app_for_render("default");
        app.current_user_id = None;
        app.websocket_token = None;
        app.displaying_overlay = DisplayingOverlay::SettingsMenu;
        let profile_index = app
            .settings_menu_entries()
            .iter()
            .position(|(_, _, action)| {
                matches!(action, SettingsAction::OpenForm(FormAction::UpdateProfile))
            })
            .expect("设置菜单应有改资料条目");
        app.menu_list_state.select(Some(profile_index));
        app.handle_event(&Event::Key(crossterm::event::KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::NONE,
        )));
        assert_eq!(
            app.displaying_overlay,
            DisplayingOverlay::SettingsMenu,
            "未登录不该切进表单浮层"
        );
        assert!(app.active_form.is_none());
        assert!(
            app.notifications
                .iter()
                .any(|(text, _, _)| text == &app.t("error_not_logged_in"))
        );
        // Local display switches and language/appearance do not depend on login state and should still take effect normally
        let toggle_index = app
            .settings_menu_entries()
            .iter()
            .position(|(_, _, action)| matches!(action, SettingsAction::ToggleShowUid))
            .expect("设置菜单应有显示 UID 开关");
        app.menu_list_state.select(Some(toggle_index));
        let before = app.show_uid;
        app.handle_event(&Event::Key(crossterm::event::KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::NONE,
        )));
        assert_eq!(app.show_uid, !before);
    }

    #[test]
    fn avatar_overlay_hands_url_input_over_to_the_form() {
        let mut app = chat_page_app_for_render("default");
        app.displaying_overlay = DisplayingOverlay::AvatarSelect;
        app.avatar_list_state.select(Some(0));
        app.handle_event(&Event::Key(crossterm::event::KeyEvent::new(
            KeyCode::Char('u'),
            KeyModifiers::CONTROL,
        )));
        assert_eq!(app.displaying_overlay, DisplayingOverlay::Form);
        assert_eq!(
            app.active_form.as_ref().map(|(action, _)| action.clone()),
            Some(FormAction::ChangeAvatar),
            "Ctrl+U 应打开原来的修改头像表单"
        );
    }

    #[test]
    fn avatar_directory_offers_only_uploadable_images() {
        let directory = std::env::temp_dir().join("baihua-avatar-source-listing");
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(directory.join("子目录")).expect("临时目录应可创建");
        for name in [
            "me.png",
            "other.JPG",
            "notes.txt",
            "archive.tar.gz",
            "icon.webp",
        ] {
            fs::write(directory.join(name), b"x").expect("临时文件应可写入");
        }
        let names: Vec<String> = avatar_files_in(&directory)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(names, vec!["icon.webp", "me.png", "other.JPG"]);
        // Each one returns a real path; that is what the Enter-to-upload uses
        let entries = avatar_files_in(&directory);
        assert!(entries.iter().all(|(_, path)| path.starts_with(&directory)));
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn completion_descriptions_move_onto_their_own_line_when_tight() {
        let label = "/profile bobbington";
        let description = "01a070d7-d079-71c0-a254-32706c393476";
        let wide = completion_lines(label, description, Style::default(), Style::default(), 80);
        assert_eq!(wide.len(), 1, "放得下时不该多占一行");
        let tight = completion_lines(label, description, Style::default(), Style::default(), 24);
        assert!(tight.len() >= 2, "挤不下时说明要另起一行");
        let flattened: String = tight
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>()
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        let expected = format!("{label}{description}")
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        assert_eq!(flattened, expected, "挤不下时说明要完整挪到下一行");
    }

    /// Create bytes for a solid-color PNG: card tests do not depend on asset files in the repository
    fn synthetic_avatar_png() -> Vec<u8> {
        let image_buffer = image::RgbaImage::from_pixel(64, 64, image::Rgba([220, 30, 30, 255]));
        let mut encoded = std::io::Cursor::new(Vec::new());
        image_buffer
            .write_to(&mut encoded, image::ImageFormat::Png)
            .expect("Test image should be encodable");
        encoded.into_inner()
    }

    // The avatar grid must always have "columns = 2×rows" (one cell holds top and bottom pixels), otherwise the square source image will be squashed into a rectangle.
    #[test]
    fn avatar_grid_keeps_the_square_pixel_ratio_at_every_width() {
        for columns_available in [4u16, 7, 12, 20, 21, 32, 48] {
            let (columns, rows) = avatar_grid_within(columns_available, 30);
            assert_eq!(columns, rows * 2, "{columns_available} 列可用时比例失真");
            assert!(
                columns <= columns_available.max(2),
                "{columns_available} 列可用时超出宽度"
            );
            assert!(
                rows <= profile_avatar_cells().1 as u16,
                "行数不该超过最大网格"
            );
        }
    }

    // The pixel block actually drawn on the card must also keep the same ratio (width only counts the column where the half-character sits)
    #[test]
    fn profile_card_paints_an_avatar_that_is_not_stretched() {
        let mut app = chat_page_app_for_render("default");
        app.profile_view = Some(PublicProfile {
            id: "user-self".to_string(),
            username: "self".to_string(),
            nickname: None,
            bio: Some("短".to_string()),
            avatar: Some("/static/avatars/me.png".to_string()),
        });
        app.avatar_images
            .insert("user-self".to_string(), Some(synthetic_avatar_png()));
        app.displaying_overlay = DisplayingOverlay::ProfileCard;
        for (width, height) in [(40u16, 22u16), (64, 24), (120, 36)] {
            let buffer = render_snapshot(&mut app, width, height);
            let mut columns: Vec<u16> = Vec::new();
            let mut rows: Vec<u16> = Vec::new();
            for row in 0..buffer.area.height {
                for column in 0..buffer.area.width {
                    if buffer[(column, row)].symbol() == "▀" {
                        if !columns.contains(&column) {
                            columns.push(column);
                        }
                        if !rows.contains(&row) {
                            rows.push(row);
                        }
                    }
                }
            }
            assert!(
                !rows.is_empty(),
                "{width}x{height} 下没画出头像素块（头像被文字挤掉了）"
            );
            assert_eq!(
                columns.len(),
                rows.len() * 2,
                "{width}x{height} 下头像被压成 {}×{} 的矩形",
                columns.len(),
                rows.len()
            );
        }
    }

    #[test]
    fn profile_card_wraps_long_fields_instead_of_clipping_them() {
        let mut app = chat_page_app_for_render("default");
        app.own_contact = Some((
            "someone.with.a.long.mail@example.com".to_string(),
            "13800000000".to_string(),
        ));
        app.profile_view = Some(PublicProfile {
            id: "user-self".to_string(),
            username: "self".to_string(),
            nickname: Some("长着中文昵称的自己".to_string()),
            bio: Some("这是一段非常长的个人简介，专门用来验证窄屏下资料卡不会裁掉尾部".to_string()),
            avatar: Some("https://avatar.example.com/users/0123456789abcdef.png".to_string()),
        });
        app.displaying_overlay = DisplayingOverlay::ProfileCard;
        let buffer = render_snapshot(&mut app, 62, 24);
        assert!(
            buffer_contains(&buffer, "裁掉尾部"),
            "窄屏下长简介尾部被右边界切掉"
        );
        assert!(
            buffer_contains(&buffer, "abcdef.png"),
            "窄屏下长头像链接尾部被右边界切掉"
        );
        assert!(
            buffer_contains(&buffer, "example.com"),
            "窄屏下长邮箱尾部被右边界切掉"
        );
    }

    #[test]
    fn form_overlay_masks_password_fields() {
        let mut app = chat_page_app_for_render("default");
        app.active_form = Some((
            FormAction::ChangePassword,
            vec![
                FormField::new("password_old_label", "hunter2", true),
                FormField::new("password_new_label", "", true),
                FormField::new("password_confirm_label", "", true),
            ],
        ));
        app.displaying_overlay = DisplayingOverlay::Form;
        let buffer = render_snapshot(&mut app, 90, 24);
        assert!(buffer_contains(&buffer, &app.t("password_old_label")));
        assert!(buffer_contains(&buffer, &app.t("password_confirm_label")));
        assert!(
            !buffer_contains(&buffer, "hunter2"),
            "密码字段必须以遮蔽字符显示，不能把明文画到屏幕上"
        );
        // Label column width takes the widest label; the focus marker only appears on the current item
        assert!(buffer_contains(&buffer, &app.t("form_password_hint")));
    }

    #[test]
    fn profile_field_value_skips_empty_and_writes_the_rest() {
        // Leave empty = this item does not enter the request body (server semantics is keep original value); if there is content, write the new value.
        // A single minus sign no longer has special meaning; it is just an ordinary value
        assert_eq!(profile_field_value("   "), None);
        assert_eq!(profile_field_value("-"), Some(Some("-".to_string())));
        assert_eq!(
            profile_field_value("  新昵称  "),
            Some(Some("新昵称".to_string()))
        );
    }

    #[test]
    fn reloading_keeps_this_rooms_plaintext_and_drops_another_rooms_messages() {
        let mut app = chat_page_app_for_render("default");
        // The base URL points at a closed port: fetching the server page fails, which is exactly the branch that keeps
        // whatever the local side already holds (the branch a live server would cover by returning an empty history body).
        app.rooms.push(RoomInfo {
            id: "room-secret".to_string(),
            name: None,
            is_group: false,
            created_by: "user-self".to_string(),
            members: vec!["user-self".to_string(), "user-other".to_string()],
            is_encrypted: true,
            created_at: String::new(),
        });
        app.rooms_state.select(Some(1));
        app.messages = vec![MessageInfo {
            id: "message-secret".to_string(),
            room_id: "room-secret".to_string(),
            sender_id: "user-other".to_string(),
            content: "只存在于内存里的明文".to_string(),
            created_at: "2026-09-06T00:00:00+00:00".to_string(),
        }];
        app.load_messages_for_selected_room();
        assert!(
            app.messages
                .iter()
                .any(|message| message.id == "message-secret"
                    && message.content == "只存在于内存里的明文"),
            "重新加载同一个加密私聊时，本端解出来的明文不能被整表换掉，实际 {:?}",
            app.messages
                .iter()
                .map(|message| message.content.clone())
                .collect::<Vec<String>>()
        );

        // Switching back to the group chat: the private chat's messages must not stay on screen under another room's title.
        app.rooms_state.select(Some(0));
        app.load_messages_for_selected_room();
        assert!(
            app.messages
                .iter()
                .all(|message| message.room_id == "room-one"),
            "换房间后上一个房间的内容不得残留，实际 {:?}",
            app.messages
                .iter()
                .map(|message| message.room_id.clone())
                .collect::<Vec<String>>()
        );
    }

    #[test]
    fn plain_room_history_is_cached_and_encrypted_room_is_not() {
        let root = std::env::temp_dir().join(format!("baihua-app-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mut app = chat_page_app_for_render("default");
        app.current_user_id = Some("user-self".to_string());
        app.chat_cache = Some(baihua_core::chat_cache::ChatCache::open_in(
            "user-self",
            &root,
        ));

        // Unencrypted rooms: after writing the whole room, it can be read back as-is, with a paging cursor returned
        app.cache_loaded_messages("room-one");
        let cache = app.chat_cache.as_ref().expect("应已建立缓存目录");
        let cached = cache.load_room("room-one").expect("明聊房间应已落盘");
        assert_eq!(cached.messages.len(), 2);
        assert_eq!(cached.messages[0].id, "message-1");

        // Encrypted rooms: never write to disk
        app.rooms.push(RoomInfo {
            id: "room-secret".to_string(),
            name: None,
            is_group: false,
            created_by: "user-self".to_string(),
            members: vec!["user-self".to_string(), "user-other".to_string()],
            is_encrypted: true,
            created_at: String::new(),
        });
        app.messages.push(MessageInfo {
            id: "message-secret".to_string(),
            room_id: "room-secret".to_string(),
            sender_id: "user-other".to_string(),
            content: "只存在于内存里的明文".to_string(),
            created_at: "2026-08-30T08:02:00+00:00".to_string(),
        });
        app.cache_loaded_messages("room-secret");
        assert!(
            cache.load_room("room-secret").is_none(),
            "加密房间不得写入本地缓存"
        );
        // When the message list mixes content from two rooms, it is also not allowed to write to disk by room
        assert!(
            cache.load_room("room-one").is_some(),
            "此前写好的明聊缓存不该被误删"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn exit_alias_runs_the_same_quit_path() {
        let commands = chat_commands();
        let quit = commands
            .iter()
            .find(|(name, _)| *name == "quit")
            .expect("应有 /quit");
        let exit = commands
            .iter()
            .find(|(name, _)| *name == "exit")
            .expect("应有 /exit 别名");
        assert_eq!(quit.1, exit.1, "别名必须共用同一条说明文案");
        // When there are no private chats to clean up, the exit flow is immediately ready, which is exactly used to verify that the alias follows the same path
        let mut app = chat_page_app_for_render("default");
        assert!(!app.should_quit_now());
        app.execute_chat_command("/exit");
        assert!(app.should_quit_now(), "/exit 应像 /quit 一样进入退出流程");
    }

    #[test]
    fn dark_theme_is_shipped_complete_and_differs_from_default() {
        let names = Appearance::available_names();
        assert!(
            names.iter().any(|name| name == "dark"),
            "应随仓库提供暗色主题"
        );
        let (dark, has_missing_field, extra_fields) = Appearance::load("dark");
        assert!(!has_missing_field);
        assert!(extra_fields.is_empty());
        let built_in = Appearance::built_in();
        assert_ne!(dark.app_background, built_in.app_background);
        assert_ne!(dark.message_text, built_in.message_text);
        // Under the dark theme, body text must be brighter than the background, otherwise it is invisible
        assert!(
            theme_luminance(dark.message_text) > theme_luminance(dark.app_background),
            "暗色主题的正文颜色应明显亮于背景"
        );
    }

    /// Perceived brightness of colors (same weighting as contrasting_foreground, used for theme self-check)
    fn theme_luminance(color: Color) -> u32 {
        match color {
            Color::Rgb(red, green, blue) => {
                (u32::from(red) * 299 + u32::from(green) * 587 + u32::from(blue) * 114) / 1000
            }
            _ => 255,
        }
    }

    #[test]
    fn form_with_one_field_falls_back_to_box_input_and_still_masks_it() {
        let mut app = chat_page_app_for_render("default");
        // A one-item form (delete account) uses the box input as appropriate, not the arrow row
        app.active_form = Some((
            FormAction::DeleteAccount,
            vec![FormField::new(
                "delete_account_password_label",
                "hunter2",
                true,
            )],
        ));
        app.displaying_overlay = DisplayingOverlay::Form;
        let buffer = render_snapshot(&mut app, 90, 24);
        let body = buffer_row_text(&buffer, 0);
        assert!(!body.contains("hunter2"), "口令不该出现在屏幕上");
        // Evidence of a box: there is a top-left corner, and the border is the "unselected" input box border color
        // (the form deliberately does not use selection color, see render_box_field)
        assert!(
            buffer
                .content
                .iter()
                .any(|cell| cell.symbol() == "┌" && cell.fg == app.appearance.input_border),
            "少于三个条目的表单应自带方框输入框，且默认不是选中色"
        );
        assert!(buffer_contains(
            &buffer,
            &app.t("delete_account_password_label")
        ));
    }

    #[test]
    fn request_overlay_shows_the_whole_invitation_message() {
        let mut app = chat_page_app_for_render("default");
        let long_message =
            "这是一条很长很长的私聊验证消息，用来检验浮层会不会把内容截成一行。".repeat(3);
        app.pending_requests = vec![RoomRequestInfo {
            id: "request-long".to_string(),
            message: long_message.clone(),
            is_encrypted: false,
            created_at: String::new(),
            sender: Some(baihua_core::api::RoomRequestPeer {
                user_id: "user-other".to_string(),
                username: "bob".to_string(),
                nickname: None,
            }),
            receiver: None,
            status: Some("pending".to_string()),
        }];
        app.sent_requests = vec![RoomRequestInfo {
            id: "request-out".to_string(),
            message: "你好，加个好友".to_string(),
            is_encrypted: true,
            created_at: String::new(),
            sender: None,
            receiver: Some(baihua_core::api::RoomRequestPeer {
                user_id: "user-carol".to_string(),
                username: "carol".to_string(),
                nickname: None,
            }),
            status: Some("pending".to_string()),
        }];
        app.displaying_overlay = DisplayingOverlay::PendingRequests;
        app.request_list_state.select(Some(0));
        let buffer = render_snapshot(&mut app, 96, 30);
        let tail: String = long_message.chars().rev().take(6).collect::<String>();
        let tail: String = tail.chars().rev().collect();
        assert!(
            buffer_contains(&buffer, &tail),
            "邀请正文被截断，末尾的 {tail:?} 没出现在浮层里"
        );
        // The one sent by oneself is also there, with encryption markers and status
        assert!(buffer_contains(&buffer, "carol"));
        assert!(buffer_contains(&buffer, &app.t("request_status_pending")));
    }

    #[test]
    fn closing_an_overlay_returns_keyboard_focus_to_the_message_box() {
        let mut app = chat_page_app_for_render("default");
        // When the overlay opens, focus_index refers to input items in the overlay; after closing it must be handed back to the message input box,
        // otherwise it would return to the state of "typing has no target" (manifesting as keyboard input producing no response at all)
        app.displaying_overlay = DisplayingOverlay::Form;
        app.active_form = Some((
            FormAction::DeleteAccount,
            vec![FormField::new("delete_account_password_label", "", true)],
        ));
        app.focus_index = 0;
        let escape = Event::Key(crossterm::event::KeyEvent::new(
            KeyCode::Esc,
            KeyModifiers::NONE,
        ));
        app.handle_event(&escape);
        assert_eq!(app.displaying_overlay, DisplayingOverlay::SettingsMenu);
        app.handle_event(&escape);
        assert_eq!(app.displaying_overlay, DisplayingOverlay::Nothing);
        for character in ['/', 'p', 'r'] {
            app.handle_event(&Event::Key(crossterm::event::KeyEvent::new(
                KeyCode::Char(character),
                KeyModifiers::NONE,
            )));
        }
        assert_eq!(
            app.input_collector.message_input_state.text(),
            "/pr",
            "退出浮层后输入应落回消息输入框"
        );
    }

    #[test]
    fn login_and_register_with_arguments_are_refused_without_a_word() {
        let mut app = chat_page_app_for_render("default");
        // Login with parameters should neither execute nor be cleared and rewritten; silently reject it
        app.input_collector
            .message_input_state
            .set_text("/login somebody hunter2");
        app.handle_chat_submit();
        assert_eq!(
            app.input_collector.message_input_state.text(),
            "/login somebody hunter2",
            "带参数的登录行不该被吃掉"
        );
        assert_eq!(app.displaying_overlay, DisplayingOverlay::Nothing);
        assert!(app.notifications.is_empty(), "不该再多一句提示");
        // Only open the login overlay when there are no parameters
        app.input_collector.message_input_state.set_text("/login");
        app.handle_chat_submit();
        assert_eq!(app.displaying_overlay, DisplayingOverlay::Login);
    }

    #[test]
    fn declined_invitation_is_announced_once_to_the_sender() {
        fn invitation(status: &str) -> RoomRequestInfo {
            RoomRequestInfo {
                id: "request-1".to_string(),
                message: "加个好友".to_string(),
                is_encrypted: false,
                created_at: String::new(),
                sender: None,
                receiver: Some(baihua_core::api::RoomRequestPeer {
                    user_id: "user-carol".to_string(),
                    username: "carol".to_string(),
                    nickname: None,
                }),
                status: Some(status.to_string()),
            }
        }
        let mut app = chat_page_app_for_render("default");
        app.sent_requests = vec![invitation("pending")];
        // Polling brings back "rejected"; the sender must receive a notification
        app.announce_declined_invitations(&[invitation("declined")]);
        let notices: Vec<String> = app
            .notifications
            .iter()
            .map(|(text, _, _)| text.clone())
            .collect();
        assert_eq!(notices.len(), 1, "实际通知: {notices:?}");
        assert!(
            notices[0].contains("carol"),
            "通知里要点明是谁拒的: {notices:?}"
        );
        // After the local list is updated, another round with the same status should not prompt again
        app.notifications.clear();
        app.sent_requests = vec![invitation("declined")];
        app.announce_declined_invitations(&[invitation("declined")]);
        assert!(app.notifications.is_empty(), "同一状态变化不该报两次");
    }

    #[test]
    fn profile_completion_reads_the_cached_directory_only() {
        let mut app = chat_page_app_for_render("default");
        // When the directory has not been fetched there are no candidates, and the render path does not make requests (base_url points to an unreachable port,
        // Once it really makes a request here, it goes to the execution branch rather than the completion branch
        app.registered_users = None;
        assert!(app.completion_candidates("profile ").is_empty());
        app.registered_users = Some(vec![UserSearchResult {
            id: "01a0".to_string(),
            username: "carol".to_string(),
            nickname: Some("卡尔".to_string()),
            bio: None,
            avatar: None,
        }]);
        let candidates = app.completion_candidates("profile ");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].0, "/profile carol");
        assert_eq!(candidates[0].1, "carol - 01a0");
        assert_eq!(candidates[0].2, "卡尔");
        // Continue filtering when a prefix has been entered; do not require matching from the beginning
        assert_eq!(app.completion_candidates("profile ca").len(), 1);
        assert!(app.completion_candidates("profile zz").is_empty());
    }

    #[test]
    fn every_overlay_frame_uses_the_theme_overlay_border_color() {
        let mut app = chat_page_app_for_render("high-contrast");
        let overlay_border = app.appearance.overlay_border;
        let frames = [
            DisplayingOverlay::SettingsMenu,
            DisplayingOverlay::LanguageSelect,
            DisplayingOverlay::AppearanceSelect,
            DisplayingOverlay::Login,
            DisplayingOverlay::Register,
            DisplayingOverlay::CreateGroup,
            DisplayingOverlay::CreatePrivate,
            DisplayingOverlay::ServerAddress,
            DisplayingOverlay::PendingRequests,
            DisplayingOverlay::ProfileCard,
            DisplayingOverlay::Form,
            DisplayingOverlay::AvatarSelect,
        ];
        for frame_kind in frames {
            app.displaying_overlay = frame_kind.clone();
            if frame_kind == DisplayingOverlay::Form {
                app.active_form = Some((
                    FormAction::ChangeAvatar,
                    vec![FormField::new("avatar_input_label", "", false)],
                ));
            } else {
                app.active_form = None;
            }
            if frame_kind == DisplayingOverlay::ProfileCard {
                app.profile_view = Some(PublicProfile {
                    id: "user-other".to_string(),
                    username: "bob".to_string(),
                    nickname: None,
                    bio: None,
                    avatar: None,
                });
            } else {
                app.profile_view = None;
            }
            let buffer = render_snapshot(&mut app, 100, 30);
            assert!(
                buffer
                    .content
                    .iter()
                    .any(|cell| cell.symbol() == "└" && cell.fg == overlay_border),
                "{frame_kind:?} 的窗口边框没走外观里的 overlay_border"
            );
        }
    }

    #[test]
    fn very_long_single_line_notification_is_still_visible_on_a_small_screen() {
        let mut app = chat_page_app_for_render("default");
        let head = "很长的单行提示内容";
        app.push_notification(format!("{}结尾看得见", head.repeat(12)));
        let buffer = render_snapshot(&mut app, 60, 14);
        // The old algorithm estimated height by the total width of the entire text; on small screens if it calculated exceeding screen height the whole item was not drawn;
        // now it sets the width by "the widest row" and estimates height row by row; when it does not fit, it clips the display instead of discarding
        assert!(
            buffer_contains(&buffer, head),
            "长提示在小屏幕上被整条丢弃，没有自适应宽高"
        );
    }

    /// Use ratatui's test backend to render the entire interface into a memory buffer.
    /// When there is no real terminal, this is the only way to verify down to "pixels" (cell symbols and styles).
    fn render_snapshot(app: &mut App, width: u16, height: u16) -> ratatui::buffer::Buffer {
        let backend = ratatui::backend::TestBackend::new(width, height);
        let mut terminal = ratatui::Terminal::new(backend).expect("测试后端应能初始化");
        terminal.draw(|frame| app.ui(frame)).expect("渲染聊天页");
        terminal.backend().buffer().clone()
    }

    // Restore a row of the buffer to plain text, to assert text content like the title bar and prompt rows by string.
    /// Double-width characters (Chinese) take two cells, the second cell is an empty placeholder; must advance by display width across cells,
    /// otherwise the restored Chinese text would have spaces inserted.
    fn buffer_row_text(buffer: &ratatui::buffer::Buffer, row: u16) -> String {
        let mut text = String::new();
        let mut column = 0u16;
        while column < buffer.area.width {
            let symbol = buffer[(column, row)].symbol();
            text.push_str(symbol);
            column += display_width(symbol).max(1);
        }
        text
    }

    /// Whether any row on the entire screen contains the given text
    fn buffer_contains(buffer: &ratatui::buffer::Buffer, text: &str) -> bool {
        (0..buffer.area.height).any(|row| buffer_row_text(buffer, row).contains(text))
    }

    /// Collect the rows of cells on the entire screen that have a certain background color (deduplicated and sorted), to verify which message the highlight falls on
    fn rows_with_background(buffer: &ratatui::buffer::Buffer, background: Color) -> Vec<i32> {
        let mut rows: Vec<i32> = Vec::new();
        for row in 0..buffer.area.height {
            for column in 0..buffer.area.width {
                if buffer[(column, row)].bg == background {
                    rows.push(row as i32);
                    break;
                }
            }
        }
        rows
    }

    /// Collect the text of cells on the entire screen that have a certain background color, to verify the highlight exactly covers the matched fragment
    fn cells_with_background(buffer: &ratatui::buffer::Buffer, background: Color) -> String {
        buffer
            .content
            .iter()
            .filter(|cell| cell.bg == background)
            .map(|cell| cell.symbol())
            .collect::<String>()
    }

    // Fake message service: respond to two paging requests in order. The first returns the first page of two (has_more is true,
    /// cursor points to an older item), the second returns the last page (has_more is false, cursor is empty).
    /// Messages are arranged per server convention "newest first", used to verify the client's stop condition, reversal, deduplication, and merge sorting.
    fn spawn_two_page_message_server() -> std::net::SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("绑定本地测试端口");
        let address = listener.local_addr().expect("测试端口应能读回地址");
        std::thread::spawn(move || {
            for page_index in 0..2usize {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let mut request = vec![0u8; 4096];
                let _ = stream.read(&mut request);
                let body = if page_index == 0 {
                    r#"{"response_id":"page-one","code":"SUCCESS","message":"ok","data":{"messages":[{"id":"old-2","room_id":"room-one","sender_id":"user-other","content":"older hello second","created_at":"2026-08-30T07:00:02+00:00"},{"id":"old-1","room_id":"room-one","sender_id":"user-other","content":"older hello first","created_at":"2026-08-30T07:00:01+00:00"}],"has_more":true,"next_cursor":"old-2"}}"#
                } else {
                    r#"{"response_id":"page-two","code":"SUCCESS","message":"ok","data":{"messages":[{"id":"oldest-0","room_id":"room-one","sender_id":"user-other","content":"oldest message hello","created_at":"2026-08-30T06:00:00+00:00"}],"has_more":false,"next_cursor":null}}"#
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        address
    }

    #[test]
    fn full_history_search_pages_to_end_then_merges_sorts_and_locates_last_match() {
        let mut app = chat_page_app_for_render("default");
        app.connector
            .set_base_url(&format!("http://{}", spawn_two_page_message_server()));
        app.input_collector.message_input_state.set_text("#hello");
        // A paging cursor is left only when the server's home page response has has_more true; here simulate a room with "earlier messages remaining"
        app.messages_older_cursor = Some("message-1".to_string());

        app.execute_message_search();

        // All three pages of history are merged together, the whole is re-sorted by time ascending, the two local original entries keep their content unchanged
        let ids: Vec<&str> = app
            .messages
            .iter()
            .map(|message| message.id.as_str())
            .collect();
        assert_eq!(
            ids,
            vec!["oldest-0", "old-1", "old-2", "message-1", "message-2"]
        );
        // The hit list is arranged in display order: four messages containing hello, default positioning at the last match
        let (keyword, matched, selected) = app.search_result.clone().expect("搜索应已执行");
        assert_eq!(keyword, "hello");
        assert_eq!(matched, vec!["oldest-0", "old-1", "old-2", "message-1"]);
        assert_eq!(selected, matched.len() - 1);
        assert_eq!(app.pending_scroll_message_id, Some("message-1".to_string()));
        // All has been fetched to the bottom, the top-reached paging cursor must be closed, otherwise after searching it would repeatedly fetch the history again
        assert!(app.messages_older_cursor.is_none());
    }

    #[test]
    fn repeated_search_skips_history_fetch_when_room_is_already_complete() {
        // A null cursor means this room has no earlier messages (server has_more is false),
        // pressing Enter repeatedly should only rescan existing messages, never fetch another page, and should not error from being unable to connect
        let mut app = chat_page_app_for_render("default");
        app.input_collector.message_input_state.set_text("#hello");
        app.execute_message_search();
        let (keyword, matched, selected) = app.search_result.expect("搜索应已执行");
        assert_eq!(keyword, "hello");
        assert_eq!(matched, vec!["message-1".to_string()]);
        assert_eq!(selected, 0);
        assert!(app.notifications.is_empty());
    }

    #[test]
    fn screen_selection_extracts_rectangle_text_ignoring_wide_char_splits() {
        let rows = vec![
            "┌ 房间 ┐".to_string(),
            "│群聊一号│".to_string(),
            "│      │".to_string(),
        ];
        // Cover the four Chinese characters on the second row: split columns by display width, keep double-width characters as whole units
        assert_eq!(
            extract_selected_screen_text(&rows, (2, 1), (8, 1)),
            "群聊一号"
        );
        // Endpoint order does not matter (dragging from bottom-right to top-left)
        assert_eq!(
            extract_selected_screen_text(&rows, (8, 1), (2, 1)),
            "群聊一号"
        );
        // When only the first column of a Chinese character is boxed, take the whole character (the endpoint column itself counts toward the selection)
        assert_eq!(extract_selected_screen_text(&rows, (2, 1), (2, 1)), "群");
        // When selecting across rows, rows that are entirely empty at the start or end are discarded
        assert_eq!(extract_selected_screen_text(&rows, (13, 0), (13, 2)), "");
    }

    #[test]
    fn search_navigation_relocates_view_even_with_a_single_match() {
        // When there was only one match the old implementation returned directly (matched.len() < 2), the user pressing a modifier key had no effect;
        // now it still pushes the view to that message
        let mut app = chat_page_app_for_render("default");
        app.input_collector.message_input_state.set_text("#hello");
        app.search_result = Some(("hello".to_string(), vec!["message-1".to_string()], 0));
        app.pending_scroll_message_id = None;
        app.navigate_search_result(false);
        assert_eq!(app.pending_scroll_message_id, Some("message-1".to_string()));
        assert_eq!(
            app.search_result,
            Some(("hello".to_string(), vec!["message-1".to_string()], 0))
        );
    }

    #[test]
    fn selection_text_drops_frame_and_decoration_cells() {
        let rows = vec![
            "┌ 房间 ┐".to_string(),
            "│► 群聊一号●│".to_string(),
            "│          │".to_string(),
        ];
        // Box selection spanning entire panels: tab frame lines, selection arrows, online dots, and background whitespace must not enter the clipboard
        assert_eq!(
            extract_selected_screen_text(&rows, (0, 0), (12, 2)),
            "房间\n群聊一号"
        );
    }

    #[test]
    fn search_mode_up_down_keys_navigate_matches_with_any_modifiers() {
        // Directly feed composed key events to verify that up/down keys in search mode are taken over by match item switching:
        // all three reporting forms — no modifier, Ctrl, Ctrl+Shift — must work (different terminals give inconsistent combined key forms)
        let mut app = chat_page_app_for_render("default");
        app.input_collector.message_input_state.set_text("#hello");
        app.messages.push(MessageInfo {
            id: "message-3".to_string(),
            room_id: "room-one".to_string(),
            sender_id: "user-other".to_string(),
            content: "hello again".to_string(),
            created_at: "2026-08-30T08:02:00+00:00".to_string(),
        });
        app.search_result = Some((
            "hello".to_string(),
            vec!["message-1".to_string(), "message-3".to_string()],
            0,
        ));

        for modifiers in [
            KeyModifiers::NONE,
            KeyModifiers::CONTROL,
            KeyModifiers::CONTROL | KeyModifiers::SHIFT,
        ] {
            let before = app
                .search_result
                .as_ref()
                .map(|(_, _, selected)| *selected)
                .unwrap();
            app.handle_event(&Event::Key(crossterm::event::KeyEvent::new(
                KeyCode::Down,
                modifiers,
            )));
            let after = app
                .search_result
                .as_ref()
                .map(|(_, _, selected)| *selected)
                .expect("搜索结果应仍在");
            assert_ne!(before, after, "修饰键 {modifiers:?} 下按 ↓ 未切换匹配项");
            assert!(
                app.pending_scroll_message_id.is_some(),
                "切换后要标记待定位的消息"
            );
        }
        // Pressing again on the last match should wrap to the first
        assert_eq!(app.search_result.as_ref().unwrap().2, 1);
        app.handle_event(&Event::Key(crossterm::event::KeyEvent::new(
            KeyCode::Down,
            KeyModifiers::NONE,
        )));
        assert_eq!(app.search_result.as_ref().unwrap().2, 0);
        // Arrow keys must not change the room selection (room switching in search mode is handled by other operations)
        assert_eq!(app.rooms_state.selected(), Some(0));
    }

    #[test]
    fn pasted_text_with_carriage_returns_yields_clean_new_lines() {
        // Pasted line endings in macOS Terminal.app are \r\n; the \r must not be left in the text buffer
        let mut app = chat_page_app_for_render("default");
        app.handle_pasted_text("第一行\r\n第二行\r\n第三行");
        assert_eq!(
            app.input_collector.message_input_state.text(),
            "第一行\n第二行\n第三行"
        );
        assert!(
            !app.input_collector
                .message_input_state
                .text()
                .contains('\r'),
            "粘贴结果里不应残留回车符"
        );
        // Bare \r (old Mac line ending) converted to newline; other control characters (like bell \u{7}) are discarded directly
        assert_eq!(normalize_pasted_text("a\rb\u{7}c"), "a\nbc");
        // Tab characters belong to editable body content and are kept
        assert_eq!(normalize_pasted_text("a\tb"), "a\tb");
    }

    #[test]
    fn pasted_multiline_text_goes_into_the_input_box_without_sending() {
        let mut app = chat_page_app_for_render("default");
        let message_count_before = app.messages.len();
        app.handle_pasted_text("第一行\n第二行\n第三行");
        // All three rows stay in the input box; newline does not trigger sending
        assert_eq!(
            app.input_collector.message_input_state.text(),
            "第一行\n第二行\n第三行"
        );
        assert_eq!(app.messages.len(), message_count_before);
    }

    #[test]
    fn rendering_reserves_the_bottom_terminal_row() {
        // Leaving the bottom row empty avoids the terminal auto-scrolling due to writing in the bottom-right corner, thus no more full-screen misalignment
        assert_eq!(drawable_area(Rect::new(0, 0, 120, 36)).height, 35);
        assert_eq!(drawable_area(Rect::new(0, 0, 120, 1)).height, 1);
        let mut app = chat_page_app_for_render("default");
        let buffer = render_snapshot(&mut app, 120, 36);
        assert!(
            (0..120u16).all(|column| buffer[(column, 35u16)].symbol() == " "),
            "最底行应保持空白"
        );
        assert_eq!(app.screen_text_rows.len(), 35);
    }

    #[test]
    fn quick_search_scans_loaded_messages_without_enter() {
        let mut app = chat_page_app_for_render("default");
        app.quick_search = true;
        app.input_collector.message_input_state.set_text("#hello");
        app.apply_quick_search();
        let (keyword, matched, selected) = app
            .search_result
            .clone()
            .expect("快速搜索应随输入立即出结果");
        assert_eq!(keyword, "hello");
        assert_eq!(matched, vec!["message-1".to_string()]);
        assert_eq!(selected, 0);
        // Quick search does not trigger whole-room page fetching, so no "fetching history" prompt is left
        assert!(app.notifications.is_empty());

        // When the keyword is cleared, return to the unsearched state: results are all invalidated, the title no longer shows progress
        app.input_collector.message_input_state.set_text("#");
        app.apply_quick_search();
        assert!(app.search_result.is_none());
        assert!(app.pending_scroll_message_id.is_none());
    }

    #[test]
    fn esc_from_any_overlay_returns_to_the_settings_menu() {
        let mut app = chat_page_app_for_render("default");
        for overlay in [
            DisplayingOverlay::Login,
            DisplayingOverlay::Register,
            DisplayingOverlay::CreateGroup,
            DisplayingOverlay::CreatePrivate,
            DisplayingOverlay::ServerAddress,
            DisplayingOverlay::LanguageSelect,
            DisplayingOverlay::AppearanceSelect,
            DisplayingOverlay::PendingRequests,
        ] {
            app.displaying_overlay = overlay.clone();
            app.dismiss_overlay_back();
            assert_eq!(
                app.displaying_overlay,
                DisplayingOverlay::SettingsMenu,
                "{overlay:?} 的 Esc 应退回设置菜单"
            );
        }
        // Going back one more level from the settings menu is the chat page without overlays
        app.dismiss_overlay_back();
        assert_eq!(app.displaying_overlay, DisplayingOverlay::Nothing);
    }

    #[test]
    fn rendered_screen_paints_theme_background_over_the_whole_frame() {
        let mut app = chat_page_app_for_render("high-contrast");
        let buffer = render_snapshot(&mut app, 120, 36);
        // Background covers the entire screen: the vast majority of cells in 120x36 should have the theme's application background color
        let painted_cells = buffer
            .content
            .iter()
            .filter(|cell| cell.bg == Color::Black)
            .count();
        assert!(
            painted_cells > 120 * 36 / 2,
            "应用背景未铺满整屏，仅 {painted_cells} 个单元格着色"
        );
        // Row 0 is the top bar; the room list top-left corner border starts from row 1 (white under high-contrast)
        assert_eq!(buffer[(0u16, 1u16)].fg, Color::White);
    }

    #[test]
    fn rendered_screen_highlights_search_matches_with_theme_background() {
        let mut app = chat_page_app_for_render("high-contrast");
        // Add one more message that also matches hello, to distinguish the "other matches" color from the "current match" color
        app.messages.push(MessageInfo {
            id: "message-3".to_string(),
            room_id: "room-one".to_string(),
            sender_id: "user-other".to_string(),
            content: "hello once more".to_string(),
            created_at: "2026-08-30T08:02:00+00:00".to_string(),
        });
        // Enter search mode and execute a search once: two matches, currently stopped at the first one
        app.input_collector.message_input_state.set_text("#hello");
        app.search_result = Some((
            "hello".to_string(),
            vec!["message-1".to_string(), "message-3".to_string()],
            0,
        ));
        let buffer = render_snapshot(&mut app, 120, 36);
        // Other matches use search_match_background (light_yellow), the current one uses
        // search_current_match_background (light_red), each only covers those few characters of the keyword
        assert_eq!(
            cells_with_background(&buffer, Color::LightYellow),
            "hello".to_string()
        );
        let current_rows = rows_with_background(&buffer, Color::LightRed);
        let other_rows = rows_with_background(&buffer, Color::LightYellow);
        assert_eq!(current_rows.len(), 1, "只应有一条命中被标成当前色");
        assert_eq!(other_rows.len(), 1, "只应有一条命中保持普通命中色");
        assert!(
            current_rows[0] < other_rows[0],
            "当前停在第一条命中，特殊色应出现在更靠上的行"
        );
        // Switch to the second match: the two colors swap positions, proving the "current" marker follows the selected item
        app.search_result = Some((
            "hello".to_string(),
            vec!["message-1".to_string(), "message-3".to_string()],
            1,
        ));
        let swapped_buffer = render_snapshot(&mut app, 120, 36);
        assert_eq!(
            rows_with_background(&swapped_buffer, Color::LightRed),
            other_rows
        );
        assert_eq!(
            rows_with_background(&swapped_buffer, Color::LightYellow),
            current_rows
        );
        // The input box title gives the match progress
        assert!(buffer_contains(&buffer, "搜索模式: 第 1/2 个匹配项"));
        // Search mode border takes search_border (light_red under high-contrast)
        assert!(buffer.content.iter().any(|cell| cell.fg == Color::LightRed));
    }

    #[test]
    fn search_mode_without_match_reports_not_found_and_plain_mode_does_not_highlight() {
        let mut app = chat_page_app_for_render("high-contrast");
        app.input_collector
            .message_input_state
            .set_text("#nosuchword");
        app.search_result = Some(("nosuchword".to_string(), Vec::new(), 0));
        let buffer = render_snapshot(&mut app, 120, 36);
        assert!(buffer_contains(&buffer, "搜索模式: 未找到"));
        // When there is no match there should be no search highlight
        assert!(cells_with_background(&buffer, Color::LightYellow).is_empty());

        // Normal mode (input does not start with #) does not highlight even with residual old results
        let mut plain_app = chat_page_app_for_render("high-contrast");
        plain_app
            .input_collector
            .message_input_state
            .set_text("hello");
        plain_app.search_result = Some(("hello".to_string(), vec!["message-1".to_string()], 0));
        let plain_buffer = render_snapshot(&mut plain_app, 120, 36);
        assert!(cells_with_background(&plain_buffer, Color::LightYellow).is_empty());
        assert!(buffer_contains(&plain_buffer, "消息输入"));
    }

    #[test]
    fn message_area_title_shows_who_is_typing() {
        let mut app = chat_page_app_for_render("high-contrast");
        app.typing_members
            .push(("room-one".to_string(), "bob".to_string(), Instant::now()));
        let buffer = render_snapshot(&mut app, 120, 36);
        assert!(buffer_contains(&buffer, "bob 正在输入"));
        // Typing status of members in other rooms should not display on the current room title
        let mut other_room_app = chat_page_app_for_render("high-contrast");
        other_room_app.typing_members.push((
            "room-two".to_string(),
            "bob".to_string(),
            Instant::now(),
        ));
        let other_room_buffer = render_snapshot(&mut other_room_app, 120, 36);
        assert!(!buffer_contains(&other_room_buffer, "正在输入"));
    }

    #[test]
    fn private_room_in_list_is_marked_by_peer_presence() {
        let mut app = chat_page_app_for_render("high-contrast");
        app.rooms.push(RoomInfo {
            id: "room-private".to_string(),
            name: None,
            is_group: false,
            created_by: "user-other".to_string(),
            members: vec!["user-self".to_string(), "user-other".to_string()],
            is_encrypted: false,
            created_at: String::new(),
        });
        // The top bar connection marker is also a solid dot, so here everything is asserted as a whole of "room name + marker",
        // Avoid mistaking the dot in the status bar as an online indicator for the room list
        // Private chats display as the localized "private" text in the list; the marker is pasted right after it
        let private_room_label = app.t("private_chat_fallback");
        let peer_line = |mark: &str| format!("{private_room_label} {mark}");
        let unknown_buffer = render_snapshot(&mut app, 120, 36);
        assert!(!buffer_contains(&unknown_buffer, &peer_line("●")));
        assert!(!buffer_contains(&unknown_buffer, &peer_line("○")));
        // After receiving online broadcasts, mark with a solid dot; after going offline, mark with a hollow dot
        app.presence_by_user.insert("user-other".to_string(), true);
        let online_buffer = render_snapshot(&mut app, 120, 36);
        assert!(buffer_contains(&online_buffer, &peer_line("●")));
        app.presence_by_user.insert("user-other".to_string(), false);
        let offline_buffer = render_snapshot(&mut app, 120, 36);
        assert!(buffer_contains(&offline_buffer, &peer_line("○")));
        assert!(!buffer_contains(&offline_buffer, &peer_line("●")));
    }

    #[test]
    fn switching_appearance_changes_every_coloured_slot() {
        // The same content rendered with two different appearances; the border color must switch with the theme
        let mut built_in_app = chat_page_app_for_render("default");
        let built_in_buffer = render_snapshot(&mut built_in_app, 120, 36);
        assert_eq!(built_in_buffer[(0u16, 1u16)].fg, Color::Cyan);

        let mut light_app = chat_page_app_for_render("light");
        let light_buffer = render_snapshot(&mut light_app, 120, 36);
        assert_eq!(light_buffer[(0u16, 1u16)].fg, Color::Rgb(138, 127, 109));
        assert_eq!(light_buffer[(59u16, 20u16)].bg, Color::Rgb(239, 235, 226));
    }
}
