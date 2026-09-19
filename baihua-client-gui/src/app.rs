//! The main GUI interface. Layout follows the TUI: top status bar, left room list, middle chat history, bottom input box.
//!
//! Three places different from the TUI:
//! 1. A "settings" switch is placed below the room list; the settings panel is a right-side collapsible panel (native slide-in animation);
//! 2. A "command" switch is placed at the top-right of the message area; the command panel slides in from right to left, clicking the empty area of the message area or pressing the switch again slides it out;
//! 3. The message display area has avatars. Login/registration are centered standalone pages.
//!
//! Implementation convention: no interface closure touches `self` (it would conflict with the outer borrow); anything needing read/write is computed first,
//! or borrow the field separately first; the closure only uses local variables.

use crate::appearance::{AvatarTextures, Skin, contrasting_foreground};
use crate::client::Client;
use crate::client_actions::UiIntent;
use baihua_core::config;
use egui::style::ScrollAnimation;
use egui::{
    Align, Align2, Button, Color32, Context, Event, Frame, Id, Key, KeyboardShortcut, Margin,
    Modal, Modifiers, Pos2, Rect, Response, RichText, ScrollArea, Sense, Stroke, TextEdit, Ui,
    Vec2, Window,
};
use std::path::PathBuf;
use std::time::Duration;

/// The side length (in pixels) of the avatar block in the message area. The TUI uses half-characters to make 32×32; here we use pixel blocks of the same size.
fn avatar_side_pixels() -> usize {
    32
}

/// The side length of the avatar block in the profile card (pixels), one size larger than in message rows
fn profile_avatar_side_pixels() -> usize {
    64
}

/// Focus identifier for the message input box: the input box itself and the check "is focus on it" share this single source
fn message_input_id() -> &'static str {
    "message-input"
}

/// Identifier for the input area at the bottom of the message area. It occupies a position at the bottom first, so it needs its own panel identifier.
fn conversation_input_area_id() -> &'static str {
    "conversation-input"
}

/// The text on the plus button to the right of the room list title
fn create_menu_button_text() -> &'static str {
    "+"
}

/// Button text for the settings entry (the gear to the right of the room title)
pub(crate) fn settings_button_text() -> &'static str {
    "\u{2699}"
}

/// Width range of the left room list (points): too narrow squeezes the room name and unread badge out of view; too wide squeezes the message area out of view.
/// With upper and lower limits given, the "temporary squeeze" from the window being made smaller will not become a permanent width--
/// egui panels remember the size from the previous frame; without a lower limit, a squeezed size will be retained forever,
/// this is the full story of "the sidebar cannot be reset after being squeezed".
fn room_panel_size_range() -> std::ops::RangeInclusive<f32> {
    160.0..=360.0
}

/// Settings window identifier (window position and collapsed state are remembered by it)
fn settings_window_id() -> &'static str {
    "settings-window"
}

/// Default size of the settings window (points)
fn settings_window_width() -> f32 {
    460.0
}

fn settings_window_height() -> f32 {
    560.0
}

/// How far the settings window is from the top-left corner of the screen by default (points)
fn settings_window_offset() -> f32 {
    140.0
}

/// Unified appearance for all overlay windows: theme background color and stroke + **small corner radius**.
/// Previously each window wrote its own `Frame::new()` (right angles), which looked out of place with the theme.
fn overlay_window_frame(skin: &Skin) -> Frame {
    Frame::new()
        .fill(skin.app_background)
        .stroke(Stroke::new(1.0, skin.overlay_border))
        .corner_radius(overlay_window_corner_radius())
        .inner_margin(Margin::same(10))
}

/// Corner radius for overlay windows (points): small radius, more convergent than the window's own corner radius
fn overlay_window_corner_radius() -> f32 {
    6.0
}

/// Left room list panel: stretchable, with width limits.
/// Taken out separately so it can be tested independently for "whether it can be reset after being squeezed".
fn room_panel_default_size() -> f32 {
    220.0
}

fn room_panel(skin: &Skin) -> egui::Panel {
    egui::Panel::left("room-list")
        .resizable(true)
        .size_range(room_panel_size_range())
        .default_size(room_panel_default_size())
        .frame(
            Frame::new()
                .fill(skin.app_background)
                .stroke(Stroke::new(1.0, skin.room_border))
                .inner_margin(Margin::same(8)),
        )
}

/// Height of the message input box (points). Both drawing the input box and reserving space for it use this,
/// So the "reserved height" and the "actually drawn height" don't mismatch.
fn message_input_height() -> f32 {
    48.0
}

/// How tall the input completion tooltip occupies (points): commands are listed in full; if it exceeds this height, scroll inside
fn command_completion_height() -> f32 {
    132.0
}

/// Gap left between the completion tooltip and the input box (points)
fn command_completion_gap() -> f32 {
    4.0
}

/// The identifier for the completion popup floating layer (it's a floating layer that doesn't take layout space; scroll position is remembered by this identifier)
fn command_completion_area_id() -> &'static str {
    "command-completions"
}

/// The judgment margin (in points) for "the message display area has reached the very top": an offset less than or equal to this counts as touching the top.
/// Judging strictly by 0 would miss it due to floating-point error in the scroll animation; keeping a small margin is most stable.
fn conversation_scroll_top_threshold() -> f32 {
    1.0
}

/// Whether the message display area has scrolled to the very top and can automatically pull earlier messages from the server.
///
/// Both conditions are indispensable: the content must actually exceed the visible height (there must be room to scroll),
/// and the current offset must already be touching the top. Without the first condition, short sessions where "the content never exceeded" would
/// have an offset of 0 every frame and would be misjudged as repeatedly touching the top.
fn conversation_reached_top(content_height: f32, viewport_height: f32, offset_y: f32) -> bool {
    content_height > viewport_height + conversation_scroll_top_threshold()
        && offset_y <= conversation_scroll_top_threshold()
}

/// After drawing this frame, whether the positioning request should be cleared: only clear it when "this frame really handed it to the scroll region".
///
/// Switching to a search match happens after the message area is drawn (the key press is eaten by the input area,
/// the selection change has to wait for the closure to end), so that positioning request has to wait until the next frame to take effect;
/// clearing it as a side effect would make scrolling never happen. Conversely, when a new target is produced in the same frame,
/// the new one can't be cleared either, so judge by "whether the target has changed".
fn scroll_request_is_consumed(
    consumed_this_frame: Option<&str>,
    pending_after_this_frame: Option<&str>,
) -> bool {
    consumed_this_frame.is_some() && consumed_this_frame == pending_after_this_frame
}

/// The sum of the top and bottom padding of the input area panel (consistent with the panel `Frame`'s `Margin::symmetric(0, 4)`),
/// plus a tiny bit for the separator line.
fn conversation_input_padding() -> f32 {
    8.0 + 1.0
}

/// The height used when the input area panel is drawn for the first time (the frame where the panel hasn't remembered its own height yet).
///
/// The input area now only has the "input box" row (the shortcut hint has been removed per the developer's request),
/// so it's accurate enough to calculate as "input box + panel padding": once the panel height is recorded it won't shrink on its own,
/// making it too large would always leave a blank space; making it too small would just squeeze it the first frame, and the next frame would use the real content height
// (the extra height from the "someone is typing" row and the completion popup also follows this self-correction path).
fn conversation_input_initial_height(ui: &Ui) -> f32 {
    let _ = ui;
    message_input_height() + conversation_input_padding()
}

/// Which page the login/registration page is currently on
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AuthPage {
    Login,
    Register,
}

/// Which form the create window currently has open
#[derive(Clone, Copy, PartialEq, Eq)]
enum CreationPage {
    /// Create group chat: group name + members (comma-separated)
    Group,
    /// Create private chat: the other person's username
    Private,
}

/// Expandable sections in the settings panel
#[derive(Clone, Copy, Default)]
struct Sections {
    profile: bool,
    password: bool,
    avatar: bool,
    requests: bool,
    account: bool,
    server: bool,
}

/// A laid-out message row (compute data first, then draw, to avoid simultaneously borrowing self in the interface closure).
/// Cloneable: tests need to feed the same rows repeatedly into the draw function (the real interface also computes a fresh one every frame).
#[derive(Clone)]
struct MessageRow {
    /// The primary key of the message itself: when a search match occurs, the interface uses it to scroll this row into view
    message_id: String,
    /// The sender's user ID (use this to look up when clicking their avatar for the profile; display names may duplicate or change, ID will not)
    sender_id: String,
    sender: String,
    content: String,
    time_text: String,
    is_own: bool,
    /// Body text color (the foreground color from the theme, or the contrast color of the highlight background on match)
    content_color: Color32,
    /// The highlight background color behind the text (only on search match; the two slots in the theme are inherently "background colors")
    content_highlight: Option<Color32>,
    texture: Option<egui::TextureHandle>,
}

/// A room list row
struct RoomRow {
    index: usize,
    label: String,
    id: String,
    unread_badge: Option<String>,
}

pub struct BaihuaApp {
    /// Session layer: connections, data, and all server-side actions
    client: Client,
    /// Color set derived from the theme
    skin: Skin,
    /// Avatar texture cache
    avatars: AvatarTextures,
    /// Whether the settings panel is expanded (entry is at the bottom-left of the group display area, left of the input box)
    settings_open: bool,
    /// The centered page displayed when not logged in
    auth_page: Option<AuthPage>,
    /// Profile card
    profile_card_open: bool,
    /// Which command is selected in the input completion popup (switch with up/down arrow keys; prefix change goes back to the first)
    completion_selection: usize,
    /// Whether the create group/private chat window is open, and which one (entry is in the plus button to the right of the room list title)
    creation_page: Option<CreationPage>,
    sections: Sections,
    login_name: String,
    login_password: String,
    register_name: String,
    register_email: String,
    register_password: String,
    server_address: String,
    profile_nickname: String,
    profile_phone: String,
    profile_bio: String,
    password_old: String,
    password_new: String,
    password_repeat: String,
    avatar_url: String,
    delete_password: String,
    group_name: String,
    group_members: String,
    private_target: String,
    /// Hand keyboard focus back to the message input box next frame
    focus_message_input: bool,
}

impl BaihuaApp {
    /// Establish a session and start background threads: first restore the last login session, then probe the server
    pub fn new(context: &Context) -> Self {
        let mut client = Client::start();
        client.open_event_channel();
        client.probe_server_at_startup();
        client.start_reachability_watch();
        let restored = client.try_auto_login();
        if !restored {
            client.notify_signed_out();
        }
        let skin = Skin::from(&client.palette);
        skin.apply_to(context);
        // Install a set of CJK fonts: egui's built-in fonts have no CJK glyphs; without them all Chinese text on the interface would be tofu blocks.
        // Install only once, and use this font table for every subsequent frame's drawing.
        crate::appearance::install_cjk_font(context);
        Self {
            client,
            skin,
            avatars: AvatarTextures::default(),
            settings_open: false,
            auth_page: if restored {
                None
            } else {
                Some(AuthPage::Login)
            },
            profile_card_open: false,
            completion_selection: 0,
            creation_page: None,
            sections: Sections::default(),
            login_name: String::new(),
            login_password: String::new(),
            register_name: String::new(),
            register_email: String::new(),
            register_password: String::new(),
            server_address: String::new(),
            profile_nickname: String::new(),
            profile_phone: String::new(),
            profile_bio: String::new(),
            password_old: String::new(),
            password_new: String::new(),
            password_repeat: String::new(),
            avatar_url: String::new(),
            delete_password: String::new(),
            group_name: String::new(),
            group_members: String::new(),
            private_target: String::new(),
            // Only put the cursor into the message box when auto-login succeeds (no centered login page blocking)
            focus_message_input: restored,
        }
    }

    fn text(&self, key: &str) -> String {
        self.client.text(key)
    }

    /// The theme may have just been switched: recalculate colors and write back to egui visuals
    fn refresh_skin(&mut self, context: &Context) {
        self.skin = Skin::from(&self.client.palette);
        self.skin.apply_to(context);
    }

    fn apply_intent(&mut self, intent: UiIntent) {
        match intent {
            UiIntent::Quit | UiIntent::QuitForUpdate => self.client.quit_requested = true,
            UiIntent::ShowOwnProfile => self.profile_card_open = true,
            UiIntent::OpenSettings => self.settings_open = true,
            UiIntent::OpenSignIn(username) => {
                if let Some(username) = username {
                    self.login_name = username;
                }
                self.auth_page = Some(AuthPage::Login);
            }
            UiIntent::OpenSignUp(username) => {
                if let Some(username) = username {
                    self.register_name = username;
                }
                self.auth_page = Some(AuthPage::Register);
            }
            UiIntent::Nothing => {}
        }
    }

    // ==================== Per-frame Logic (Don't Draw Interface) ====================

    fn run_logic(&mut self, context: &Context) {
        self.client.tick();
        while let Some(event) = self.client.next_event() {
            self.client.apply_event(event);
        }
        if self.client.is_signed_in() {
            self.client.report_typing();
        }
        if self.client.quit_requested {
            context.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        // Panel animations and input state decay both need frame-driven updates; here we give a sufficiently fast beat
        context.request_repaint_after(Duration::from_millis(120));
    }

    /// Global shortcut: collapse floating layers (Esc).
    /// Enter is not handled here: sending is determined by the message input box itself based on "whether focus is on it", otherwise in another input box
    /// Pressing Enter would accidentally send a chat message. Switching matches in search mode uses **ordinary up/down arrow keys**,
    /// Eaten by the input area when handling key presses (see `draw_message_input_area`); not here.
    fn handle_shortcuts(&mut self, context: &Context) {
        let escape = context.input(|state| state.key_pressed(Key::Escape));
        if escape {
            if self.creation_page.is_some() {
                self.creation_page = None;
            } else if self.profile_card_open {
                self.profile_card_open = false;
            } else if self.settings_open {
                self.settings_open = false;
            }
        }
    }

    // ==================== Top Bar ====================

    fn draw_status_bar(&mut self, ui: &mut Ui) {
        let skin = self.skin.clone();
        let (connection_label, mark, user_text, right_text) = self.client.status_bar_texts();
        let mark_color = if self.client.connection_ready == Some(true) {
            skin.own_username_text
        } else {
            skin.notice_error_border
        };
        egui::Panel::top("status-bar")
            .resizable(false)
            .frame(
                Frame::new()
                    .fill(skin.app_background)
                    .inner_margin(Margin::same(6)),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(connection_label);
                    ui.colored_label(mark_color, mark);
                    // The current-user segment arrives with its own leading separator inside the text
                    // (same shape as the terminal version): no `ui.separator()` here, an extra one would
                    // be drawn as a vertical bar as tall as the whole panel area.
                    if !user_text.is_empty() {
                        ui.label(user_text);
                    }
                    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                        ui.colored_label(skin.hint_text, right_text);
                    });
                });
            });
    }

    // ==================== Left: Room List and Settings Switch ====================

    fn room_rows(&self) -> Vec<RoomRow> {
        self.client
            .room_entries()
            .iter()
            .enumerate()
            .map(|(index, entry)| RoomRow {
                index,
                label: if entry.encrypted {
                    format!("{} [{}]", entry.title, self.text("encrypted_badge"))
                } else {
                    entry.title.clone()
                },
                id: entry.id.clone(),
                unread_badge: match (entry.unread, entry.muted) {
                    (0, _) => None,
                    (count, false) => Some(count.to_string()),
                    (_, true) => Some("·".to_string()),
                },
            })
            .collect()
    }

    fn draw_room_panel(&mut self, ui: &mut Ui) {
        let skin = self.skin.clone();
        let rows = self.room_rows();
        let selected = self.client.selected_room_index;
        let empty_label = self.text("rooms_empty");
        let list_title = self.text("room_list_title");
        let create_group_title = self.text("create_group_title");
        let create_private_title = self.text("create_private_title");
        let settings_title = self.text("settings_title");
        let login_title = self.text("option_login");
        let signed_in = self.client.is_signed_in();
        let mut picked: Option<usize> = None;
        let mut open_login_page = false;
        let mut open_creation_page: Option<CreationPage> = None;
        let mut toggle_settings = false;
        room_panel(&skin).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.colored_label(skin.room_border, list_title);
                // To the right of the title are the gear (settings window) and plus (create group/private chat), in order:
                // Clicking the plus button expands the selection list; selecting an item opens the corresponding creation window
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    open_creation_page =
                        draw_creation_menu(ui, &create_group_title, &create_private_title);
                    // Gear and plus side by side: both are ordinary buttons; color and hover/press feedback are both uniformly provided by the theme
                    if ui
                        .button(settings_button_text())
                        .on_hover_text(settings_title)
                        .clicked()
                    {
                        toggle_settings = true;
                    }
                });
            });
            ui.separator();
            ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    let had_rooms = !rows.is_empty();
                    for row in rows {
                        ui.horizontal(|ui| {
                            let response = ui
                                .selectable_label(selected == Some(row.index), row.label)
                                .on_hover_text(row.id);
                            if response.clicked() {
                                picked = Some(row.index);
                            }
                            if let Some(badge) = row.unread_badge {
                                ui.colored_label(skin.notice_error_border, badge);
                            }
                        });
                    }
                    if !had_rooms {
                        ui.colored_label(skin.hint_text, empty_label);
                    }
                });
            ui.separator();
            // The settings entry is the gear to the right of the title (opens the standalone settings window);
            // here only the login entry for when not logged in is kept
            if !signed_in && ui.button(login_title).clicked() {
                open_login_page = true;
            }
        });
        if let Some(index) = picked {
            self.client.open_room(index);
        }
        if toggle_settings {
            self.settings_open = !self.settings_open;
        }
        if open_login_page {
            self.auth_page = Some(AuthPage::Login);
        }
        if let Some(page) = open_creation_page {
            self.creation_page = Some(page);
        }
    }

    // ==================== Middle: Message Area, Command Panel, Input Box ====================

    /// First compute what each message needs to draw (including textures); the drawing phase only reads local data
    fn message_rows(&mut self, context: &Context) -> Vec<MessageRow> {
        let own_id = self.client.current_user_id.clone().unwrap_or_default();
        let (matches, current_match) = self.client.search_matches();
        let skin = self.skin.clone();
        let with_date = self.client.time_with_date;
        // In an encrypted private chat the server has no body to give (the ciphertext only exists inside the session):
        // the seam reports "this history message has no readable body" as an empty string, and the interface fills in
        // the placeholder text from the language table. Search still scans the raw content, so an empty body never matches.
        let encrypted_history_placeholder = self.text("message_encrypted_history_unavailable");
        self.client
            .messages
            .clone()
            .into_iter()
            .map(|message| {
                let is_own = message.sender_id == own_id;
                let sender = self.client.sender_display_name(&message.sender_id);
                let sender = sender_label(&sender, &message.sender_id, self.client.show_uid);
                let bytes = self
                    .client
                    .avatar_images
                    .get(&message.sender_id)
                    .and_then(|cached| cached.as_ref())
                    .cloned();
                let texture = self.avatars.texture(
                    context,
                    &message.sender_id,
                    bytes.as_deref(),
                    avatar_side_pixels(),
                );
                // Search match: if the theme gives the "match fragment background color", lay it behind the text as intended,
                // swap the text color to the one that contrasts with this background, to avoid light-on-light being unreadable
                let content_highlight = if matches.iter().any(|id| id == &message.id) {
                    Some(if current_match.as_deref() == Some(message.id.as_str()) {
                        skin.search_current_match_background
                    } else {
                        skin.search_match_background
                    })
                } else {
                    None
                };
                let content_color = match content_highlight {
                    Some(background) => contrasting_foreground(background),
                    None if is_own => skin.own_username_text,
                    None => skin.message_text,
                };
                let content: String = if message.content.is_empty() {
                    encrypted_history_placeholder.clone()
                } else {
                    message.content.clone()
                };
                MessageRow {
                    message_id: message.id.clone(),
                    sender_id: message.sender_id.clone(),
                    time_text: format_message_time(&message.created_at, with_date),
                    sender,
                    content,
                    is_own,
                    content_color,
                    content_highlight,
                    texture,
                }
            })
            .collect()
    }

    fn draw_central(&mut self, ui: &mut Ui, context: &Context) {
        let skin = self.skin.clone();
        let title = self.chat_title();
        let border = self.input_border_color();
        let placeholder = self.text("message_input_placeholder");
        let empty_hint = self.text("messages_empty");
        let mut complete_command: Option<String> = None;
        // Whether the message area touched the top this frame (the session layer uses this to automatically pull earlier messages from the server)
        let mut reached_top = false;
        // The message to scroll to for the search match (the session layer gives this once per frame)
        let scroll_to_message = self.client.pending_scroll_message_id.clone();
        let commands: Vec<(&'static str, String)> = crate::command_entries()
            .into_iter()
            .map(|(name, key)| (name, self.text(key)))
            .collect();
        let rows = self.message_rows(context);
        let mut input_view = MessageInputView {
            draft: self.client.draft.clone(),
            placeholder,
            // Fetch all at once: only the frame that "just needs to hand the cursor to the message box" requests focus,
            // Otherwise requesting focus every frame would steal focus from other input boxes the user just clicked
            request_focus: std::mem::take(&mut self.focus_message_input),
            selected_command: self.completion_selection,
        };
        let mut send_from_input_box = false;
        let mut draft_changed = false;
        let mut clicked_avatar: Option<String> = None;
        // In search mode, press up/down arrow keys: jot down in the frame, then apply to the session layer after the closure
        let mut search_step: Option<bool> = None;
        let stick_to_bottom = self.client.pending_scroll_message_id.is_none();

        egui::CentralPanel::default()
            .frame(
                Frame::new()
                    .fill(skin.app_background)
                    .stroke(Stroke::new(1.0, border))
                    .inner_margin(Margin::same(10)),
            )
            .show(ui, |ui| {
                ui.colored_label(skin.message_border, title);
                ui.separator();
                let (_, avatar, top) = draw_conversation_area(
                    ui,
                    &skin,
                    rows,
                    empty_hint,
                    stick_to_bottom,
                    scroll_to_message.clone(),
                    |ui| {
                        let outcome =
                            draw_message_input_area(ui, &skin, &commands, &mut input_view);
                        send_from_input_box = outcome.send;
                        draft_changed = outcome.draft_changed;
                        search_step = outcome.search_step;
                        complete_command = outcome.complete_command;
                    },
                );
                clicked_avatar = avatar;
                reached_top = top;
            });

        self.client.draft = input_view.draft;
        // The selected item in the completion list must be saved across frames: `input_view` is rebuilt each frame based on the current field,
        // if not written back to the interface field, whichever item the up/down arrows selected would be lost by next frame (looks like no response)
        self.completion_selection = input_view.selected_command;
        // In search mode, press up/down arrow keys: switch matches, do not move the cursor in the input box (keys already consumed by the input area)
        if let Some(backwards) = search_step {
            self.client.navigate_search(backwards);
        }
        // Input box content changed: hand it to the session layer to process with the same rules as the terminal version
        // (clear old results when not in search mode; rescan on-the-fly when fast search is on)
        if draft_changed {
            self.client.handle_draft_changed();
        }
        if send_from_input_box {
            let appearance_before = self.client.appearance_name.clone();
            let intent = self.client.submit_draft();
            self.apply_intent(intent);
            self.focus_message_input = true;
            // `/appearance <appearance name>` switches the theme directly at the session layer: after switching, the egui visuals must also be rewritten,
            // otherwise the window appearance would stay on the old theme (the settings panel switch goes through `apply_settings_outcome`, which has already refreshed).
            if self.client.appearance_name != appearance_before {
                self.refresh_skin(context);
            }
        }
        if let Some(user_id) = clicked_avatar {
            // Clicking the avatar is a "user-initiated one-time action", following the same path as /profile:
            // Fetching the profile once synchronously here is allowed (the render path itself doesn't send requests)
            self.client.show_profile_of(&user_id);
            self.profile_card_open = true;
        }
        // Auto-scroll to top: same conditions as the terminal version — there are earlier messages, the message list indeed belongs to the current room,
        // this frame has no other positioning requests (inserting history just after positioning a search match would flush the positioning).
        // Only recognizing "the message primary key belongs to the current room", the cursor of an old room won't be misused when switching rooms before loading is complete.
        let list_matches_room = self.client.messages.last().is_some_and(|message| {
            Some(message.room_id.as_str()) == self.client.current_room_id().as_deref()
        });
        let auto_load_older = reached_top
            && self.client.has_more_older
            && self.client.older_cursor.is_some()
            && self.client.pending_scroll_message_id.is_none()
            && list_matches_room;
        if auto_load_older {
            // First remember the very top message now: after earlier history is inserted, scroll it back into view,
            // both not disturbing the position being read and moving the scroll position away from the top, to avoid repeated requests from a single touch-to-top
            let anchor_message_id = self
                .client
                .messages
                .first()
                .map(|message| message.id.clone());
            self.client.load_older_messages(auto_load_older);
            self.client.pending_scroll_message_id = anchor_message_id;
        }
        // The positioning request is used only once when drawing this frame: the scroll target has already been handed to and remembered by the scroll region,
        // leaving it uncleared would keep the message area pinned to that message. The search match change is written in after drawing,
        // so that request has to wait until the next frame to take effect, which is why only "the one this frame really used" is cleared
        if scroll_request_is_consumed(
            scroll_to_message.as_deref(),
            self.client.pending_scroll_message_id.as_deref(),
        ) {
            self.client.pending_scroll_message_id = None;
        }
        // Completing (Enter fills the selected item, or clicking one item) just fills the command into the input box,
        // Same as the terminal version: whether to actually run the command is decided by the user pressing Enter once more
        if let Some(insert_text) = complete_command {
            self.client.draft = insert_text;
            self.completion_selection = 0;
            self.focus_message_input = true;
        }
    }

    fn chat_title(&self) -> String {
        if self.client.in_search_mode() {
            return match &self.client.search_result {
                None => self.text("search_mode_title"),
                Some((_keyword, matches, _index)) if matches.is_empty() => {
                    self.text("search_mode_no_match")
                }
                Some((_keyword, matches, index)) => {
                    let position = index + 1;
                    let total = matches.len();
                    // Display "the keyword that was already searched", not what's being typed in the input box:
                    // the latter changes with every keystroke; pairing it with old keyword match counts would make people think they're searching for a new word
                    let keyword = match self.client.searched_keyword() {
                        Some(keyword) => keyword.to_string(),
                        None => self.client.search_keyword(),
                    };
                    format!(
                        "{}: {keyword} {position}/{total}",
                        self.text("search_mode_title")
                    )
                }
            };
        }
        let entries = self.client.room_entries();
        let room_title = match self
            .client
            .selected_room_index
            .and_then(|index| entries.get(index))
        {
            Some(entry) => entry.title.clone(),
            None => self.text("chat_history"),
        };
        // Input status follows the group chat name (same location and format as the terminal version):
        // "group name · someone is typing…"; doesn't occupy a message row or interrupt reading
        match self.typing_text() {
            Some(typing) => format!("{room_title} {typing}"),
            None => room_title,
        }
    }

    /// "· someone is typing…" (multiple people separated by commas); return None when no one is typing.
    /// The member list is deduplicated by the session layer (same-name members kept only once); this just selects the text based on the count.
    fn typing_text(&self) -> Option<String> {
        typing_text(
            &self.text("typing_one"),
            &self.text("typing_multiple"),
            &self.client.typing_names(),
        )
    }

    fn input_border_color(&self) -> Color32 {
        if self.client.in_search_mode() {
            self.skin.search_border
        } else if self.client.draft.trim_start().starts_with('/') {
            self.skin.command_border
        } else {
            self.skin.input_border
        }
    }

    // ==================== Settings Panel ====================

    /// Settings window: a standalone floating layer, no longer occupying the message display area (entry is the gear to the right of the room title).
    /// The window has slide-in/slide-out and collapse; when content is too tall, the inside of the window scrolls.
    fn draw_settings_window(&mut self, context: &Context) {
        let skin = self.skin.clone();
        let title = self.text("settings_title");
        let mut open = self.settings_open;
        Window::new(title)
            .id(Id::new(settings_window_id()))
            .open(&mut open)
            .collapsible(true)
            .resizable(true)
            .default_pos([settings_window_offset(), settings_window_offset()])
            .default_size([settings_window_width(), settings_window_height()])
            .max_height(settings_window_height())
            .scroll(true)
            .frame(overlay_window_frame(&skin))
            .show(context, |ui| {
                let mut view = self.state_view();
                let outcome = draw_settings_form(ui, &skin, &mut view);
                let fields = view.fields;
                self.apply_settings_fields(fields);
                self.apply_settings_outcome(outcome, ui.ctx());
            });
        self.settings_open = open;
    }

    /// Take a snapshot of the fields the settings panel needs to read (avoid borrowing the entire self in the interface closure)
    /// Text box content the settings panel needs to read and write (the panel closure doesn't touch self, so take it out first and write it back)
    fn settings_fields(&self) -> SettingsFields {
        SettingsFields {
            profile_nickname: if self.profile_nickname.is_empty() {
                self.client.profile_nickname_draft.clone()
            } else {
                self.profile_nickname.clone()
            },
            profile_phone: self.profile_phone.clone(),
            profile_bio: if self.profile_bio.is_empty() {
                self.client.profile_bio_draft.clone()
            } else {
                self.profile_bio.clone()
            },
            password_old: self.password_old.clone(),
            password_new: self.password_new.clone(),
            password_repeat: self.password_repeat.clone(),
            avatar_url: self.avatar_url.clone(),
            delete_password: self.delete_password.clone(),
            server_address: if self.server_address.is_empty() {
                self.client.connector.base_url().to_string()
            } else {
                self.server_address.clone()
            },
        }
    }

    fn state_view(&self) -> SettingsView {
        SettingsView {
            settings_title: self.text("settings_title"),
            language_title: self.text("option_language"),
            appearance_title: self.text("option_appearance"),
            show_uid: self.client.show_uid,
            show_uid_title: self.text("option_show_uid"),
            time_with_date: self.client.time_with_date,
            time_title: self.text("option_time_format"),
            quick_search: self.client.quick_search,
            quick_title: self.text("option_quick_search"),
            sound_enabled: self.client.sound_enabled,
            sound_title: self.text("option_sound_enabled"),
            avatar_title: self.text("option_change_avatar"),
            avatar_choices: Client::avatar_choices(),
            avatar_directory: Client::avatar_directory().map(|path| path.display().to_string()),
            avatar_empty_hint: self.text("hint_avatar_directory_empty"),
            avatar_input_label: self.text("avatar_input_label"),
            profile_title: self.text("option_edit_profile"),
            profile_hint: self.text("form_profile_hint"),
            nickname_label: self.text("profile_nickname_label"),
            phone_label: self.text("profile_phone_label"),
            bio_label: self.text("profile_bio_label"),
            password_title: self.text("option_change_password"),
            old_label: self.text("password_old_label"),
            new_label: self.text("password_new_label"),
            repeat_label: self.text("password_repeat_label"),
            requests_title: self.text("option_pending_requests"),
            requests_empty: self.text("no_pending_requests"),
            received_title: self.text("request_section_received"),
            sent_title: self.text("request_section_sent"),
            accept_title: self.text("button_accept"),
            decline_title: self.text("button_decline"),
            cancel_title: self.text("button_cancel"),
            account_title: self.text("option_delete_account"),
            delete_hint: self.text("form_delete_hint"),
            server_title: self.text("option_server_address"),
            server_hint: self.text("hint_server_address"),
            update_title: self.text("option_update_client"),
            logout_title: self.text("option_logout"),
            confirm_title: self.text("button_confirm"),
            save_title: self.text("button_save"),
            current_language: config::preference_string("language", "zh-CN"),
            language_codes: config::Language::available_codes(),
            current_appearance: self.client.appearance_name.clone(),
            appearance_names: config::Palette::available_names(),
            request_rows: self.request_rows(),
            pending_count: self.client.pending_request_count(),
            sections: self.sections,
            fields: self.settings_fields(),
        }
    }

    /// Convert a private chat request entry into interface data (including "whether it can still be operated")
    fn request_rows(&self) -> Vec<RequestRow> {
        self.client
            .request_entries()
            .into_iter()
            .map(|(is_sent, request)| {
                let peer = if is_sent {
                    request.receiver
                } else {
                    request.sender
                };
                let status = request
                    .status
                    .as_ref()
                    .map(|status| self.client.request_status_label(status))
                    .unwrap_or_default();
                let actionable = match request.status.as_deref() {
                    None => !is_sent,
                    Some("pending") => true,
                    _ => false,
                };
                RequestRow {
                    id: request.id,
                    is_sent,
                    peer: peer
                        .map(|peer| peer.username)
                        .unwrap_or_else(|| self.text("unknown_user")),
                    status,
                    message: request.message,
                    actionable,
                    cancellable: is_sent && request.status.as_deref() == Some("pending"),
                }
            })
            .collect()
    }

    /// Write the text modified in the panel back to the interface state (input content can't be lost because of a redraw this frame)
    fn apply_settings_fields(&mut self, fields: SettingsFields) {
        self.profile_nickname = fields.profile_nickname;
        self.profile_phone = fields.profile_phone;
        self.profile_bio = fields.profile_bio;
        self.password_old = fields.password_old;
        self.password_new = fields.password_new;
        self.password_repeat = fields.password_repeat;
        self.avatar_url = fields.avatar_url;
        self.delete_password = fields.delete_password;
        self.server_address = fields.server_address;
    }

    /// Apply the actions the settings panel hands back to the session layer
    fn apply_settings_outcome(&mut self, outcome: SettingsOutcome, context: &Context) {
        match outcome {
            SettingsOutcome::Nothing => {}
            SettingsOutcome::Language(code) => {
                self.client.switch_language(&code);
                self.refresh_skin(context);
            }
            SettingsOutcome::Appearance(name) => {
                self.client.switch_appearance(&name);
                self.refresh_skin(context);
            }
            SettingsOutcome::Toggles {
                show_uid,
                time_with_date,
                quick_search,
                sound_enabled,
            } => {
                self.client.show_uid = show_uid;
                self.client.time_with_date = time_with_date;
                self.client.quick_search = quick_search;
                self.client.sound_enabled = sound_enabled;
                self.client.write_display_preferences();
            }
            SettingsOutcome::Sections(sections) => {
                let opened_profile = sections.profile && !self.sections.profile;
                self.sections = sections;
                if opened_profile {
                    self.client.prepare_profile_form();
                }
            }
            SettingsOutcome::AvatarFile(path) => {
                self.client.apply_local_avatar(&path);
                let own_id = self.client.current_user_id.clone().unwrap_or_default();
                self.avatars.forget(&own_id);
            }
            SettingsOutcome::AvatarUrl(url) => {
                self.client.apply_avatar_url(&url);
                let own_id = self.client.current_user_id.clone().unwrap_or_default();
                self.avatars.forget(&own_id);
            }
            SettingsOutcome::Profile {
                nickname,
                phone,
                bio,
            } => {
                self.profile_nickname = nickname.clone();
                self.profile_phone = phone.clone();
                self.profile_bio = bio.clone();
                self.client.update_profile(&nickname, &phone, &bio);
            }
            SettingsOutcome::Password { old, new, repeat } => {
                self.client.change_password(&old, &new, &repeat);
                self.password_old = String::new();
                self.password_new = String::new();
                self.password_repeat = String::new();
                if !self.client.is_signed_in() {
                    self.auth_page = Some(AuthPage::Login);
                    self.settings_open = false;
                }
            }
            SettingsOutcome::Accept(id) => self.client.accept_request(&id),
            SettingsOutcome::Decline(id) => self.client.decline_request(&id),
            SettingsOutcome::Cancel(id) => self.client.cancel_sent_request(&id),
            SettingsOutcome::DeleteAccount(password) => {
                self.client.delete_account(&password);
                self.delete_password = String::new();
                self.auth_page = Some(AuthPage::Login);
                self.settings_open = false;
            }
            SettingsOutcome::ServerAddress(address) => {
                self.server_address = address.clone();
                self.client.apply_server_address(&address);
            }
            SettingsOutcome::CheckUpdate => {
                let version = env!("CARGO_PKG_VERSION").to_string();
                self.client.start_update_check(&version);
            }
            SettingsOutcome::Logout => {
                self.client.sign_out();
                self.auth_page = Some(AuthPage::Login);
                self.settings_open = false;
            }
        }
    }

    // ==================== Login / Registration Page ====================

    fn auth_view(&self, page: AuthPage) -> AuthView {
        AuthView {
            page,
            login_title: self.text("option_login"),
            register_title: self.text("option_register"),
            username_label: self.text("label_username"),
            email_label: self.text("label_email"),
            password_label: self.text("label_password"),
            server_label: self.text("option_server_address"),
            server_hint: self.text("hint_server_address"),
            confirm_title: self.text("button_confirm"),
            server_address: if self.server_address.is_empty() {
                self.client.connector.base_url().to_string()
            } else {
                self.server_address.clone()
            },
        }
    }

    fn draw_auth_page(&mut self, context: &Context) {
        let Some(page) = self.auth_page else {
            return;
        };
        if self.client.is_signed_in() {
            self.auth_page = None;
            return;
        }
        let skin = self.skin.clone();
        let view = self.auth_view(page);
        let mut drafts = AuthDrafts {
            login_name: self.login_name.clone(),
            login_password: self.login_password.clone(),
            register_name: self.register_name.clone(),
            register_email: self.register_email.clone(),
            register_password: self.register_password.clone(),
            server_address: view.server_address.clone(),
        };
        let mut outcome = AuthOutcome::Nothing;
        let response = Modal::new(Id::new("auth-page"))
            .backdrop_color(Color32::from_black_alpha(140))
            .frame(
                Frame::new()
                    .fill(skin.app_background)
                    .stroke(Stroke::new(1.0, skin.overlay_border))
                    .corner_radius(8.0)
                    .inner_margin(Margin::same(16)),
            )
            .show(context, |ui| {
                ui.set_min_width(420.0);
                outcome = draw_auth_form(ui, &view, &mut drafts);
            });
        self.store_auth_drafts(drafts);
        match outcome {
            AuthOutcome::Nothing => {}
            AuthOutcome::SwitchTo(page) => self.auth_page = Some(page),
            AuthOutcome::SignIn => {
                let (name, password) = (self.login_name.clone(), self.login_password.clone());
                if self.client.sign_in(&name, &password) {
                    self.login_password = String::new();
                    self.auth_page = None;
                    self.focus_message_input = true;
                }
            }
            AuthOutcome::SignUp => {
                let (name, email, password) = (
                    self.register_name.clone(),
                    self.register_email.clone(),
                    self.register_password.clone(),
                );
                if self.client.sign_up(&name, &email, &password) {
                    self.register_password = String::new();
                    self.login_name = name;
                    self.auth_page = Some(AuthPage::Login);
                }
            }
            AuthOutcome::ServerAddress(address) => self.client.apply_server_address(&address),
        }
        let _ = response;
    }

    /// Write the draft of the login/registration page for this frame back to the interface fields in full.
    ///
    /// `draw_auth_form` modifies a copy inside `AuthDrafts`; it must write each item back; missing one means
    /// "that input box can't accept text": next frame the draft is rebuilt from interface fields, and the unwritten item goes back to its old value.
    /// The previous version missed `register_password`, so the registration page's password box couldn't hold a single character.
    fn store_auth_drafts(&mut self, drafts: AuthDrafts) {
        self.login_name = drafts.login_name;
        self.login_password = drafts.login_password;
        self.register_name = drafts.register_name;
        self.register_email = drafts.register_email;
        self.register_password = drafts.register_password;
        self.server_address = drafts.server_address;
    }

    // ==================== Notifications and Profile Card ====================

    fn draw_notices(&mut self, context: &Context) {
        let notices: Vec<(String, bool)> = self
            .client
            .notices
            .iter()
            .map(|notice| (notice.text.clone(), notice.is_error))
            .collect();
        if notices.is_empty() {
            return;
        }
        let skin = self.skin.clone();
        Window::new("notices")
            .id(Id::new("notices"))
            .anchor(Align2::RIGHT_TOP, Vec2::new(-12.0, 34.0))
            .title_bar(false)
            .resizable(false)
            .movable(false)
            .frame(
                Frame::new()
                    .fill(skin.app_background)
                    .stroke(Stroke::new(1.0, skin.notice_hint_border))
                    .corner_radius(overlay_window_corner_radius())
                    .inner_margin(Margin::same(8)),
            )
            .show(context, |ui| {
                for (text, is_error) in notices {
                    let color = if is_error {
                        skin.notice_error_border
                    } else {
                        skin.notice_hint_border
                    };
                    ui.colored_label(color, text);
                }
            });
    }

    fn profile_card_view(&self) -> Option<ProfileCardView> {
        let profile = self.client.profile_view.clone()?;
        let is_self = Some(&profile.id) == self.client.current_user_id.as_ref();
        let bytes = self
            .client
            .avatar_images
            .get(&profile.id)
            .and_then(|cached| cached.as_ref())
            .cloned();
        let (email, phone) = match (self.client.own_contact.clone(), is_self) {
            (Some(contact), true) => contact,
            _ => (String::new(), String::new()),
        };
        let none = self.text("profile_none");
        Some(ProfileCardView {
            username: profile.username.clone(),
            nickname: profile.nickname.filter(|value| !value.is_empty()),
            id: profile.id.clone(),
            email: if email.is_empty() {
                none.clone()
            } else {
                email
            },
            phone: if phone.is_empty() {
                none.clone()
            } else {
                phone
            },
            bio: profile
                .bio
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| none.clone()),
            avatar: match profile.avatar.as_deref() {
                None => none.clone(),
                Some(path) if path.starts_with('/') => self.text("profile_avatar_local"),
                Some(path) => path.to_string(),
            },
            presence: match self.client.presence_by_user.get(&profile.id) {
                Some(true) => self.text("status_online"),
                Some(false) => self.text("status_offline"),
                None => none,
            },
            texture_identity: profile.id,
            bytes,
            // Same order as the terminal version's profile card, so the same language keys describe the same rows.
            labels: vec![
                self.text("profile_nickname_label"),
                self.text("profile_uid"),
                self.text("presence_state"),
                self.text("profile_email_label"),
                self.text("profile_phone_label"),
                self.text("profile_bio_label"),
                self.text("profile_avatar_url"),
            ],
        })
    }

    fn draw_profile_card(&mut self, context: &Context) {
        if !self.profile_card_open {
            return;
        }
        let Some(view) = self.profile_card_view() else {
            return;
        };
        let skin = self.skin.clone();
        let texture = self.avatars.texture(
            context,
            &view.texture_identity,
            view.bytes.as_deref(),
            profile_avatar_side_pixels(),
        );
        let mut open = self.profile_card_open;
        Window::new(view.username.clone())
            .id(Id::new("profile-card"))
            .open(&mut open)
            .collapsible(true)
            .default_pos([120.0, 80.0])
            .frame(overlay_window_frame(&skin))
            .show(context, |ui| {
                ui.horizontal(|ui| {
                    match texture {
                        Some(handle) => {
                            ui.add(egui::Image::from_texture(&handle).fit_to_exact_size(
                                Vec2::splat(profile_avatar_side_pixels() as f32),
                            ));
                        }
                        None => {
                            draw_placeholder(
                                ui,
                                &view.username,
                                profile_avatar_side_pixels() as f32,
                            );
                        }
                    }
                    ui.vertical(|ui| {
                        let labels = &view.labels;
                        if let Some(nickname) = view.nickname {
                            ui.colored_label(
                                skin.selected_text,
                                format!("{}: {nickname}", labels[0]),
                            );
                        }
                        ui.label(format!("{}: {}", labels[1], view.id));
                        ui.label(format!("{}: {}", labels[2], view.presence));
                        ui.label(format!("{}: {}", labels[3], view.email));
                        ui.label(format!("{}: {}", labels[4], view.phone));
                        ui.label(format!("{}: {}", labels[5], view.bio));
                        ui.label(format!("{}: {}", labels[6], view.avatar));
                    });
                });
            });
        self.profile_card_open = open;
    }

    // ==================== Create Group/Private Chat Window ====================

    /// Draw the create group/private chat window. Entry is in the plus button to the right of the room list title.
    fn draw_creation_panel(&mut self, context: &Context) {
        let Some(page) = self.creation_page else {
            return;
        };
        let skin = self.skin.clone();
        let mut view = self.creation_view(page);
        let (keep_open, submitted) = draw_creation_window(context, &skin, &mut view);
        self.apply_creation_view(page, view);
        if submitted && !self.submit_creation(page) {
            // Input is invalid: the window stays, the draft stays, fix and click again
            return;
        }
        if submitted || !keep_open {
            self.creation_page = None;
        }
    }

    /// All text and data the create window needs to read and write (the window closure doesn't touch self, so take it out first and write it back)
    fn creation_view(&self, page: CreationPage) -> CreationView {
        match page {
            CreationPage::Group => CreationView {
                page,
                title: self.text("create_group_title"),
                first_label: self.text("group_name_label"),
                first_value: self.group_name.clone(),
                members_label: self.text("create_group_members_label"),
                members_placeholder: members_placeholder(),
                members_value: self.group_members.clone(),
                confirm: self.text("button_confirm"),
            },
            CreationPage::Private => CreationView {
                page,
                title: self.text("create_private_title"),
                first_label: self.text("private_target_label"),
                first_value: self.private_target.clone(),
                members_label: String::new(),
                members_placeholder: String::new(),
                members_value: String::new(),
                confirm: self.text("button_confirm"),
            },
        }
    }

    /// Write the input in the window back to the draft: close the window and reopen and it's still what was last filled in, making it easy to retry after editing
    fn apply_creation_view(&mut self, page: CreationPage, view: CreationView) {
        match page {
            CreationPage::Group => {
                self.group_name = view.first_value;
                self.group_members = view.members_value;
            }
            CreationPage::Private => self.private_target = view.first_value,
        }
    }

    /// Clicked the create button: empty input errors on the spot and keeps the window open; only with content does it actually send.
    /// Return whether it was submitted (if submitted, collapse the window).
    fn submit_creation(&mut self, page: CreationPage) -> bool {
        match page {
            CreationPage::Group => {
                if self.group_name.trim().is_empty() {
                    self.client
                        .notify_error(self.text("error_group_name_empty"));
                    return false;
                }
                let (name, members) = (self.group_name.clone(), self.group_members.clone());
                self.client.create_group(&name, &members);
                true
            }
            CreationPage::Private => {
                if self.private_target.trim().is_empty() {
                    self.client.notify_error(self.text("error_username_empty"));
                    return false;
                }
                let target = self.private_target.clone();
                self.client.create_private_chat(&target);
                true
            }
        }
    }
}

impl eframe::App for BaihuaApp {
    /// Each frame run logic first: fetch background events, maintain notifications and handshakes, check whether to exit
    fn logic(&mut self, context: &Context, _frame: &mut eframe::Frame) {
        self.run_logic(context);
    }

    /// Then draw the interface. Panel order determines positioning: top bar → settings → room list → message area;
    // ==================== Create Group/Private Chat Window ====================
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let context = ui.ctx().clone();
        self.draw_status_bar(ui);
        self.draw_room_panel(ui);
        self.draw_central(ui, &context);
        self.handle_shortcuts(&context);
        self.draw_settings_window(&context);
        self.draw_notices(&context);
        self.draw_profile_card(&context);
        self.draw_creation_panel(&context);
        self.draw_auth_page(&context);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.client.flush_before_exit();
        self.client.persist_session_before_exit();
    }
}

// ==================== Stateless Draw Functions ====================

/// All text and data the create group/private chat window needs to read and write.
/// The two windows have the same shape: several rows of "label + input box", plus a create button;
/// the difference is only in the title, the label on the first row, and whether to draw an extra row for members.
struct CreationView {
    /// Which form to draw
    page: CreationPage,
    /// Window title
    title: String,
    /// The label on the first row (group name / other person's username)
    first_label: String,
    /// The content in the first-row input box
    first_value: String,
    /// The label for the members row (only for creating group chat)
    members_label: String,
    /// Placeholder hint for the member input box (only for creating group chat)
    members_placeholder: String,
    /// Content in the member input box (only for creating group chat)
    members_value: String,
    /// Text on the create button
    confirm: String,
}

/// Draw the create group/private chat window. Returns `(is the window still open, did this frame click the create button)`:
/// Close the window via the close button in the title bar's top-right corner; submit via the create button; both are handled separately by the caller.
fn draw_creation_window(context: &Context, skin: &Skin, view: &mut CreationView) -> (bool, bool) {
    let mut keep_open = true;
    let mut submitted = false;
    Window::new(view.title.clone())
        .id(Id::new("creation-window"))
        .open(&mut keep_open)
        // Unified with other floating layers: small border radius, collapsible (the triangle in the title bar)
        .resizable(true)
        .collapsible(true)
        .default_pos([160.0, 120.0])
        .frame(overlay_window_frame(skin))
        .show(context, |ui| {
            submitted = draw_creation_form(ui, view);
        });
    (keep_open, submitted)
}

/// Draw the form content in the create window: several rows of "label + input box", plus a create button.
/// Return whether the create button was clicked this frame.
fn draw_creation_form(ui: &mut Ui, view: &mut CreationView) -> bool {
    draw_labeled_input(ui, &view.first_label, &mut view.first_value, "");
    if view.page == CreationPage::Group {
        draw_labeled_input(
            ui,
            &view.members_label,
            &mut view.members_value,
            &view.members_placeholder,
        );
    }
    ui.button(view.confirm.clone()).clicked()
}

/// Width of a "one label + one input box" row in the creation form (points)
fn creation_input_width() -> f32 {
    200.0
}

/// Draw one row of the create form: label on the left, input box on the right. Don't draw the placeholder hint when it's left empty.
fn draw_labeled_input(ui: &mut Ui, label: &str, value: &mut String, placeholder: &str) {
    ui.horizontal(|ui| {
        ui.label(label);
        let editor = TextEdit::singleline(value).desired_width(creation_input_width());
        if placeholder.is_empty() {
            ui.add(editor);
        } else {
            ui.add(editor.hint_text(placeholder));
        }
    });
}

/// A selectable list item; when selected, egui draws `selection.bg_fill` as the background behind the text.
/// In the default theme, both `selected_text` and `selection_background` are yellow; taking `selected_text` directly
/// as the foreground color for selected items makes it "yellow on yellow", and both the completion list and current language/appearance in settings would be invisible.
/// Here we pick a contrast color by the "used as background" rule (same fix as the terminal version); the caller-given color is used only when not selected.
///
/// `unselected_color` is the normal text color for an item when not selected: the completion list uses `selected_text` (yellow command name),
/// settings uses body text color for language/appearance.
fn selectable_text_color(skin: &Skin, selected: bool, unselected_color: Color32) -> Color32 {
    if selected {
        contrasting_foreground(skin.selection_background)
    } else {
        unselected_color
    }
}

/// The unified drawing method for "switch" entries in the settings panel (language/appearance options, section titles, avatar options).
///
/// These entries originally used `ui.selectable_label(...)` directly: it's equivalent to `Button::selectable`,
/// **no border is drawn in the normal state** (`frame_when_inactive(false)`), only a background when selected or the mouse is hovering,
/// so they blend into the background normally and you can't tell they're clickable switches.
/// here we uniformly open `frame_when_inactive`: the normal state also draws the border given by the theme (same rules as ordinary buttons,
/// the color comes from `room_border`), when selected it still swaps to the theme's selection background, and the text color is taken as a contrast by `selectable_text_color`.
///
/// Room list and command completion list are not here: they are "list items" (pick one from a column), and not drawing a border in the normal state is how a list should look.
fn draw_switch(ui: &mut Ui, skin: &Skin, selected: bool, label: String) -> Response {
    let text_color = selectable_text_color(skin, selected, skin.message_text);
    ui.add(
        Button::selectable(selected, RichText::new(label).color(text_color))
            .frame_when_inactive(true),
    )
}

/// A completion candidate is a tuple of `(full text to fill into the input box, name displayed in the list, description text)`.
///
/// Same source and order as the terminal version:
/// - When input starts with `/` and hasn't typed a space yet, filter the command table by prefix (display `/commandname` and description);
/// - After `/language ` followed by a space: list all language codes under `config/languages`, continue typing to filter by prefix;
/// - After `/appearance ` followed by a space: list all appearance names under `config/themes`, continue typing to filter by prefix.
///
/// Parameter filtering uses **case-sensitive** prefix matching (the server's usernames, language codes, and appearance names all distinguish case,
/// the client doesn't do any case folding here to avoid sending incorrect case to the server).
fn completion_candidates(
    draft: &str,
    commands: &[(&'static str, String)],
) -> Vec<(String, String, String)> {
    if let Some(filter_text) = draft.strip_prefix("/language ") {
        return config::Language::available_codes()
            .into_iter()
            .filter(|code| code.starts_with(filter_text))
            .map(|code| (format!("/language {code}"), code.clone(), String::new()))
            .collect();
    }
    if let Some(filter_text) = draft.strip_prefix("/appearance ") {
        return config::Palette::available_names()
            .into_iter()
            .filter(|name| name.starts_with(filter_text))
            .map(|name| (format!("/appearance {name}"), name.clone(), String::new()))
            .collect();
    }
    let Some(prefix) = baihua_core::commands::pending_command_prefix(draft) else {
        return Vec::new();
    };
    commands
        .iter()
        .filter(|(name, _)| name.starts_with(prefix))
        .map(|(name, description)| (format!("/{name}"), format!("/{name}"), description.clone()))
        .collect()
}

/// Input completion popup: list the current candidates one per line
// (selected item highlighted, up/down arrow switches, Enter or clicking an item only fills the full text into the input box),
/// Each line is "name + description". Return the full text to fill into the input box this frame.
///
/// It's drawn as a **floating layer** (`egui::Area` + `Order::Foreground`), pasted above the input box:
/// The floating layer doesn't participate in layout, so opening completion doesn't push a chunk out of the message display area (it used to take up layout space,
/// once the message area opened it would shrink by a chunk, and after the panel remembered its height it wouldn't shrink back on its own).
/// Height is fixed within `command_completion_height()`, scrolling within the block when there are many commands.
///
/// `selection_moved` is "a selection change was made with up/down arrow keys this frame": only scroll the selected row into view when changed.
/// Scrolling only when the selection changes is to not compete with the user's own mouse wheel — if it scrolled unconditionally every frame,
/// the user would scroll away to look at other commands, and next frame they'd be dragged back to the selected row.
fn draw_command_completions(
    context: &Context,
    anchor: Rect,
    skin: &Skin,
    candidates: &[(String, String, String)],
    selected: usize,
    selection_moved: bool,
) -> Option<String> {
    if candidates.is_empty() {
        return None;
    }
    let mut picked = None;
    // Stick above the input box; when there's not enough room above, stick below the input box edge, at least it won't run off the screen
    let above = anchor.top() - command_completion_height() - command_completion_gap();
    let position = Pos2::new(
        anchor.left(),
        if above >= 0.0 {
            above
        } else {
            anchor.bottom() + command_completion_gap()
        },
    );
    egui::Area::new(Id::new(command_completion_area_id()))
        .order(egui::Order::Foreground)
        .fixed_pos(position)
        .show(context, |ui| {
            ui.set_width(anchor.width());
            Frame::new()
                .fill(skin.app_background)
                .stroke(Stroke::new(1.0, skin.command_border))
                .corner_radius(4.0)
                .inner_margin(Margin::same(4))
                .show(ui, |ui| {
                    ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .max_height(command_completion_height())
                        .show(ui, |ui| {
                            // The rectangle of the selected row: the scroll region uses it to pull the selected item back into view
                            let mut selected_row: Option<Rect> = None;
                            for (index, (insert_text, label, description)) in
                                candidates.iter().enumerate()
                            {
                                let is_selected = index == selected;
                                let name_color =
                                    selectable_text_color(skin, is_selected, skin.selected_text);
                                let row = ui.horizontal(|ui| {
                                    if ui
                                        .selectable_label(
                                            is_selected,
                                            egui::RichText::new(label.clone()).color(name_color),
                                        )
                                        .clicked()
                                    {
                                        picked = Some(insert_text.clone());
                                    }
                                    if !description.is_empty() {
                                        ui.label(
                                            egui::RichText::new(description.clone())
                                                .color(skin.hint_text)
                                                .small(),
                                        );
                                    }
                                });
                                if is_selected {
                                    selected_row = Some(row.response.rect);
                                }
                            }
                            // The selection changed with up/down arrow keys: scroll this row into the visible range.
                            // Use "no animation" scrolling: the interface only redraws every 120 milliseconds,
                            // the animated version would take several frames to complete, pressing an arrow key would mean waiting a bit before seeing the list move;
                            // the positioning happens right after this key press, landing within one frame is most intuitive.
                            if selection_moved && let Some(row) = selected_row {
                                ui.scroll_to_rect_animation(
                                    row,
                                    Some(Align::Center),
                                    ScrollAnimation::none(),
                                );
                            }
                        });
                });
        });
    picked
}

/// The message input box. A multi-line box's native behavior is "Enter for newline"; here newline is given to Shift+Enter
// (`return_key` is egui's own switch), the freed-up regular Enter is treated as sending.
/// Return (is focus in this input box, should this frame send the draft, did the draft change this frame, input box rectangle).
/// The frame requesting focus also moves the cursor to the end: after completing a command you can directly start typing parameters.
fn draw_message_input(
    ui: &mut Ui,
    draft: &mut String,
    placeholder: String,
    request_focus: bool,
    text_color: Color32,
) -> (bool, bool, bool, Rect) {
    let editor = TextEdit::multiline(draft)
        .text_color(text_color)
        .hint_text(placeholder)
        .id_source(message_input_id())
        .return_key(KeyboardShortcut::new(Modifiers::SHIFT, Key::Enter))
        .desired_rows(2)
        .desired_width(f32::INFINITY);
    let response: Response = ui.add_sized(
        Vec2::new(ui.available_width(), message_input_height()),
        editor,
    );
    if request_focus {
        response.request_focus();
        move_caret_to_end(ui.ctx(), response.id, draft);
    }
    // Whether Enter counts as "sending" depends on the modifiers carried by this event: `InputState::modifiers` is the state of the whole frame,
    // doesn't guarantee it equals the modifiers when this Key was pressed; using it directly would misjudge Shift+Enter as a regular Enter.
    let enter_without_shift = ui.input(|state| {
        state.events.iter().any(|event| {
            matches!(event,
                Event::Key { key: Key::Enter, pressed: true, modifiers, .. } if !modifiers.shift)
        })
    });
    (
        response.has_focus(),
        response.has_focus() && enter_without_shift,
        response.changed(),
        response.rect,
    )
}

/// Move the cursor in the input box to the end of the text (useful for completing a command or after sending a message)
fn move_caret_to_end(context: &Context, id: Id, draft: &str) {
    let Some(mut state) = egui::widgets::text_edit::TextEditState::load(context, id) else {
        return;
    };
    let end = egui::text::CCursor::new(draft.chars().count());
    state
        .cursor
        .set_char_range(Some(egui::text::CCursorRange::one(end)));
    state.store(context, id);
}

/// The plus button to the right of the room list title: clicking it expands the "Create Group / Create Private" selection list,
/// Return which item is selected this frame (None if nothing selected). The menu is egui's own popup layer,
/// Selecting one of them collapses it.
///
/// Button background and border are uniformly provided by the theme (`Skin::apply_to` sets the three-state colors for widgets),
/// here just use the most ordinary button: appearance follows the theme, and hover/press feedback is the same as other buttons.
fn draw_creation_menu(
    ui: &mut Ui,
    create_group_title: &str,
    create_private_title: &str,
) -> Option<CreationPage> {
    let button = egui::Button::new(create_menu_button_text());
    egui::containers::menu::MenuButton::from_button(button)
        .ui(ui, |ui| {
            let mut picked = None;
            if ui.button(create_group_title.to_string()).clicked() {
                picked = Some(CreationPage::Group);
            }
            if ui.button(create_private_title.to_string()).clicked() {
                picked = Some(CreationPage::Private);
            }
            picked
        })
        .1
        .and_then(|inner_response| inner_response.inner)
}

/// All text and data the settings panel needs to read and write
struct SettingsView {
    settings_title: String,
    language_title: String,
    appearance_title: String,
    show_uid: bool,
    show_uid_title: String,
    time_with_date: bool,
    time_title: String,
    quick_search: bool,
    quick_title: String,
    sound_enabled: bool,
    sound_title: String,
    avatar_title: String,
    avatar_choices: Vec<(String, PathBuf)>,
    avatar_directory: Option<String>,
    avatar_empty_hint: String,
    avatar_input_label: String,
    profile_title: String,
    profile_hint: String,
    nickname_label: String,
    phone_label: String,
    bio_label: String,
    password_title: String,
    old_label: String,
    new_label: String,
    repeat_label: String,
    requests_title: String,
    requests_empty: String,
    received_title: String,
    sent_title: String,
    accept_title: String,
    decline_title: String,
    cancel_title: String,
    account_title: String,
    delete_hint: String,
    server_title: String,
    server_hint: String,
    update_title: String,
    logout_title: String,
    confirm_title: String,
    save_title: String,
    current_language: String,
    language_codes: Vec<String>,
    current_appearance: String,
    appearance_names: Vec<String>,
    request_rows: Vec<RequestRow>,
    pending_count: usize,
    sections: Sections,
    /// Content of each text box in the panel, written back to the interface as-is after drawing
    fields: SettingsFields,
}

/// Content of each text box in the settings panel
struct SettingsFields {
    profile_nickname: String,
    profile_phone: String,
    profile_bio: String,
    password_old: String,
    password_new: String,
    password_repeat: String,
    avatar_url: String,
    delete_password: String,
    server_address: String,
}

/// The actions the settings panel hands back to the session layer
enum SettingsOutcome {
    Nothing,
    Language(String),
    Appearance(String),
    Toggles {
        show_uid: bool,
        time_with_date: bool,
        quick_search: bool,
        sound_enabled: bool,
    },
    Sections(Sections),
    AvatarFile(PathBuf),
    AvatarUrl(String),
    Profile {
        nickname: String,
        phone: String,
        bio: String,
    },
    Password {
        old: String,
        new: String,
        repeat: String,
    },
    Accept(String),
    Decline(String),
    Cancel(String),
    DeleteAccount(String),
    ServerAddress(String),
    CheckUpdate,
    Logout,
}

/// All content the profile card needs to display (computed first, only read during drawing)
struct ProfileCardView {
    username: String,
    nickname: Option<String>,
    id: String,
    email: String,
    phone: String,
    bio: String,
    avatar: String,
    presence: String,
    texture_identity: String,
    bytes: Option<Vec<u8>>,
    /// Field labels in display order: nickname, UID, presence, email, phone, bio, avatar URL.
    /// The first one is only drawn when a nickname exists; the remaining six always get a row.
    labels: Vec<String>,
}

/// A row of a private chat request
struct RequestRow {
    id: String,
    is_sent: bool,
    peer: String,
    status: String,
    message: String,
    actionable: bool,
    cancellable: bool,
}

fn draw_settings_form(ui: &mut Ui, skin: &Skin, view: &mut SettingsView) -> SettingsOutcome {
    let mut outcome = SettingsOutcome::Nothing;
    ui.colored_label(skin.selected_text, view.settings_title.clone());
    ui.separator();
    ui.label(view.language_title.clone());
    ui.horizontal_wrapped(|ui| {
        for code in &view.language_codes {
            let selected = code == &view.current_language;
            if draw_switch(ui, skin, selected, code.clone()).clicked() {
                outcome = SettingsOutcome::Language(code.clone());
            }
        }
    });
    ui.label(view.appearance_title.clone());
    ui.horizontal_wrapped(|ui| {
        for name in &view.appearance_names {
            let selected = name == &view.current_appearance;
            if draw_switch(ui, skin, selected, name.clone()).clicked() {
                outcome = SettingsOutcome::Appearance(name.clone());
            }
        }
    });
    ui.separator();
    let mut changed = false;
    changed |= ui
        .checkbox(&mut view.show_uid, view.show_uid_title.clone())
        .changed();
    changed |= ui
        .checkbox(&mut view.time_with_date, view.time_title.clone())
        .changed();
    changed |= ui
        .checkbox(&mut view.quick_search, view.quick_title.clone())
        .changed();
    changed |= ui
        .checkbox(&mut view.sound_enabled, view.sound_title.clone())
        .changed();
    if changed {
        outcome = SettingsOutcome::Toggles {
            show_uid: view.show_uid,
            time_with_date: view.time_with_date,
            quick_search: view.quick_search,
            sound_enabled: view.sound_enabled,
        };
    }
    ui.separator();
    draw_avatar_group(ui, skin, view, &mut outcome);
    draw_profile_group(ui, skin, view, &mut outcome);
    draw_password_group(ui, skin, view, &mut outcome);
    draw_requests_group(ui, skin, view, &mut outcome);
    draw_account_group(ui, skin, view, &mut outcome);
    ui.separator();
    if ui.button(view.update_title.clone()).clicked() {
        outcome = SettingsOutcome::CheckUpdate;
    }
    if ui.button(view.logout_title.clone()).clicked() {
        outcome = SettingsOutcome::Logout;
    }
    outcome
}

fn draw_avatar_group(
    ui: &mut Ui,
    skin: &Skin,
    view: &mut SettingsView,
    outcome: &mut SettingsOutcome,
) {
    // The open/close here must follow the same path as other sections (hand the entire state back to the interface).
    // Previously written as "return directly if the title wasn't clicked", so after opening it the next frame would return directly because no click happened,
    // content only appeared once in the frame that was clicked, looking like "cannot open change avatar".
    toggle_section(
        ui,
        skin,
        &mut view.sections,
        |sections| &mut sections.avatar,
        view.avatar_title.clone(),
        outcome,
    );
    if !view.sections.avatar {
        return;
    }
    if view.avatar_choices.is_empty() {
        ui.colored_label(skin.hint_text, view.avatar_empty_hint.clone());
        if let Some(directory) = &view.avatar_directory {
            ui.colored_label(skin.hint_text, directory.clone());
        }
    } else {
        ScrollArea::vertical().max_height(120.0).show(ui, |ui| {
            for (name, path) in &view.avatar_choices {
                if draw_switch(ui, skin, false, name.clone()).clicked() {
                    *outcome = SettingsOutcome::AvatarFile(path.clone());
                }
            }
        });
    }
    ui.horizontal(|ui| {
        ui.label(view.avatar_input_label.clone());
        ui.text_edit_singleline(&mut view.fields.avatar_url);
        if ui.button(view.confirm_title.clone()).clicked() {
            *outcome = SettingsOutcome::AvatarUrl(view.fields.avatar_url.clone());
        }
    });
}

fn draw_profile_group(
    ui: &mut Ui,
    skin: &Skin,
    view: &mut SettingsView,
    outcome: &mut SettingsOutcome,
) {
    toggle_section(
        ui,
        skin,
        &mut view.sections,
        |sections| &mut sections.profile,
        view.profile_title.clone(),
        outcome,
    );
    if !view.sections.profile {
        return;
    }
    ui.label(view.nickname_label.clone());
    ui.text_edit_singleline(&mut view.fields.profile_nickname);
    ui.label(view.phone_label.clone());
    ui.text_edit_singleline(&mut view.fields.profile_phone);
    ui.label(view.bio_label.clone());
    ui.text_edit_singleline(&mut view.fields.profile_bio);
    if ui.button(view.save_title.clone()).clicked() {
        *outcome = SettingsOutcome::Profile {
            nickname: view.fields.profile_nickname.clone(),
            phone: view.fields.profile_phone.clone(),
            bio: view.fields.profile_bio.clone(),
        };
    }
    ui.colored_label(skin.hint_text, view.profile_hint.clone());
}

fn draw_password_group(
    ui: &mut Ui,
    skin: &Skin,
    view: &mut SettingsView,
    outcome: &mut SettingsOutcome,
) {
    toggle_section(
        ui,
        skin,
        &mut view.sections,
        |sections| &mut sections.password,
        view.password_title.clone(),
        outcome,
    );
    if !view.sections.password {
        return;
    }
    ui.horizontal(|ui| {
        ui.label(view.old_label.clone());
        ui.add(TextEdit::singleline(&mut view.fields.password_old).password(true));
    });
    ui.horizontal(|ui| {
        ui.label(view.new_label.clone());
        ui.add(TextEdit::singleline(&mut view.fields.password_new).password(true));
    });
    ui.horizontal(|ui| {
        ui.label(view.repeat_label.clone());
        ui.add(TextEdit::singleline(&mut view.fields.password_repeat).password(true));
    });
    if ui.button(view.confirm_title.clone()).clicked() {
        *outcome = SettingsOutcome::Password {
            old: view.fields.password_old.clone(),
            new: view.fields.password_new.clone(),
            repeat: view.fields.password_repeat.clone(),
        };
    }
}

fn draw_requests_group(
    ui: &mut Ui,
    skin: &Skin,
    view: &mut SettingsView,
    outcome: &mut SettingsOutcome,
) {
    let title = format!("{} ({})", view.requests_title, view.pending_count);
    toggle_section(
        ui,
        skin,
        &mut view.sections,
        |sections| &mut sections.requests,
        title,
        outcome,
    );
    if !view.sections.requests {
        return;
    }
    if view.request_rows.is_empty() {
        ui.colored_label(skin.hint_text, view.requests_empty.clone());
        return;
    }
    ui.colored_label(skin.selected_text, view.received_title.clone());
    for row in view.request_rows.iter().filter(|row| !row.is_sent) {
        ui.group(|ui| {
            ui.label(format!("{}  {}", row.peer, row.status));
            ui.colored_label(skin.hint_text, row.message.clone());
            if row.actionable {
                ui.horizontal(|ui| {
                    if ui.button(view.accept_title.clone()).clicked() {
                        *outcome = SettingsOutcome::Accept(row.id.clone());
                    }
                    if ui.button(view.decline_title.clone()).clicked() {
                        *outcome = SettingsOutcome::Decline(row.id.clone());
                    }
                });
            }
        });
    }
    ui.colored_label(skin.selected_text, view.sent_title.clone());
    for row in view.request_rows.iter().filter(|row| row.is_sent) {
        ui.group(|ui| {
            ui.label(format!("{}  {}", row.peer, row.status));
            ui.colored_label(skin.hint_text, row.message.clone());
            if row.cancellable && ui.button(view.cancel_title.clone()).clicked() {
                *outcome = SettingsOutcome::Cancel(row.id.clone());
            }
        });
    }
}

fn draw_account_group(
    ui: &mut Ui,
    skin: &Skin,
    view: &mut SettingsView,
    outcome: &mut SettingsOutcome,
) {
    toggle_section(
        ui,
        skin,
        &mut view.sections,
        |sections| &mut sections.account,
        view.account_title.clone(),
        outcome,
    );
    if view.sections.account {
        ui.colored_label(skin.notice_error_border, view.delete_hint.clone());
        ui.horizontal(|ui| {
            ui.label(view.old_label.clone());
            ui.add(TextEdit::singleline(&mut view.fields.delete_password).password(true));
        });
        if ui.button(view.confirm_title.clone()).clicked() {
            *outcome = SettingsOutcome::DeleteAccount(view.fields.delete_password.clone());
        }
    }
    ui.separator();
    toggle_section(
        ui,
        skin,
        &mut view.sections,
        |sections| &mut sections.server,
        view.server_title.clone(),
        outcome,
    );
    if view.sections.server {
        ui.horizontal(|ui| {
            ui.text_edit_singleline(&mut view.fields.server_address);
            if ui.button(view.confirm_title.clone()).clicked() {
                *outcome = SettingsOutcome::ServerAddress(view.fields.server_address.clone());
            }
        });
        ui.colored_label(skin.hint_text, view.server_hint.clone());
    }
}

/// Draw an expandable section title: clicking toggles it, and writes the **full** open/close state back to the interface.
///
/// Previously only the internal copy of the panel was toggled, not written back (`SettingsOutcome::Nothing`),
/// So clicking the six section headers got no response -- the panel redrew with the old state from the interface every frame.
/// `pick` specifies which section was clicked this time; `Sections` is Copy, so the whole thing can be carried back without trouble.
fn toggle_section(
    ui: &mut Ui,
    skin: &Skin,
    sections: &mut Sections,
    pick: impl Fn(&mut Sections) -> &mut bool,
    title: String,
    outcome: &mut SettingsOutcome,
) {
    let selected = *pick(sections);
    if draw_switch(ui, skin, selected, title).clicked() {
        let open = pick(sections);
        *open = !*open;
        *outcome = SettingsOutcome::Sections(*sections);
    }
}

/// Layout of the message area and bottom input area. Order is key: first use `egui::Panel::bottom` to let the input area take its own
/// needed height, then hand the remaining height to the scrollable message list.
///
/// Conversely (message list drawn first, input area second), the message list's `ScrollArea` would eat all the available height —
/// its outer frame dimension is "all the space remaining from the parent", once content is tall enough it fills up, and the input box drawn after it can only fall into
/// outside the visible area, looking like "when there's a lot of chat, the input box gets squeezed out". The panel positioning first naturally avoids this problem:
/// the input area is always its own height, and the list only gets what's left.
///
/// The panel height is "content-driven" (egui's panel remembers the real height from the last frame), and the input area's content
/// is laid out sticking to the bottom edge from top to bottom, so when the "someone is typing" row appears or disappears, the input box itself stays completely still,
/// the only thing that changes is the height left above it for the message list.
///
/// The input area itself is drawn by the caller (`draw_input_area`); the function passes its return value through unchanged.
/// Note that inside it's laid out from bottom to top: **what's drawn first sticks to the bottom**, so the caller should draw in the order of
/// "input box → the hint row above it".
///
/// Return `(return value of the input area, user ID of the person whose avatar was clicked this frame, whether the message view is scrolled to the top)`:
/// Clicking is unrelated to the input area; the caller uses the ID to look up the profile card; touching the top is decided by the caller whether to pull earlier messages from the server.
///
/// `scroll_to_message` is "which message to scroll into view this frame" (used when switching search matches):
/// it's only valid this frame, and when drawing that message it's scrolled to the middle as a bonus.
fn draw_conversation_area<R>(
    ui: &mut Ui,
    skin: &Skin,
    rows: Vec<MessageRow>,
    empty_hint: String,
    stick_to_bottom: bool,
    scroll_to_message: Option<String>,
    draw_input_area: impl FnOnce(&mut Ui) -> R,
) -> (R, Option<String>, bool) {
    let had_rows = !rows.is_empty();
    let mut clicked_avatar: Option<String> = None;
    // The input area only takes the height it needs and doesn't resize with pointer dragging
    let input_area = egui::Panel::bottom(conversation_input_area_id())
        .resizable(false)
        .default_size(conversation_input_initial_height(ui))
        .frame(
            Frame::new()
                .fill(skin.app_background)
                .inner_margin(Margin::symmetric(0, 4)),
        )
        .show(ui, |ui| {
            ui.with_layout(egui::Layout::bottom_up(Align::Min), draw_input_area)
                .inner
        })
        .inner;
    let scroll_output = ScrollArea::vertical()
        .stick_to_bottom(stick_to_bottom)
        .auto_shrink([true, true])
        .show(ui, |ui| {
            for row in rows {
                let scroll_to_this_row =
                    scroll_to_message.as_deref() == Some(row.message_id.as_str());
                if let Some(user_id) = draw_message_row(ui, skin, row, scroll_to_this_row) {
                    clicked_avatar = Some(user_id);
                }
            }
            if !had_rows {
                ui.colored_label(skin.hint_text, empty_hint);
            }
        });
    // Touch-the-top judgment uses the scroll region's own output: content height, visible height, and this frame's final offset
    let reached_top = conversation_reached_top(
        scroll_output.content_size.y,
        scroll_output.inner_rect.height(),
        scroll_output.state.offset.y,
    );
    (input_area, clicked_avatar, reached_top)
}

/// Draw a message row. Your own messages are right-aligned (avatar on the far right, username, time, and body all aligned to the right),
/// Other people's messages are left-aligned. Right-alignment isn't achieved by just swapping the outermost layer to right-to-left: egui's
/// `right_to_left` only determines which top-level sub-block occupies position first (what's drawn first sticks to the right); inside the inner `vertical`,
/// the username row and body default to left alignment, so the result is "avatar on the right, text all stuck to the left edge".
/// so your own messages must swap every inner part to right-to-left layout, or the text won't actually stick to the right side.
///
/// Avatar is clickable: clicking returns that person's user ID, the caller looks up the profile card (one of the mouse operation entry points).
/// Not clicking the avatar returns None; body text and username do not respond to clicks.
fn draw_message_row(
    ui: &mut Ui,
    skin: &Skin,
    row: MessageRow,
    scroll_to_this_row: bool,
) -> Option<String> {
    let row_layout = if row.is_own {
        egui::Layout::right_to_left(Align::Min)
    } else {
        egui::Layout::left_to_right(Align::Min)
    };
    let text_direction = if row.is_own {
        egui::Layout::right_to_left(Align::Min)
    } else {
        egui::Layout::left_to_right(Align::Min)
    };
    let name_color = if row.is_own {
        skin.own_username_text
    } else {
        skin.other_username_text
    };
    // The entire row fills the available width; only then is there "rightmost" to stick to when laid out right-to-left
    let row_width = ui.available_width();
    let mut avatar_clicked = false;
    let row_area = ui.allocate_ui_with_layout(Vec2::new(row_width, 0.0), row_layout, |ui| {
        let avatar = match row.texture {
            Some(handle) => ui.add(
                egui::Image::from_texture(&handle)
                    .fit_to_exact_size(Vec2::splat(avatar_side_pixels() as f32))
                    .sense(Sense::click()),
            ),
            None => draw_placeholder(ui, &row.sender, avatar_side_pixels() as f32)
                .interact(Sense::click()),
        };
        // Hand cursor makes it visible the avatar is clickable
        avatar_clicked = avatar
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .clicked();
        ui.with_layout(text_direction, |ui| {
            ui.vertical(|ui| {
                ui.with_layout(text_direction, |ui| {
                    ui.colored_label(name_color, row.sender);
                    ui.colored_label(skin.time_text, row.time_text);
                });
                ui.with_layout(text_direction, |ui| {
                    // Search highlights are drawn as "the background color behind the text"; the text itself uses a contrast color
                    let mut content = egui::RichText::new(row.content).color(row.content_color);
                    if let Some(highlight) = row.content_highlight {
                        content = content.background_color(highlight);
                    }
                    ui.label(content);
                });
            });
        });
    });
    // When the search switches to this message, scroll it to the middle of the view (the positioning request is only valid this frame)
    if scroll_to_this_row {
        ui.scroll_to_rect(row_area.response.rect, Some(Align::Center));
    }
    if avatar_clicked {
        Some(row.sender_id)
    } else {
        None
    }
}

/// All text and data the message input area needs to read and write (the input area closure doesn't touch self, so take it out first and write it back)
struct MessageInputView {
    /// Draft in the input box
    draft: String,
    /// Placeholder hint for the input box
    placeholder: String,
    /// Whether this frame should hand keyboard focus to the input box (only true for the frame just clicked in or just after sending a message)
    request_focus: bool,
    /// Which item is currently selected in the completion tooltip (up/down arrow switches)
    selected_command: usize,
}

/// The input area's result this frame
struct MessageInputOutcome {
    /// Whether to send the draft (normal Enter with focus in the input box)
    send: bool,
    /// Whether the input box content changed this frame (search and fast search use this to decide whether to rescan)
    draft_changed: bool,
    /// In search mode, up/down arrow keys were pressed: Some(true) is the previous match, Some(false) is the next
    search_step: Option<bool>,
    /// Which complete text to fill into the input box (Enter to fill the selected completion, or click a row);
    /// command name completion is `/commandname`, and `/language` / `/appearance` parameter completion is `/commandname parameter`
    complete_command: Option<String>,
    /// Which rectangle the input box falls into this frame (the completion popup uses this to stick above the input box)
    input_rect: Rect,
}

/// Draw the message input area. Inside it's laid out from bottom to top (outer uses `Layout::bottom_up`), so the order is:
/// bottom row (settings entry + input box) → shortcut hint → "someone is typing" → input completion popup.
///
/// The settings entry is placed to the left of the input box, at the bottom-left of the group display area: it neither blocks messages,
/// nor would it disappear because the left room list gets dragged narrow.
fn draw_message_input_area(
    ui: &mut Ui,
    skin: &Skin,
    commands: &[(&'static str, String)],
    view: &mut MessageInputView,
) -> MessageInputOutcome {
    let mut outcome = MessageInputOutcome {
        send: false,
        draft_changed: false,
        search_step: None,
        complete_command: None,
        input_rect: Rect::NOTHING,
    };
    // List completable items when typing a command name or writing `/language` / `/appearance` parameters;
    // up/down arrow keys switch the selection, Enter fills the selected item into the input box
    // (same operation as terminal version: Enter completes, and executes directly only when the input is already a candidate)
    let candidates = completion_candidates(&view.draft, commands);
    // Whether the completion selection was changed with up/down arrow keys this frame: if changed, the completion list must scroll along
    let mut completion_selection_moved = false;
    if !candidates.is_empty() {
        view.selected_command = view.selected_command.min(candidates.len() - 1);
        if ui.input_mut(|state| state.consume_key(Modifiers::NONE, Key::ArrowUp)) {
            view.selected_command = view.selected_command.saturating_sub(1);
            completion_selection_moved = true;
        }
        if ui.input_mut(|state| state.consume_key(Modifiers::NONE, Key::ArrowDown)) {
            view.selected_command = (view.selected_command + 1).min(candidates.len() - 1);
            completion_selection_moved = true;
        }
        // When the content in the input box is already a candidate (command name fully typed, or the parameter is exactly some selectable value),
        // Enter is "execute"; otherwise Enter fills the selected candidate into the input box first.
        let typed_is_exact_candidate = candidates
            .iter()
            .any(|(insert_text, _, _)| insert_text == &view.draft);
        if !typed_is_exact_candidate
            && ui.input_mut(|state| state.consume_key(Modifiers::NONE, Key::Enter))
        {
            outcome.complete_command = Some(candidates[view.selected_command].0.clone());
        }
    } else if view.draft.trim_start().starts_with('#') {
        // In search mode (input starts with #), up/down arrow keys are used to switch matches, and shouldn't move the cursor in the input box.
        // Here the two key presses are first taken from the event queue, so the input box layer never sees them —
        // same as the terminal version (the terminal version also directly switches matches with arrow keys in search mode).
        let backwards = ui.input_mut(|state| state.consume_key(Modifiers::NONE, Key::ArrowUp));
        let forwards = ui.input_mut(|state| state.consume_key(Modifiers::NONE, Key::ArrowDown));
        if backwards {
            outcome.search_step = Some(true);
        } else if forwards {
            outcome.search_step = Some(false);
        }
    }
    // The input box row first uses a fixed height as a placeholder, then draws the stuff inside — the outer layer is `bottom_up`,
    // if the inner container doesn't give a size first it would lay out at minimum height and overflow downward,
    // the panel height would grow frame by frame (the root cause of the message area being squeezed away row by row).
    ui.allocate_ui_with_layout(
        Vec2::new(ui.available_width(), message_input_height()),
        egui::Layout::left_to_right(Align::Center),
        |ui| {
            let input = draw_message_input(
                ui,
                &mut view.draft,
                view.placeholder.clone(),
                view.request_focus,
                skin.input_text,
            );
            outcome.send = input.1;
            outcome.draft_changed = input.2;
            outcome.input_rect = input.3;
        },
    );
    // When the input changes, the selection is pulled back to the first item (same as terminal version: when the prefix changes, selection starts from the beginning)
    if outcome.draft_changed {
        view.selected_command = 0;
    }
    // The completion tooltip is drawn as a floating layer (does not occupy layout): it does not push the message area, clicking one item fills it into the input box
    if !candidates.is_empty()
        && let Some(picked) = draw_command_completions(
            ui.ctx(),
            outcome.input_rect,
            skin,
            &candidates,
            view.selected_command,
            completion_selection_moved,
        )
    {
        outcome.complete_command = Some(picked);
    }
    outcome
}

/// Draw an "avatar placeholder": use this to take the place when this person has no avatar (or the avatar hasn't been fetched yet).
/// Return the response of the whole block; the caller can use it to turn it into a clickable entry (click the message avatar to view the profile).
fn draw_placeholder(ui: &mut Ui, name: &str, side: f32) -> Response {
    let initial = name
        .chars()
        .next()
        .unwrap_or('?')
        .to_uppercase()
        .to_string();
    let color = placeholder_color(name);
    Frame::new()
        .fill(color)
        .corner_radius(4.0)
        .inner_margin(Margin::same(4))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(initial);
            });
            ui.set_width(side);
            ui.set_height(side);
        })
        .response
}

/// Text needed for the login/registration page
struct AuthView {
    page: AuthPage,
    login_title: String,
    register_title: String,
    username_label: String,
    email_label: String,
    password_label: String,
    server_label: String,
    server_hint: String,
    confirm_title: String,
    server_address: String,
}

enum AuthOutcome {
    Nothing,
    SwitchTo(AuthPage),
    SignIn,
    SignUp,
    ServerAddress(String),
}

/// Drafts for each input box on the login/registration page (the interface closure doesn't touch self; drafts are passed in and out in full before and after drawing)
struct AuthDrafts {
    login_name: String,
    login_password: String,
    register_name: String,
    register_email: String,
    register_password: String,
    server_address: String,
}

fn draw_auth_form(ui: &mut Ui, view: &AuthView, drafts: &mut AuthDrafts) -> AuthOutcome {
    // Borrow by field once, and below when drawing each input box you can write the name directly
    let AuthDrafts {
        login_name,
        login_password,
        register_name,
        register_email,
        register_password,
        server_address,
    } = drafts;
    let mut outcome = AuthOutcome::Nothing;
    ui.horizontal(|ui| {
        if ui
            .selectable_label(view.page == AuthPage::Login, view.login_title.clone())
            .clicked()
        {
            outcome = AuthOutcome::SwitchTo(AuthPage::Login);
        }
        if ui
            .selectable_label(view.page == AuthPage::Register, view.register_title.clone())
            .clicked()
        {
            outcome = AuthOutcome::SwitchTo(AuthPage::Register);
        }
    });
    ui.add_space(8.0);
    match view.page {
        AuthPage::Login => {
            ui.label(view.username_label.clone());
            ui.add(TextEdit::singleline(login_name).desired_width(f32::INFINITY));
            ui.label(view.password_label.clone());
            ui.add(
                TextEdit::singleline(login_password)
                    .password(true)
                    .desired_width(f32::INFINITY),
            );
            if ui.button(view.login_title.clone()).clicked() {
                outcome = AuthOutcome::SignIn;
            }
        }
        AuthPage::Register => {
            ui.label(view.username_label.clone());
            ui.add(TextEdit::singleline(register_name).desired_width(f32::INFINITY));
            ui.label(view.email_label.clone());
            ui.add(TextEdit::singleline(register_email).desired_width(f32::INFINITY));
            ui.label(view.password_label.clone());
            ui.add(
                TextEdit::singleline(register_password)
                    .password(true)
                    .desired_width(f32::INFINITY),
            );
            if ui.button(view.register_title.clone()).clicked() {
                outcome = AuthOutcome::SignUp;
            }
        }
    }
    ui.separator();
    ui.label(view.server_label.clone());
    ui.horizontal(|ui| {
        ui.text_edit_singleline(server_address);
        if ui.button(view.confirm_title.clone()).clicked() {
            outcome = AuthOutcome::ServerAddress(server_address.clone());
        }
    });
    ui.label(view.server_hint.clone());
    outcome
}

/// Placeholder hint for the member input box: comma-separated usernames
fn members_placeholder() -> String {
    "user1,user2".to_string()
}

/// The sender name displayed in the message row.
/// When "show sender UID" is on, append a user ID in parentheses after the name (same as terminal version):
/// only the display carries the ID; the name itself doesn't change, and places like `/kick` that look up by name are unaffected.
fn sender_label(name: &str, user_id: &str, show_uid: bool) -> String {
    if show_uid && !name.is_empty() {
        format!("{name} ({user_id})")
    } else {
        name.to_string()
    }
}

/// The input status text on the message area title: "· someone is typing…" (multiple people separated by commas).
/// The template comes from the language table (`typing_one` / `typing_multiple`); the member list is deduplicated by the session layer;
/// return None when no one is typing (the title just shows the group chat name).
fn typing_text(one_template: &str, multiple_template: &str, names: &[String]) -> Option<String> {
    match names.len() {
        0 => None,
        1 => Some(one_template.replace("{username}", &names[0])),
        _ => Some(multiple_template.replace("{names}", &names.join(", "))),
    }
}

/// Test-visible entry: verify the time format changes with the switch
#[cfg(test)]
pub fn format_message_time_for_test(created_at: &str, with_date: bool) -> String {
    format_message_time(created_at, with_date)
}

/// Time text: whether to include the date is decided by the user toggle
fn format_message_time(created_at: &str, with_date: bool) -> String {
    let parsed = chrono::DateTime::parse_from_rfc3339(created_at)
        .ok()
        .map(|value| value.with_timezone(&chrono::Local));
    match parsed {
        Some(local) if with_date => local.format("%Y-%m-%d %H:%M:%S").to_string(),
        Some(local) => local.format("%H:%M:%S").to_string(),
        None => created_at.to_string(),
    }
}

/// Placeholder background color: the same person sees the same color each time
fn placeholder_color(name: &str) -> Color32 {
    let mut hash: u64 = 1469598103934665603;
    for byte in name.as_bytes() {
        hash = (hash ^ *byte as u64).wrapping_mul(1099511628211);
    }
    let red = (((hash >> 32) as u8) >> 1).max(48);
    let green = (((hash >> 40) as u8) >> 1).max(48);
    let blue = (((hash >> 48) as u8) >> 1).max(48);
    Color32::from_rgb(red, green, blue)
}

#[cfg(test)]
mod input_box_tests {
    use super::draw_message_input;
    use egui::{
        CentralPanel, Color32, Context, Event, Key, Modifiers, PointerButton, Pos2, RawInput, Rect,
        TextEdit, Vec2,
    };

    fn raw_input(events: Vec<Event>) -> RawInput {
        RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, Vec2::new(800.0, 600.0))),
            focused: true,
            events,
            ..Default::default()
        }
    }

    fn click_at(point: Pos2) -> Vec<Event> {
        vec![
            Event::PointerButton {
                pos: point,
                button: PointerButton::Primary,
                pressed: true,
                modifiers: Modifiers::NONE,
            },
            Event::PointerButton {
                pos: point,
                button: PointerButton::Primary,
                pressed: false,
                modifiers: Modifiers::NONE,
            },
        ]
    }

    fn key_event(key: Key, modifiers: Modifiers) -> Event {
        Event::Key {
            key,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers,
        }
    }

    /// In one frame, first draw "the other input box" (simulating the login page username box), then draw the message input box.
    /// Return (focus in message box, whether to send this frame, center of message box); the last item is used as a target for click test cases,
    /// so that hardcoded coordinates don't cause misjudgment as the layout drifts.
    fn run_one_frame(
        context: &Context,
        draft: &mut String,
        events: Vec<Event>,
        request_focus: bool,
    ) -> (bool, bool, Pos2) {
        let mut draft_copy = draft.clone();
        let mut input_has_focus = false;
        let mut send_requested = false;
        let mut input_center = Pos2::ZERO;
        context
            .run_ui(raw_input(events), |ctx| {
                CentralPanel::default().show(ctx, |ui| {
                    ui.add(TextEdit::singleline(&mut draft_copy).hint_text("用户名"));
                    let body_top = ui.cursor().min;
                    let input = draw_message_input(
                        ui,
                        &mut draft_copy,
                        "输入消息".to_string(),
                        request_focus,
                        Color32::WHITE,
                    );
                    input_has_focus = input.0;
                    send_requested = input.1;
                    input_center = Pos2::new(ui.max_rect().center().x, body_top.y + 20.0);
                });
            })
            .drop_without_applying_deltas();
        *draft = draft_copy;
        (input_has_focus, send_requested, input_center)
    }

    /// After requesting focus, the input box acknowledges it received focus itself
    #[test]
    fn asking_for_focus_puts_the_caret_in_the_input_box() {
        let context = Context::default();
        let mut draft = String::new();
        let (input_has_focus, send, _center) =
            run_one_frame(&context, &mut draft, Vec::new(), true);
        assert!(input_has_focus, "请求焦点这一帧输入框应当有焦点");
        assert!(!send, "只是聚焦不该发送");
    }

    /// Mouse clicking the input box must receive focus; the GUI can't rely on keyboard alone
    #[test]
    fn clicking_the_input_box_focuses_it() {
        let context = Context::default();
        let mut draft = String::new();
        let (_focus, _send, center) = run_one_frame(&context, &mut draft, Vec::new(), false);
        let (input_has_focus, send, _center) =
            run_one_frame(&context, &mut draft, click_at(center), false);
        assert!(input_has_focus, "点击落在输入框上 {center:?} 应当聚焦");
        assert!(!send, "只是点一下不该发送");
    }

    /// This is a root-cause regression for "the input box is unusable": in a normal frame without requesting focus,
    /// the message input box must never steal focus back, otherwise the login, registration, and settings forms the user clicked on would all be untypeable
    #[test]
    fn the_input_box_never_steals_focus_from_another_field() {
        let context = Context::default();
        let mut draft = String::new();
        let (_focus, _send, center) = run_one_frame(&context, &mut draft, Vec::new(), false);
        // Click the input box above (simulating a user clicking the username box on the login page)
        let other_point = Pos2::new(center.x, 12.0);
        run_one_frame(&context, &mut draft, click_at(other_point), false);
        let (input_has_focus, _send, _center) =
            run_one_frame(&context, &mut draft, Vec::new(), false);
        assert!(
            !input_has_focus,
            "焦点在别的输入框上时，消息输入框不得自己声明拿到焦点"
        );
    }

    /// After getting focus, typed characters go into the draft
    #[test]
    fn typed_characters_land_in_the_draft() {
        let context = Context::default();
        let mut draft = String::new();
        run_one_frame(&context, &mut draft, Vec::new(), true);
        let (input_has_focus, send, _center) = run_one_frame(
            &context,
            &mut draft,
            vec![Event::Text("你好".to_string())],
            false,
        );
        assert!(input_has_focus, "打字之后焦点应当还在输入框里");
        assert!(!send, "打字不该发送");
        assert!(
            draft.ends_with("你好"),
            "打进去的字要留在草稿里，实际 {draft:?}"
        );
    }

    /// Regular Enter = send: don't put newlines into the draft anymore
    #[test]
    fn plain_enter_asks_to_send_instead_of_inserting_a_newline() {
        let context = Context::default();
        let mut draft = String::new();
        run_one_frame(&context, &mut draft, Vec::new(), true);
        let (input_has_focus, send, _center) = run_one_frame(
            &context,
            &mut draft,
            vec![key_event(Key::Enter, Modifiers::NONE)],
            false,
        );
        assert!(input_has_focus, "回车之后焦点该留在输入框");
        assert!(send, "输入框聚焦时按回车应当报发送");
        assert!(
            !draft.contains('\n'),
            "回车不该往草稿里塞换行，实际 {draft:?}"
        );
    }

    /// Shift+Enter = newline (goes through egui's own return_key), and doesn't send
    #[test]
    fn shift_enter_inserts_a_newline_without_sending() {
        let context = Context::default();
        let mut draft = String::from("abc");
        run_one_frame(&context, &mut draft, Vec::new(), true);
        let (_focus, send, _center) = run_one_frame(
            &context,
            &mut draft,
            vec![key_event(Key::Enter, Modifiers::SHIFT)],
            false,
        );
        assert!(!send, "Shift+回车是换行，不该发送");
    }

    /// When focus is not on the input box, Enter must not send: pressing Enter in another input box shouldn't accidentally send a chat message
    #[test]
    fn enter_without_focus_does_not_send() {
        let context = Context::default();
        let mut draft = String::from("abc");
        let (_focus, send, _center) = run_one_frame(
            &context,
            &mut draft,
            vec![key_event(Key::Enter, Modifiers::NONE)],
            false,
        );
        assert!(!send, "没聚焦就不该发送");
    }
}

#[cfg(test)]
mod message_alignment_tests {
    use super::{MessageRow, avatar_side_pixels, draw_message_row};
    use crate::appearance::Skin;
    use baihua_core::config::Palette;
    use egui::{CentralPanel, Color32, Context, Pos2, RawInput, Rect, Vec2};

    /// Test window size: leave enough blank space on both sides so you can measure "which side it's sticking to"
    fn screen_width() -> f32 {
        800.0
    }

    fn raw_input() -> RawInput {
        RawInput {
            screen_rect: Some(Rect::from_min_size(
                Pos2::ZERO,
                Vec2::new(screen_width(), 600.0),
            )),
            ..Default::default()
        }
    }

    /// Draw a message row and take back all the text drawn (content, horizontal start point).
    /// Only take text, not color blocks: the entire screen's panel background would fill the bounding box, making it impossible to measure the real hit point.
    fn painted_texts(row: MessageRow) -> Vec<(String, f32)> {
        let context = Context::default();
        let skin = Skin::from(&Palette::built_in());
        let mut row_slot = Some(row);
        let mut collected: Vec<(String, f32)> = Vec::new();
        context
            .run_ui(raw_input(), |ctx| {
                if let Some(row) = row_slot.take() {
                    CentralPanel::default().show(ctx, |ui| {
                        draw_message_row(ui, &skin, row, false);
                    });
                }
                collected = ctx.graphics_mut(|graphics| {
                    let mut texts: Vec<(String, f32)> = Vec::new();
                    if let Some(list) = graphics.get(egui::LayerId::background()) {
                        for entry in list.all_entries() {
                            if let egui::Shape::Text(text_shape) = &entry.shape {
                                texts
                                    .push((text_shape.galley.text().to_string(), text_shape.pos.x));
                            }
                        }
                    }
                    texts
                });
            })
            .drop_without_applying_deltas();
        collected
    }

    fn position_of(texts: &[(String, f32)], needle: &str) -> f32 {
        texts
            .iter()
            .find(|(text, _)| text == needle)
            .map(|(_, position)| *position)
            .unwrap_or_else(|| {
                panic!("This frame did not draw {needle:?}; actually drew {texts:?}")
            })
    }

    fn own_message() -> MessageRow {
        MessageRow {
            message_id: "message-1".to_string(),
            sender_id: "me".to_string(),
            sender: "我".to_string(),
            content: "这是一条自己的消息".to_string(),
            time_text: "12:00".to_string(),
            is_own: true,
            content_color: Color32::WHITE,
            content_highlight: None,
            texture: None,
        }
    }

    fn other_message() -> MessageRow {
        MessageRow {
            message_id: "message-1".to_string(),
            sender_id: "someone".to_string(),
            sender: "别人".to_string(),
            content: "这是一条别人的消息".to_string(),
            time_text: "12:01".to_string(),
            is_own: false,
            content_color: Color32::WHITE,
            content_highlight: None,
            texture: None,
        }
    }

    /// Your own messages must be fully right-aligned: username, time, and body must all fall in the right half.
    /// This is the regression for feedback "your own messages align to the left" —
    /// The old approach only wrapped the outermost layer with right-to-left, but the inner username row and body were still left-aligned,
    /// so the avatar ended up on the far right but the text was all stuck to the left edge.
    #[test]
    fn own_message_text_sits_on_the_right_side() {
        let texts = painted_texts(own_message());
        let middle = screen_width() / 2.0;
        for expected in ["我", "12:00", "这是一条自己的消息"] {
            let position = position_of(&texts, expected);
            assert!(
                position > middle,
                "自己的消息里 {expected:?} 应当落在右半边，实际起点 {position}"
            );
        }
    }

    /// Other people's messages must still be left-aligned: the fix must not push both sides to the right
    #[test]
    fn other_message_text_sits_on_the_left_side() {
        let texts = painted_texts(other_message());
        let middle = screen_width() / 2.0;
        for expected in ["别人", "12:01", "这是一条别人的消息"] {
            let position = position_of(&texts, expected);
            assert!(
                position < middle,
                "别人的消息里 {expected:?} 应当落在左半边，实际起点 {position}"
            );
        }
    }

    /// In the right-aligned text block where body and username are in the same column: the body's start point shouldn't be further left than the username row,
    /// indicating the whole block is laid out right-to-left (not "username on the right, body slides back left").
    /// Note that the first letter of the avatar placeholder is also the first character of `row.sender`, so here we judge by "except the rightmost
    /// letter's sender position, to avoid treating the avatar's coordinates as the username.
    #[test]
    fn own_message_content_is_right_aligned_with_its_name() {
        let texts = painted_texts(own_message());
        let avatar_initial_x = screen_width() - avatar_side_pixels() as f32;
        let name_positions: Vec<f32> = texts
            .iter()
            .filter(|(text, position)| text == "我" && (*position < avatar_initial_x - 0.5))
            .map(|(_, position)| *position)
            .collect();
        assert_eq!(
            name_positions.len(),
            1,
            "应当有且仅有一处用户名标签（头像占位字母另算），实际 {texts:?}"
        );
        let name_position = name_positions[0];
        let content_position = position_of(&texts, "这是一条自己的消息");
        assert!(
            (content_position - name_position).abs() <= 1.0,
            "正文与用户名同在一列右对齐，起点应当一致；用户名 {name_position}，正文 {content_position}"
        );
    }
}

#[cfg(test)]
mod conversation_layout_tests {
    use super::{
        MessageInputView, MessageRow, draw_conversation_area, draw_message_input_area,
        message_input_height,
    };
    use crate::appearance::Skin;
    use baihua_core::config::Palette;
    use egui::{CentralPanel, Color32, Context, Pos2, RawInput, Rect, Sense, Ui, Vec2};

    /// Test window height: enough for dozens of messages, but not hundreds
    fn screen_height() -> f32 {
        600.0
    }

    fn raw_input() -> RawInput {
        RawInput {
            screen_rect: Some(Rect::from_min_size(
                Pos2::ZERO,
                Vec2::new(800.0, screen_height()),
            )),
            ..Default::default()
        }
    }

    /// Messages like those in "a group chat with a lot of conversation": far more rows than the screen can display at once
    fn many_messages() -> Vec<MessageRow> {
        (0..60)
            .map(|index| MessageRow {
                message_id: format!("message-{index}"),
                sender_id: format!("user-{index}"),
                sender: format!("用户{index}"),
                content: format!("第 {index} 条消息，这个群聊得有点多"),
                time_text: "12:00".to_string(),
                is_own: index % 2 == 0,
                content_color: Color32::WHITE,
                content_highlight: None,
                texture: None,
            })
            .collect()
    }

    /// Draw a frame of "a message-heavy conversation area" and return the rectangle the input area occupies.
    /// Inside the input area, use an empty block with the same height as a real message box instead of an input box: what this measures is "whether this position was squeezed out by the message list
    /// or moves up and down with the hint row"; regardless of whether text or something else is drawn in the box.
    fn input_area_after_one_frame(
        context: &Context,
        skin: &Skin,
        typing_line_visible: bool,
    ) -> Rect {
        let mut input_area = Rect::NOTHING;
        context
            .run_ui(raw_input(), |ctx| {
                CentralPanel::default().show(ctx, |ui| {
                    draw_conversation_area(
                        ui,
                        skin,
                        many_messages(),
                        "还没有消息".to_string(),
                        true,
                        None,
                        |ui: &mut Ui| {
                            // Draw from bottom to top just like the real interface: input box first, then the two hint rows above it
                            let (rect, _response) = ui.allocate_exact_size(
                                Vec2::new(ui.available_width(), message_input_height()),
                                Sense::hover(),
                            );
                            input_area = rect;
                            if typing_line_visible {
                                ui.label("某人正在输入");
                            }
                        },
                    );
                });
            })
            .drop_without_applying_deltas();
        input_area
    }

    /// Regression for feedback "in a group chat with a lot of conversation, the text input box for sending messages gets squeezed out":
    /// No matter how many messages there are, the bottom input area must stay completely within the visible area — height unchanged, doesn't fall off the bottom of the screen.
    ///
    /// Before the fix the order was to draw the scrollable message list first, then the input box: the `ScrollArea` outer frame is all the space remaining from the parent
    /// all the space; once content is tall enough it fills up, and the input box drawn after it can only fall outside the visible area (this assertion would fail).
    #[test]
    fn message_input_stays_visible_when_the_history_is_long() {
        let context = Context::default();
        let skin = Skin::from(&Palette::built_in());
        let input_area = input_area_after_one_frame(&context, &skin, false);
        assert!(
            (input_area.height() - message_input_height()).abs() <= 0.5,
            "输入区应当拿到它需要的 {} 点高度，实际 {}",
            message_input_height(),
            input_area.height()
        );
        assert!(
            input_area.max.y <= screen_height() + 0.5,
            "输入区不该被挤到屏幕下沿之外，实际下沿 {}",
            input_area.max.y
        );
        assert!(
            input_area.min.y >= 0.0,
            "输入区不该跑到屏幕上方，实际上沿 {}",
            input_area.min.y
        );
    }

    /// The position of the input box can't jump up and down with the "someone is typing" row: the panel height is determined by content,
    /// and content is laid out sticking to the bottom, so the hint row appearing or disappearing should only change the height of the message list.
    /// This alternates between the two scenarios, and the input box's position must be identical.
    #[test]
    fn input_box_keeps_its_place_when_the_typing_line_shows_up() {
        let context = Context::default();
        let skin = Skin::from(&Palette::built_in());
        let without_typing_line = input_area_after_one_frame(&context, &skin, false);
        let with_typing_line = input_area_after_one_frame(&context, &skin, true);
        assert_eq!(
            without_typing_line, with_typing_line,
            "提示行出现不该挪动输入框：没有提示行时 {without_typing_line:?}，有提示行时 {with_typing_line:?}"
        );
    }

    /// This round's change: after the completion popup was changed to a floating layer, opening it no longer occupies layout space,
    /// so the height of the message area (the block above the input box) won't be pushed up
    #[test]
    fn completion_list_does_not_shrink_the_message_area() {
        // Use an independent context for each of the two scenarios so the previous input area height doesn't affect this one
        let without_completion = input_area_rect_for_draft("");
        let with_completion = input_area_rect_for_draft("/");
        assert_eq!(
            without_completion, with_completion,
            "打开补全提示不该改变输入区（也就不会挤掉消息区）：没有补全时 {without_completion:?}，有补全时 {with_completion:?}"
        );
    }

    /// The command table used by the completion popup (name + description)
    fn command_list() -> Vec<(&'static str, String)> {
        vec![
            ("info", "查看群聊信息".to_string()),
            ("kick", "踢出群聊成员".to_string()),
        ]
    }

    /// This round's change: when the search switches to a match, the message area must scroll to that message.
    /// 60 messages, target is the 40th from the bottom: without scrolling it would be squeezed above the view (negative Y coordinate),
    /// after scrolling it should fall within the middle section of the visible area.
    #[test]
    fn scrolling_to_a_search_match_brings_it_into_view() {
        let context = Context::default();
        let skin = Skin::from(&Palette::built_in());
        let target = "第 40 条消息，这个群聊得有点多";
        let mut painted: Vec<(String, Pos2)> = Vec::new();
        // Scrolling there is animated (egui's scroll animation advances per frame); draw several more frames to let it settle
        for _ in 0..20 {
            context
                .run_ui(raw_input(), |ctx| {
                    CentralPanel::default().show(ctx, |ui| {
                        let _ = draw_conversation_area(
                            ui,
                            &skin,
                            many_messages(),
                            "还没有消息".to_string(),
                            // Same as the real interface: when scrolling to a match, first turn off "stick to bottom",
                            // otherwise the stick-to-bottom logic would pull the scroll position back to the very bottom
                            false,
                            Some("message-40".to_string()),
                            |_ui: &mut Ui| {},
                        );
                    });
                    painted = ctx.graphics_mut(|graphics| {
                        let mut texts: Vec<(String, Pos2)> = Vec::new();
                        if let Some(list) = graphics.get(egui::LayerId::background()) {
                            for entry in list.all_entries() {
                                if let egui::Shape::Text(text_shape) = &entry.shape {
                                    texts.push((
                                        text_shape.galley.text().to_string(),
                                        text_shape.pos,
                                    ));
                                }
                            }
                        }
                        texts
                    });
                })
                .drop_without_applying_deltas();
        }
        let position = position_of(&painted, target);
        assert!(
            position.y > 80.0 && position.y < screen_height() - 120.0,
            "命中项应当被滚到可视区里，实际纵坐标 {}",
            position.y
        );
    }

    /// This round's addition: when the message area scrolls to the very top (the first message), the "touching top" status must be reported back to the caller,
    /// so the session layer can automatically pull earlier messages from the server.
    #[test]
    fn reaching_the_first_message_reports_reached_the_top() {
        let context = Context::default();
        let skin = Skin::from(&Palette::built_in());
        let mut reached_top = false;
        // Scroll to the first message with animation; draw several more frames to let it stick to the top
        for _ in 0..20 {
            context
                .run_ui(raw_input(), |ctx| {
                    CentralPanel::default().show(ctx, |ui| {
                        let (_, _, top) = draw_conversation_area(
                            ui,
                            &skin,
                            many_messages(),
                            "还没有消息".to_string(),
                            false,
                            Some("message-0".to_string()),
                            |_ui: &mut Ui| {},
                        );
                        reached_top = top;
                    });
                })
                .drop_without_applying_deltas();
        }
        assert!(reached_top, "滚到第一条消息之后消息区要报出「已经触顶」");
    }

    /// Control: must not report "touching top" when stuck to the bottom, otherwise just opening a room would immediately auto-pull history.
    #[test]
    fn staying_at_the_bottom_is_not_reached_the_top() {
        let context = Context::default();
        let skin = Skin::from(&Palette::built_in());
        let mut reached_top = false;
        for _ in 0..3 {
            context
                .run_ui(raw_input(), |ctx| {
                    CentralPanel::default().show(ctx, |ui| {
                        let (_, _, top) = draw_conversation_area(
                            ui,
                            &skin,
                            many_messages(),
                            "还没有消息".to_string(),
                            true,
                            None,
                            |_ui: &mut Ui| {},
                        );
                        reached_top = top;
                    });
                })
                .drop_without_applying_deltas();
        }
        assert!(!reached_top, "贴着底边看最新消息时不该被判成触顶");
    }

    /// Touch-to-top auto-paging must not fire multiple times in one touch: the session layer's judgment and the "insert a page" action
    /// must be played through in the real call order; when the user stops scrolling, only one page of earlier messages should be pulled.
    #[test]
    fn one_reach_to_the_top_loads_a_single_page() {
        let context = Context::default();
        let skin = Skin::from(&Palette::built_in());
        let mut rows = many_messages();
        // First let the user scroll all the way to the top (scroll position settled), at this point the session layer has no positioning requests yet
        for _ in 0..20 {
            context
                .run_ui(raw_input(), |ctx| {
                    CentralPanel::default().show(ctx, |ui| {
                        let _ = draw_conversation_area(
                            ui,
                            &skin,
                            rows.clone(),
                            "还没有消息".to_string(),
                            false,
                            Some("message-0".to_string()),
                            |_ui: &mut Ui| {},
                        );
                    });
                })
                .drop_without_applying_deltas();
        }
        let mut pending: Option<String> = None;
        let mut loaded_pages = 0;
        // The user has "left the stick-to-bottom state"; every subsequent frame no longer forces stick-to-bottom (same as real interface)
        for _ in 0..60 {
            let consumed = pending.clone();
            let mut reached_top = false;
            context
                .run_ui(raw_input(), |ctx| {
                    CentralPanel::default().show(ctx, |ui| {
                        let (_, _, top) = draw_conversation_area(
                            ui,
                            &skin,
                            rows.clone(),
                            "还没有消息".to_string(),
                            false,
                            consumed.clone(),
                            |_ui: &mut Ui| {},
                        );
                        reached_top = top;
                    });
                })
                .drop_without_applying_deltas();
            if reached_top && pending.is_none() {
                let anchor = rows.first().map(|row| row.message_id.clone());
                let mut older: Vec<MessageRow> = (0..50)
                    .map(|index| MessageRow {
                        message_id: format!("older-{index}"),
                        sender_id: "user-old".to_string(),
                        sender: "更早的用户".to_string(),
                        content: format!("更早的第 {index} 条消息"),
                        time_text: "11:00".to_string(),
                        is_own: false,
                        content_color: Color32::WHITE,
                        content_highlight: None,
                        texture: None,
                    })
                    .collect();
                older.extend(rows);
                rows = older;
                pending = anchor;
                loaded_pages += 1;
            }
            if consumed.is_some() && consumed == pending {
                pending = None;
            }
        }
        assert_eq!(
            loaded_pages, 1,
            "一次触顶（用户不再滚动）只该拉一页更早的消息，实际拉了 {loaded_pages} 页"
        );
    }

    fn position_of(texts: &[(String, Pos2)], needle: &str) -> Pos2 {
        texts
            .iter()
            .find(|(text, _)| text == needle)
            .map(|(_, position)| *position)
            .unwrap_or_else(|| panic!("这一帧没画出 {needle:?}"))
    }

    /// Draw several frames with a given draft (the floating layer needs a warm-up frame to land on the layer); return the rectangle of the input area block
    fn input_area_rect_for_draft(draft: &str) -> Rect {
        let context = Context::default();
        let skin = Skin::from(&Palette::built_in());
        let mut area = Rect::NOTHING;
        let mut view = MessageInputView {
            draft: draft.to_string(),
            placeholder: "输入消息".to_string(),
            request_focus: false,
            selected_command: 0,
        };
        for _ in 0..3 {
            context
                .run_ui(raw_input(), |ctx| {
                    CentralPanel::default().show(ctx, |ui| {
                        draw_conversation_area(
                            ui,
                            &skin,
                            many_messages(),
                            "还没有消息".to_string(),
                            true,
                            None,
                            |ui: &mut Ui| {
                                let (rect, _response) = ui.allocate_exact_size(
                                    Vec2::new(ui.available_width(), message_input_height()),
                                    Sense::hover(),
                                );
                                area = rect;
                                draw_message_input_area(ui, &skin, &command_list(), &mut view)
                            },
                        );
                    });
                })
                .drop_without_applying_deltas();
        }
        area
    }
}

#[cfg(test)]
mod message_scroll_tests {
    use super::{conversation_reached_top, scroll_request_is_consumed};

    /// Touch-to-top judgment: the content must actually exceed the visible height (there must be room to scroll), and the offset must be touching the top.
    /// Short sessions (content doesn't exceed) have an offset of 0 every frame; they can't be judged as touching the top and repeatedly pull history.
    #[test]
    fn only_overflowing_content_at_the_top_counts_as_reached_the_top() {
        // Long session scrolled to the top: touching top
        assert!(conversation_reached_top(2000.0, 400.0, 0.0));
        // Long session still stopped in the middle: not touching top
        assert!(!conversation_reached_top(2000.0, 400.0, 120.0));
        // Short session has no room to scroll at all: not touching top (otherwise it would auto-page every frame)
        assert!(!conversation_reached_top(120.0, 400.0, 0.0));
    }

    /// Positioning request clearing rule: only clear when "this frame really handed it to the scroll region".
    /// The search match change is written in after the message area is drawn; it has to wait until the next frame to take effect.
    #[test]
    fn a_scroll_request_set_after_painting_survives_to_the_next_frame() {
        // This frame used a, and after drawing it's still a: already consumed, clear it
        assert!(scroll_request_is_consumed(Some("a"), Some("a")));
        // This frame has no target, after drawing new b was written (search match change): wait until next frame
        assert!(!scroll_request_is_consumed(None, Some("b")));
        // This frame used a, but after drawing it switched to b (arrow key pressed in succession): the new one must be kept
        assert!(!scroll_request_is_consumed(Some("a"), Some("b")));
    }
}

#[cfg(test)]
mod avatar_click_tests {
    use super::{MessageRow, draw_message_row};
    use crate::appearance::Skin;
    use baihua_core::config::Palette;
    use egui::{
        CentralPanel, Color32, Context, Event, Modifiers, PointerButton, Pos2, RawInput, Rect, Vec2,
    };

    fn raw_input(events: Vec<Event>) -> RawInput {
        RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, Vec2::new(800.0, 600.0))),
            focused: true,
            events,
            ..Default::default()
        }
    }

    fn click_at(point: Pos2) -> Vec<Event> {
        vec![
            Event::PointerButton {
                pos: point,
                button: PointerButton::Primary,
                pressed: true,
                modifiers: Modifiers::NONE,
            },
            Event::PointerButton {
                pos: point,
                button: PointerButton::Primary,
                pressed: false,
                modifiers: Modifiers::NONE,
            },
        ]
    }

    /// A message from someone else: when there's no avatar, what's drawn is an avatar placeholder block, and the letter on the placeholder is the first character of the sender's name.
    fn other_message() -> MessageRow {
        MessageRow {
            message_id: "message-1".to_string(),
            sender_id: "user-2".to_string(),
            sender: "别人".to_string(),
            content: "这是一条别人的消息".to_string(),
            time_text: "12:01".to_string(),
            is_own: false,
            content_color: Color32::WHITE,
            content_highlight: None,
            texture: None,
        }
    }

    /// A message from yourself: the avatar is on the far right
    fn own_message() -> MessageRow {
        MessageRow {
            message_id: "message-1".to_string(),
            sender_id: "me".to_string(),
            sender: "我".to_string(),
            content: "这是一条自己的消息".to_string(),
            time_text: "12:00".to_string(),
            is_own: true,
            content_color: Color32::WHITE,
            content_highlight: None,
            texture: None,
        }
    }

    /// Draw a message row for one frame, return (the text and positions drawn this frame, the user ID reported when clicking the avatar)
    fn run_one_frame(
        context: &Context,
        row: MessageRow,
        events: Vec<Event>,
    ) -> (Vec<(String, Pos2)>, Option<String>) {
        let skin = Skin::from(&Palette::built_in());
        let mut row_slot = Some(row);
        let mut clicked_sender: Option<String> = None;
        let mut painted: Vec<(String, Pos2)> = Vec::new();
        context
            .run_ui(raw_input(events), |ctx| {
                if let Some(row) = row_slot.take() {
                    CentralPanel::default().show(ctx, |ui| {
                        clicked_sender = draw_message_row(ui, &skin, row, false);
                    });
                }
                painted = ctx.graphics_mut(|graphics| {
                    let mut texts: Vec<(String, Pos2)> = Vec::new();
                    if let Some(list) = graphics.get(egui::LayerId::background()) {
                        for entry in list.all_entries() {
                            if let egui::Shape::Text(text_shape) = &entry.shape {
                                texts.push((text_shape.galley.text().to_string(), text_shape.pos));
                            }
                        }
                    }
                    texts
                });
            })
            .drop_without_applying_deltas();
        (painted, clicked_sender)
    }

    /// Where a piece of text is drawn (taking the top-left corner of the text)
    fn position_of(texts: &[(String, Pos2)], needle: &str) -> Pos2 {
        texts
            .iter()
            .find(|(text, _)| text == needle)
            .map(|(_, position)| *position)
            .unwrap_or_else(|| {
                panic!("This frame did not draw {needle:?}; actually drew {texts:?}")
            })
    }

    /// This round's change: the profile no longer has a button at the bottom; instead click the avatar in the message to view.
    /// The first character on the avatar placeholder block is definitely inside the avatar block; using it as the hit point is most stable.
    #[test]
    fn clicking_the_avatar_reports_the_sender_id() {
        let context = Context::default();
        let (texts, clicked) = run_one_frame(&context, other_message(), Vec::new());
        assert!(clicked.is_none(), "什么都不点的时候不该报出用户 ID");
        let avatar = position_of(&texts, "别");
        let (_texts, clicked) = run_one_frame(
            &context,
            other_message(),
            click_at(avatar + Vec2::new(2.0, 8.0)),
        );
        assert_eq!(
            clicked.as_deref(),
            Some("user-2"),
            "点别人的头像应当报出这个人的用户 ID"
        );
    }

    /// Your own message avatar is on the far right, and it must also be clickable (clicking it opens your own profile)
    #[test]
    fn clicking_the_own_avatar_reports_the_own_user_id() {
        let context = Context::default();
        let (texts, _clicked) = run_one_frame(&context, own_message(), Vec::new());
        let avatar = position_of(&texts, "我");
        let (_texts, clicked) = run_one_frame(
            &context,
            own_message(),
            click_at(avatar + Vec2::new(2.0, 8.0)),
        );
        assert_eq!(
            clicked.as_deref(),
            Some("me"),
            "点自己的头像应当报出自己的用户 ID"
        );
    }

    /// Only the avatar is clickable: clicking on the body text shouldn't report a user ID (otherwise the body text couldn't be selected or dragged)
    #[test]
    fn clicking_the_message_text_reports_nothing() {
        let context = Context::default();
        let (texts, _clicked) = run_one_frame(&context, other_message(), Vec::new());
        let content = position_of(&texts, "这是一条别人的消息");
        let (_texts, clicked) = run_one_frame(
            &context,
            other_message(),
            click_at(content + Vec2::new(4.0, 8.0)),
        );
        assert!(
            clicked.is_none(),
            "点在正文上不该报出用户 ID，实际 {clicked:?}"
        );
    }
}

#[cfg(test)]
mod creation_window_tests {
    use super::{CreationPage, CreationView, draw_creation_form};
    use egui::{
        CentralPanel, Context, Event, Modifiers, PointerButton, Pos2, RawInput, Rect, Vec2,
    };

    fn raw_input(events: Vec<Event>) -> RawInput {
        RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, Vec2::new(640.0, 480.0))),
            focused: true,
            events,
            ..Default::default()
        }
    }

    fn click_at(point: Pos2) -> Vec<Event> {
        vec![
            Event::PointerButton {
                pos: point,
                button: PointerButton::Primary,
                pressed: true,
                modifiers: Modifiers::NONE,
            },
            Event::PointerButton {
                pos: point,
                button: PointerButton::Primary,
                pressed: false,
                modifiers: Modifiers::NONE,
            },
        ]
    }

    /// Create group chat form: two rows of input boxes plus a create button
    fn group_view() -> CreationView {
        CreationView {
            page: CreationPage::Group,
            title: "创建群聊".to_string(),
            first_label: "群聊名称".to_string(),
            first_value: String::new(),
            members_label: "成员（逗号分隔）".to_string(),
            members_placeholder: "user1,user2".to_string(),
            members_value: String::new(),
            confirm: "确定".to_string(),
        }
    }

    /// Create private chat form: only one row of input box plus a create button
    fn private_view() -> CreationView {
        CreationView {
            page: CreationPage::Private,
            title: "创建私聊".to_string(),
            first_label: "对方用户名".to_string(),
            first_value: String::new(),
            members_label: String::new(),
            members_placeholder: String::new(),
            members_value: String::new(),
            confirm: "确定".to_string(),
        }
    }

    /// Draw a create form for one frame, return (the text and positions drawn this frame, whether the create button was clicked)
    fn run_one_frame(
        context: &Context,
        view: &mut CreationView,
        events: Vec<Event>,
    ) -> (Vec<(String, Pos2)>, bool) {
        let mut submitted = false;
        let mut painted: Vec<(String, Pos2)> = Vec::new();
        context
            .run_ui(raw_input(events), |ctx| {
                CentralPanel::default().show(ctx, |ui| {
                    submitted = draw_creation_form(ui, view);
                });
                painted = ctx.graphics_mut(|graphics| {
                    let mut texts: Vec<(String, Pos2)> = Vec::new();
                    if let Some(list) = graphics.get(egui::LayerId::background()) {
                        for entry in list.all_entries() {
                            if let egui::Shape::Text(text_shape) = &entry.shape {
                                texts.push((text_shape.galley.text().to_string(), text_shape.pos));
                            }
                        }
                    }
                    texts
                });
            })
            .drop_without_applying_deltas();
        (painted, submitted)
    }

    fn position_of(texts: &[(String, Pos2)], needle: &str) -> Pos2 {
        texts
            .iter()
            .find(|(text, _)| text == needle)
            .map(|(_, position)| *position)
            .unwrap_or_else(|| {
                panic!("This frame did not draw {needle:?}; actually drew {texts:?}")
            })
    }

    fn drawn_texts(texts: &[(String, Pos2)]) -> Vec<String> {
        texts.iter().map(|(text, _)| text.clone()).collect()
    }

    /// The create group chat window needs group name and members as two input rows plus a create button
    #[test]
    fn group_form_shows_the_inputs_and_the_create_button() {
        let context = Context::default();
        let mut view = group_view();
        let (texts, _submitted) = run_one_frame(&context, &mut view, Vec::new());
        let drawn = drawn_texts(&texts);
        for expected in ["群聊名称", "成员（逗号分隔）", "确定"] {
            assert!(
                drawn.iter().any(|text| text == expected),
                "创建群聊的表单里应当画上 {expected:?}，实际画出 {drawn:?}"
            );
        }
    }

    /// The create private chat window should only have the "other person's username" row; it shouldn't have an extra members row
    #[test]
    fn private_form_shows_only_the_target_row() {
        let context = Context::default();
        let mut view = private_view();
        let (texts, _submitted) = run_one_frame(&context, &mut view, Vec::new());
        let drawn = drawn_texts(&texts);
        for expected in ["对方用户名", "确定"] {
            assert!(
                drawn.iter().any(|text| text == expected),
                "创建私聊的表单里应当画上 {expected:?}，实际画出 {drawn:?}"
            );
        }
        assert!(
            !drawn.iter().any(|text| text == "成员（逗号分隔）"),
            "创建私聊不该画出成员那一行，实际画出 {drawn:?}"
        );
    }

    /// Clicking the create button must report "it was submitted this frame"
    #[test]
    fn clicking_the_create_button_reports_submit() {
        let context = Context::default();
        let mut view = group_view();
        let (texts, _submitted) = run_one_frame(&context, &mut view, Vec::new());
        let button = position_of(&texts, "确定");
        let (_texts, submitted) =
            run_one_frame(&context, &mut view, click_at(button + Vec2::new(4.0, 8.0)));
        assert!(submitted, "点在创建按钮上应当报出提交");
    }

    /// The input box can type: click into the first input row, then type, and the content must go into the draft
    #[test]
    fn typing_lands_in_the_first_input() {
        let context = Context::default();
        let mut view = group_view();
        let (texts, _submitted) = run_one_frame(&context, &mut view, Vec::new());
        let label = position_of(&texts, "群聊名称");
        // The input box is right after the label: shift right from the label's left edge, the hit point is still inside the input box
        let input_point = Pos2::new(label.x + 150.0, label.y + 8.0);
        run_one_frame(&context, &mut view, click_at(input_point));
        run_one_frame(
            &context,
            &mut view,
            vec![Event::Text("图形版联调群".to_string())],
        );
        assert_eq!(
            view.first_value, "图形版联调群",
            "敲进去的字要留在群聊名称里，实际 {:?}",
            view.first_value
        );
    }
}

#[cfg(test)]
mod panel_size_tests {
    use super::{room_panel, room_panel_default_size, room_panel_size_range};
    use crate::appearance::Skin;
    use baihua_core::config::Palette;
    use egui::{CentralPanel, Context, Pos2, RawInput, Rect, Vec2};

    fn raw_input(width: f32) -> RawInput {
        RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, Vec2::new(width, 400.0))),
            ..Default::default()
        }
    }

    /// Draw a room list panel for one frame, return its width
    fn room_width_after_one_frame(context: &Context, screen_width: f32) -> f32 {
        let skin = Skin::from(&Palette::built_in());
        let mut expanded = true;
        let mut width = 0.0;
        context
            .run_ui(raw_input(screen_width), |ctx| {
                CentralPanel::default().show(ctx, |ui| {
                    let response = room_panel(&skin).show_collapsible(ui, &mut expanded, |ui| {
                        ui.label("房间");
                    });
                    if let Some(response) = response {
                        width = response.response.rect.width();
                    }
                });
            })
            .drop_without_applying_deltas();
        width
    }

    /// Regression for feedback "when the message display area is too compressed, the sidebar is squeezed and can't be restored":
    /// A window being squeezed smaller can temporarily narrow the sidebar, but when the window is enlarged again it must return to at least the minimum width.
    /// Without a minimum width, egui's panel would keep using the squeezed-smaller size.
    #[test]
    fn squeezed_room_panel_recovers_to_its_minimum_width() {
        let range = room_panel_size_range();
        assert!(
            *range.start() > 0.0 && *range.end() > *range.start(),
            "侧边栏必须给出正的宽度下限与更大的上限，实际 {range:?}"
        );
        let context = Context::default();
        let squeezed = room_width_after_one_frame(&context, 200.0);
        let restored = room_width_after_one_frame(&context, 1200.0);
        let minimum = *room_panel_size_range().start();
        assert!(
            squeezed < room_panel_default_size(),
            "窄窗口下应当确实被压窄过，实际宽度 {squeezed}"
        );
        assert!(
            restored >= minimum,
            "窗口放大回来之后应当恢复到下限宽度 {minimum} 以上，实际宽度 {restored}"
        );
    }
}

#[cfg(test)]
mod message_input_area_tests {
    use super::{
        MessageInputOutcome, MessageInputView, command_completion_gap, command_completion_height,
        draw_message_input_area,
    };
    use crate::appearance::Skin;
    use baihua_core::config::Palette;
    use egui::{
        CentralPanel, Context, Event, Key, Modifiers, PointerButton, Pos2, RawInput, Rect, Vec2,
    };

    fn raw_input(events: Vec<Event>) -> RawInput {
        RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, Vec2::new(900.0, 600.0))),
            focused: true,
            events,
            ..Default::default()
        }
    }

    fn click_at(point: Pos2) -> Vec<Event> {
        vec![
            Event::PointerButton {
                pos: point,
                button: PointerButton::Primary,
                pressed: true,
                modifiers: Modifiers::NONE,
            },
            Event::PointerButton {
                pos: point,
                button: PointerButton::Primary,
                pressed: false,
                modifiers: Modifiers::NONE,
            },
        ]
    }

    /// The data for drawing the input area: the draft is provided by the parameter, the rest uses fixed Chinese text,
    /// so that assertions can find hit points directly by text
    fn input_view(draft: &str) -> MessageInputView {
        MessageInputView {
            draft: draft.to_string(),
            placeholder: "输入消息".to_string(),
            request_focus: false,
            selected_command: 0,
        }
    }

    /// Press a certain key (without modifier keys)
    fn key_event(key: Key) -> Event {
        Event::Key {
            key,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: Modifiers::NONE,
        }
    }

    /// Command table: descriptions are in Chinese, used directly as lookup targets in assertions
    fn test_commands() -> Vec<(&'static str, String)> {
        vec![
            ("list_users", "列出全部注册用户".to_string()),
            ("login", "打开登录界面".to_string()),
            ("logout", "退出登录".to_string()),
            ("kick", "踢出群聊成员".to_string()),
        ]
    }

    /// Draw the input area for one frame, return (the text and positions drawn this frame, the input area result, whether arrow keys are still in the event queue)
    fn run_one_frame(
        context: &Context,
        view: &mut MessageInputView,
        events: Vec<Event>,
    ) -> (Vec<(String, Pos2)>, MessageInputOutcome, bool) {
        run_one_frame_with_commands(context, view, events, test_commands())
    }

    /// Same as `run_one_frame` except the command table is provided by the parameter:
    /// Testing "when the completion list doesn't fit on one screen it scrolls by itself" needs a sufficiently long command table
    fn run_one_frame_with_commands(
        context: &Context,
        view: &mut MessageInputView,
        events: Vec<Event>,
        commands: Vec<(&'static str, String)>,
    ) -> (Vec<(String, Pos2)>, MessageInputOutcome, bool) {
        // First warm up a frame: the completion tooltip is a floating layer (`Area` + scroll area), the first frame only does size probing,
        // The text inside hasn't landed on the layer yet; in the real interface it's always drawn continuously, so here also warm up one frame first
        draw_one_frame_with_commands(context, view, Vec::new(), commands.clone());
        draw_one_frame_with_commands(context, view, events, commands)
    }

    /// Draw the input area for one frame and collect the text drawn this frame (command table provided by parameter)
    fn draw_one_frame_with_commands(
        context: &Context,
        view: &mut MessageInputView,
        events: Vec<Event>,
        commands: Vec<(&'static str, String)>,
    ) -> (Vec<(String, Pos2)>, MessageInputOutcome, bool) {
        let skin = Skin::from(&Palette::built_in());
        let mut outcome = MessageInputOutcome {
            send: false,
            draft_changed: false,
            search_step: None,
            complete_command: None,
            input_rect: Rect::NOTHING,
        };
        let mut arrow_survived = false;
        let mut painted: Vec<(String, Pos2)> = Vec::new();
        context
            .run_ui(raw_input(events), |ctx| {
                CentralPanel::default().show(ctx, |ui| {
                    // The input area in the real interface is laid out from bottom to top; here lay it out the same way,
                    // so you can accurately measure "which row is at the very bottom"
                    ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                        outcome = draw_message_input_area(ui, &skin, &commands, view);
                    });
                });
                // After the input area is drawn, are the arrow keys still in this frame's event queue?
                // (if they stay, it means the input box layer still sees them and the cursor would move)
                arrow_survived = ctx.input(|state| {
                    state.events.iter().any(|event| {
                        matches!(
                            event,
                            Event::Key {
                                key: Key::ArrowUp | Key::ArrowDown,
                                pressed: true,
                                ..
                            }
                        )
                    })
                });
                painted = ctx.graphics_mut(|graphics| {
                    let mut texts: Vec<(String, Pos2)> = Vec::new();
                    // Text in the input area is on the background layer; the completion tooltip is a floating layer (`egui::Area`),
                    // painted on its own `Order::Foreground` layer, need to read it separately
                    for layer in [
                        egui::LayerId::background(),
                        egui::LayerId::new(
                            egui::Order::Foreground,
                            egui::Id::new(super::command_completion_area_id()),
                        ),
                    ] {
                        if let Some(list) = graphics.get(layer) {
                            for entry in list.all_entries() {
                                if let egui::Shape::Text(text_shape) = &entry.shape {
                                    texts.push((
                                        text_shape.galley.text().to_string(),
                                        text_shape.pos,
                                    ));
                                }
                            }
                        }
                    }
                    texts
                });
            })
            .drop_without_applying_deltas();
        (painted, outcome, arrow_survived)
    }

    fn position_of(texts: &[(String, Pos2)], needle: &str) -> Pos2 {
        texts
            .iter()
            .find(|(text, _)| text == needle)
            .map(|(_, position)| *position)
            .unwrap_or_else(|| {
                panic!("This frame did not draw {needle:?}; actually drew {texts:?}")
            })
    }

    /// This round's change (same as terminal version): in search mode, up/down arrow keys are for "switching matches",
    /// this key press must be eaten before the input box; otherwise the input box would still use it to move the cursor.
    #[test]
    fn search_mode_takes_the_arrow_keys_for_match_navigation() {
        let context = Context::default();
        let mut view = input_view("#关键词");
        let (_texts, outcome, arrow_survived) =
            run_one_frame(&context, &mut view, vec![key_event(Key::ArrowUp)]);
        assert_eq!(
            outcome.search_step,
            Some(true),
            "搜索模式下按上方向键应当报出「换到上一个命中项」"
        );
        assert!(
            !arrow_survived,
            "上方向键应当已经被输入区吃掉，不能在事件队列里留给输入框去挪光标"
        );
    }

    /// Control: when not in search mode, arrow keys still go to the input box (move the cursor as usual)
    #[test]
    fn arrow_keys_stay_with_the_input_box_outside_search_mode() {
        let context = Context::default();
        let mut view = input_view("普通消息");
        let (_texts, outcome, arrow_survived) =
            run_one_frame(&context, &mut view, vec![key_event(Key::ArrowUp)]);
        assert_eq!(
            outcome.search_step, None,
            "Normal input should not capture the up/down arrow keys"
        );
        assert!(
            arrow_survived,
            "Normal input's up arrow key should be left for the input box to handle itself"
        );
    }

    /// This round's change: which item in the completion list is selected is decided by up/down arrow keys,
    /// these keys must also be eaten before the input box (otherwise the cursor would move along)
    #[test]
    fn completion_arrow_keys_move_the_selection() {
        let context = Context::default();
        let mut view = input_view("/l");
        let (_texts, _outcome, arrow_survived) =
            run_one_frame(&context, &mut view, vec![key_event(Key::ArrowDown)]);
        assert_eq!(
            view.selected_command, 1,
            "按一下下方向键应当选到第二条候选（/login）"
        );
        assert!(
            !arrow_survived,
            "补全列表开着时方向键应当已经被吃掉，不能留给输入框挪光标"
        );
        // Pressing the up arrow again goes back to the first item; won't go out of bounds
        run_one_frame(&context, &mut view, vec![key_event(Key::ArrowUp)]);
        run_one_frame(&context, &mut view, vec![key_event(Key::ArrowUp)]);
        assert_eq!(
            view.selected_command, 0,
            "Up arrow stops at the first item when at the top"
        );
    }

    /// This round's fix: the completion selection switched by up/down arrow keys must be saved across frames.
    ///
    /// Every frame the interface rebuilds `MessageInputView` based on the cross-frame field `completion_selection`,
    /// then write `view.selected_command` back after drawing. Previously only the view was changed, not written back,
    /// next frame it goes back to the first item, so the operation is "up/down arrow keys have no response".
    #[test]
    fn completion_selection_survives_across_frames() {
        let context = Context::default();
        // Simulate the interface main loop: cross-frame saved selection → new view → draw one frame → write back
        let mut stored_selection = 0;
        for events in [vec![key_event(Key::ArrowDown)], Vec::new()] {
            let mut view = input_view("/l");
            view.selected_command = stored_selection;
            run_one_frame(&context, &mut view, events);
            stored_selection = view.selected_command;
        }
        assert_eq!(
            stored_selection, 1,
            "按过一次下方向键之后，下一帧补全列表要停在第二条（/login）"
        );
    }

    /// This round's change: when the command name isn't fully typed yet, Enter fills the selected item into the input box instead of sending
    #[test]
    fn enter_completes_the_selected_command_instead_of_sending() {
        let context = Context::default();
        let mut view = input_view("/k");
        view.request_focus = true;
        let (_texts, outcome, _arrow) =
            run_one_frame(&context, &mut view, vec![key_event(Key::Enter)]);
        assert_eq!(
            outcome.complete_command,
            Some("/kick".to_string()),
            "回车应当把选中的 /kick 填进输入框"
        );
        assert!(
            !outcome.send,
            "The Enter key for completion should not send the draft at the same time"
        );
    }

    /// Control: when the command name is already a complete known command, Enter still sends (same as terminal version)
    #[test]
    fn enter_still_sends_when_the_command_name_is_complete() {
        let context = Context::default();
        let mut view = input_view("/info");
        view.request_focus = true;
        let (_texts, outcome, _arrow) =
            run_one_frame(&context, &mut view, vec![key_event(Key::Enter)]);
        assert_eq!(
            outcome.complete_command, None,
            "When the command name is complete, no longer completes"
        );
        assert!(
            outcome.send,
            "After the command name is complete, Enter should send (execute)"
        );
    }

    /// When typing a command name, show the completion list: only list commands matching the prefix
    #[test]
    fn command_prefix_shows_matching_completions() {
        let context = Context::default();
        let mut view = input_view("/l");
        let (texts, _outcome, _arrow) = run_one_frame(&context, &mut view, Vec::new());
        let drawn: Vec<String> = texts.iter().map(|(text, _)| text.clone()).collect();
        for expected in ["/list_users", "/login", "/logout"] {
            assert!(
                drawn.iter().any(|text| text == expected),
                "When typing /l, should suggest {expected:?}; actually drew {drawn:?}"
            );
        }
        assert!(
            !drawn.iter().any(|text| text == "/kick"),
            "Non-matching commands should not appear in completions; actually drew {drawn:?}"
        );
    }

    /// This round's change: every completion item must have its description text (last round to fit on one row the description was moved into the hover tooltip,
    /// now one item per row, the description is drawn directly to the right of the command name)
    #[test]
    fn every_completion_row_shows_its_description() {
        let context = Context::default();
        let mut view = input_view("/l");
        let (texts, _outcome, _arrow) = run_one_frame(&context, &mut view, Vec::new());
        let drawn: Vec<String> = texts.iter().map(|(text, _)| text.clone()).collect();
        for expected in ["列出全部注册用户", "打开登录界面", "退出登录"] {
            assert!(
                drawn.iter().any(|text| text == expected),
                "The completion tooltip should include the description {expected:?}; actually drew {drawn:?}"
            );
        }
    }

    /// Clicking one item in the completion list: should report "complete into the input box" (not execute the command directly)
    #[test]
    fn clicking_a_completion_reports_the_command() {
        let context = Context::default();
        let mut view = input_view("/log");
        let (texts, _outcome, _arrow) = run_one_frame(&context, &mut view, Vec::new());
        let entry = position_of(&texts, "/logout");
        let (_texts, outcome, _arrow) =
            run_one_frame(&context, &mut view, click_at(entry + Vec2::new(4.0, 8.0)));
        assert_eq!(
            outcome.complete_command,
            Some("/logout".to_string()),
            "Clicking /logout in the completion list should \"complete into the input box\", not execute directly"
        );
    }

    /// After typing the command name and starting to type the parameter, there shouldn't be a prompt anymore (otherwise it would keep blocking the input area)
    #[test]
    fn no_completions_after_the_command_name_is_finished() {
        let context = Context::default();
        let mut view = input_view("/kick 某人");
        let (texts, _outcome, _arrow) = run_one_frame(&context, &mut view, Vec::new());
        let drawn: Vec<String> = texts.iter().map(|(text, _)| text.clone()).collect();
        assert!(
            !drawn.iter().any(|text| text == "/kick"),
            "Should no longer list commands after starting to type arguments; actually drew {drawn:?}"
        );
    }

    /// This round's change: `/language ` and `/appearance ` followed by a space list all available languages/appearance,
    /// displayed exactly like command name completion (one per row, can select up/down, Enter fills into the input box).
    /// If language/appearance from the config directory can't be read, skip the assertion (a test machine without a config directory is not a failure).
    #[test]
    fn argument_completion_lists_languages_and_appearances() {
        let context = Context::default();
        let languages = baihua_core::config::Language::available_codes();
        let appearances = baihua_core::config::Palette::available_names();
        if languages.is_empty() || appearances.is_empty() {
            return;
        }
        for (draft, expected) in [
            ("/language ", languages.clone()),
            ("/appearance ", appearances.clone()),
        ] {
            let mut view = input_view(draft);
            let (texts, _outcome, _arrow) = run_one_frame(&context, &mut view, Vec::new());
            let drawn: Vec<String> = texts.iter().map(|(text, _)| text.clone()).collect();
            for candidate in &expected {
                assert!(
                    drawn.iter().any(|text| text == candidate),
                    "{draft} 应当列出 {candidate:?}；实际画了 {drawn:?}"
                );
            }
        }
    }

    /// Parameter completion after `/language ` continues to filter by prefix as you type (case-sensitive: `zh` matches `zh-CN`, `ZH` matches nothing).
    #[test]
    fn argument_completion_filters_by_prefix_case_sensitively() {
        let context = Context::default();
        let languages = baihua_core::config::Language::available_codes();
        if languages.is_empty() {
            return;
        }
        let Some(sample) = languages.first() else {
            return;
        };
        let Some(first_character) = sample.chars().next() else {
            return;
        };
        let mut view = input_view(&format!("/language {first_character}"));
        let (texts, _outcome, _arrow) = run_one_frame(&context, &mut view, Vec::new());
        let drawn: Vec<String> = texts.iter().map(|(text, _)| text.clone()).collect();
        assert!(
            drawn.iter().any(|text| text == sample),
            "小写/原样前缀应当命中原样的语言码 {sample:?}；实际画了 {drawn:?}"
        );
        // Same letter changed to uppercase: language codes are case-sensitive, no longer match
        let mut upper_view = input_view(&format!("/language {}", first_character.to_uppercase()));
        upper_view.selected_command = 0;
        let (upper_texts, _, _) = run_one_frame(&context, &mut upper_view, Vec::new());
        let upper_drawn: Vec<String> = upper_texts.iter().map(|(text, _)| text.clone()).collect();
        assert!(
            !upper_drawn.iter().any(|text| text == sample),
            "大写前缀不该命中 {sample:?}（大小写敏感）；实际画了 {upper_drawn:?}"
        );
    }

    /// Enter fills the selected parameter candidate in full into the input box (a complete command line like `/language zh-CN`),
    /// rather than filling just a lonely language code.
    #[test]
    fn argument_completion_fills_the_whole_command_line() {
        let context = Context::default();
        let languages = baihua_core::config::Language::available_codes();
        let Some(first) = languages.first() else {
            return;
        };
        let mut view = input_view("/language ");
        view.request_focus = true;
        let (_texts, outcome, _arrow) =
            run_one_frame(&context, &mut view, vec![key_event(Key::Enter)]);
        assert_eq!(
            outcome.complete_command,
            Some(format!("/language {first}")),
            "回车应当把整条 `/language 语言码` 填进输入框"
        );
    }

    /// This round's fix for "the completion background and internal text color are too close under the "default" theme":
    /// The background of the selected row is `selection_background` (yellow in the default theme),
    /// the text must be swapped to a contrasting color; can't continue using `selected_text` which is also yellow.
    #[test]
    fn selected_completion_text_contrasts_with_the_selection_background() {
        fn brightness(color: egui::Color32) -> u32 {
            (color.r() as u32 * 299 + color.g() as u32 * 587 + color.b() as u32 * 114) / 1000
        }
        let skin = Skin::from(&Palette::built_in());
        let selected_color = super::selectable_text_color(&skin, true, skin.selected_text);
        assert!(
            brightness(selected_color).abs_diff(brightness(skin.selection_background)) >= 128,
            "选中项文字与选中底色要分得开：文字 {selected_color:?}、底色 {:?}",
            skin.selection_background
        );
        assert_eq!(
            super::selectable_text_color(&skin, false, skin.selected_text),
            skin.selected_text,
            "没选中时照旧用调用方给的颜色，不改动未选中项的外观"
        );
    }

    /// This round's change: every command in the completion popup occupies one line, not squeezed on the same line
    #[test]
    fn each_completion_gets_its_own_line() {
        let context = Context::default();
        let mut view = input_view("/l");
        let (texts, _outcome, _arrow) = run_one_frame(&context, &mut view, Vec::new());
        let entries: Vec<Pos2> = ["/login", "/logout", "/list_users"]
            .iter()
            .map(|name| position_of(&texts, name))
            .collect();
        for (index, first) in entries.iter().enumerate() {
            for second in entries.iter().skip(index + 1) {
                assert!(
                    (first.y - second.y).abs() > 1.0,
                    "补全提示里每条指令要各占一行，这两条落在同一行：{first:?} 与 {second:?}"
                );
            }
        }
        let mut sorted: Vec<(f32, &str)> = ["/login", "/logout", "/list_users"]
            .iter()
            .map(|name| (position_of(&texts, name).y, *name))
            .collect();
        sorted.sort_by(|left, right| left.0.partial_cmp(&right.0).expect("坐标不会是 NaN"));
        assert_eq!(
            sorted.iter().map(|(_, name)| *name).collect::<Vec<&str>>(),
            vec!["/list_users", "/login", "/logout"],
            "The completion list should be ordered by the command table from top to bottom; actual {sorted:?}"
        );
    }

    /// A sufficiently long command table: 12 commands with the same prefix, one screen doesn't fit (the popup's max height is `command_completion_height()`),
    /// used to verify "the completion list scrolls by itself when pressing up/down arrow keys"
    fn long_command_list() -> Vec<(&'static str, String)> {
        vec![
            ("l0", "第 0 条".to_string()),
            ("l1", "第 1 条".to_string()),
            ("l2", "第 2 条".to_string()),
            ("l3", "第 3 条".to_string()),
            ("l4", "第 4 条".to_string()),
            ("l5", "第 5 条".to_string()),
            ("l6", "第 6 条".to_string()),
            ("l7", "第 7 条".to_string()),
            ("l8", "第 8 条".to_string()),
            ("l9", "第 9 条".to_string()),
            ("l10", "第 10 条".to_string()),
            ("l11", "第 11 条".to_string()),
        ]
    }

    /// This round's change: when command completion is on, pressing up/down arrow keys must scroll the completion list,
    /// so the selected item always stays within the popup's visible range.
    ///
    /// Previously the list was a fixed-height scroll region: even when a selected item ran outside the box it would still be drawn outside,
    /// the user pressing arrow keys could only see the highlight disappear, not knowing which item was selected.
    #[test]
    fn arrow_keys_scroll_the_completion_list_to_the_selected_item() {
        let context = Context::default();
        let commands = long_command_list();
        let mut view = input_view("/l");
        // Pressing the down arrow ten times in a row: the selected item ran outside the popup
        for _ in 0..10 {
            run_one_frame_with_commands(
                &context,
                &mut view,
                vec![key_event(Key::ArrowDown)],
                commands.clone(),
            );
        }
        assert_eq!(view.selected_command, 10, "连按十下应当选到第 11 条");
        // egui's scroll target only takes effect on the next frame's offset, so draw one more frame before measuring the hit point
        let (texts, outcome, _arrow) =
            run_one_frame_with_commands(&context, &mut view, Vec::new(), commands.clone());
        let completion_top =
            outcome.input_rect.top() - command_completion_height() - command_completion_gap();
        let completion_bottom = completion_top + command_completion_height();
        let selected_position = position_of(&texts, "/l10");
        assert!(
            selected_position.y > completion_top && selected_position.y < completion_bottom,
            "选中项要留在补全浮层的可见范围里：浮层 {completion_top}..{completion_bottom}，实际 {selected_position:?}"
        );
        // The first item has already scrolled above the popup: text that scrolls out of the visible range is simply not drawn by egui,
        // so both "not drawn" and "drawn above the popup top" count as having scrolled out
        let first_position = texts
            .iter()
            .find(|(text, _)| text == "/l0")
            .map(|(_, position)| *position);
        assert!(
            first_position.is_none_or(|position| position.y < completion_top),
            "列表滚动之后第一条要滚到浮层上边之外：浮层顶 {completion_top}，实际 {first_position:?}"
        );
    }
}

#[cfg(test)]
mod settings_section_tests {
    use super::{Sections, SettingsOutcome, draw_switch, toggle_section};
    use crate::appearance::Skin;
    use baihua_core::config::Palette;
    use egui::{
        CentralPanel, Context, Event, Modifiers, PointerButton, Pos2, RawInput, Rect, Vec2,
    };

    fn raw_input(events: Vec<Event>) -> RawInput {
        RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, Vec2::new(600.0, 400.0))),
            focused: true,
            events,
            ..Default::default()
        }
    }

    fn click_at(point: Pos2) -> Vec<Event> {
        vec![
            Event::PointerButton {
                pos: point,
                button: PointerButton::Primary,
                pressed: true,
                modifiers: Modifiers::NONE,
            },
            Event::PointerButton {
                pos: point,
                button: PointerButton::Primary,
                pressed: false,
                modifiers: Modifiers::NONE,
            },
        ]
    }

    /// Draw a section title for one frame and take back (the title hit point, the result handed to the interface this frame)
    fn run_one_frame(
        context: &Context,
        sections: &mut Sections,
        events: Vec<Event>,
    ) -> (Pos2, SettingsOutcome) {
        let mut outcome = SettingsOutcome::Nothing;
        let mut painted: Vec<(String, Pos2)> = Vec::new();
        context
            .run_ui(raw_input(events), |ctx| {
                CentralPanel::default().show(ctx, |ui| {
                    let skin = Skin::from(&Palette::built_in());
                    toggle_section(
                        ui,
                        &skin,
                        sections,
                        |sections| &mut sections.avatar,
                        "修改头像".to_string(),
                        &mut outcome,
                    );
                });
                painted = ctx.graphics_mut(|graphics| {
                    let mut texts: Vec<(String, Pos2)> = Vec::new();
                    if let Some(list) = graphics.get(egui::LayerId::background()) {
                        for entry in list.all_entries() {
                            if let egui::Shape::Text(shape) = &entry.shape {
                                texts.push((shape.galley.text().to_string(), shape.pos));
                            }
                        }
                    }
                    texts
                });
            })
            .drop_without_applying_deltas();
        let title_position = painted
            .iter()
            .find(|(text, _)| text == "修改头像")
            .map(|(_, position)| *position)
            .expect("这一帧应当画出分节标题");
        (title_position, outcome)
    }

    /// Regression for feedback "six buttons from changing avatar to custom server address in settings had no response".
    ///
    /// Root cause is the section title only toggled the internal copy of the panel, didn't hand the entire open/close state back to the interface,
    /// so the panel redrew with the old state every frame, looking like clicks had no effect.
    #[test]
    fn clicking_a_section_header_reports_the_new_sections() {
        let context = Context::default();
        let mut sections = Sections::default();
        let (title, _outcome) = run_one_frame(&context, &mut sections, Vec::new());
        let (_title, outcome) = run_one_frame(
            &context,
            &mut sections,
            click_at(title + Vec2::new(4.0, 8.0)),
        );
        let reported = match outcome {
            SettingsOutcome::Sections(reported) => reported,
            _ => panic!(
                "Clicking a section header should return the full open/close state, not some other result"
            ),
        };
        assert!(
            reported.avatar,
            "点开修改头像这一节之后，交回界面的状态里它必须是展开的"
        );
        assert!(
            sections.avatar,
            "This frame's state should also become expanded"
        );
    }

    /// Regression for feedback "the normal state of switches in settings doesn't show a border".
    ///
    /// The switch entry uses `Button::selectable`: when `frame_when_inactive` is not opened,
    /// only the selected or mouse-hover frame draws a border; the normal state blends into the background.
    /// This assertion "a switch that is not selected and the mouse is not over it" must draw the border given by the theme this frame.
    #[test]
    fn an_unselected_switch_paints_its_border() {
        let context = Context::default();
        let skin = Skin::from(&Palette::built_in());
        // The switch's outer border comes from egui's visuals (`widgets.inactive.bg_stroke`), so before this frame the theme must be applied
        skin.apply_to(&context);
        let mut output = context.run_ui(raw_input(Vec::new()), |ctx| {
            CentralPanel::default().show(ctx, |ui| {
                let _ = draw_switch(ui, &skin, false, "修改头像".to_string());
            });
        });
        // Same convention as the button test: clear the texture delta before letting the output drop when there is no other consumer
        output.textures_delta.clear();
        let painted_borders: Vec<egui::Color32> = output
            .shapes
            .into_iter()
            .filter_map(|clipped| match clipped.shape {
                egui::Shape::Rect(rect) if rect.stroke.width > 0.0 => Some(rect.stroke.color),
                _ => None,
            })
            .collect();
        assert!(
            painted_borders.contains(&skin.room_border),
            "未选中的开关这一帧应当画出主题色的描边（实际 {painted_borders:?}，期望含 {:?}）",
            skin.room_border
        );
    }
}

#[cfg(test)]
mod input_area_growth_tests {
    use super::{MessageInputView, draw_conversation_area, draw_message_input_area};
    use crate::appearance::Skin;
    use baihua_core::config::Palette;
    use egui::{CentralPanel, Context, Pos2, RawInput, Rect, Ui, Vec2};

    fn raw_input() -> RawInput {
        RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, Vec2::new(900.0, 600.0))),
            ..Default::default()
        }
    }

    fn input_view() -> MessageInputView {
        MessageInputView {
            draft: String::new(),
            placeholder: "输入消息".to_string(),
            request_focus: false,
            selected_command: 0,
        }
    }

    /// Draw a conversation area for one frame, return the height the input area panel got this frame
    fn input_area_height_after_one_frame(context: &Context, view: &mut MessageInputView) -> f32 {
        let skin = Skin::from(&Palette::built_in());
        let commands: Vec<(&'static str, String)> = vec![("info", "查看群聊信息".to_string())];
        let mut height = 0.0;
        context
            .run_ui(raw_input(), |ctx| {
                CentralPanel::default().show(ctx, |ui| {
                    let _ = draw_conversation_area(
                        ui,
                        &skin,
                        Vec::new(),
                        "还没有消息".to_string(),
                        true,
                        None,
                        |ui: &mut Ui| {
                            // The input area is drawn inside the panel content; its available height is whatever the panel remembered
                            height = ui.max_rect().height();
                            draw_message_input_area(ui, &skin, &commands, view)
                        },
                    );
                });
            })
            .drop_without_applying_deltas();
        height
    }

    /// Regression for feedback "the message display area has a large blank space with only a small bit at the top showing messages".
    ///
    /// Root cause: the input area uses `bottom_up` layout, and the "settings entry + input box" row is an inner container;
    /// the inner container is placed at minimum height when the outer is bottom_up, then overflows downward,
    /// so the height remembered by the input area panel grows frame by frame (measured at +30 per frame), and the message area is squeezed out.
    /// Now the entire row uses a fixed height as a placeholder; the panel height must be stable from the second frame onward.
    #[test]
    fn input_area_height_stops_growing_after_the_first_frame() {
        let context = Context::default();
        let mut view = input_view();
        let heights: Vec<f32> = (0..5)
            .map(|_| input_area_height_after_one_frame(&context, &mut view))
            .collect();
        for (index, height) in heights.iter().enumerate().skip(1) {
            assert_eq!(
                *height, heights[1],
                "Input area height must be stable from the second frame onward，第 {index} 帧是 {height}（各帧：{heights:?}）"
            );
        }
        assert!(
            heights[1] < 200.0,
            "The input area should not keep growing taller，实际 {}（各帧：{heights:?}）",
            heights[1]
        );
    }
}

#[cfg(test)]
mod sender_label_tests {
    use super::{sender_label, typing_text};

    /// Regression for this round's feedback that "showing sender UID didn't work": when the switch is on, append the user ID after the name
    #[test]
    fn show_uid_appends_the_user_id_to_the_sender_name() {
        assert_eq!(sender_label("小明", "u-1", false), "小明");
        assert_eq!(sender_label("小明", "u-1", true), "小明 (u-1)");
        // When the name is unavailable (e.g., a speaker who has been deregistered), only keep the ID without an empty pair of parentheses
        assert_eq!(sender_label("", "u-1", true), "");
    }

    /// Regression for feedback "the same person might be shown twice as typing" (this display side):
    /// The input status on the title selects the text based on the count; the member list has already been deduplicated
    #[test]
    fn typing_text_formats_one_and_many_names() {
        let one = "· {username} 正在输入...";
        let many = "· {names} 正在输入...";
        assert_eq!(typing_text(one, many, &[]), None);
        assert_eq!(
            typing_text(one, many, &["小明".to_string()]),
            Some("· 小明 正在输入...".to_string())
        );
        assert_eq!(
            typing_text(one, many, &["小明".to_string(), "小红".to_string()]),
            Some("· 小明, 小红 正在输入...".to_string())
        );
    }
}

#[cfg(test)]
mod auth_draft_tests {
    use super::{AuthDrafts, AuthPage, BaihuaApp, Sections};
    use crate::appearance::{AvatarTextures, Skin};
    use crate::client::Client;
    use baihua_core::config::Palette;

    /// A shell that can hold any page without network: the session layer uses `Client::default()` (no network, no background threads),
    /// used by this module for "writing the draft back to interface fields in full after drawing"
    /// and by the status bar module for "what the top bar really paints in a frame".
    pub(super) fn test_app() -> BaihuaApp {
        BaihuaApp {
            client: Client::default(),
            skin: Skin::from(&Palette::built_in()),
            avatars: AvatarTextures::default(),
            settings_open: false,
            auth_page: Some(AuthPage::Register),
            profile_card_open: false,
            completion_selection: 0,
            creation_page: None,
            sections: Sections::default(),
            login_name: String::new(),
            login_password: String::new(),
            register_name: String::new(),
            register_email: String::new(),
            register_password: String::new(),
            server_address: String::new(),
            profile_nickname: String::new(),
            profile_phone: String::new(),
            profile_bio: String::new(),
            password_old: String::new(),
            password_new: String::new(),
            password_repeat: String::new(),
            avatar_url: String::new(),
            delete_password: String::new(),
            group_name: String::new(),
            group_members: String::new(),
            private_target: String::new(),
            focus_message_input: false,
        }
    }

    /// Regression fix for "password can't be typed on the registration page":
    /// The draw function modifies a copy inside `AuthDrafts`; it must write each item back to the interface fields.
    /// The previous version missed `register_password`; characters typed into the password box would be gone by the next frame.
    #[test]
    fn every_auth_draft_field_is_written_back_including_the_register_password() {
        let mut app = test_app();
        app.store_auth_drafts(AuthDrafts {
            login_name: "登录名".to_string(),
            login_password: "登录密码".to_string(),
            register_name: "注册名".to_string(),
            register_email: "mail@example.com".to_string(),
            register_password: "注册密码".to_string(),
            server_address: "http://localhost:2424".to_string(),
        });
        assert_eq!(app.login_name, "登录名");
        assert_eq!(app.login_password, "登录密码");
        assert_eq!(app.register_name, "注册名");
        assert_eq!(app.register_email, "mail@example.com");
        assert_eq!(
            app.register_password, "注册密码",
            "注册密码必须写回界面字段，否则注册页的密码框敲不进字"
        );
        assert_eq!(app.server_address, "http://localhost:2424");
    }
}

#[cfg(test)]
mod rendered_text_tests {
    use super::auth_draft_tests::test_app;
    use baihua_core::api::MessageInfo;
    use egui::{CentralPanel, Context, Pos2, RawInput, Rect, Vec2};

    fn raw_input() -> RawInput {
        RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, Vec2::new(900.0, 600.0))),
            focused: true,
            ..Default::default()
        }
    }

    /// The top bar must not paint a separator of its own: the vertical bars live in the text segments
    /// (`status_bar_texts` writes them, exactly like the terminal version).
    ///
    /// Regression for "an extra vertical bar shows up in front of the current user": a `Separator` inside a
    /// horizontal row takes its length from the available space, so inside a top panel (which starts from the
    /// whole area and shrinks to its content) it is painted all the way down the window.
    #[test]
    fn status_bar_paints_no_vertical_separator_of_its_own() {
        let context = Context::default();
        let mut app = test_app();
        app.client.current_username = "alice".to_string();
        let mut line_segments: Vec<(Pos2, Pos2)> = Vec::new();
        context
            .run_ui(raw_input(), |ctx| {
                CentralPanel::default().show(ctx, |ui| {
                    app.draw_status_bar(ui);
                });
                line_segments = ctx.graphics_mut(|graphics| {
                    let mut lines: Vec<(Pos2, Pos2)> = Vec::new();
                    if let Some(list) = graphics.get(egui::LayerId::background()) {
                        for entry in list.all_entries() {
                            if let egui::Shape::LineSegment { points, .. } = &entry.shape {
                                lines.push((points[0], points[1]));
                            }
                        }
                    }
                    lines
                });
            })
            .drop_without_applying_deltas();
        for (start, end) in line_segments {
            let painted_height = (end.y - start.y).abs();
            assert!(
                painted_height <= 4.0,
                "顶栏自己画了一条高 {painted_height} 的竖线（{start:?} -> {end:?}）：竖杠要写在文案里"
            );
        }
    }

    /// A message whose body is empty (encrypted private chat history: the server has no readable body to give)
    /// must be drawn with the localized placeholder, never as an empty row.
    #[test]
    fn a_message_without_a_body_uses_the_localized_placeholder() {
        let context = Context::default();
        let mut app = test_app();
        app.client.messages = vec![MessageInfo {
            id: "message-secret".to_string(),
            room_id: "room-secret".to_string(),
            sender_id: "user-other".to_string(),
            content: String::new(),
            created_at: "2026-09-06T00:00:00+00:00".to_string(),
        }];
        let placeholder = app.client.text("message_encrypted_history_unavailable");
        let rows = app.message_rows(&context);
        assert_eq!(rows.len(), 1);
        assert_ne!(rows[0].content, "", "空正文不能原样画成一行空消息");
        assert_eq!(rows[0].content, placeholder);
    }
}
