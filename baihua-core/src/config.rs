//! Configuration layer: language texts, appearance themes, display preferences, and login session persistence.
//!
//! This layer is shared by both the TUI and GUI, so it **contains no interface types**: theme colors are expressed as the neutral `ThemeColor`
//! expression (terminal basic color names or RGB triples); each interface converts them into its own color type before rendering.
//! Language and appearance follow the same convention: carried by dedicated structs, with a read method that returns the whole struct at once.

use crate::crypto;
use crate::paths;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// A color value in a theme file. Terminal basic color names keep their original names (the terminal colors itself; the TUI uses them directly),
/// RGB notation keeps three components; each interface converts to its own color type; this layer does not guess approximate colors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemeColor {
    /// Use terminal default foreground/background color
    Default,
    Black,
    DarkGray,
    Gray,
    Red,
    LightRed,
    Green,
    LightGreen,
    Yellow,
    LightYellow,
    Blue,
    LightBlue,
    Magenta,
    LightMagenta,
    Cyan,
    LightCyan,
    White,
    /// True color read from hex or array notation
    Rgb(u8, u8, u8),
}

/// xterm approximate RGB for terminal basic colors: the GUI has no ANSI color concept and must convert to true color,
/// brightness calculation also uses this table; sharing the same approximation in both places prevents drifting.
fn named_rgb(color: ThemeColor) -> (u8, u8, u8) {
    match color {
        ThemeColor::Rgb(red, green, blue) => (red, green, blue),
        ThemeColor::Default => (128, 128, 128),
        ThemeColor::Black => (0, 0, 0),
        ThemeColor::DarkGray => (85, 85, 85),
        ThemeColor::Gray => (170, 170, 170),
        ThemeColor::White => (255, 255, 255),
        ThemeColor::Red => (205, 0, 0),
        ThemeColor::LightRed => (255, 85, 85),
        ThemeColor::Green => (0, 205, 0),
        ThemeColor::LightGreen => (85, 255, 85),
        ThemeColor::Yellow => (205, 205, 0),
        ThemeColor::LightYellow => (255, 255, 85),
        ThemeColor::Blue => (0, 0, 238),
        ThemeColor::LightBlue => (85, 85, 255),
        ThemeColor::Magenta => (205, 0, 205),
        ThemeColor::LightMagenta => (255, 85, 255),
        ThemeColor::Cyan => (0, 205, 205),
        ThemeColor::LightCyan => (85, 255, 255),
    }
}

impl ThemeColor {
    /// Convert to RGB (for the GUI; the TUI can use the color name directly and do its own conversion)
    pub fn to_rgb(self) -> (u8, u8, u8) {
        named_rgb(self)
    }

    /// Weighted grayscale brightness, serving only the purpose of "which to use: light or dark text given the background color"
    pub fn brightness(self) -> u32 {
        let (red, green, blue) = named_rgb(self);
        (red as u32 * 299 + green as u32 * 587 + blue as u32 * 114) / 1000
    }

    /// Choose a readable foreground color based on background brightness: dark background pairs with light text, light background pairs with dark text.
    /// The theme only provides background color for text selection and search hits; using the body foreground color may result in text and background being the same depth and hard to read.
    pub fn contrasting_foreground(self) -> ThemeColor {
        if self.brightness() >= 128 {
            ThemeColor::Black
        } else {
            ThemeColor::White
        }
    }
}

/// Color notation in theme files: supports hex "#rrggbb", terminal basic color names, and [red, green, blue] three-element arrays.
/// Return None when unrecognized; the caller handles it as "that slot is missing" and never guesses an approximate color.
fn parse_theme_color(value: &serde_json::Value) -> Option<ThemeColor> {
    if let Some(components) = value.as_array() {
        let mut bytes = [0u8; 3];
        for (index, component) in components.iter().take(3).enumerate() {
            bytes[index] = component.as_u64()?.try_into().ok()?;
        }
        if components.len() != 3 {
            return None;
        }
        return Some(ThemeColor::Rgb(bytes[0], bytes[1], bytes[2]));
    }
    let text = value.as_str()?.trim().to_lowercase();
    if let Some(hexadecimal) = text.strip_prefix('#') {
        if hexadecimal.len() != 6 {
            return None;
        }
        let red = u8::from_str_radix(&hexadecimal[0..2], 16).ok()?;
        let green = u8::from_str_radix(&hexadecimal[2..4], 16).ok()?;
        let blue = u8::from_str_radix(&hexadecimal[4..6], 16).ok()?;
        return Some(ThemeColor::Rgb(red, green, blue));
    }
    let named = match text.as_str() {
        "default" | "reset" => ThemeColor::Default,
        "black" => ThemeColor::Black,
        "red" => ThemeColor::Red,
        "green" => ThemeColor::Green,
        "yellow" => ThemeColor::Yellow,
        "blue" => ThemeColor::Blue,
        "magenta" => ThemeColor::Magenta,
        "cyan" => ThemeColor::Cyan,
        "white" => ThemeColor::White,
        "dark_gray" | "dark-gray" | "bright_black" | "bright-black" => ThemeColor::DarkGray,
        "light_red" | "light-red" | "bright_red" | "bright-red" => ThemeColor::LightRed,
        "light_green" | "light-green" | "bright_green" | "bright-green" => ThemeColor::LightGreen,
        "light_yellow" | "light-yellow" | "bright_yellow" | "bright-yellow" => {
            ThemeColor::LightYellow
        }
        "light_blue" | "light-blue" | "bright_blue" | "bright-blue" => ThemeColor::LightBlue,
        "light_magenta" | "light-magenta" | "bright_magenta" | "bright-magenta" => {
            ThemeColor::LightMagenta
        }
        "light_cyan" | "light-cyan" | "bright_cyan" | "bright-cyan" => ThemeColor::LightCyan,
        "gray" | "grey" => ThemeColor::Gray,
        "bright_white" | "bright-white" => ThemeColor::White,
        _ => return None,
    };
    Some(named)
}

/// Data carrier for the appearance system: centralized definition of all colorable slots in the client.
/// Each field corresponds to a same-named key in config/themes/{appearance_name}.json; the user-chosen name is persisted in
/// the appearance field of preferences.json; the interface takes colors from here for rendering, no longer scattering hardcoded colors.
/// This struct contains no interface types; the TUI and GUI each use their own `Appearance`/visual style converted before rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    /// Overall application background color (covers terminal or window background, including popup areas)
    pub app_background: ThemeColor,
    /// Message display area border color
    pub message_border: ThemeColor,
    /// Group chat list border color
    pub room_border: ThemeColor,
    /// Border color for all overlay windows (overlay style unified to this slot; can be adjusted separately in the theme)
    pub overlay_border: ThemeColor,
    /// Message body text color
    pub message_text: ThemeColor,
    /// Selected text color (room list items, settings menu items, command auto-completion items)
    pub selected_text: ThemeColor,
    /// Other user's username text color
    pub other_username_text: ThemeColor,
    /// Own username text color
    pub own_username_text: ThemeColor,
    /// Message timestamp text color
    pub time_text: ThemeColor,
    /// Keyboard shortcut hint text color
    pub hint_text: ThemeColor,
    /// Border color when the tooltip is in hint state
    pub notice_hint_border: ThemeColor,
    /// Border color when the tooltip is in error state
    pub notice_error_border: ThemeColor,
    /// Message input box default state border color
    pub input_border: ThemeColor,
    /// Message input box body text color
    pub input_text: ThemeColor,
    /// Message input box command mode border color
    pub command_border: ThemeColor,
    /// Message input box search mode border color
    pub search_border: ThemeColor,
    /// Background color for text selected by mouse for copying
    pub selection_background: ThemeColor,
    /// Background color for search mode matched fragments
    pub search_match_background: ThemeColor,
    /// Background color for "the currently located match" in search mode (distinguished from other hits)
    pub search_current_match_background: ThemeColor,
    /// Read/unread status text color below messages
    pub read_state_text: ThemeColor,
    /// Color the button images are tinted with: the shipped images are pure white
    pub icon_color: ThemeColor,
}

/// Result of loading a theme: theme content + whether there are missing slots + unknown field names in the theme file.
pub struct ThemeFile {
    /// Theme content (missing slots use built-in default colors as fallback)
    pub palette: Palette,
    /// True as long as there are missing slots. By convention only reports "incomplete" without listing which specific field is missing
    pub has_missing_field: bool,
    /// Unknown top-level key names in the theme file (explicitly listed so the user can fix the file themselves)
    pub extra_fields: Vec<String>,
}

impl Palette {
    /// Built-in fallback palette: the same colors as the shipped `themes/default.json` (neither side
    /// may drift); a theme file with missing slots falls back to these colors.
    pub fn built_in() -> Self {
        Self {
            app_background: ThemeColor::Rgb(43, 48, 56),
            message_border: ThemeColor::Rgb(91, 107, 125),
            room_border: ThemeColor::Rgb(91, 107, 125),
            overlay_border: ThemeColor::Rgb(107, 122, 141),
            message_text: ThemeColor::White,
            selected_text: ThemeColor::Yellow,
            other_username_text: ThemeColor::Cyan,
            own_username_text: ThemeColor::Green,
            time_text: ThemeColor::DarkGray,
            hint_text: ThemeColor::DarkGray,
            notice_hint_border: ThemeColor::Blue,
            notice_error_border: ThemeColor::Red,
            input_border: ThemeColor::Rgb(91, 107, 125),
            input_text: ThemeColor::White,
            command_border: ThemeColor::Yellow,
            search_border: ThemeColor::Red,
            selection_background: ThemeColor::Yellow,
            search_match_background: ThemeColor::Red,
            search_current_match_background: ThemeColor::LightYellow,
            read_state_text: ThemeColor::Blue,
            icon_color: ThemeColor::Rgb(147, 165, 184),
        }
    }

    /// The name of the default appearance: what every client starts with when the person has never
    /// picked a theme file, and what `preferences.json` stores for that state. Unlike the retired
    /// reserved name, it is not a code-only appearance — it is an ordinary theme file
    /// (`config/themes/default.json`) shipped with the configuration directory, so loading it goes
    /// through the regular file path and the settings panel lists it like any other theme.
    /// Everything that compares an appearance name against "the default one" must use this function
    /// instead of writing the literal out again.
    pub fn default_name() -> &'static str {
        "default"
    }

    /// Read `<config_dir>/themes/{name}.json` and return the complete theme at once.
    /// When the file is unreadable or not valid JSON, return the built-in fallback colors and mark
    /// "missing field" as true.
    ///
    /// There is no reserved name any more: the default appearance (`default_name`) is an ordinary
    /// theme file shipped under `config/themes`, so it is loaded through this same file path like
    /// every other theme. The retired reserved name `built_in` has no theme file by design and is
    /// therefore reported as incomplete — an old `preferences.json` still holding that value gets a
    /// clear notice instead of silent special-casing.
    pub fn load(name: &str) -> ThemeFile {
        let palette = Self::built_in();
        let path = paths::config_path(&format!("themes/{name}.json"));
        let Ok(content) = fs::read_to_string(&path) else {
            return ThemeFile {
                palette,
                has_missing_field: true,
                extra_fields: Vec::new(),
            };
        };
        let Ok(document) = serde_json::from_str::<serde_json::Value>(&content) else {
            return ThemeFile {
                palette,
                has_missing_field: true,
                extra_fields: Vec::new(),
            };
        };
        let mut loaded = palette;
        let mut has_missing_field = false;
        let fields: [&str; 21] = [
            "app_background",
            "message_border",
            "room_border",
            "overlay_border",
            "message_text",
            "selected_text",
            "other_username_text",
            "own_username_text",
            "time_text",
            "hint_text",
            "notice_hint_border",
            "notice_error_border",
            "input_border",
            "input_text",
            "command_border",
            "search_border",
            "selection_background",
            "search_match_background",
            "search_current_match_background",
            "read_state_text",
            "icon_color",
        ];
        for field in fields {
            match document.get(field).and_then(parse_theme_color) {
                Some(color) => loaded.set_slot(field, color),
                None => has_missing_field = true,
            }
        }
        let known_field_names: Vec<&str> = fields.to_vec();
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
        ThemeFile {
            palette: loaded,
            has_missing_field,
            extra_fields,
        }
    }

    /// Write to the corresponding slot based on the key name in the theme file. Key names correspond one-to-one with struct fields,
    /// when adding new slots, add them here and to the struct together; missing them will cause a compilation failure.
    fn set_slot(&mut self, field: &str, color: ThemeColor) {
        match field {
            "app_background" => self.app_background = color,
            "message_border" => self.message_border = color,
            "room_border" => self.room_border = color,
            "overlay_border" => self.overlay_border = color,
            "message_text" => self.message_text = color,
            "selected_text" => self.selected_text = color,
            "other_username_text" => self.other_username_text = color,
            "own_username_text" => self.own_username_text = color,
            "time_text" => self.time_text = color,
            "hint_text" => self.hint_text = color,
            "notice_hint_border" => self.notice_hint_border = color,
            "notice_error_border" => self.notice_error_border = color,
            "input_border" => self.input_border = color,
            "input_text" => self.input_text = color,
            "command_border" => self.command_border = color,
            "search_border" => self.search_border = color,
            "selection_background" => self.selection_background = color,
            "search_match_background" => self.search_match_background = color,
            "search_current_match_background" => self.search_current_match_background = color,
            "read_state_text" => self.read_state_text = color,
            "icon_color" => self.icon_color = color,
            _ => {}
        }
    }

    /// List all available appearance names: the theme files under `config/themes` (`.json` suffix
    /// removed), sorted alphabetically and deduplicated.
    ///
    /// Every entry is backed by a real theme file — nothing is injected from code any more. The
    /// default appearance is reachable through its shipped file `themes/default.json`, so the
    /// settings panel and `/appearance <name>` can always switch back to it without a reserved name.
    pub fn available_names() -> Vec<String> {
        let mut file_names: Vec<String> = fs::read_dir(paths::config_directory().join("themes"))
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
        file_names.sort();
        file_names.dedup();
        file_names
    }
}

/// Language text carrier: reads all key-value pairs from `config/languages/{code}.json` at once; look up by key name.
/// Keys not found are returned as the key name itself (makes it easy to see which key was missed on the interface).
#[derive(Debug, Clone, Default)]
pub struct Language {
    /// Current language code (such as zh-CN); only used for display and writing back to preferences.json
    pub code: String,
    /// Key name → localized text
    texts: HashMap<String, String>,
}

/// Read one language file and merge its entries into the table collected so far.
///
/// The merge rule is "the first file that supplied a key wins": callers feed files in
/// candidate-directory order, keys already present from an earlier file (the user's own
/// copy) are kept untouched, and only missing keys are filled in — user edits survive while new entries still arrive.
///
/// The return value answers "did this file really yield a table": a missing file, an unreadable file,
/// or a JSON root that is not a "key to text" object (an array, say) all count as "did not read".
fn merge_language_text_file(path: &Path, texts: &mut HashMap<String, String>) -> bool {
    let Ok(content) = fs::read_to_string(path) else {
        return false;
    };
    let Ok(serde_json::Value::Object(table)) = serde_json::from_str::<serde_json::Value>(&content)
    else {
        return false;
    };
    for (key, value) in table {
        if let Some(text) = value.as_str() {
            texts.entry(key).or_insert_with(|| text.to_string());
        }
    }
    true
}

impl Language {
    /// Fallback language code when the config file is missing or corrupted
    pub fn fallback_code() -> String {
        "zh-CN".to_string()
    }

    /// Read `<config_dir>/languages/{code}.json` and return the whole text table at once.
    ///
    /// Language files are **merged file by file** in `paths::config_directory_candidates()` order, not "first file wins":
    /// the copy in the user's configuration directory comes first (its entries are authoritative),
    /// and the source-tree / installed copy behind it only fills the gaps.
    /// A `languages/*.json` installed by an older version stays in the user directory forever (the installer only adds missing files, never rewrites),
    /// so keys introduced by a newer version are absent there and the interface would show raw keys — the root cause of "most texts turned into placeholders".
    /// When no file can be read (missing, or not a "key to text" object) it returns **the path of the offending file**,
    /// never canned prose: each interface localizes the complaint through its own table
    /// (the graphical version uses the key `error_lang_file_read`); the core layer produces no user text in one language.
    pub fn load(code: &str) -> Result<Self, PathBuf> {
        let relative_path = format!("languages/{code}.json");
        let files: Vec<PathBuf> = paths::config_directory_candidates()
            .into_iter()
            .map(|directory| directory.join(&relative_path))
            .collect();
        let mut texts: HashMap<String, String> = HashMap::new();
        let mut read_any_file = false;
        for file in &files {
            read_any_file |= merge_language_text_file(file, &mut texts);
        }
        if !read_any_file {
            return Err(paths::config_path(&relative_path));
        }
        Ok(Self {
            code: code.to_string(),
            texts,
        })
    }

    /// Look up text by language key; return the key name itself when not found
    pub fn text(&self, key: &str) -> String {
        self.texts
            .get(key)
            .cloned()
            .unwrap_or_else(|| key.to_string())
    }

    /// Text table snapshot: the background thread needs this for localization; it must not read the interface state in reverse
    pub fn texts(&self) -> HashMap<String, String> {
        self.texts.clone()
    }

    /// Return all available language codes under config/languages (removing .json suffix)
    pub fn available_codes() -> Vec<String> {
        let dir = paths::config_directory().join("languages");
        fs::read_dir(dir)
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
            .collect()
    }
}

/// Read the JSON root node of preferences.json (for reading only). Return an empty object when the file is missing or the format is wrong.
pub fn read_preferences() -> serde_json::Value {
    let path = paths::readable_config_path("preferences.json");
    fs::read_to_string(&path)
        .ok()
        .and_then(|content| serde_json::from_str::<serde_json::Value>(&content).ok())
        .unwrap_or_else(|| serde_json::json!({}))
}

/// Write back a batch of top-level keys in preferences.json after modification (read old values → modify keys → formatted write),
/// consistent with the writing style before the config layer was introduced: do not overwrite other keys, only add or delete the keys passed in.
/// Keys with a value of None are removed. Files are written with `secure_write` (0600, which may contain encrypted tokens).
pub fn write_preferences(changes: &[(&str, Option<serde_json::Value>)]) {
    let mut preferences = read_preferences();
    if let Some(map) = preferences.as_object_mut() {
        for (key, value) in changes {
            match value {
                Some(value) => {
                    map.insert((*key).to_string(), value.clone());
                }
                None => {
                    map.remove(*key);
                }
            }
        }
    }
    if let Ok(pretty) = serde_json::to_string_pretty(&preferences) {
        let path = paths::writable_config_path("preferences.json");
        let _ = secure_write(&path, &pretty);
    }
}

/// Get a boolean switch from preferences.json; default to the given fallback value
pub fn preference_bool(key: &str, fallback: bool) -> bool {
    read_preferences()
        .get(key)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(fallback)
}

/// Get a string item from preferences.json; default to the given fallback value
pub fn preference_string(key: &str, fallback: &str) -> String {
    read_preferences()
        .get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
        .unwrap_or_else(|| fallback.to_string())
}

/// Write a file with owner-only read/write permissions: `preferences.json` contains encrypted session tokens and contact info,
/// must not end up with default permissions readable by other users on the same machine.
pub fn secure_write(path: &std::path::Path, content: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        let _ = fs::create_dir_all(parent);
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(content.as_bytes())?;
    Ok(())
}

/// A pair of contact info (email, phone number) written to preferences.json after static encryption.
/// The server has no "look up my contact info" endpoint; the auto-login path needs this to restore the two lines of the profile card.
pub fn store_saved_contact(email: &str, phone_number: &str) {
    write_preferences(&[
        (
            "email",
            Some(serde_json::json!(crypto::encrypt_at_rest(email))),
        ),
        (
            "phone_number",
            Some(serde_json::json!(crypto::encrypt_at_rest(phone_number))),
        ),
    ]);
}

/// Read the email and phone number stored when last exiting; return None when missing or decryption fails.
pub fn load_saved_contact() -> Option<(String, String)> {
    let preferences = read_preferences();
    let email = crypto::decrypt_at_rest(preferences.get("email")?.as_str()?)?;
    let phone_number = crypto::decrypt_at_rest(preferences.get("phone_number")?.as_str()?)?;
    Some((email, phone_number))
}

/// Read the saved login session (token + user ID). The token is decrypted first; return None when missing or decryption fails.
pub fn load_saved_session() -> Option<(String, String)> {
    let preferences = read_preferences();
    let token = crypto::decrypt_at_rest(preferences.get("token")?.as_str()?)?;
    let user_id = preferences.get("user_id")?.as_str()?.to_string();
    Some((token, user_id))
}

/// Persist the login session before exit: token is written after static encryption, contact info is stored at the same time (see `load_saved_contact` for the reason).
pub fn save_session_preferences(token: &str, user_id: &str, contact: Option<&(String, String)>) {
    let mut changes: Vec<(&str, Option<serde_json::Value>)> = vec![
        (
            "token",
            Some(serde_json::json!(crypto::encrypt_at_rest(token))),
        ),
        ("user_id", Some(serde_json::json!(user_id))),
    ];
    match contact {
        Some((email, phone_number)) => {
            changes.push((
                "email",
                Some(serde_json::json!(crypto::encrypt_at_rest(email))),
            ));
            changes.push((
                "phone_number",
                Some(serde_json::json!(crypto::encrypt_at_rest(phone_number))),
            ));
        }
        None => {
            changes.push(("email", None));
            changes.push(("phone_number", None));
        }
    }
    write_preferences(&changes);
}

/// Clear the saved login session (called when the token is invalid, logging out, or auto-login is no longer needed)
pub fn clear_saved_session() {
    write_preferences(&[
        ("token", None),
        ("user_id", None),
        ("email", None),
        ("phone_number", None),
    ]);
}

/// Disk cache path for avatar bytes: `<client_directory>/cache/avatar/<user_id>.img`.
/// The user ID in the key may contain path separators; uniformly replace with underscores to avoid writing files outside the directory.
pub fn avatar_cache_path(user_id: &str) -> Option<std::path::PathBuf> {
    let file_name: String = user_id
        .chars()
        .map(|character| match character {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => character,
            _ => '_',
        })
        .collect();
    Some(paths::avatar_directory()?.join(format!("{file_name}.img")))
}

/// Read cached avatar bytes
pub fn load_cached_avatar(user_id: &str) -> Option<Vec<u8>> {
    fs::read(avatar_cache_path(user_id)?).ok()
}

/// Write avatar byte cache (if the directory cannot be created or the write fails, it just means downloading again next time; no error is reported to the user)
pub fn store_cached_avatar(user_id: &str, bytes: &[u8]) {
    let Some(path) = avatar_cache_path(user_id) else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(path, bytes);
}

/// Delete a user's avatar bytes: after changing the avatar the old bytes are wrong; keeping them would always show the first cached one.
pub fn drop_cached_avatar(user_id: &str) {
    if let Some(path) = avatar_cache_path(user_id) {
        let _ = fs::remove_file(path);
    }
}

/// Debug log: written in debug builds and in every mobile release build (the
/// phone is the one place a developer cannot attach a debugger to).
///
/// The location follows the client root: on desktops (no `BAIHUA_DIR` override)
/// it stays the familiar fixed `/tmp` file, while on mobile -- where `BAIHUA_DIR`
/// points into the app's private directory -- the log lands in that sandbox,
/// which is the only place a phone can write and the only place a developer can
/// pull from the device (Android has no `/tmp`, so those writes used to vanish
/// without a trace and left the black-screen reports with no evidence at all).
#[cfg(any(debug_assertions, target_os = "android", target_os = "ios"))]
pub fn debug_log(message: &str) {
    use std::sync::Mutex;
    static LOG_LOCK: Mutex<()> = Mutex::new(());
    let _guard = match LOG_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let line = format!("{}\n", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"));
    if let Ok(mut file) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(debug_log_path())
    {
        let _ = writeln!(file, "{line} {message}");
    }
}

/// Where `debug_log` appends: `<BAIHUA_DIR>/client/debug.log` when the
/// environment override is present (the mobile sandbox sets it at startup), the
/// historical `/tmp/baihua_client_debug.log` otherwise (desktops: the location
/// developers already know, unchanged).
#[cfg(any(debug_assertions, target_os = "android", target_os = "ios"))]
fn debug_log_path() -> std::path::PathBuf {
    match std::env::var_os("BAIHUA_DIR").filter(|value| !value.is_empty()) {
        Some(root) => std::path::PathBuf::from(root)
            .join("client")
            .join("debug.log"),
        None => std::path::PathBuf::from("/tmp/baihua_client_debug.log"),
    }
}

#[cfg(not(any(debug_assertions, target_os = "android", target_os = "ios")))]
pub fn debug_log(_message: &str) {}

#[cfg(test)]
mod tests {
    use super::{Language, Palette, merge_language_text_file};
    use crate::paths;
    use std::collections::{BTreeSet, HashMap};
    use std::fs;
    use std::path::PathBuf;

    /// A staging area: drop a few language files here so "merge several files" tests never touch the real config
    fn staging_area(label: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!("baihua-language-{label}"));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).expect("the staging directory must be creatable");
        directory
    }

    /// The core of the "most texts fell back to placeholder keys" fix:
    /// the language file in the user directory comes from an older install (new keys missing),
    /// so the merged table must fill new keys from the shipped file while the user's own edits survive.
    #[test]
    fn a_later_language_file_fills_the_entries_an_earlier_one_is_missing() {
        let staging = staging_area("merge");
        let user_file = staging.join("user-zh-CN.json");
        let shipped_file = staging.join("shipped-zh-CN.json");
        fs::write(
            &user_file,
            "{\"page_login\":\"my edited login\",\"page_register\":\"register\"}",
        )
        .expect("writing the user copy must succeed");
        fs::write(
            &shipped_file,
            "{\"page_login\":\"log in\",\"page_register\":\"register\",\"message_input_placeholder\":\"type a message\"}",
        )
        .expect("writing the shipped copy must succeed");

        let mut texts: HashMap<String, String> = HashMap::new();
        assert!(
            merge_language_text_file(&user_file, &mut texts),
            "the user copy must count as read"
        );
        assert!(
            merge_language_text_file(&shipped_file, &mut texts),
            "the shipped copy must count as read"
        );
        assert_eq!(
            texts.get("page_login").map(String::as_str),
            Some("my edited login"),
            "earlier files win; user edits must not be overwritten by the later file"
        );
        assert_eq!(
            texts.get("message_input_placeholder").map(String::as_str),
            Some("type a message"),
            "entries missing from the first file must be filled by the later one, or the interface shows key placeholders"
        );
        let _ = fs::remove_dir_all(&staging);
    }

    /// An unreadable file is skipped, not counted as a language file; a non-object root is the same.
    /// This guards "one broken file among the candidates cannot poison the whole table".
    #[test]
    fn unreadable_language_files_are_skipped() {
        let staging = staging_area("unreadable");
        let mut texts: HashMap<String, String> = HashMap::new();
        assert!(
            !merge_language_text_file(&staging.join("does-not-exist.json"), &mut texts),
            "a missing file must count as not read"
        );
        let array_file = staging.join("array.json");
        fs::write(&array_file, "[\"this is not a language table\"]")
            .expect("writing the malformed file must succeed");
        assert!(
            !merge_language_text_file(&array_file, &mut texts),
            "a JSON root that is not an object must count as not read"
        );
        assert!(
            texts.is_empty(),
            "nothing may enter the table when nothing was read"
        );
        let _ = fs::remove_dir_all(&staging);
    }

    /// The default appearance is an **ordinary theme file** (`themes/default.json`), no longer a reserved code-built-in name:
    /// loading it must go through the same file path as any theme, with complete fields, no extras, and colors matching the code fallback
    /// (default.json mirrors the built-in fallback palette; neither side may drift).
    #[test]
    fn the_default_appearance_is_an_ordinary_complete_theme_file() {
        let name = Palette::default_name();
        assert!(
            paths::config_path(&format!("themes/{name}.json")).exists(),
            "the default appearance must really ship a theme file now, or the client reports incomplete fields at startup"
        );
        let theme = Palette::load(name);
        assert!(
            !theme.has_missing_field,
            "the default appearance ({name}) must be complete, got {:?}",
            theme.palette
        );
        assert!(
            theme.extra_fields.is_empty(),
            "the default appearance must not carry unknown fields"
        );
        assert_eq!(
            theme.palette,
            Palette::built_in(),
            "the default appearance must match the code fallback palette exactly"
        );
    }

    /// The reserved name `built_in` is gone from the appearance system: the available list **only names real theme files**,
    /// it must no longer contain built_in and must list the default appearance through default.json;
    /// and actually loading the name built_in must honestly report incomplete fields — no silent special cases.
    #[test]
    fn the_retired_reserved_name_is_gone_and_default_is_listed() {
        let names = Palette::available_names();
        assert!(
            !names.iter().any(|name| name == "built_in"),
            "built_in must no longer be an available appearance, got {names:?}"
        );
        assert_eq!(
            names
                .iter()
                .filter(|name| name.as_str() == Palette::default_name())
                .count(),
            1,
            "the default appearance must come from themes/default.json and appear exactly once: {names:?}"
        );
        let retired = Palette::load("built_in");
        assert!(
            retired.has_missing_field,
            "loading the retired reserved name must report incomplete fields honestly (no special case left)"
        );
    }

    /// The room list marks unsent text with the localized `draft_mark`; both shipped
    /// tables must really carry their own wording, or the rows would show the raw key.
    #[test]
    fn the_draft_marker_is_localized_in_both_shipped_languages() {
        for (code, expected) in [("zh-CN", "[草稿]"), ("en-US", "[Draft]")] {
            let Ok(language) = Language::load(code) else {
                // 机器上没有语言文件时跳过（与其它读取语言文件的测试一致）
                continue;
            };
            assert_eq!(
                language.text("draft_mark"),
                expected,
                "{code} must localize draft_mark as {expected}"
            );
            assert_ne!(
                language.text("draft_mark"),
                "draft_mark",
                "{code} lacks draft_mark; the room list would show the raw key"
            );
        }
    }

    /// The shipped language files must carry **exactly the same key set**.
    ///
    /// Whichever file misses a key shows that key verbatim to users (`Language::text` falls back to the key name),
    /// the root cause of "Chinese text or raw underscore keys leaking into the English interface"; merging (per-key fill-in) cannot help when every language file lacks the key.
    #[test]
    fn shipped_language_files_carry_the_same_keys() {
        let codes = Language::available_codes();
        assert!(
            !codes.is_empty(),
            "config/languages must ship at least one language file"
        );
        let mut key_sets: Vec<(String, BTreeSet<String>)> = Vec::new();
        for code in &codes {
            let Ok(language) = Language::load(code) else {
                continue;
            };
            let keys: BTreeSet<String> = language.texts().into_keys().collect();
            assert!(
                !keys.is_empty(),
                "{code} must yield a non-empty table of texts"
            );
            key_sets.push((code.clone(), keys));
        }
        let Some((first_code, first_keys)) = key_sets.first() else {
            return;
        };
        for (code, keys) in key_sets.iter().skip(1) {
            let missing: Vec<&String> = first_keys.difference(keys).collect();
            let extra: Vec<&String> = keys.difference(first_keys).collect();
            assert!(
                missing.is_empty() && extra.is_empty(),
                "the keys of {first_code} and {code} differ: {code} lacks {missing:?}, carries extra {extra:?}"
            );
        }
    }
}
