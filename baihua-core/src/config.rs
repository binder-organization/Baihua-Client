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
    /// Built-in default appearance: identical to the hardcoded color scheme before the appearance system was introduced,
    /// and also serves as the fallback color when a theme file has missing slots, ensuring users without a configured theme see the original effect.
    pub fn built_in() -> Self {
        Self {
            app_background: ThemeColor::Default,
            message_border: ThemeColor::Cyan,
            room_border: ThemeColor::Cyan,
            overlay_border: ThemeColor::Cyan,
            message_text: ThemeColor::White,
            selected_text: ThemeColor::Yellow,
            other_username_text: ThemeColor::Cyan,
            own_username_text: ThemeColor::Green,
            time_text: ThemeColor::DarkGray,
            hint_text: ThemeColor::DarkGray,
            notice_hint_border: ThemeColor::Blue,
            notice_error_border: ThemeColor::Red,
            input_border: ThemeColor::Cyan,
            input_text: ThemeColor::White,
            command_border: ThemeColor::Yellow,
            search_border: ThemeColor::Red,
            selection_background: ThemeColor::Yellow,
            search_match_background: ThemeColor::Red,
            search_current_match_background: ThemeColor::LightYellow,
            read_state_text: ThemeColor::Blue,
        }
    }

    /// Read `<config_dir>/themes/{name}.json` and return the complete theme at once.
    /// When the file is unreadable or not valid JSON, return the built-in default theme and mark "missing field" as true.
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
        let fields: [&str; 20] = [
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
            _ => {}
        }
    }

    /// List all available appearance names under config/themes (removing .json suffix), sorted alphabetically
    pub fn available_names() -> Vec<String> {
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

/// Language text carrier: reads all key-value pairs from `config/languages/{code}.json` at once; look up by key name.
/// Keys not found are returned as the key name itself (makes it easy to see which key was missed on the interface).
#[derive(Debug, Clone, Default)]
pub struct Language {
    /// Current language code (such as zh-CN); only used for display and writing back to preferences.json
    pub code: String,
    /// Key name → localized text
    texts: HashMap<String, String>,
}

/// 读一份语言文件，把里面的条目并进已经读到的表里。
///
/// 合并规则是"先生效的键优先"：调用方按配置目录候选顺序一份份喂进来，
/// 排在前面的文件（用户配置目录那一份）已经有的键保持原样，只补它缺的键。
/// 这样用户改过的文案不会被后一份冲掉，后一份多出来的新条目又能补进来。
///
/// 返回值是"这份文件有没有真的读出一张表"：文件不存在、打不开、
/// 或者 JSON 根节点不是"键 → 文本"的对象（比如写成了一个数组）都算没读到。
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
    /// 语言文件按 `paths::config_directory_candidates()` 的顺序**逐份合并**，不是只读第一份：
    /// 用户配置目录里的那份排在前面（用户改过的条目以它为准），
    /// 排在后面的源码树/安装目录那份只用来补齐前面缺的条目。
    /// 旧版本安装出来的 `languages/*.json` 会一直留在用户目录里（安装器只补缺失的文件、不重写已有文件），
    /// 新版本加进来的键在那一份里根本没有，界面上就会把键名当文案显示出来（"大量文本变成占位符"的根因）。
    /// 一份都读不到（文件不存在或不是"键 → 文本"的对象）时返回**出错的那份文件路径**，
    /// 不返回任何写好的文案：提示文字由各界面按自己的语言表补
    /// （图形版用语言键 `error_lang_file_read`），核心层不产出某一种语言的用户文案。
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

/// Debug log: only written in debug builds. Written to a fixed file under `/tmp`,
/// making it easy for users to send the file when encountering problems without having to reproduce them (append-only, silently ignored on failure).
#[cfg(debug_assertions)]
pub fn debug_log(message: &str) {
    use std::sync::Mutex;
    static LOG_LOCK: Mutex<()> = Mutex::new(());
    let _guard = match LOG_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let path = std::path::Path::new("/tmp/baihua_client_debug.log");
    let line = format!("{}\n", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"));
    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{line} {message}");
    }
}

#[cfg(not(debug_assertions))]
pub fn debug_log(_message: &str) {}

#[cfg(test)]
mod tests {
    use super::{Language, merge_language_text_file};
    use std::collections::{BTreeSet, HashMap};
    use std::fs;
    use std::path::PathBuf;

    /// 一件临时场地：放几份语言文件，测"多份合并"时不碰真实配置目录
    fn staging_area(label: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!("baihua-language-{label}"));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).expect("临时目录应可创建");
        directory
    }

    /// 本轮修复"大量文本无法读取语言文件，显示占位符"的核心：
    /// 用户配置目录里那份语言文件是旧版本留下的（缺新条目），
    /// 合并后新条目要由随程序发布的那一份补齐，而用户自己改过的条目不能被冲掉。
    #[test]
    fn a_later_language_file_fills_the_entries_an_earlier_one_is_missing() {
        let staging = staging_area("merge");
        let user_file = staging.join("user-zh-CN.json");
        let shipped_file = staging.join("shipped-zh-CN.json");
        fs::write(
            &user_file,
            "{\"page_login\":\"我改过的登录\",\"page_register\":\"注册\"}",
        )
        .expect("写入用户那份应成功");
        fs::write(
            &shipped_file,
            "{\"page_login\":\"登录\",\"page_register\":\"注册\",\"message_input_placeholder\":\"输入消息\"}",
        )
        .expect("写入随程序发布的那份应成功");

        let mut texts: HashMap<String, String> = HashMap::new();
        assert!(
            merge_language_text_file(&user_file, &mut texts),
            "用户那份要算读到了"
        );
        assert!(
            merge_language_text_file(&shipped_file, &mut texts),
            "随程序发布的那份要算读到了"
        );
        assert_eq!(
            texts.get("page_login").map(String::as_str),
            Some("我改过的登录"),
            "排在前面的文件优先，用户改过的文案不能被后一份冲掉"
        );
        assert_eq!(
            texts.get("message_input_placeholder").map(String::as_str),
            Some("输入消息"),
            "前面缺的条目要由后面的文件补上，否则界面上会显示成键名占位符"
        );
        let _ = fs::remove_dir_all(&staging);
    }

    /// 读不到的文件只跳过，不算一份语言文件；根节点不是"键 → 文本"的对象也一样。
    /// 这条保证的是"多份候选里坏一份不会把整个语言表带坏"。
    #[test]
    fn unreadable_language_files_are_skipped() {
        let staging = staging_area("unreadable");
        let mut texts: HashMap<String, String> = HashMap::new();
        assert!(
            !merge_language_text_file(&staging.join("不存在.json"), &mut texts),
            "文件不存在要算没读到"
        );
        let array_file = staging.join("array.json");
        fs::write(&array_file, "[\"这不是一张语言表\"]").expect("写入坏格式应成功");
        assert!(
            !merge_language_text_file(&array_file, &mut texts),
            "JSON 根节点不是对象要算没读到"
        );
        assert!(texts.is_empty(), "没读到就不该往表里塞东西");
        let _ = fs::remove_dir_all(&staging);
    }

    /// 随程序发布的语言文件必须**键集合完全一致**。
    ///
    /// 少写一个键的那一边，界面上会把键名当文案显示给用户（`Language::text` 找不到就回退成键名），
    /// 这正是"英文界面里冒出一段中文/一串下划线键名"的根因；合并（条目级补缺）救不了"所有语言文件都缺这个键"。
    #[test]
    fn shipped_language_files_carry_the_same_keys() {
        let codes = Language::available_codes();
        assert!(!codes.is_empty(), "config/languages 下应至少有一份语言文件");
        let mut key_sets: Vec<(String, BTreeSet<String>)> = Vec::new();
        for code in &codes {
            let Ok(language) = Language::load(code) else {
                continue;
            };
            let keys: BTreeSet<String> = language.texts().into_keys().collect();
            assert!(!keys.is_empty(), "{code} 应能读出一张非空的文案表");
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
                "{first_code} 与 {code} 的文案键不一致：{code} 缺 {missing:?}，多 {extra:?}"
            );
        }
    }
}
