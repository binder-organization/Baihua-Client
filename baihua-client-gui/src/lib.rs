//! The graphical client as a library: the desktop, Android and iOS entry points
//! all start here. Modules: app, client, client_actions, appearance, desktop_notice.

#[cfg(target_os = "android")]
mod android_platform;
pub mod app;
pub mod appearance;
pub mod client;
pub mod client_actions;
pub mod desktop_notice;
#[cfg(target_os = "ios")]
mod ios_platform;

use app::BaihuaApp;

/// Room list entry: the session layer provides data, the interface only renders it.
pub struct RoomEntry {
    pub id: String,
    pub title: String,
    /// How many people are in the room, shown right after the room title
    pub member_count: usize,
    pub encrypted: bool,
    pub unread: u32,
    pub muted: bool,
    /// Text typed into this room's input box but never sent, empty when there is none; the
    /// room list appends it behind the localized "[Draft]" mark (see `room_row_draft_suffix`)
    pub draft: String,
}

/// Command table shared by the command panel, input completion and `/command`,
/// as (name, description key); `/login` is dropped because the interface has a form.
pub fn command_entries() -> Vec<(&'static str, &'static str)> {
    baihua_core::commands::chat_commands()
        .into_iter()
        .filter(|(name, _description)| *name != "login")
        .collect()
}

/// WebSocket auth expired sentinel string (same source as in the seam)
pub fn auth_expired_marker() -> &'static str {
    baihua_core::api::websocket_auth_sentinel()
}

/// Logo shown centered in the message area while no group chat is open; the
/// image lives inside the binary because mobile packages have no assets directory.
pub fn logo_bytes() -> &'static [u8] {
    include_bytes!("../assets/images/logo.png")
}

/// Decode side of the logo texture in pixels: sharp enough for the retina
/// scale, small enough for one upload (the painted size never exceeds it).
pub fn logo_texture_side() -> usize {
    512
}

/// The application icon bytes, embedded for the same reason as the logo.
pub fn icon_bytes() -> &'static [u8] {
    include_bytes!("../assets/images/icon.png")
}

/// Chinese fallback font embedded in the binary, iOS only: the sandbox cannot
/// read the system font table. Built by `assets/fonts/build-subset.py`.
#[cfg(target_os = "ios")]
pub fn embedded_font_bytes() -> &'static [u8] {
    include_bytes!("../assets/fonts/SourceHanSansSC-Regular-Subset.ttf")
}

/// The embedded icon decoded into the window-icon shape egui expects; a failure
/// to decode an embedded asset is a build-time bug, hence the expect.
fn window_icon() -> egui::IconData {
    let image = image::load_from_memory(icon_bytes())
        .expect("the embedded application icon must decode")
        .to_rgba8();
    let (width, height) = image.dimensions();
    egui::IconData {
        width,
        height,
        rgba: image.into_raw(),
    }
}

/// The window the desktop starts with (mobile windowing ignores most of this).
fn application_options() -> eframe::NativeOptions {
    eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1080.0, 680.0])
            .with_min_inner_size([640.0, 420.0])
            .with_title(format!("baihua-gui {}", env!("CARGO_PKG_VERSION")))
            .with_icon(window_icon()),
        ..Default::default()
    }
}

/// Build the application for a live `eframe` context (font install and session
/// restore happen inside `BaihuaApp::new`).
fn create_application(creation: &eframe::CreationContext<'_>) -> BaihuaApp {
    BaihuaApp::new(&creation.egui_ctx)
}

/// Start the graphical interface on desktops (and, through the iOS entry
/// point below, on iPhones).
pub fn run_interface() -> Result<(), Box<dyn std::error::Error>> {
    // `baihua_core::paths` owns the config location: `config/` under the working
    // directory first, then upward from the program directory; writes go to the user tree.
    eframe::run_native(
        "baihua-gui",
        application_options(),
        Box::new(|creation| Ok(Box::new(create_application(creation)))),
    )?;
    Ok(())
}

/// Language and theme files the mobile packages carry inside the binary; the
/// paths mirror the shared `config/` tree the guard tests compare against.
#[cfg(any(target_os = "android", target_os = "ios", test))]
fn embedded_configs() -> &'static [(&'static str, &'static str)] {
    &[
        (
            "languages/en-US.json",
            include_str!("../../config/languages/en-US.json"),
        ),
        (
            "languages/zh-CN.json",
            include_str!("../../config/languages/zh-CN.json"),
        ),
        (
            "themes/default.json",
            include_str!("../../config/themes/default.json"),
        ),
        (
            "themes/dark.json",
            include_str!("../../config/themes/dark.json"),
        ),
        (
            "themes/light.json",
            include_str!("../../config/themes/light.json"),
        ),
        (
            "themes/high-contrast.json",
            include_str!("../../config/themes/high-contrast.json"),
        ),
    ]
}

/// Unpack the embedded config tree into `<root>/config/`, never overwriting an
/// existing file so user edits survive an application update.
#[cfg(any(target_os = "android", target_os = "ios"))]
fn install_configs(root: &std::path::Path) -> std::io::Result<()> {
    for (relative_path, contents) in embedded_configs() {
        let destination = root.join("config").join(relative_path);
        if destination.exists() {
            continue;
        }
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(destination, contents)?;
    }
    Ok(())
}

/// Android entry point (cargo-apk native activity): unpack the configuration
/// into the app private directory, then run the same interface as everywhere.
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
fn android_main(android_application: winit::platform::android::activity::AndroidApp) {
    let root = android_application
        .internal_data_path()
        .unwrap_or_else(std::env::temp_dir);
    let _installed = install_configs(&root);
    if std::env::set_current_dir(&root).is_ok() {
        // `config_directory_candidates()` looks for `config/` under the working
        // directory; the writable user tree moves into the same app private sandbox.
        unsafe {
            std::env::set_var("BAIHUA_DIR", &root);
        }
    }
    // Window tuning (keyboard resize, status-bar flags) and the notification
    // permission prompt: see `android_platform`.
    android_platform::install(&android_application);
    let mut options = application_options();
    options.android_app = Some(android_application.clone());
    let activity = android_application.clone();
    let result = eframe::run_native(
        "baihua-gui",
        options,
        Box::new(move |creation| {
            let mut application = create_application(creation);
            application.attach_activity(activity.clone());
            Ok(Box::new(application))
        }),
    );
    if let Err(error) = result {
        baihua_core::config::debug_log(&format!("eframe stopped: {error}"));
    }
}

/// iOS entry point for the hand-rolled runner (`ios/`, BUILDING.md section 6): winit
/// needs the main thread and calls `UIApplicationMain` itself, so call this once.
#[cfg(target_os = "ios")]
#[unsafe(no_mangle)]
pub extern "C" fn baihua_ios_main() {
    if let Some(home) = std::env::var_os("HOME").map(std::path::PathBuf::from) {
        let _installed = install_configs(&home);
        let _moved = std::env::set_current_dir(&home);
    }
    if let Err(error) = run_interface() {
        baihua_core::config::debug_log(&format!("eframe stopped: {error}"));
    }
}

#[cfg(test)]
mod embedded_tests {
    use std::collections::BTreeSet;

    /// The embedded images decode: the window icon is square (so the operating
    /// system letters it instead of stretching it) and the logo side is sane.
    #[test]
    fn embedded_images() {
        let decoded = image::load_from_memory(crate::icon_bytes()).expect("the icon must decode");
        assert_eq!(
            decoded.width(),
            decoded.height(),
            "the application icon must be square"
        );
        let icon = crate::window_icon();
        assert_eq!(icon.width, icon.height);
        assert_eq!(icon.rgba.len(), (icon.width * icon.height * 4) as usize);
        assert!(crate::logo_texture_side() >= 128);
    }

    /// The embedded manifest must name exactly the files `config/languages` and
    /// `config/themes` hold, and every one of them must parse as JSON.
    #[test]
    fn embedded_configs() {
        let mut from_disk: BTreeSet<String> = BTreeSet::new();
        for directory in ["languages", "themes"] {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../config")
                .join(directory);
            for entry in std::fs::read_dir(&path).expect("the config tree must exist") {
                let entry = entry.expect("readable directory entry");
                if entry.path().extension().map(|s| s == "json") == Some(true) {
                    from_disk.insert(format!(
                        "{directory}/{}",
                        entry.file_name().to_string_lossy()
                    ));
                }
            }
        }
        let embedded: BTreeSet<String> = crate::embedded_configs()
            .iter()
            .map(|(relative_path, _contents)| (*relative_path).to_string())
            .collect();
        assert_eq!(
            embedded, from_disk,
            "the embedded config manifest and config/ on disk must name the same files"
        );
        for (relative_path, contents) in crate::embedded_configs() {
            serde_json::from_str::<serde_json::Value>(contents)
                .unwrap_or_else(|error| panic!("{relative_path} must be valid JSON: {error}"));
        }
    }
}
