//! GUI entry point: only starts the graphical interface.
//!
//! Command-line responsibilities such as install, uninstall, update, version report, and "launch the other interface" are all collected into the unified entry
//! `baihua` (package `baihua-cli`); this file no longer duplicates them. This file only retains a read-only `version`
//! subcommand, used by `baihua` to aggregate the installed GUI version; all other arguments are ignored.

mod app;
mod appearance;
mod client;
mod client_actions;
mod desktop_notice;

/// Room list entry: the session layer provides data, the interface only renders it.
pub struct RoomEntry {
    pub id: String,
    pub title: String,
    pub encrypted: bool,
    pub unread: u32,
    pub muted: bool,
}

/// Entry shared by the command panel, input completion, and `/command`: (command name, description text key).
/// The table itself is in shared code `baihua_core::commands`; the terminal version reads the same one.
///
/// `/login` is left out for the graphical end: the graphical end opens the sign-in form by itself
/// (a modal page when no session is restored, plus the sign-in button in the room list), so the command
/// did nothing a user could observe; the session layer also has no branch for it any more.
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    report_version_if_requested();
    run_graphical_interface()
}

/// Read-only `version` subcommand: the command-line `baihua` relies on it to aggregate the installed GUI version.
/// Besides this, the GUI does not touch any command-line arguments — install, uninstall, update, launching the terminal version are all in `baihua`.
fn report_version_if_requested() {
    let Some(first_argument) = std::env::args().nth(1) else {
        return;
    };
    match first_argument.as_str() {
        "version" | "--version" | "-V" => {
            println!("baihua-gui {}", env!("CARGO_PKG_VERSION"));
            println!("baihua-core {}", baihua_core::core_version());
            std::process::exit(0);
        }
        other => {
            eprintln!(
                "baihua-gui does not handle the option `{other}`; run `baihua help` for the command line entry"
            );
            std::process::exit(2);
        }
    }
}

/// Start the graphical interface.
fn run_graphical_interface() -> Result<(), Box<dyn std::error::Error>> {
    // Configuration directory location is fully delegated to `baihua_core::paths`: first look at `config/` under the current working directory,
    // then look at `config/` traversed upward from the program directory; writes always go to `<client root>/config` under the user directory.
    // The terminal version follows the same rule, so running in the source tree both sides read the `config/` at the repository root,
    // after installation both sides read `<client root>/config`: one configuration, one cache, shared by both sides.
    // Previously the GUI would first switch its working directory to the client root, so during development the GUI read the user directory's
    // configuration while the terminal read the repository root's — the two were actually split. This round removes that block (see AGENTS.md).
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1080.0, 680.0])
            .with_min_inner_size([640.0, 420.0])
            .with_title(format!("baihua-gui {}", env!("CARGO_PKG_VERSION"))),
        ..Default::default()
    };
    eframe::run_native(
        "baihua-client-gui",
        options,
        Box::new(|creation| Ok(Box::new(app::BaihuaApp::new(&creation.egui_ctx)))),
    )?;
    Ok(())
}
