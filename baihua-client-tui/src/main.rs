//! Terminal edition entry point: only starts the terminal interface.
//!
//! Command-line responsibilities such as install, uninstall, update, version report, and "launch the other interface" are all gathered in a unified entry
//! `baihua` (package `baihua-cli`). This file no longer duplicates them. This file only retains a read-only `version`
//! subcommand, for `baihua` to summarize the installed terminal edition's version; all other arguments are not processed.

mod app;
mod avatar;

use crate::app::{App, ensure_avatar_source_directory};
use crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    KeyboardEnhancementFlags, PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
};
use crossterm::execute;
use std::io::{self, stdout};
use std::sync::mpsc;
use std::time::Duration;

fn main() -> io::Result<()> {
    report_version_if_requested();
    run_terminal_interface()
}

/// Read-only `version` subcommand: the command-line edition `baihua` relies on it to summarize the installed terminal edition's version.
/// Beyond this, the terminal edition does not touch any command-line arguments — install, uninstall, update, and launching the graphical edition are all in `baihua`.
fn report_version_if_requested() {
    let Some(first_argument) = std::env::args().nth(1) else {
        return;
    };
    match first_argument.as_str() {
        "version" | "--version" | "-V" => {
            println!("baihua-tui {}", App::client_version());
            println!("baihua-core {}", App::core_version());
            std::process::exit(0);
        }
        other => {
            eprintln!(
                "baihua-tui does not handle the option `{other}`; run `baihua help` for the command line entry"
            );
            std::process::exit(2);
        }
    }
}

/// Start the terminal chat interface.
fn run_terminal_interface() -> io::Result<()> {
    let mut app = App::default();

    let lang = App::current_language();
    app.load_language(&lang);
    app.load_display_preferences();
    // Create the avatar directory first: "Change Avatar" in settings directly lists image files here
    ensure_avatar_source_directory();

    // Create channels for background thread to communicate with the main thread
    let (sender, receiver) = mpsc::channel();
    app.set_polling_sender(Some(sender));

    // First confirm the server is reachable and fetch the version; both the interface top bar and auto-login use this result
    app.probe_server_at_startup();
    // After that, connection state is maintained by the persistent probe thread based on facts: it's independent of login state,
    // keeps probing after logout, won't misreport "no session" as "can't connect to server"
    app.start_reachability_watch();

    // Try to auto-login with the session saved by the last /quit; on failure stay on the login page
    app.try_auto_login();
    // When not logged in (no valid session), pop a hint guiding to /login or /register; the chat window displays normally without covering
    if !app.is_logged_in() {
        app.notify_signed_out();
    }
    // Background check for new client version: only pop a notification after really downloading and verifying the package, don't interrupt startup
    app.start_update_check_thread(App::client_version());

    // Enable mouse capture: scroll wheel reports as real mouse events, used to scroll the message display area;
    // otherwise the terminal will escape the scroll wheel as arrow keys causing accidental room switching. Universal across terminals, enabled separately.
    execute!(stdout(), EnableMouseCapture)?;

    // Enable bracketed paste mode: pasted content arrives as a single Event::Paste chunk, not split into per-character key events.
    // Without it, newlines in pasted text would be treated as pressing Enter, so multi-line pasting would send multiple messages in sequence.
    // Non-fatal skip when the terminal does not support it (behavior falls back to original).
    let bracketed_paste_enabled = execute!(stdout(), EnableBracketedPaste).is_ok();

    // Keyboard enhancement flag: only supported by newer protocol terminals like kitty/SGR, used to report modifier keys such as Shift/Ctrl+Enter.
    // Traditional Windows console (conhost) does not support it; PushKeyboardEnhancementFlags would return
    // "Keyboard progressive enhancement not implemented for the legacy Windows API."。
    // Therefore first probe support and skip non-fatal if enabling fails: Ctrl+J/Ctrl+U for multi-line input as ordinary control characters
    // can still be reported on old terminals without relying on this enhancement protocol; skipping does not affect functionality or startup.
    let keyboard_flags = KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES
        | KeyboardEnhancementFlags::REPORT_ALL_KEYS_AS_ESCAPE_CODES;
    let keyboard_enhancement_supported =
        crossterm::terminal::supports_keyboard_enhancement().unwrap_or(false);
    let keyboard_enhancement_pushed = keyboard_enhancement_supported
        && execute!(stdout(), PushKeyboardEnhancementFlags(keyboard_flags)).is_ok();

    let run_result = ratatui::run(|terminal| {
        loop {
            // Application requests full-screen redraw: clear first to make ratatui discard the incremental baseline, full redraw next frame,
            // used to fix screen-buffer misalignment caused by occasional auto-scroll on the terminal side
            if app.take_full_repaint_request() {
                terminal.clear()?;
            }
            terminal.draw(|frame| app.ui(frame))?;

            if event::poll(Duration::from_millis(100))? && app.handle_event(&event::read()?) {
                break Ok(());
            }

            app.handle_tick();

            // Check messages sent from background threads
            while let Ok(polling_event) = receiver.try_recv() {
                app.handle_polling_event(polling_event);
            }

            // Safely exit here after /quit background cleanup (encrypted sessions and room unsubscription) is complete
            if app.should_quit_now() {
                break Ok(());
            }
            // /update has suspended the installation process; this process exits directly to yield to the replacement
            if app.should_exit_for_update() {
                break Ok(());
            }
        }
    });

    // Restore terminal: only pop the keyboard enhancement flag when successfully enabled (otherwise Pop would error on traditional Windows),
    // mouse capture is always off. Both use is_ok/non-fatal handling to avoid interruption again during cleanup due to unsupported features.
    if keyboard_enhancement_pushed {
        let _ = execute!(stdout(), PopKeyboardEnhancementFlags);
    }
    if bracketed_paste_enabled {
        let _ = execute!(stdout(), DisableBracketedPaste);
    }
    let _ = execute!(stdout(), DisableMouseCapture);
    run_result
}
