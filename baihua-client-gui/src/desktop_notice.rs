//! Desktop notifications (GUI).
//!
//! The GUI uses notify-rust to pop system notifications: one each for incoming messages and private chat requests,
//! the trigger points are the same batch as the TUI (the TUI falls back to osascript on macOS; the GUI uses notify-rust directly).
//! sending is done in a background thread, the render thread does not wait for it; failures are only logged and do not affect the interface.

use baihua_core::config;

/// system notification sound file: uses the same one as the terminal version; among macOS built-in sounds it is the one least likely to be missing.
fn notification_sound_path() -> &'static str {
    "/System/Library/Sounds/Ping.aiff"
}

/// Play the system notification sound in a background thread.
///
/// previously only desktop notifications were sent: notify-rust is silent by default on macOS, so after the "sound notification" switch is turned on,
/// nothing is heard. Here we use the same approach as the terminal version, calling macOS's afplay to play a sound;
/// playback is in a background thread, the render thread doesn't wait for it, and failures are only logged.
fn play_notification_sound() {
    #[cfg(target_os = "macos")]
    std::thread::spawn(|| {
        use std::process::Stdio;
        // the GUI has no console, so the player's output (especially errors like "this machine can't play") shouldn't leak into the terminal running it;
        // playback success or failure is only recorded in the debug log
        match std::process::Command::new("afplay")
            .arg(notification_sound_path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            Ok(status) if status.success() => config::debug_log("Notification sound played"),
            Ok(status) => config::debug_log(&format!("Notification sound exited with {status:?}")),
            Err(error) => config::debug_log(&format!("Notification sound failed: {error}")),
        }
    });
}

/// Pop a system notification: title + body, plus the system alert sound.
/// When the "sound notification" switch in settings is off, do not send (same switch as the TUI, see `Client::sound_enabled`).
pub fn send(sound_enabled: bool, title: &str, body: &str) {
    if !sound_enabled {
        return;
    }
    play_notification_sound();
    let title = title.to_string();
    let body = body.to_string();
    std::thread::spawn(move || {
        match notify_rust::Notification::new()
            .summary(&title)
            .body(&body)
            .appname("Baihua Client")
            .show()
        {
            Ok(_handle) => config::debug_log(&format!("Desktop notification sent: {title}")),
            Err(error) => {
                config::debug_log(&format!("Desktop notification sending failed: {error}"))
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::send;
    use std::time::Duration;

    /// the notification sound file must actually exist, otherwise afplay only prints a failure and the user still can't hear anything.
    /// only check on macOS: other systems use the desktop notification's own sound.
    #[cfg(target_os = "macos")]
    #[test]
    fn notification_sound_file_exists() {
        assert!(
            std::path::Path::new(super::notification_sound_path()).is_file(),
            "系统提示音文件要真实存在: {}",
            super::notification_sound_path()
        );
    }

    /// Whether notify-rust can actually pop on this machine: pop a real one and check if the terminal prints success or failure.
    /// Only verifies "the call does not error"; failing to pop does not make the test fail (the system notification center behavior is out of our control).
    /// Skipped by default: running tests should not pop system notifications every time. Manual run:
    /// `cargo test -p baihua-client-gui -- --ignored notification_call_is_attempted --nocapture`
    #[test]
    #[ignore = "Will actually pop a system notification, run manually"]
    fn notification_call_is_attempted() {
        let outcome = notify_rust::Notification::new()
            .summary("Baihua 客户端")
            .body("Desktop notification self-check: 看到这条说明 notify-rust 可用")
            .appname("Baihua Client")
            .show();
        match outcome {
            Ok(_handle) => println!("Desktop notification self-check succeeded"),
            Err(error) => println!("Desktop notification self-check failed: {error}"),
        }
        // send() runs in a background thread; confirm here that it will not panic or block
        send(
            false,
            "Do not send when the switch is off",
            "这一条不该出现",
        );
        send(
            true,
            "Baihua 客户端",
            "Desktop notification self-check (background thread)",
        );
        // the notification sound plays in a background thread; afplay takes about three seconds from starting the audio device to finishing,
        // give enough time for it to finish playing and write the debug log before ending the process
        std::thread::sleep(Duration::from_millis(3500));
    }
}
