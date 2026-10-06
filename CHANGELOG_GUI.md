# Changelog

All notable changes to the Baihua Client will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Every room keeps its own message draft: switching or closing a chat clears the input box and stores the text for that room, reopening the room restores it, and the room list marks rooms holding unsent text with `[Draft]xxx`.

### Fixed

- Removing a room that sits above the selected one now shifts the selection down, so the highlight and the input box no longer silently belong to another chat.

## [0.1.0] - 2026-9-26

### Added
- Support selecting the avatar file with the system file picker.
- Added a standalone search button.
- Added a group chat settings button.
- Added a standalone send button.
- Added support for the macOS, Windows, Linux, Android, and iOS platforms.
- Added narrow screen adaptation.
- Popups can be closed.
- When no group chat is selected, the logo is shown by default.

### Changed
- Changed the default color scheme.
- Added rounded corners to the chat box.
- Added images to some buttons.
- Added chat bubbles.
- When space is too small, the username and send time are hidden.
- Improved the automation workflow.

## [0.1.0-alpha.1] - 2026-9-12

### Added
- A relatively complete GUI interface;
- Some functions of the TUI version.
