# Changelog

All notable changes to the Baihua Client will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-9-6

### Added

- Added a top sidebar.
- Added a dark theme.
- Added local cache, stored under the "~/.baihua/client/cache" directory.
- Added an update module.
- Added an installer for initial installation and automatic client updates.
- Added the `/list_users` command to display all registered users.
- Added the `/profile <username/UID>` command, which outputs in a prompt box. If left empty, it displays your own profile; entering a valid username or UID displays that person's profile.
- Added support for displaying user avatars; avatars can be viewed when using `/profile`.
- Added a new settings entry "Set Profile", supporting modification of nickname, bio, and phone number.
- Added a new settings entry "Delete Account", which requires re-entering the password to delete.
- Added a new settings entry "Change Password", which requires entering the old password once and the new password to take effect.
- Added a new settings entry "Change Avatar", which takes effect by providing a valid link.
- Added the `/search_users <keyword>` command to search for registered users.
- Added a CLI tool; type `baihua` to start it, used to launch the client and perform installation and uninstallation operations.

### Changed

- Improved the private chat management page to display invitations sent by the user to others. Rejecting such an invitation cancels the invitation sent to the other person.
- Enriched the content displayed by `/info`.
- Added `/exit` as an alias for `/quit`.
- `/login` and `/register` no longer support providing arguments directly for operation.
- Box selection copying can now select all text.
- In search mode, the currently selected match is specially marked with a different color (this content should be extended to the appearance list).
- When unable to connect to the server, the "unable to connect to server" error no longer pops up repeatedly; after popping up once, it is marked using the top sidebar.

### Fixed

- Fixed the issue where the prompt box could not automatically stretch to fit when a single line of text was too long.
- Fixed the issue in non-quick search mode where using backspace to delete text would retain the original search results.

## [0.1.0-alpha.2] - 2026-8-30

### Added
- When someone is typing in a group chat, others are notified;
- Use /info to view the online status of group chat members;
- Enter # to activate message search mode; press Enter or enable quick search mode to search for matching text in the current group chat;
- Use /appearance or select Appearance in settings to modify the interface colors. Appearance configuration files are currently stored in the config/themes directory, with three built-in themes: default, high contrast, and light;
- Support selecting most text.
### Changed
- Removed /list_member; its functionality has been merged into /info;
- No longer display hints related to Tab/Esc/Enter operations;
- When closing an overlay opened from settings, return to the settings page instead of directly closing the overlay.
### Fixed
- In some cases, after logging out and logging back in, messages could not be received in real time.

## [0.1.0-alpha.1] - 2026-8-29

### Added
- A relatively complete TUI interface;
- Chat communication with the server;
- JWT automatic login;
- Encrypted private chat.
