![Baihua](docs/images/logo.png)

# Baihua Client

## A Collaboration Tool for Developers 🌳

[![Author: ChepleBob](https://img.shields.io/badge/Author-ChepleBob-00B4D8)](https://github.com/ChepleBob30)
[![Language: Rust](https://img.shields.io/badge/Language-Rust-5F4C49)](https://www.rust-lang.org/)
[![License: Apache v2](https://img.shields.io/badge/License-Apache%20v2-yellow.svg)](https://opensource.org/licenses/Apache-2.0)
[![TUI Version](https://img.shields.io/badge/TUI%20Version-v0.1.0-3D35DB)](https://github.com/binder-organization/Baihua-Client/releases)
[![Core Version](https://img.shields.io/badge/Core%20Version-v0.3.0-EB9317)](https://github.com/binder-organization/Baihua-Client/tree/main/baihua-core)

[English](./README.md) | [简体中文](docs/zh-CN/README_zh-CN.md)

---

## Table of Contents

- [Version Information](#version-information)
- [Overview](#overview)
- [Quick Start](#quick-start)
- [Special Thanks](#special-thanks)
- [Contributors](#contributors)
- [License](#license)
- [Epilogue](#epilogue)

---

## Version Information

### Changelog - TUI

#### Added

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

#### Changed

- Improved the private chat management page to display invitations sent by the user to others. Rejecting such an invitation cancels the invitation sent to the other person.
- Enriched the content displayed by `/info`.
- Added `/exit` as an alias for `/quit`.
- `/login` and `/register` no longer support providing arguments directly for operation.
- Box selection copying can now select all text.
- In search mode, the currently selected match is specially marked with a different color (this content should be extended to the appearance list).
- When unable to connect to the server, the "unable to connect to server" error no longer pops up repeatedly; after popping up once, it is marked using the top sidebar.

#### Fixed

- Fixed the issue where the prompt box could not automatically stretch to fit when a single line of text was too long.
- Fixed the issue in non-quick search mode where using backspace to delete text would retain the original search results.

---

## Overview

### Introduction

Baihua is an instant messaging tool comprising three parts: server, TUI client, and GUI client.

### Features

The Baihua client supports two modes: TUI and GUI (not yet complete). The TUI version allows you to perform all operations quickly within the terminal, with a usage logic similar to `opencode`, suitable for developers to quickly adapt and actively communicate.
Leveraging the powerful server, the client supports end-to-end encryption and JWT automatic login, offering both security and convenience. It also supports viewing read/unread status (to be added in the future) and whether others are typing.
Currently, the client is in the testing phase, and we will continue adding new features.

### Purpose of Creating Baihua

For a long time, developers have had to switch between different software, consuming performance and wasting precious time. Worse still, many closed-source projects have engaged in shameless acts of stealing user privacy data, severely harming users' rights. Baihua was born to solve this problem. Our server adopts an open-source distributed server architecture, allowing developers to self-deploy and adjust details. For the client, we use TUI mode, meaning you can complete critical team communication and daily chat entirely within the terminal.

---

## Quick Start

### TUI

- For the beta version, you can only download the compressed package from the releases and extract it, then run `cargo run` in the TUI root directory to start the client.
- In the future, the client will support installation via some package managers, and a GUI version will be added.
- After startup, use `/server_address` or select "Custom Server Address" in the settings to configure your Baihua server address, then call `/register` or select "Register" in the settings to register an account, and finally use `/login` or select "Login" in the settings to start chatting.

---

## Special Thanks
Sincere thanks to the following people who have made outstanding contributions to Baihua (in no particular order):
- [Gavin](https://github.com/GavZheng): provided strong backend support for the client and was the client's first user.

---

## Contributors

<a href="https://github.com/binder-organization/Baihua-Client/contributors">
  <img src="https://contrib.rocks/image?repo=binder-organization/Baihua-Client" alt="Contributors"/>
</a>

---

## License

[Apache v2](LICENSE), Copyright 2026 ChepleBob.

## Epilogue

- If you like this project, please recommend it to more people, and you can also submit issues to help us improve the project.
- You can also try joining our organization [Binder](https://github.com/binder-organization).
