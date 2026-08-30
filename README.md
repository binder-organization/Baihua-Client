![Baihua](docs/images/logo.png)

# Baihua Client

## A Collaboration Tool for Developers 🌳

[![Author: ChepleBob](https://img.shields.io/badge/Author-ChepleBob-00B4D8)](https://github.com/ChepleBob30)
[![Language: Rust](https://img.shields.io/badge/Language-Rust-5F4C49)](https://www.rust-lang.org/)
[![License: Apache v2](https://img.shields.io/badge/License-Apache%20v2-yellow.svg)](https://opensource.org/licenses/Apache-2.0)
[![TUI Version](https://img.shields.io/badge/TUI%20Version-v0.1.0--alpha.2-3D35DB)](https://github.com/binder-organization/Baihua-Client/releases)
[![Core Version](https://img.shields.io/badge/Core%20Version-v0.2.0-EB9317)](https://github.com/binder-organization/Baihua-Client/tree/main/baihua-core)

English | [简体中文](docs/zh-CN/README_zh-CN.md)

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

### Latest Versions

- TUI 0.1.0-alpha.2
- Core 0.2.0

### Changelog - TUI

#### Added

- When someone is typing in a group chat, others are notified;
- Use `/info` to view the online status of group chat members;
- Enter `#` to activate message search mode; press Enter or enable quick search mode to search for matching text in the current group chat;
- Use `/appearance` or select `Appearance` in settings to modify the interface colors. Appearance configuration files are currently stored in the `config/themes` directory, with three built-in themes: default, high contrast, and light;
- Support selecting most text.

#### Changed

- Removed `/list_member`; its functionality has been merged into `/info`;
- No longer display hints related to Tab/Esc/Enter operations;
- When closing an overlay opened from settings, return to the settings page instead of directly closing the overlay.

#### Fixed

- In some cases, after logging out and logging back in, messages could not be received in real time.

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
