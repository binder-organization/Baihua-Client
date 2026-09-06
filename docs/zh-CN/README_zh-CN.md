![Baihua](../images/logo.png)

# 白桦客户端

## 开发者的协作工具🌳

[![作者: ChepleBob](https://img.shields.io/badge/作者-ChepleBob-00B4D8)](https://github.com/ChepleBob30)
[![语言: Rust](https://img.shields.io/badge/语言-Rust-5F4C49)](https://www.rust-lang.org/)
[![许可证: Apache v2](https://img.shields.io/badge/许可证-Apache%20v2-yellow.svg)](https://opensource.org/licenses/Apache-2.0)
[![TUI版本](https://img.shields.io/badge/TUI版本-v0.1.0-3D35DB)](https://github.com/binder-organization/Baihua-Client/releases)
[![Core版本](https://img.shields.io/badge/Core版本-v0.3.0-EB9317)](https://github.com/binder-organization/Baihua-Client/tree/main/baihua-core)

[English](../../README.md) | [简体中文](./README_zh-CN.md)

---

## 目录

- [版本信息](#版本信息)
- [总览](#总览)
- [快速开始](#快速开始)
- [特别致谢](#特别致谢)
- [贡献者](#贡献者)
- [许可证](#许可证)
- [尾声](#尾声)

---

## 版本信息

### 更新日志 - TUI

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

## 总览

### 简介

白桦是一个即时通讯工具，包含服务端、客户端TUI、客户端GUI三个部分。

### 特色

白桦客户端采用TUI和GUI(暂未完工)两种模式，TUI版本可在终端内快速完成所有操作，使用逻辑类似于`opencode`，适用于开发者快速适应并积极沟通。
借由强大的服务端，客户端支持端对端加密与jwt自动登录，兼具安全与便利。还支持查看已读/未读(未来添加)与他人是否在打字。
目前客户端处于测试阶段，我们将不断为客户端添加新的功能。

### 创建白桦的目的

长久以来，开发者都需要在不同软件间来回切换，这样做不仅消耗了性能，还浪费了宝贵的时间。更糟糕的是，不少闭源项目都存在窃取用户隐私数据的无耻行径，严重损害了用户的权益。白桦正是为了解决此问题而生。我们的服务端采用开源的分布式服务器架构，让开发者能够自行部署并调整细节。对于客户端，我们采用TUI模式，这意味着你可以只在终端里就完成关键的团队沟通与日常聊天。

---

## 快速开始

### TUI

- 客户端会在未来支持在一些包管理器中安装，并添加GUI版本。
- 启动后，使用/server_address或在设置中选择“自定义服务器地址”来配置你的白桦服务器地址，然后调用/register或在设置中选择“注册”来注册账号，最后使用/login或在设置中选择“登录”以开始聊天。

---

## 特别致谢
对以下为白桦做出突出贡献的人员表示真挚地感谢（没有先后之分）：
- [Gavin](https://github.com/GavZheng)：为客户端提供了强大的后端保障，也是客户端的第一个用户。

---

## 贡献者

<a href="https://github.com/binder-organization/Baihua-Client/contributors">
  <img src="https://contrib.rocks/image?repo=binder-organization/Baihua-Client" alt="Contributors"/>
</a>

---

## 许可证

[Apache v2](../../LICENSE), Copyright 2026 ChepleBob.

## 尾声

- 如果你喜欢此项目，请推荐给更多的人，也可以提交issue来帮助我们改进项目。
- 你还可以试试加入我们的组织[必达](https://github.com/binder-organization)。
