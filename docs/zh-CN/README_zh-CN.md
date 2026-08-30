![Baihua](../images/logo.png)

# 白桦客户端

## 开发者的协作工具🌳

[![作者: ChepleBob](https://img.shields.io/badge/作者-ChepleBob-00B4D8)](https://github.com/ChepleBob30)
[![语言: Rust](https://img.shields.io/badge/语言-Rust-5F4C49)](https://www.rust-lang.org/)
[![许可证: Apache v2](https://img.shields.io/badge/许可证-Apache%20v2-yellow.svg)](https://opensource.org/licenses/Apache-2.0)
[![TUI版本](https://img.shields.io/badge/TUI版本-v0.1.0--alpha.2-3D35DB)](https://github.com/binder-organization/Baihua-Client/releases)
[![Core版本](https://img.shields.io/badge/Core版本-v0.2.0-EB9317)](https://github.com/binder-organization/Baihua-Client/tree/main/baihua-core)

[English](../../README.md) | 简体中文

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

### 最新版本

- TUI 0.1.0-alpha.2
- Core 0.2.0

### 更新日志 - TUI

#### 添加

- 群聊中有人在打字时，会提示其他人；
- 使用`/info`可以查看群聊成员在线情况；
- 输入`#`可以开启消息搜索模式，按下enter或启用快速搜索模式即可搜索当前群聊的匹配文本；
- 使用`/appearance`或在设置中选择`外观`可以修改界面颜色，目前外观配置文件存储于config/themes目录下，自带默认/高对比度/亮色三种外观配置；
- 支持选中绝大多数文本。

#### 更改

- 移除了`/list_member`，其功能已被整合到`/info`中；
- 不再提示tab/esc/enter相关的操作；
- 在设置里唤出的叠加层关闭时统一回到设置页面，而不是直接关闭叠加层。

#### 修复

- 在部分情况下退出登录再重新登录回无法实时收到消息。


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

- 测试版目前只能在release中下载压缩包并解压，然后在TUI根目录下运行`cargo run`来启动客户端。
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
