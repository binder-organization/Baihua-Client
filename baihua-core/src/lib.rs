/// The core library of Baihua.
pub mod api;
pub mod chat_cache;
pub mod crypto;
pub mod paths;
pub mod update;

/// 核心库版本（编译期取自本包的 Cargo.toml）。客户端顶栏与 `--version` 都要与界面版本一并展示，
/// 便于定位问题出在界面上还是在与服务端通信的这层。
pub fn core_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
