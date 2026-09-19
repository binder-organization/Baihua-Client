/// The core library of Baihua.
pub mod api;
pub mod chat_cache;
pub mod commands;
pub mod config;
pub mod crypto;
pub mod fonts;
pub mod installer;
pub mod paths;
pub mod update;

/// Core library version (taken from this package's Cargo.toml at compile time). The client top bar and `--version` must both be displayed together with the interface version,
/// making it easy to locate whether the problem is in the interface or in the layer communicating with the server.
pub fn core_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
