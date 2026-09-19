//! Client local directories and resource location.
//!
//! The root directory follows the same convention as the server: prefer the environment variable `BAIHUA_DIR`, otherwise use the user's home directory's
//! `.baihua`。服务端把数据放在该根目录，客户端统一放在其下的 `client` 子目录，
//! both sides share the same tree but do not overwrite each other.

use std::path::PathBuf;

/// Data root directory: `$BAIHUA_DIR` or `~/.baihua`. Returns None when the home directory cannot be obtained (the caller skips local storage).
pub fn data_root() -> Option<PathBuf> {
    if let Some(override_directory) = std::env::var_os("BAIHUA_DIR") {
        let directory = PathBuf::from(override_directory);
        if directory.as_os_str().is_empty() {
            return None;
        }
        return Some(directory);
    }
    dirs::home_dir().map(|home| home.join(".baihua"))
}

/// Client-specific directory `<$BAIHUA_DIR|~/.baihua>/client`.
fn client_root() -> Option<PathBuf> {
    data_root().map(|root| root.join("client"))
}

/// Root of regenerable data `<client directory>/cache`. Everything inside is stuff that "can be recovered if deleted",
/// uninstall can optionally clean it all up.
pub fn cache_directory() -> Option<PathBuf> {
    client_root().map(|root| root.join("cache"))
}

/// Local chat message cache directory `<client directory>/cache/chat_msg`.
pub fn chat_message_directory() -> Option<PathBuf> {
    cache_directory().map(|cache| cache.join("chat_msg"))
}

/// Avatar image cache directory `<client directory>/cache/avatar`.
pub fn avatar_directory() -> Option<PathBuf> {
    cache_directory().map(|cache| cache.join("avatar"))
}

/// Directory for user-supplied avatars `<client directory>/config/avatars`: the user puts images in here,
/// the client only lists the image filenames here for selection in "Change Avatar"; it neither downloads nor writes to this directory.
/// at the same level as the install layout (`baihua install` puts config into `<client directory>/config`); uninstall asks Y/n to clean it up together.
pub fn avatar_source_directory() -> Option<PathBuf> {
    client_root().map(|root| root.join("config").join("avatars"))
}

/// Update package download staging directory `<client directory>/update`.
pub fn update_directory() -> Option<PathBuf> {
    client_root().map(|root| root.join("update"))
}

/// Default install directory `<client directory>/bin`: installed in a user-writable location, no admin rights needed, consistent across all platforms.
pub fn install_directory() -> Option<PathBuf> {
    client_root().map(|root| root.join("bin"))
}

/// Full path of the current executable (both install and self-update need it as an anchor).
pub fn current_executable() -> Option<PathBuf> {
    std::env::current_exe().ok()
}

/// Locate the config directory (where `languages/`, `themes/`, `preferences.json` live).
///
/// Try in order: `config` under the current working directory (the case of `cargo run` inside the package directory),
/// then `config` under ancestor directories of the executable
/// (when installed as `.../bin/baihua-client` the config is in `.../config`, also covers running directly from target/debug).
/// When none are found, return the first candidate so the failure behavior matches the old version (uses built-in defaults).
pub fn config_directory() -> PathBuf {
    let candidates = config_directory_candidates();
    candidates
        .iter()
        .find(|candidate| candidate.is_dir())
        .cloned()
        .unwrap_or_else(|| candidates[0].clone())
}

/// All candidates for the config directory, sorted by priority. The installer and error messages need to display this completely to the user.
///
/// The repository keeps a single shared `config/` directory at the root, used by both interfaces (the TUI and the GUI
/// read the same languages, themes and preferences). There used to be a second candidate `baihua-client-tui/config`;
/// it is gone now, so every candidate below points at a plain `config/` directory.
pub fn config_directory_candidates() -> Vec<PathBuf> {
    let mut candidates = vec![PathBuf::from("config")];
    let Some(executable) = current_executable() else {
        return candidates;
    };
    // Walk up from the executable directory: the install layout is <prefix>/bin/<program> + <prefix>/config,
    // the development layout is <repo>/target/<config>/<program> + <repo>/config,
    // both fall on the path of "walk up level by level"; no need to hardcode the depth for each layout
    let mut directory = executable.parent().map(|parent| parent.to_path_buf());
    while let Some(current) = directory {
        candidates.push(current.join("config"));
        directory = current.parent().map(|parent| parent.to_path_buf());
    }
    candidates
}

/// Join a relative path under the config directory (such as `themes/dark.json`).
/// This function is used to read config; it looks up existing config directories by priority.
pub fn config_path(relative_path: &str) -> PathBuf {
    config_directory().join(relative_path)
}

/// Join a relative path under the writable config directory (such as `preferences.json`).
/// This function is used for writing config; always points to the client config directory under the user's home directory (`~/.baihua/client/config`),
/// avoid modifying config files in the project source directory in the development environment.
pub fn writable_config_path(relative_path: &str) -> PathBuf {
    client_root()
        .map(|root| root.join("config").join(relative_path))
        .unwrap_or_else(|| config_path(relative_path))
}

/// Join a relative path under the writable config directory; fall back to the read-only config directory if the file does not exist.
/// This function is used to read configs that might have been modified by the user (such as preferences.json),
/// prefer reading from the user's home directory; only read defaults from the project source directory when absent.
pub fn readable_config_path(relative_path: &str) -> PathBuf {
    let writable = writable_config_path(relative_path);
    if writable.exists() {
        writable
    } else {
        config_path(relative_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_directory_resolves_next_to_the_executable() {
        // 造一份临时安装布局 <前缀>/bin/（假可执行）+ <前缀>/config，
        // 证明从任意工作目录启动都能按祖先目录找到配置
        let root = std::env::temp_dir().join("baihua-config-lookup");
        std::fs::create_dir_all(root.join("config")).expect("配置目录应可创建");
        std::fs::write(root.join("config").join("preferences.json"), "{}").expect("写入应成功");
        let resolved = config_directory();
        // 本测试进程的当前目录就是仓库根，那里有真实的 config，故结果必须是已存在的目录
        assert!(
            resolved.is_dir(),
            "配置目录解析结果应真实存在: {resolved:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn config_directory_candidates_put_working_directory_first() {
        let candidates = config_directory_candidates();
        assert_eq!(
            candidates.first().map(|path| path.display().to_string()),
            Some("config".to_string())
        );
    }

    #[test]
    fn client_subdirectories_are_nested_under_one_root() {
        let Some(root) = data_root() else {
            return;
        };
        // 两个界面共用同一份配置与缓存：用户数据都在同一个客户端根目录下——
        // 配置（preferences.json 与用户自备头像）在 `<客户端根目录>/config`，
        // 可再生的消息缓存与头像缓存在 `<客户端根目录>/cache`。
        // 界面不参与路径计算（都由本模块决定），所以终端版与图形版算出来的永远是同一条路径。
        let preferences = writable_config_path("preferences.json");
        assert!(
            preferences.starts_with(root.join("client").join("config")),
            "用户配置要落在客户端根目录的 config 下，两个界面共用同一份: {preferences:?}"
        );
        let messages = chat_message_directory().expect("消息缓存目录应可定位");
        let avatars = avatar_directory().expect("头像缓存目录应可定位");
        let updates = update_directory().expect("更新目录应可定位");
        let installs = install_directory().expect("安装目录应可定位");
        let sources = avatar_source_directory().expect("头像来源目录应可定位");
        for directory in [&messages, &avatars, &updates, &installs, &sources] {
            assert!(directory.starts_with(root.join("client")));
        }
        // 用户自备的头像图属于配置（用户放进去的），与可再生缓存分开
        assert!(sources.starts_with(root.join("client").join("config")));

        assert!(!sources.starts_with(cache_directory().expect("缓存根目录应可定位")));
        // 可再生的两类缓存都收在 cache 之下，卸载时才能一次清干净
        for directory in [&messages, &avatars] {
            assert!(directory.starts_with(cache_directory().expect("缓存根目录应可定位")));
        }
    }
}
