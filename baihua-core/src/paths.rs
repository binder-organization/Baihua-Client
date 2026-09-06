//! 客户端本地目录与资源定位。
//!
//! 目录根与服务端保持一致的约定：优先取环境变量 `BAIHUA_DIR`，否则用用户主目录下的
//! `.baihua`。服务端把数据放在该根目录，客户端统一放在其下的 `client` 子目录，
//! 两端共用同一棵树但不互相覆盖。

use std::path::PathBuf;

/// 数据根目录：`$BAIHUA_DIR` 或 `~/.baihua`。取不到主目录时返回 None（调用方跳过本地存储）。
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

/// 客户端专属目录 `<$BAIHUA_DIR|~/.baihua>/client`。
fn client_root() -> Option<PathBuf> {
    data_root().map(|root| root.join("client"))
}

/// 可再生数据的根 `<客户端目录>/cache`。里面全部是"删了也能重新拿回来"的东西，
/// 卸载时可以选择一并清掉。
pub fn cache_directory() -> Option<PathBuf> {
    client_root().map(|root| root.join("cache"))
}

/// 聊天消息本地缓存目录 `<客户端目录>/cache/chat_msg`。
pub fn chat_message_directory() -> Option<PathBuf> {
    cache_directory().map(|cache| cache.join("chat_msg"))
}

/// 头像图片缓存目录 `<客户端目录>/cache/avatar`。
pub fn avatar_directory() -> Option<PathBuf> {
    cache_directory().map(|cache| cache.join("avatar"))
}

/// 用户自备头像的目录 `<客户端目录>/config/avatars`：用户自己把图片放进去，
/// 客户端只在"修改头像"里列出这里的图片文件名供选择，不下载也不写入这个目录。
/// 与安装布局同级（`baihua install` 把配置装到 `<客户端目录>/config`），卸载按 Y/n 一并询问。
pub fn avatar_source_directory() -> Option<PathBuf> {
    client_root().map(|root| root.join("config").join("avatars"))
}

/// 更新包下载暂存目录 `<客户端目录>/update`。
pub fn update_directory() -> Option<PathBuf> {
    client_root().map(|root| root.join("update"))
}

/// 默认安装目录 `<客户端目录>/bin`：安装在用户可写位置，无需管理员权限，三端一致。
pub fn install_directory() -> Option<PathBuf> {
    client_root().map(|root| root.join("bin"))
}

/// 当前可执行文件的完整路径（安装与自更新都要以它为锚点）。
pub fn current_executable() -> Option<PathBuf> {
    std::env::current_exe().ok()
}

/// 定位配置目录（`languages/`、`themes/`、`preferences.json` 所在处）。
///
/// 依次尝试：当前工作目录下的 `config`（在包目录内 `cargo run` 的情形）、
/// 仓库里的 `baihua-client-tui/config`（在仓库根目录直接跑二进制的开发情形）、
/// 可执行文件各级祖先目录下的 `config` 与 `baihua-client-tui/config`
/// （安装为 `.../bin/baihua-client` 时配置在 `.../config`，也覆盖从 target/debug 直接跑的情形）。
/// 一处都没有时返回首个候选，让读取失败的表现与旧版一致（沿用内置默认值）。
pub fn config_directory() -> PathBuf {
    let candidates = config_directory_candidates();
    candidates
        .iter()
        .find(|candidate| candidate.is_dir())
        .cloned()
        .unwrap_or_else(|| candidates[0].clone())
}

/// 配置目录的全部候选，按优先级排列。安装程序与错误提示需要把它完整展示给用户。
pub fn config_directory_candidates() -> Vec<PathBuf> {
    let mut candidates = vec![
        PathBuf::from("config"),
        PathBuf::from("baihua-client-tui/config"),
    ];
    let Some(executable) = current_executable() else {
        return candidates;
    };
    // 从可执行文件所在目录逐级上溯：安装布局是 <前缀>/bin/<程序> + <前缀>/config，
    // 开发布局是 <仓库>/target/<配置>/<程序> + <仓库>/baihua-client-tui/config，
    // 两种都落在"一层层往上找"这条路径上，不需要为每种布局单独写死深度
    let mut directory = executable.parent().map(|parent| parent.to_path_buf());
    while let Some(current) = directory {
        candidates.push(current.join("config"));
        candidates.push(current.join("baihua-client-tui/config"));
        directory = current.parent().map(|parent| parent.to_path_buf());
    }
    candidates
}

/// 拼出配置目录下某个相对路径（如 `themes/dark.json`）。
/// 此函数用于读取配置，会按优先级查找已存在的配置目录。
pub fn config_path(relative_path: &str) -> PathBuf {
    config_directory().join(relative_path)
}

/// 拼出可写配置目录下某个相对路径（如 `preferences.json`）。
/// 此函数用于写入配置，始终指向用户主目录下的客户端配置目录（`~/.baihua/client/config`），
/// 避免在开发环境下修改项目源码目录中的配置文件。
pub fn writable_config_path(relative_path: &str) -> PathBuf {
    client_root()
        .map(|root| root.join("config").join(relative_path))
        .unwrap_or_else(|| config_path(relative_path))
}

/// 拼出可写配置目录下某个相对路径，如果该文件不存在则回退到只读配置目录。
/// 此函数用于读取可能被用户修改的配置（如 preferences.json），
/// 优先从用户主目录读取，不存在时才从项目源码目录读取默认值。
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
