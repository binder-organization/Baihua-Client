//! Chat command table.
//!
//! Both the TUI and GUI share the same table: command names and their language key names are all here,
//! input completion, command panel, and "unknown command" prompts all read from it, so both sides won't diverge by writing separate versions.
//!
//! This module is "shared code": it only deals with command names and language key names, not recognizing any interface type
//! (no egui/epaint/ratatui), so anyone can use it and it's easy to test separately.

/// 内置聊天命令表，元素为 (命令名, 描述文案的语言键名)，顺序即界面上的展示顺序。
///
/// 扩展新命令：在此追加条目，再在各界面执行命令的 match 里增加分支。
/// `exit` 与 `quit` 是同一个动作的两个写法，两条都列出来供补全用。
pub fn chat_commands() -> Vec<(&'static str, &'static str)> {
    vec![
        ("quit", "command_quit"),
        ("exit", "command_quit"),
        ("quit_group", "command_quit_group"),
        ("kick", "command_kick"),
        ("info", "command_info"),
        ("list_users", "command_list_users"),
        ("search_users", "command_search_users"),
        ("profile", "command_profile"),
        ("language", "command_language"),
        ("appearance", "command_appearance"),
        ("update", "command_update"),
        ("logout", "command_logout"),
        ("server_address", "command_server_address"),
        ("add_member", "command_add_member"),
        ("mute", "command_mute"),
        ("login", "command_login"),
        ("register", "command_register"),
    ]
}

/// 按已经输入的命令名前缀过滤出可补全的条目。
/// 前缀为空（只敲了一个斜杠）时返回整张表，让用户先看见有哪些命令。
pub fn command_completions(prefix: &str) -> Vec<(&'static str, &'static str)> {
    chat_commands()
        .into_iter()
        .filter(|(name, _)| name.starts_with(prefix))
        .collect()
}

/// 这个命令要不要跟参数。
///
/// 要参数的命令（如 `/kick 用户名`）在界面上点一下只把 `/命令名 ` 补进输入框，
/// 由用户补完再回车；不要参数的命令点一下就直接执行。
/// `/profile` 与 `/mute` 的参数是可选的，所以算"不要参数"：点一下先执行最常用的那一种。
pub fn command_takes_argument(name: &str) -> bool {
    matches!(
        name,
        "kick" | "search_users" | "add_member" | "language" | "appearance" | "server_address"
    )
}

/// 这个命令名是不是表里的完整已知命令。
///
/// 用来区分"命令名已经敲全了"与"还在补全中"：敲全了按回车就是执行，
/// 没敲全时按回车是先把补全提示里选中的那条补进输入框（终端版与图形版同一套）。
pub fn is_known_command(name: &str) -> bool {
    chat_commands().iter().any(|(known, _)| *known == name)
}

/// 命令名后面第一个空格之前的部分：输入框里正在敲的是哪条命令。
/// 输入不是命令（不以斜杠开头，或已经敲完命令名开始写参数）时返回 None。
pub fn pending_command_prefix(draft: &str) -> Option<&str> {
    let rest = draft.strip_prefix('/')?;
    if rest.contains(char::is_whitespace) {
        return None;
    }
    Some(rest)
}

/// 未登录时也允许用的命令（登录、注册、退出登录与不依赖账号的本地开关）。
/// 其余命令在未登录时会被拒绝并提示先登录。
pub fn command_allowed_signed_out(name: &str) -> bool {
    matches!(
        name,
        "login"
            | "register"
            | "logout"
            | "quit"
            | "exit"
            | "update"
            | "language"
            | "appearance"
            | "server_address"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 命令表不许有重复命令名，否则补全列表里会出现两条一样的
    #[test]
    fn command_names_are_unique() {
        let commands = chat_commands();
        assert!(!commands.is_empty(), "命令表不能是空的");
        let mut seen: Vec<&str> = Vec::new();
        for (name, _) in &commands {
            assert!(!seen.contains(name), "命令表里出现了重复的命令 {name}");
            assert!(
                !name.starts_with('/') && !name.contains(char::is_whitespace),
                "命令名写成裸名，不带斜杠也不带空格，实际 {name:?}"
            );
            seen.push(name);
        }
    }

    /// 前缀补全按前缀过滤，空前缀给出全部
    #[test]
    fn completions_filter_by_prefix() {
        assert_eq!(command_completions("").len(), chat_commands().len());
        let filtered = command_completions("li");
        assert_eq!(
            filtered.len(),
            1,
            "以 li 开头的命令只有一条，实际 {filtered:?}"
        );
        assert_eq!(filtered[0].0, "list_users");
        assert!(command_completions("不存在的命令").is_empty());
    }

    /// 只有"正在敲命令名"时才补全，敲完命令名开始写参数就不再补全
    #[test]
    fn pending_prefix_stops_after_the_command_name() {
        assert_eq!(pending_command_prefix("/ki"), Some("ki"));
        assert_eq!(pending_command_prefix("/"), Some(""));
        assert_eq!(pending_command_prefix("/kick alice"), None);
        assert_eq!(pending_command_prefix("普通消息"), None);
    }
}
