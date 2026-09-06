//! 聊天消息本地缓存。
//!
//! 落盘位置与服务端同一目录树下的客户端缓存子目录：
//! `<$BAIHUA_DIR|~/.baihua>/client/cache/chat_msg/<用户 ID>/<房间 ID>.json`，
//! 按用户隔离，避免同一台机器上多账号互相看到对方的聊天记录。
//!
//! 缓存边界（安全前提）：只缓存未加密房间的消息。端到端加密私聊的明文只在内存里存在，
//! 会话结束后服务端也只留密文，把解密结果写到磁盘会让"端到端"退化成"本机可读"，
//! 因此加密房间一律不写入、不读取，退出登录时也不会为它们建文件。
//!
//! 完整性：每个房间的文件同时记录服务端的更早消息游标 `older_cursor` 与 `has_more`，
//! 切回房间时先把缓存整体载入显示，再用服务端最新一页按消息 ID 合并（只增不减、按时间排序），
//! 因此既不必重复拉取已看过的历史，也不会因为只拉一页而丢掉本地已有的更早消息。

use crate::api::MessageInfo;
use serde::{Deserialize, Serialize};

/// 单个房间的缓存文件内容：消息列表加上恢复分页所需的游标信息。
#[derive(Debug, Serialize, Deserialize)]
struct CachedRoom {
    /// 缓存格式版本，格式变化时旧文件直接作废而不是强行解析
    version: u32,
    room_id: String,
    /// 已缓存的最早一条消息的服务端 ID（服务端 before 游标），None 表示本地已握有全部历史
    older_cursor: Option<String>,
    /// 服务端是否仍报告有更早消息可拉
    has_more: bool,
    /// 落盘时刻（Unix 秒），用于排查缓存新旧
    saved_at: i64,
    messages: Vec<MessageInfo>,
}

/// 一个账号的消息缓存。目录不可用（拿不到主目录、磁盘只读）时不创建实例，调用方按无缓存处理。
#[derive(Debug, Clone)]
pub struct ChatCache {
    directory: std::path::PathBuf,
}

impl ChatCache {
    /// 为指定用户打开缓存目录（不存在则创建）。用户 ID 为空或目录无法建立时返回 None。
    pub fn open(user_id: &str) -> Option<Self> {
        if user_id.is_empty() {
            return None;
        }
        let directory = crate::paths::chat_message_directory()?.join(safe_file_stem(user_id));
        if std::fs::create_dir_all(&directory).is_err() {
            return None;
        }
        Some(Self { directory })
    }

    /// 在指定根目录下为某用户打开缓存目录。供测试与自定义存储位置的调用方使用，
    /// 语义与 `open` 一致，只是不从环境变量与主目录推导根路径。
    pub fn open_in(user_id: &str, root: &std::path::Path) -> Self {
        let directory = root.join(safe_file_stem(user_id));
        let _ = std::fs::create_dir_all(&directory);
        Self { directory }
    }

    fn file_path(&self, room_id: &str) -> std::path::PathBuf {
        self.directory
            .join(format!("{}.json", safe_file_stem(room_id)))
    }

    /// 读取某房间的缓存；文件缺失、损坏、版本不符或房间为空时返回 None。
    pub fn load_room(&self, room_id: &str) -> Option<CachedMessages> {
        let content = std::fs::read_to_string(self.file_path(room_id)).ok()?;
        let cached: CachedRoom = serde_json::from_str(&content).ok()?;
        if cached.version != 1 || cached.room_id != room_id || cached.messages.is_empty() {
            return None;
        }
        Some(CachedMessages {
            messages: cached.messages,
            older_cursor: cached.older_cursor,
            has_more: cached.has_more,
        })
    }

    /// 整房写入（切房加载、翻页、全量搜索之后调用）。消息为空时删除文件而不是留个空壳。
    pub fn store_room(
        &self,
        room_id: &str,
        messages: &[MessageInfo],
        older_cursor: Option<&str>,
        has_more: bool,
    ) {
        if messages.is_empty() {
            self.forget_room(room_id);
            return;
        }
        let mut ordered = merge_by_id(messages, &[]);
        sort_messages(&mut ordered);
        // 单房间只保留最近的这部分消息，超出的最旧部分丢弃（游标仍指向服务端，可再次拉回）
        if ordered.len() > 2000 {
            let excess = ordered.len() - 2000;
            ordered.drain(0..excess);
        }
        let cached = CachedRoom {
            version: 1,
            room_id: room_id.to_string(),
            older_cursor: older_cursor.map(|cursor| cursor.to_string()),
            has_more,
            saved_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_secs() as i64)
                .unwrap_or(0),
            messages: ordered,
        };
        let Ok(serialized) = serde_json::to_string(&cached) else {
            return;
        };
        let _ = std::fs::write(self.file_path(room_id), serialized);
    }

    /// 追加少量消息（实时收到或自己发出）：与已有缓存按 ID 合并，避免整文件重写时丢历史。
    pub fn append_messages(&self, room_id: &str, messages: &[MessageInfo]) {
        if messages.is_empty() {
            return;
        }
        let cached = self.load_room(room_id);
        let existing: Vec<MessageInfo> = cached
            .as_ref()
            .map(|cached| cached.messages.clone())
            .unwrap_or_default();
        let existing_cursor = cached
            .as_ref()
            .and_then(|cached| cached.older_cursor.clone());
        let existing_has_more = cached.map(|cached| cached.has_more).unwrap_or(true);
        let merged = merge_by_id(&existing, messages);
        self.store_room(
            room_id,
            &merged,
            existing_cursor.as_deref(),
            existing_has_more,
        );
    }

    /// 删除某房间缓存（被移出房间、主动退房、本地关闭私聊时调用）。
    pub fn forget_room(&self, room_id: &str) {
        let path = self.file_path(room_id);
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
    }

    /// 清空当前账号的全部缓存（注销账户时调用，绝不留残余）。
    pub fn clear_all(&self) {
        if let Ok(entries) = std::fs::read_dir(&self.directory) {
            for entry in entries.flatten() {
                if entry
                    .path()
                    .extension()
                    .map(|ext| ext == "json")
                    .unwrap_or(false)
                {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }
}

/// `load_room` 的返回视图：缓存的消息与恢复分页所需的游标。
#[derive(Debug, Clone)]
pub struct CachedMessages {
    pub messages: Vec<MessageInfo>,
    pub older_cursor: Option<String>,
    pub has_more: bool,
}

/// 把两批消息按 ID 合并成一批：已有的优先保留（加密私聊里本地是解密后的明文，
/// 服务端回的是密文占位），新出现的条目追加进来。
fn merge_by_id(existing: &[MessageInfo], incoming: &[MessageInfo]) -> Vec<MessageInfo> {
    let mut merged: Vec<MessageInfo> = Vec::with_capacity(existing.len() + incoming.len());
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for message in existing.iter().chain(incoming.iter()) {
        if seen.insert(message.id.as_str()) {
            merged.push(message.clone());
        }
    }
    merged
}

/// 按创建时间升序排列；时间相同的按服务端 ID（UUIDv7 本身单调）兜底，保证显示顺序稳定。
fn sort_messages(messages: &mut [MessageInfo]) {
    messages
        .sort_by(|left, right| (&left.created_at, &left.id).cmp(&(&right.created_at, &right.id)));
}

/// 把任意字符串压成可安全用作文件名的片段：UUID 与房间 ID 原样通过，
/// 其余字符（含路径分隔符）替换为下划线，防止越出缓存目录。
fn safe_file_stem(text: &str) -> String {
    text.chars()
        .map(|character| match character {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => character,
            _ => '_',
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(id: &str, room_id: &str, created_at: &str, content: &str) -> MessageInfo {
        MessageInfo {
            id: id.to_string(),
            room_id: room_id.to_string(),
            sender_id: "sender".to_string(),
            content: content.to_string(),
            created_at: created_at.to_string(),
        }
    }

    fn temporary_cache(label: &str) -> ChatCache {
        let directory = std::env::temp_dir().join(format!("baihua-cache-{label}"));
        std::fs::create_dir_all(&directory).expect("临时缓存目录应可创建");
        ChatCache { directory }
    }

    #[test]
    fn merge_keeps_existing_copy_of_duplicated_message_ids() {
        let existing = vec![message("1", "room", "2026-01-01T00:00:00Z", "本地明文")];
        let incoming = vec![
            message("1", "room", "2026-01-01T00:00:00Z", "服务端密文占位"),
            message("2", "room", "2026-01-01T00:01:00Z", "新消息"),
        ];
        let merged = merge_by_id(&existing, &incoming);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].content, "本地明文");
        assert_eq!(merged[1].id, "2");
    }

    #[test]
    fn sorting_orders_by_creation_time_then_identifier() {
        let mut messages = vec![
            message("b", "room", "2026-01-02T00:00:00Z", "后"),
            message("a", "room", "2026-01-01T00:00:00Z", "先"),
        ];
        sort_messages(&mut messages);
        assert_eq!(messages[0].content, "先");
        assert_eq!(messages[1].content, "后");
    }

    #[test]
    fn cached_room_round_trips_with_paging_cursor() {
        let cache = temporary_cache("round-trip");
        let room_id = "room-round-trip";
        cache.store_room(
            room_id,
            &[
                message("2", room_id, "2026-01-02T00:00:00Z", "第二条"),
                message("1", room_id, "2026-01-01T00:00:00Z", "第一条"),
            ],
            Some("1"),
            true,
        );
        let cached = cache.load_room(room_id).expect("应能读回刚写入的缓存");
        assert_eq!(cached.messages.len(), 2);
        assert_eq!(cached.messages[0].content, "第一条");
        assert_eq!(cached.older_cursor.as_deref(), Some("1"));
        assert!(cached.has_more);
        cache.forget_room(room_id);
        assert!(cache.load_room(room_id).is_none());
        let _ = std::fs::remove_dir_all(&cache.directory);
    }

    #[test]
    fn appending_preserves_older_cached_messages() {
        let cache = temporary_cache("append");
        let room_id = "room-append";
        cache.store_room(
            room_id,
            &[message("1", room_id, "2026-01-01T00:00:00Z", "旧")],
            None,
            false,
        );
        cache.append_messages(
            room_id,
            &[message("2", room_id, "2026-01-02T00:00:00Z", "新")],
        );
        let cached = cache.load_room(room_id).expect("追加后仍应读到缓存");
        assert_eq!(cached.messages.len(), 2);
        assert_eq!(cached.older_cursor, None);
        assert!(!cached.has_more);
        let _ = std::fs::remove_dir_all(&cache.directory);
    }

    #[test]
    fn file_stem_neutralizes_path_separators() {
        assert_eq!(
            safe_file_stem("0192f8a1-2b3c-7d4e-8f90-abcdef012345").len(),
            36
        );
        assert!(!safe_file_stem("../../etc/passwd").contains('/'));
        assert!(!safe_file_stem("../../etc/passwd").contains('.'));
    }
}
