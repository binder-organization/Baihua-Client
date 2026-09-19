//! Local cache for chat messages.
//!
//! The on-disk location is a client cache subdirectory under the same directory tree as the server:
//! `<$BAIHUA_DIR|~/.baihua>/client/cache/chat_msg/<用户 ID>/<房间 ID>.json`，
//! Isolated by user to prevent multiple accounts on the same machine from seeing each other's chat records.
//!
//! Cache boundary (security premise): only cache messages from unencrypted rooms. Plaintext for end-to-end encrypted private chats exists only in memory,
//! after the session ends the server also keeps only ciphertext; writing the decryption result to disk would degrade "end-to-end" to "readable on this machine",
//! so encrypted rooms are never written or read, and no files are created for them on logout.
//!
//! Integrity: each room's file records both the server's older message cursor `older_cursor` and `has_more`,
//! when returning to a room, the full cache is loaded and displayed first, then merged with the server's latest page by message ID (only increasing, sorted by time),
//! so there is no need to re-fetch already-seen history, and no local earlier messages are lost from fetching only one page.

use crate::api::MessageInfo;
use serde::{Deserialize, Serialize};

/// The cache file content for a single room: message list plus cursor info for restoring pagination.
#[derive(Debug, Serialize, Deserialize)]
struct CachedRoom {
    /// Cache format version; when the format changes, old files are invalidated rather than forcibly parsed
    version: u32,
    room_id: String,
    /// The server ID of the earliest cached message (server before cursor); None means the local side already has all history
    older_cursor: Option<String>,
    /// Whether the server still reports having older messages to fetch
    has_more: bool,
    /// On-disk timestamp (Unix seconds), used for debugging cache freshness
    saved_at: i64,
    messages: Vec<MessageInfo>,
}

/// Message cache for one account. When the directory is unavailable (cannot get home directory, disk read-only), no instance is created and the caller treats it as having no cache.
#[derive(Debug, Clone)]
pub struct ChatCache {
    directory: std::path::PathBuf,
}

impl ChatCache {
    /// Open the cache directory for a specified user (create if not exists). Returns None when the user ID is empty or the directory cannot be established.
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

    /// Open a cache directory for a user under a specified root. Used by tests and callers with custom storage locations,
    /// Same semantics as `open`, except the root path is not derived from environment variables and the home directory.
    pub fn open_in(user_id: &str, root: &std::path::Path) -> Self {
        let directory = root.join(safe_file_stem(user_id));
        let _ = std::fs::create_dir_all(&directory);
        Self { directory }
    }

    fn file_path(&self, room_id: &str) -> std::path::PathBuf {
        self.directory
            .join(format!("{}.json", safe_file_stem(room_id)))
    }

    /// Read the cache for a room; returns None when the file is missing, corrupted, version mismatch, or the room is empty.
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

    /// Write the entire room (called after room switching, pagination, full search). Deletes the file when messages are empty instead of leaving an empty shell.
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
        // Keep only the most recent portion for a single room; discard the oldest excess (the cursor still points to the server, so it can be fetched again)
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

    /// Append a few messages (received in real-time or sent by self): merge with the existing cache by ID to avoid losing history when rewriting the whole file.
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

    /// Delete a room's cache (called when removed from the room, voluntarily left, or a private chat is locally closed).
    pub fn forget_room(&self, room_id: &str) {
        let path = self.file_path(room_id);
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
    }

    /// Clear all caches for the current account (called on logout; leave no residue).
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

/// Return view of `load_room`: cached messages plus cursor for restoring pagination.
#[derive(Debug, Clone)]
pub struct CachedMessages {
    pub messages: Vec<MessageInfo>,
    pub older_cursor: Option<String>,
    pub has_more: bool,
}

/// Merge two batches of messages by ID into one: existing ones are kept first (in encrypted private chats, the local side has decrypted plaintext,
/// the server returns a ciphertext placeholder), newly appearing entries are appended.
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

/// Sort by creation time ascending; ties broken by server ID (UUIDv7 is itself monotonically increasing), ensuring stable display order.
fn sort_messages(messages: &mut [MessageInfo]) {
    messages
        .sort_by(|left, right| (&left.created_at, &left.id).cmp(&(&right.created_at, &right.id)));
}

/// Compress any string into a fragment safe for use as a filename: UUIDs and room IDs pass through as-is,
/// other characters (including path separators) are replaced with underscores to prevent escaping the cache directory.
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
