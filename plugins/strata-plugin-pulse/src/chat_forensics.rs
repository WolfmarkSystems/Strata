//! Desktop chat-application forensics (R-5).
//!
//! Covers three desktop chat apps — Slack, Microsoft Teams (classic),
//! and Discord — from the well-known on-disk locations.
//!
//! Research reference: chat4n6 (MIT) — studied only; implementation
//! written independently.
//!
//! | App     | Path fragment                                    | Format       |
//! |---------|--------------------------------------------------|--------------|
//! | Slack   | `Slack/storage/` — `root-state.db` or `C*-*.db`   | SQLite       |
//! | Teams   | `Microsoft/Teams/storage.db`                     | SQLite       |
//! | Discord | `discord/Local Storage/leveldb/*.ldb` or `*.log` | LevelDB blob |
//!
//! Discord's LevelDB isn't a full schema parse — we carve JSON message
//! fragments via balanced-brace scanning. Keys and structure are
//! Discord-specific (`channel_id`, `author`, `content`, `timestamp`).
//!
//! ## MITRE ATT&CK
//! * **T1552.003** — Credentials / Chat content access on endpoint
//!   (treated uniformly for all three platforms per SPRINT R-5).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OpenFlags};
use std::path::Path;

/// Which desktop chat app produced the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatApp {
    Slack,
    Teams,
    Discord,
}

impl ChatApp {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChatApp::Slack => "Slack",
            ChatApp::Teams => "Teams",
            ChatApp::Discord => "Discord",
        }
    }
}

/// Common typed chat record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatMessage {
    pub app: ChatApp,
    /// Channel / conversation ID when known.
    pub channel_id: Option<String>,
    /// Sender user ID or handle.
    pub sender: Option<String>,
    /// Plain text body.
    pub content: String,
    /// Timestamp if recoverable (UTC).
    pub timestamp: Option<DateTime<Utc>>,
}

/// Slack `root-state.db` / `C{workspace}-{channel}.db` reader. Looks
/// for a `messages` table; yields every row.
pub fn parse_slack(path: &Path) -> Vec<ChatMessage> {
    let Some(conn) = open_ro(path) else {
        return Vec::new();
    };
    let sql = "SELECT ts, user_id, text FROM messages ORDER BY ts ASC";
    let Ok(mut stmt) = conn.prepare(sql) else {
        return Vec::new();
    };
    let rows = stmt.query_map([], |row| {
        let ts: Option<f64> = row.get(0)?;
        let user_id: Option<String> = row.get(1)?;
        let text: Option<String> = row.get(2)?;
        Ok((ts, user_id, text))
    });
    let mut out = Vec::new();
    if let Ok(rows) = rows {
        for r in rows.flatten() {
            let (ts, user, text) = r;
            out.push(ChatMessage {
                app: ChatApp::Slack,
                channel_id: None,
                sender: user,
                content: text.unwrap_or_default(),
                timestamp: ts.and_then(|t| {
                    let secs = t.trunc() as i64;
                    let nanos = ((t - t.trunc()) * 1_000_000_000.0) as u32;
                    DateTime::<Utc>::from_timestamp(secs, nanos)
                }),
            });
        }
    }
    out
}

/// Teams classic `storage.db` reader. Reads the `messages` table if
/// present and joins to `conversations` for display_name.
pub fn parse_teams(path: &Path) -> Vec<ChatMessage> {
    let Some(conn) = open_ro(path) else {
        return Vec::new();
    };
    let sql = "SELECT m.originalarrivaltime, m.content, m.messagetype, c.id, c.creator \
               FROM messages m \
               LEFT JOIN conversations c ON c.id = m.conversation_id \
               ORDER BY m.originalarrivaltime ASC";
    let Ok(mut stmt) = conn.prepare(sql) else {
        return Vec::new();
    };
    let rows = stmt.query_map([], |row| {
        let ts: Option<String> = row.get(0)?;
        let content: Option<String> = row.get(1)?;
        let _mt: Option<String> = row.get(2)?;
        let chan: Option<String> = row.get(3)?;
        let creator: Option<String> = row.get(4)?;
        Ok((ts, content, chan, creator))
    });
    let mut out = Vec::new();
    if let Ok(rows) = rows {
        for r in rows.flatten() {
            let (ts, content, chan, creator) = r;
            out.push(ChatMessage {
                app: ChatApp::Teams,
                channel_id: chan,
                sender: creator,
                content: content.unwrap_or_default(),
                timestamp: ts
                    .as_deref()
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                    .map(|dt| dt.with_timezone(&Utc)),
            });
        }
    }
    out
}

/// Discord LevelDB fragment carver. Pulls JSON objects containing a
/// `content` key and a `timestamp` key; tolerant of truncation.
pub fn parse_discord(bytes: &[u8]) -> Vec<ChatMessage> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'{' {
            i += 1;
            continue;
        }
        // Find the matching closing brace with a depth counter; bail at
        // 16 KiB to avoid runaway.
        let mut depth = 0i32;
        let mut end = i;
        let limit = (i + 16_384).min(bytes.len());
        while end < limit {
            match bytes[end] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            end += 1;
        }
        if depth != 0 || end >= bytes.len() {
            i += 1;
            continue;
        }
        let candidate = &bytes[i..=end];
        if let Ok(s) = std::str::from_utf8(candidate) {
            if s.contains("\"content\"") && s.contains("\"timestamp\"") {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
                    let channel_id = v
                        .get("channel_id")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string());
                    let sender = v
                        .get("author")
                        .and_then(|x| x.get("id"))
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string())
                        .or_else(|| {
                            v.get("author_id")
                                .and_then(|x| x.as_str())
                                .map(|s| s.to_string())
                        });
                    let content = v
                        .get("content")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    let timestamp = v
                        .get("timestamp")
                        .and_then(|x| x.as_str())
                        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                        .map(|dt| dt.with_timezone(&Utc));
                    out.push(ChatMessage {
                        app: ChatApp::Discord,
                        channel_id,
                        sender,
                        content,
                        timestamp,
                    });
                }
            }
        }
        i = end + 1;
    }
    out
}

/// Filename-based classifier. Returns the app + parse mode when a path
/// is one of the supported desktop locations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatSource {
    SlackDb,
    TeamsDb,
    DiscordLdb,
}

pub fn classify(path: &Path) -> Option<ChatSource> {
    // Normalise separators so the same logic handles POSIX and Windows
    // paths regardless of host OS.
    let normalised = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let name = normalised.rsplit('/').next().unwrap_or("");
    if normalised.contains("slack/storage/")
        && (name == "root-state.db"
            || (name.starts_with('c') && name.ends_with(".db") && name.contains('-')))
    {
        return Some(ChatSource::SlackDb);
    }
    if normalised.contains("microsoft/teams/") && name == "storage.db" {
        return Some(ChatSource::TeamsDb);
    }
    if normalised.contains("discord/local storage/leveldb/")
        && (name.ends_with(".ldb") || name.ends_with(".log"))
    {
        return Some(ChatSource::DiscordLdb);
    }
    None
}

fn open_ro(path: &Path) -> Option<Connection> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn classify_routes_all_three_sources() {
        assert_eq!(
            classify(Path::new(
                "/Users/me/Library/Application Support/Slack/storage/root-state.db"
            )),
            Some(ChatSource::SlackDb)
        );
        assert_eq!(
            classify(Path::new(
                "C:\\Users\\me\\AppData\\Roaming\\Microsoft\\Teams\\storage.db"
            )),
            Some(ChatSource::TeamsDb)
        );
        assert_eq!(
            classify(Path::new(
                "/Users/me/Library/Application Support/discord/Local Storage/leveldb/000003.ldb"
            )),
            Some(ChatSource::DiscordLdb)
        );
        assert!(classify(Path::new("/tmp/random.db")).is_none());
    }

    #[test]
    fn parse_slack_extracts_messages() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("root-state.db");
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch("CREATE TABLE messages (ts REAL, user_id TEXT, text TEXT);")
            .expect("schema");
        conn.execute(
            "INSERT INTO messages VALUES (1717243200.5, 'U123', 'hello slack')",
            [],
        )
        .expect("insert");
        drop(conn);
        let msgs = parse_slack(&path);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, "hello slack");
        assert_eq!(msgs[0].sender.as_deref(), Some("U123"));
        assert_eq!(
            msgs[0].timestamp.map(|d| d.timestamp()),
            Some(1_717_243_200)
        );
    }

    #[test]
    fn parse_teams_joins_conversations() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("storage.db");
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch(
            "CREATE TABLE conversations (id TEXT, creator TEXT, create_time INTEGER, display_name TEXT); \
             CREATE TABLE messages (originalarrivaltime TEXT, content TEXT, messagetype TEXT, conversation_id TEXT);",
        )
        .expect("schema");
        conn.execute(
            "INSERT INTO conversations VALUES ('conv-1', 'alice@x.test', 0, 'General')",
            [],
        )
        .expect("conv");
        conn.execute(
            "INSERT INTO messages VALUES ('2024-06-01T12:00:00Z', 'Team hello', 'Text', 'conv-1')",
            [],
        )
        .expect("msg");
        drop(conn);
        let msgs = parse_teams(&path);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].channel_id.as_deref(), Some("conv-1"));
        assert_eq!(msgs[0].sender.as_deref(), Some("alice@x.test"));
        assert_eq!(msgs[0].content, "Team hello");
        assert_eq!(
            msgs[0].timestamp.map(|d| d.timestamp()),
            Some(1_717_243_200)
        );
    }

    #[test]
    fn parse_discord_carves_json_fragments() {
        let mut blob = Vec::new();
        blob.extend_from_slice(b"random leveldb prelude ");
        blob.extend_from_slice(br#"{"channel_id":"C-1","author":{"id":"U-1"},"content":"hi discord","timestamp":"2024-06-01T12:00:00Z"}"#);
        blob.extend_from_slice(b" padding ");
        blob.extend_from_slice(br#"{"channel_id":"C-2","author":{"id":"U-2"},"content":"another","timestamp":"2024-06-01T12:05:00Z"}"#);
        let msgs = parse_discord(&blob);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].channel_id.as_deref(), Some("C-1"));
        assert_eq!(msgs[0].content, "hi discord");
        assert_eq!(msgs[0].sender.as_deref(), Some("U-1"));
        assert_eq!(
            msgs[1].timestamp.map(|d| d.timestamp()),
            Some(1_717_243_500)
        );
    }

    #[test]
    fn parse_discord_empty_when_no_fragments() {
        assert!(parse_discord(b"no braces here").is_empty());
    }
}
