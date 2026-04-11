//! Telegram Channels — subscribed channels and admin roles.
//!
//! Source path: `/data/data/org.telegram.messenger/files/cache4.db`.
//!
//! Schema note: complements `telegram.rs` (which parses messages and
//! dialogs) by enumerating subscribed channels from `chats` table.
//! Channels are a subset of dialogs where the dialog ID is a broadcast
//! channel (negative ID with `-100` prefix convention).

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "org.telegram.messenger/files/cache4.db",
    "org.telegram.messenger/files/cache",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "chats") {
        out.extend(read_chats(&conn, path));
    }
    if table_exists(&conn, "channel_users_v2") {
        out.extend(read_channel_members(&conn, path));
    }
    out
}

fn read_chats(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    // uid is the chat ID; positive = user, -100xxx = channel, -xxx = group
    let sql = "SELECT uid, name FROM chats ORDER BY uid LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (uid, name) in rows.flatten() {
        let uid = uid.unwrap_or(0);
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let kind = classify_chat(uid);
        let title = format!("Telegram {}: {}", kind, name);
        let detail = format!(
            "Telegram chat uid={} name='{}' kind='{}'",
            uid, name, kind
        );
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "Telegram Channel",
            title,
            detail,
            path,
            None,
            ForensicValue::High,
            false,
        ));
    }
    out
}

fn read_channel_members(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT did, uid, data FROM channel_users_v2 LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<Vec<u8>>>(2).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (did, uid, data) in rows.flatten() {
        let did = did.unwrap_or(0);
        let uid = uid.unwrap_or(0);
        let data_len = data.as_ref().map(|d| d.len()).unwrap_or(0);
        let title = format!("Telegram channel member: channel={} user={}", did, uid);
        let detail = format!(
            "Telegram channel_users_v2 did={} uid={} data_bytes={}",
            did, uid, data_len
        );
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "Telegram Channel Member",
            title,
            detail,
            path,
            None,
            ForensicValue::Medium,
            false,
        ));
    }
    out
}

/// Classify a Telegram chat ID into kind.
///
/// Telegram uses the convention:
/// - Positive ID: private chat with a user
/// - Negative ID starting with -100: broadcast channel or supergroup
/// - Other negative ID: basic group
fn classify_chat(uid: i64) -> &'static str {
    if uid > 0 {
        "private"
    } else if uid <= -1_000_000_000_000 {
        "channel"
    } else {
        "group"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn make_db() -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE chats (
                uid INTEGER,
                name TEXT
            );
            INSERT INTO chats VALUES(500001,'Alice');
            INSERT INTO chats VALUES(-1001234567890,'Crypto News');
            INSERT INTO chats VALUES(-12345,'Book Club');
            CREATE TABLE channel_users_v2 (
                did INTEGER,
                uid INTEGER,
                data BLOB
            );
            INSERT INTO channel_users_v2 VALUES(-1001234567890,12345,X'0102');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_chats_and_members() {
        let db = make_db();
        let r = parse(db.path());
        let chats: Vec<_> = r.iter().filter(|a| a.subcategory == "Telegram Channel").collect();
        let members: Vec<_> = r.iter().filter(|a| a.subcategory == "Telegram Channel Member").collect();
        assert_eq!(chats.len(), 3);
        assert_eq!(members.len(), 1);
    }

    #[test]
    fn chat_kinds_classified() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("Telegram private: Alice")));
        assert!(r.iter().any(|a| a.title.contains("Telegram channel: Crypto News")));
        assert!(r.iter().any(|a| a.title.contains("Telegram group: Book Club")));
    }

    #[test]
    fn channel_classifier_boundaries() {
        assert_eq!(classify_chat(500001), "private");
        assert_eq!(classify_chat(-1_001_234_567_890), "channel");
        assert_eq!(classify_chat(-12345), "group");
    }

    #[test]
    fn missing_table_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE unrelated (id INTEGER);").unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}
