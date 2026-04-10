//! Discord — Android chat message extraction.
//!
//! ALEAPP reference: `scripts/artifacts/discordChats.py`. Source path:
//! `/data/data/com.discord/databases/discord_database*.db`.
//!
//! Table: `messages` (or `messages0` in KV-storage variant).

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.discord/databases/",
    "com.discord/files/kv-storage/",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if table_exists(&conn, "messages") {
        read_messages(&conn, path, "messages")
    } else if table_exists(&conn, "messages0") {
        read_messages(&conn, path, "messages0")
    } else {
        Vec::new()
    }
}

fn read_messages(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT author_id, channel_id, content, timestamp \
         FROM {} WHERE content IS NOT NULL AND content != '' \
         ORDER BY timestamp DESC LIMIT 10000",
        table
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (author, channel, content, ts_ms) in rows.flatten() {
        let author = author.unwrap_or_else(|| "(unknown)".to_string());
        let channel = channel.unwrap_or_else(|| "(unknown)".to_string());
        let body = content.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let preview: String = body.chars().take(120).collect();
        let title = format!("Discord {}: {}", author, preview);
        let detail = format!(
            "Discord message author='{}' channel='{}' body='{}'",
            author, channel, body
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Discord Message",
            title,
            detail,
            path,
            ts,
            ForensicValue::High,
            false,
        ));
    }
    out
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
            CREATE TABLE messages (
                _id INTEGER PRIMARY KEY,
                author_id TEXT,
                channel_id TEXT,
                content TEXT,
                timestamp INTEGER
            );
            INSERT INTO messages VALUES(1,'user123','ch456','Hello Discord!',1609459200000);
            INSERT INTO messages VALUES(2,'user789','ch456','What server is this?',1609459300000);
            INSERT INTO messages VALUES(3,'user123','ch999','DM message',1609459400000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_three_messages() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|a| a.subcategory == "Discord Message"));
    }

    #[test]
    fn author_and_channel_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("author='user123'")));
        assert!(r.iter().any(|a| a.detail.contains("channel='ch456'")));
    }

    #[test]
    fn body_appears_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("Hello Discord!")));
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
