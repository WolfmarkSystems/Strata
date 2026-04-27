//! Facebook Messenger — Android message and call extraction.
//!
//! ALEAPP reference: `scripts/artifacts/FacebookMessenger.py`. Source paths:
//! - `/data/data/com.facebook.orca/databases/threads_db2` (legacy)
//! - `/data/data/com.facebook.orca/databases/msys_database_*` (newer)
//!
//! Key tables: `messages`, `threads`, `thread_users`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.facebook.orca/databases/threads_db2",
    "com.facebook.orca/databases/msys_database",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "messages") {
        out.extend(read_messages(&conn, path));
    }
    out
}

fn read_messages(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    // threads_db2 schema uses timestamp_ms; msys uses timestamp_ms too
    let sql = "SELECT sender_key, thread_key, text, timestamp_ms, \
               snippet \
               FROM messages WHERE text IS NOT NULL \
               ORDER BY timestamp_ms DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        // Try alternate column names for msys_database
        Err(_) => {
            return read_messages_msys(conn, path);
        }
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (sender, thread, text, ts_ms, snippet) in rows.flatten() {
        let sender = sender.unwrap_or_else(|| "(unknown)".to_string());
        let thread = thread.unwrap_or_else(|| "(unknown)".to_string());
        let body = text.unwrap_or_else(|| snippet.unwrap_or_default());
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let preview: String = body.chars().take(120).collect();
        let title = format!("Messenger {}: {}", sender, preview);
        let detail = format!(
            "Facebook Messenger sender='{}' thread='{}' body='{}'",
            sender, thread, body
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Facebook Messenger",
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

fn read_messages_msys(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT sender_id, thread_key, text, timestamp_ms \
               FROM messages WHERE text IS NOT NULL \
               ORDER BY timestamp_ms DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
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
    for (sender, thread, text, ts_ms) in rows.flatten() {
        let sender = sender.unwrap_or_else(|| "(unknown)".to_string());
        let thread = thread.unwrap_or_else(|| "(unknown)".to_string());
        let body = text.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let preview: String = body.chars().take(120).collect();
        let title = format!("Messenger {}: {}", sender, preview);
        let detail = format!(
            "Facebook Messenger sender='{}' thread='{}' body='{}'",
            sender, thread, body
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Facebook Messenger",
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
                sender_key TEXT,
                thread_key TEXT,
                text TEXT,
                timestamp_ms INTEGER,
                snippet TEXT
            );
            INSERT INTO messages VALUES(1,'fbid:100001','thread:2001','Hey what''s up?',1609459200000,NULL);
            INSERT INTO messages VALUES(2,'fbid:100002','thread:2001','Not much, you?',1609459300000,NULL);
            INSERT INTO messages VALUES(3,'fbid:100001','thread:2002','Check this out',1609459400000,NULL);
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
        assert!(r.iter().all(|a| a.subcategory == "Facebook Messenger"));
    }

    #[test]
    fn sender_and_thread_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("sender='fbid:100001'")));
        assert!(r.iter().any(|a| a.detail.contains("thread='thread:2001'")));
    }

    #[test]
    fn body_appears_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("Hey what")));
    }

    #[test]
    fn missing_table_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE unrelated (id INTEGER);")
            .unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}
