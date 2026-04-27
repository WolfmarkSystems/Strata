//! Voxer — Android push-to-talk messaging.
//!
//! Source path: `/data/data/com.rebelvox.voxer/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. Voxer stores messages in a
//! `messages` table with `sender_id`, `thread_id`, `type`, and
//! `created` columns. Message types include "text", "audio", and "photo".

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.rebelvox.voxer/databases/"];

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
    let sql = "SELECT sender_id, thread_id, type, content, created \
               FROM messages \
               ORDER BY created DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (sender_id, thread_id, msg_type, content, ts_ms) in rows.flatten() {
        let sender = sender_id.unwrap_or_else(|| "(unknown)".to_string());
        let thread = thread_id.unwrap_or_else(|| "(unknown)".to_string());
        let kind = msg_type.unwrap_or_else(|| "unknown".to_string());
        let body = content.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let preview: String = body.chars().take(120).collect();
        let title = if body.is_empty() {
            format!("Voxer {} [{}]", sender, kind)
        } else {
            format!("Voxer {}: {}", sender, preview)
        };
        let detail = format!(
            "Voxer message sender_id='{}' thread_id='{}' type='{}' content='{}'",
            sender, thread, kind, body
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Voxer Message",
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
                id INTEGER PRIMARY KEY,
                sender_id TEXT,
                thread_id TEXT,
                type TEXT,
                content TEXT,
                created INTEGER
            );
            INSERT INTO messages VALUES(1,'user_a','thread_1','text','Meet at the warehouse',1609459200000);
            INSERT INTO messages VALUES(2,'user_b','thread_1','audio','',1609459300000);
            INSERT INTO messages VALUES(3,'user_a','thread_2','text','Package ready',1609459400000);
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
        assert!(r.iter().all(|a| a.subcategory == "Voxer Message"));
    }

    #[test]
    fn sender_and_thread_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("sender_id='user_a'")
            && a.detail.contains("thread_id='thread_1'")));
        // Audio message with no body gets [type] in title
        assert!(r
            .iter()
            .any(|a| a.title.contains("user_b") && a.title.contains("[audio]")));
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
