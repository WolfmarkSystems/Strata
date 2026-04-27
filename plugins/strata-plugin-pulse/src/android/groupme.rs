//! GroupMe — group messaging extraction.
//!
//! Source: /data/data/com.groupme.android/databases/groupme.db

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.groupme.android/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "messages") {
        return Vec::new();
    }
    read_messages(&conn, path)
}

fn read_messages(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT text, sender_id, group_id, created_at \
               FROM messages \
               WHERE text IS NOT NULL AND text != '' \
               ORDER BY created_at DESC LIMIT 5000";
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
    for (text, sender_id, group_id, created_at) in rows.flatten() {
        let body = text.unwrap_or_default();
        let sender = sender_id.unwrap_or_else(|| "(unknown)".to_string());
        let group = group_id.unwrap_or_else(|| "(unknown)".to_string());
        let ts = created_at.and_then(unix_ms_to_i64);
        let preview: String = body.chars().take(120).collect();
        let display = format!("GroupMe Message: {}", preview);
        let detail = format!(
            "GroupMe message sender_id='{}' group_id='{}' text='{}'",
            sender, group, body
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "GroupMe Message",
            display,
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
                text TEXT,
                sender_id TEXT,
                group_id TEXT,
                created_at INTEGER
            );
            INSERT INTO messages VALUES(1,'Hey everyone!','user123','grp456',1609459200000);
            INSERT INTO messages VALUES(2,'Meeting at 3pm','user789','grp456',1609459300000);
            INSERT INTO messages VALUES(3,'On my way','user123','grp999',1609459400000);
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
        assert!(r.iter().all(|a| a.subcategory == "GroupMe Message"));
    }

    #[test]
    fn sender_and_group_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("sender_id='user789'")
                && a.detail.contains("group_id='grp456'")));
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
