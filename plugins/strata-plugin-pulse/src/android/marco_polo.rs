//! Marco Polo — Android video messaging conversations.
//!
//! Source path: `/data/data/co.marcopolo.android/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. Marco Polo stores video message
//! metadata in `conversations` or `messages` tables with `sender`,
//! `group_name`, and `timestamp` columns.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["co.marcopolo.android/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "messages") {
        out.extend(read_messages(&conn, path));
    } else if table_exists(&conn, "conversations") {
        out.extend(read_conversations(&conn, path));
    }
    out
}

fn read_messages(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT sender, group_name, type, timestamp \
               FROM messages \
               ORDER BY timestamp DESC LIMIT 5000";
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
    for (sender, group_name, msg_type, ts_ms) in rows.flatten() {
        let sender = sender.unwrap_or_else(|| "(unknown)".to_string());
        let group = group_name.unwrap_or_else(|| "(direct)".to_string());
        let msg_type = msg_type.unwrap_or_else(|| "video".to_string());
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Marco Polo: {} in {}", sender, group);
        let detail = format!(
            "Marco Polo message sender='{}' group='{}' type='{}'",
            sender, group, msg_type
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Marco Polo",
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

fn read_conversations(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT name, creator, updated_at \
               FROM conversations \
               ORDER BY updated_at DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (name, creator, ts_ms) in rows.flatten() {
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let creator = creator.unwrap_or_else(|| "(unknown)".to_string());
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Marco Polo group: {} by {}", name, creator);
        let detail = format!(
            "Marco Polo conversation name='{}' creator='{}'",
            name, creator
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Marco Polo",
            title,
            detail,
            path,
            ts,
            ForensicValue::Medium,
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
                sender TEXT,
                group_name TEXT,
                type TEXT,
                timestamp INTEGER
            );
            INSERT INTO messages VALUES(1,'alice','Family Group','video',1609459200000);
            INSERT INTO messages VALUES(2,'bob','Family Group','video',1609459300000);
            INSERT INTO messages VALUES(3,'alice',NULL,'voice',1609459400000);
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
        assert!(r.iter().all(|a| a.subcategory == "Marco Polo"));
    }

    #[test]
    fn sender_and_group_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("sender='alice'")
                && a.detail.contains("group='Family Group'")));
        assert!(r.iter().any(|a| a.detail.contains("group='(direct)'")));
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
