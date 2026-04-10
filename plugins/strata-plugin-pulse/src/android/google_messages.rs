//! Google Messages — Android RCS/SMS via Google Messages app.
//!
//! ALEAPP reference: `scripts/artifacts/googleMessages.py`. Source path:
//! `/data/data/com.google.android.apps.messaging/databases/bugle_db`.
//!
//! Google Messages uses a different schema from the native AOSP SMS provider.
//! Key tables: `messages`, `conversations`, `participants`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.google.android.apps.messaging/databases/bugle_db",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "messages") {
        return Vec::new();
    }
    read_messages(&conn, path)
}

fn status_name(code: i64) -> &'static str {
    match code {
        1 => "received",
        2 => "sent",
        3 => "draft",
        4 => "sending",
        5 => "failed",
        _ => "unknown",
    }
}

fn read_messages(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT m.received_timestamp, m.message_status, \
               p.normalized_destination, m.text, m.conversation_id \
               FROM messages m \
               LEFT JOIN participants p ON m.sender_id = p._id \
               WHERE m.text IS NOT NULL \
               ORDER BY m.received_timestamp DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        // Fallback without join
        Err(_) => return read_messages_simple(conn, path),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (ts_ms, status, sender, text, conv_id) in rows.flatten() {
        let direction = status_name(status.unwrap_or(0));
        let sender = sender.unwrap_or_else(|| "(unknown)".to_string());
        let body = text.unwrap_or_default();
        let conv = conv_id.unwrap_or_else(|| "(unknown)".to_string());
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let preview: String = body.chars().take(120).collect();
        let title = format!("Google Messages {} {}: {}", direction, sender, preview);
        let detail = format!(
            "Google Messages direction={} sender='{}' conversation='{}' body='{}'",
            direction, sender, conv, body
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Google Messages",
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

fn read_messages_simple(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT received_timestamp, message_status, text, conversation_id \
               FROM messages WHERE text IS NOT NULL \
               ORDER BY received_timestamp DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (ts_ms, status, text, conv_id) in rows.flatten() {
        let direction = status_name(status.unwrap_or(0));
        let body = text.unwrap_or_default();
        let conv = conv_id.unwrap_or_else(|| "(unknown)".to_string());
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let preview: String = body.chars().take(120).collect();
        let title = format!("Google Messages {}: {}", direction, preview);
        let detail = format!(
            "Google Messages direction={} conversation='{}' body='{}'",
            direction, conv, body
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Google Messages",
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
            CREATE TABLE participants (
                _id INTEGER PRIMARY KEY,
                normalized_destination TEXT
            );
            INSERT INTO participants VALUES(1,'+15551234567');
            INSERT INTO participants VALUES(2,'+15559999999');
            CREATE TABLE messages (
                _id INTEGER PRIMARY KEY,
                received_timestamp INTEGER,
                message_status INTEGER,
                sender_id INTEGER,
                text TEXT,
                conversation_id TEXT
            );
            INSERT INTO messages VALUES(1,1609459200000,1,1,'Hello via Google Messages','conv_001');
            INSERT INTO messages VALUES(2,1609459300000,2,2,'Reply sent','conv_001');
            INSERT INTO messages VALUES(3,1609459400000,1,1,'New thread','conv_002');
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
        assert!(r.iter().all(|a| a.subcategory == "Google Messages"));
    }

    #[test]
    fn direction_is_mapped() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("received")));
        assert!(r.iter().any(|a| a.title.contains("sent")));
    }

    #[test]
    fn conversation_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("conversation='conv_001'")));
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
