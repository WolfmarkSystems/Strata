//! IMO — Android message extraction.
//!
//! ALEAPP reference: `scripts/artifacts/imo.py`. Source path:
//! `/data/data/com.imo.android.imous/databases/imofriends.db`.
//!
//! Key tables: `messages`, `friends`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.imo.android.imous/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "messages") {
        out.extend(read_messages(&conn, path));
    }
    if table_exists(&conn, "friends") {
        out.extend(read_friends(&conn, path));
    }
    out
}

fn read_messages(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT buid, last_message, timestamp, message_type, message_read \
               FROM messages WHERE last_message IS NOT NULL \
               ORDER BY timestamp DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (buid, msg, ts_raw, msg_type, read) in rows.flatten() {
        let buid = buid.unwrap_or_else(|| "(unknown)".to_string());
        let body = msg.unwrap_or_default();
        // IMO uses nanoseconds timestamp
        let ts = ts_raw.map(|t| t / 1_000_000_000);
        let direction = if msg_type.unwrap_or(0) == 1 {
            "incoming"
        } else {
            "outgoing"
        };
        let read_flag = read.unwrap_or(0) != 0;
        let preview: String = body.chars().take(120).collect();
        let title = format!("IMO {} {}: {}", direction, buid, preview);
        let detail = format!(
            "IMO message direction={} buid='{}' read={} body='{}'",
            direction, buid, read_flag, body
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "IMO Message",
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

fn read_friends(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT buid, display_name \
               FROM friends ORDER BY display_name LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (buid, name) in rows.flatten() {
        let buid = buid.unwrap_or_else(|| "(unknown)".to_string());
        let name = name.unwrap_or_else(|| "(no name)".to_string());
        let title = format!("IMO friend: {} ({})", name, buid);
        let detail = format!("IMO friend buid='{}' name='{}'", buid, name);
        out.push(build_record(
            ArtifactCategory::Communications,
            "IMO Friend",
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
                buid TEXT,
                last_message TEXT,
                timestamp INTEGER,
                message_type INTEGER,
                message_read INTEGER
            );
            INSERT INTO messages VALUES(1,'user_001','Hello IMO',1609459200000000000,1,1);
            INSERT INTO messages VALUES(2,'user_001','Reply back',1609459300000000000,0,1);
            INSERT INTO messages VALUES(3,'user_002','Another chat',1609459400000000000,1,0);
            CREATE TABLE friends (
                buid TEXT,
                display_name TEXT
            );
            INSERT INTO friends VALUES('user_001','Alice');
            INSERT INTO friends VALUES('user_002','Bob');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_messages_and_friends() {
        let db = make_db();
        let r = parse(db.path());
        let msgs: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "IMO Message")
            .collect();
        let friends: Vec<_> = r.iter().filter(|a| a.subcategory == "IMO Friend").collect();
        assert_eq!(msgs.len(), 3);
        assert_eq!(friends.len(), 2);
    }

    #[test]
    fn nanosecond_timestamp_converted() {
        let db = make_db();
        let r = parse(db.path());
        let msg = r.iter().find(|a| a.detail.contains("Hello IMO")).unwrap();
        // 1609459200000000000 ns → 1609459200 seconds
        assert_eq!(msg.timestamp, Some(1609459200));
    }

    #[test]
    fn direction_is_correct() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.title.contains("incoming") && a.title.contains("Hello IMO")));
        assert!(r
            .iter()
            .any(|a| a.title.contains("outgoing") && a.title.contains("Reply back")));
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
