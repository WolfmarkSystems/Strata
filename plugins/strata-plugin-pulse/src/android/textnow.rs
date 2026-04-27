//! TextNow — Android VoIP message and call extraction.
//!
//! ALEAPP reference: `scripts/artifacts/textnow.py`. Source path:
//! `/data/data/com.enflick.android.TextNow/databases/textnow_data.db`.
//!
//! Key table: `messages` with `message_type` discriminator:
//! - `message_type IN (100, 102)` → call logs
//! - otherwise → text messages

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.enflick.android.textnow/databases/textnow_data.db"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "messages") {
        return Vec::new();
    }
    let mut out = Vec::new();
    out.extend(read_messages(&conn, path));
    out.extend(read_calls(&conn, path));
    out
}

fn direction_name(code: i64) -> &'static str {
    match code {
        1 => "incoming",
        2 => "outgoing",
        _ => "unknown",
    }
}

fn read_messages(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT contact_value, message_direction, message_text, date, read \
               FROM messages WHERE message_type NOT IN (100, 102) \
               AND message_text IS NOT NULL \
               ORDER BY date DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (contact, dir, text, date_ms, read) in rows.flatten() {
        let contact = contact.unwrap_or_else(|| "(unknown)".to_string());
        let direction = direction_name(dir.unwrap_or(0));
        let body = text.unwrap_or_default();
        let ts = date_ms.and_then(unix_ms_to_i64);
        let read_flag = read.unwrap_or(0) != 0;
        let preview: String = body.chars().take(120).collect();
        let title = format!("TextNow {} {}: {}", direction, contact, preview);
        let detail = format!(
            "TextNow message direction={} contact='{}' read={} body='{}'",
            direction, contact, read_flag, body
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "TextNow Message",
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

fn read_calls(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT contact_value, message_direction, date, message_text \
               FROM messages WHERE message_type IN (100, 102) \
               ORDER BY date DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (contact, dir, date_ms, text) in rows.flatten() {
        let contact = contact.unwrap_or_else(|| "(unknown)".to_string());
        let direction = direction_name(dir.unwrap_or(0));
        let ts = date_ms.and_then(unix_ms_to_i64);
        let info = text.unwrap_or_default();
        let title = format!("TextNow call {} {}", direction, contact);
        let detail = format!(
            "TextNow call direction={} contact='{}' info='{}'",
            direction, contact, info
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "TextNow Call",
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
                contact_value TEXT,
                message_direction INTEGER,
                message_text TEXT,
                date INTEGER,
                read INTEGER,
                message_type INTEGER
            );
            INSERT INTO messages VALUES(1,'+15551234567',1,'Hello from TextNow',1609459200000,1,1);
            INSERT INTO messages VALUES(2,'+15551234567',2,'Reply here',1609459300000,1,1);
            INSERT INTO messages VALUES(3,'+15559999999',1,NULL,1609459400000,0,100);
            INSERT INTO messages VALUES(4,'+15559999999',2,'Voicemail',1609459500000,0,102);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_messages_and_calls() {
        let db = make_db();
        let r = parse(db.path());
        let msgs: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "TextNow Message")
            .collect();
        let calls: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "TextNow Call")
            .collect();
        assert_eq!(msgs.len(), 2);
        assert_eq!(calls.len(), 2);
    }

    #[test]
    fn direction_is_correct() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.title.contains("incoming") && a.title.contains("Hello")));
        assert!(r
            .iter()
            .any(|a| a.title.contains("outgoing") && a.title.contains("Reply")));
    }

    #[test]
    fn contact_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("contact='+15551234567'")));
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
