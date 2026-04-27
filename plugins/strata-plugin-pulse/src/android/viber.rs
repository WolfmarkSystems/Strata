//! Viber — Android message and call extraction.
//!
//! ALEAPP reference: `scripts/artifacts/Viber.py`. Source paths:
//! - `/data/data/com.viber.voip/databases/viber_data` — calls & contacts
//! - `/data/data/com.viber.voip/databases/viber_messages` — messages
//!
//! Key tables: `messages`, `calls`, `phonebookcontact`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.viber.voip/databases/viber"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "messages") {
        out.extend(read_messages(&conn, path));
    }
    if table_exists(&conn, "calls") {
        out.extend(read_calls(&conn, path));
    }
    if table_exists(&conn, "phonebookcontact") {
        out.extend(read_contacts(&conn, path));
    }
    out
}

fn read_messages(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT address, body, date, msg_type \
               FROM messages WHERE body IS NOT NULL \
               ORDER BY date DESC LIMIT 10000";
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
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (address, body, date_ms, msg_type) in rows.flatten() {
        let address = address.unwrap_or_else(|| "(unknown)".to_string());
        let body = body.unwrap_or_default();
        let ts = date_ms.and_then(unix_ms_to_i64);
        let direction = if msg_type.unwrap_or(0) == 0 {
            "received"
        } else {
            "sent"
        };
        let preview: String = body.chars().take(120).collect();
        let title = format!("Viber {} {}: {}", direction, address, preview);
        let detail = format!(
            "Viber message direction={} address='{}' body='{}'",
            direction, address, body
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Viber Message",
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
    let sql = "SELECT number, date, duration, type \
               FROM calls ORDER BY date DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (number, date_ms, duration, call_type) in rows.flatten() {
        let number = number.unwrap_or_else(|| "(unknown)".to_string());
        let ts = date_ms.and_then(unix_ms_to_i64);
        let dur = duration.unwrap_or(0);
        let direction = match call_type.unwrap_or(0) {
            1 => "incoming",
            2 => "outgoing",
            3 => "missed",
            _ => "unknown",
        };
        let title = format!("Viber call {} {} ({}s)", direction, number, dur);
        let detail = format!(
            "Viber call direction={} number='{}' duration={}s",
            direction, number, dur
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Viber Call",
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

fn read_contacts(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT display_name, number \
               FROM phonebookcontact ORDER BY display_name LIMIT 5000";
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
    for (name, number) in rows.flatten() {
        let name = name.unwrap_or_else(|| "(no name)".to_string());
        let number = number.unwrap_or_else(|| "(no number)".to_string());
        let title = format!("Viber contact: {} ({})", name, number);
        let detail = format!("Viber contact name='{}' number='{}'", name, number);
        out.push(build_record(
            ArtifactCategory::Communications,
            "Viber Contact",
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
                address TEXT,
                body TEXT,
                date INTEGER,
                msg_type INTEGER
            );
            INSERT INTO messages VALUES(1,'+15551234567','Hello Viber',1609459200000,0);
            INSERT INTO messages VALUES(2,'+15551234567','Reply',1609459300000,1);
            CREATE TABLE calls (
                _id INTEGER PRIMARY KEY,
                number TEXT,
                date INTEGER,
                duration INTEGER,
                type INTEGER
            );
            INSERT INTO calls VALUES(1,'+15551234567',1609459400000,120,1);
            CREATE TABLE phonebookcontact (
                display_name TEXT,
                number TEXT
            );
            INSERT INTO phonebookcontact VALUES('Alice','+15551234567');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_messages_calls_contacts() {
        let db = make_db();
        let r = parse(db.path());
        let msgs: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "Viber Message")
            .collect();
        let calls: Vec<_> = r.iter().filter(|a| a.subcategory == "Viber Call").collect();
        let contacts: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "Viber Contact")
            .collect();
        assert_eq!(msgs.len(), 2);
        assert_eq!(calls.len(), 1);
        assert_eq!(contacts.len(), 1);
    }

    #[test]
    fn message_direction_correct() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.title.contains("received") && a.title.contains("Hello Viber")));
        assert!(r
            .iter()
            .any(|a| a.title.contains("sent") && a.title.contains("Reply")));
    }

    #[test]
    fn call_details_present() {
        let db = make_db();
        let r = parse(db.path());
        let call = r.iter().find(|a| a.subcategory == "Viber Call").unwrap();
        assert!(call.detail.contains("direction=incoming"));
        assert!(call.detail.contains("duration=120s"));
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
