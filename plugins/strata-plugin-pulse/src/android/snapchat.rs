//! Snapchat — Android message and friend extraction.
//!
//! ALEAPP reference: `scripts/artifacts/snapchat.py`. Source paths:
//! - `/data/data/com.snapchat.android/databases/main.db` (newer)
//! - `/data/data/com.snapchat.android/databases/tcspahn.db` (legacy)
//!
//! Key tables: `message`, `friend`, `feed`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.snapchat.android/databases/main.db",
    "com.snapchat.android/databases/tcspahn.db",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    // Try newer 'message' table, then legacy 'chat'
    if table_exists(&conn, "message") {
        out.extend(read_messages(&conn, path));
    }
    if table_exists(&conn, "friend") {
        out.extend(read_friends(&conn, path));
    }
    out
}

fn read_messages(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT sender_id, content, timestamp, type \
               FROM message WHERE content IS NOT NULL \
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
            row.get::<_, Option<String>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (sender, content, ts_ms, msg_type) in rows.flatten() {
        let sender = sender.unwrap_or_else(|| "(unknown)".to_string());
        let body = content.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let kind = msg_type.unwrap_or_else(|| "text".to_string());
        let preview: String = body.chars().take(120).collect();
        let title = format!("Snapchat {}: {}", sender, preview);
        let detail = format!(
            "Snapchat message sender='{}' type='{}' body='{}'",
            sender, kind, body
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Snapchat Message",
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
    let sql = "SELECT username, display_name, phone, birthday, added_timestamp \
               FROM friend ORDER BY added_timestamp DESC LIMIT 5000";
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
    for (username, display, phone, birthday, ts_ms) in rows.flatten() {
        let username = username.unwrap_or_else(|| "(unknown)".to_string());
        let display = display.unwrap_or_else(|| "(no name)".to_string());
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Snapchat friend: {} ({})", display, username);
        let mut detail = format!(
            "Snapchat friend username='{}' display_name='{}'",
            username, display
        );
        if let Some(p) = phone.filter(|p| !p.is_empty()) {
            detail.push_str(&format!(" phone='{}'", p));
        }
        if let Some(b) = birthday.filter(|b| !b.is_empty()) {
            detail.push_str(&format!(" birthday='{}'", b));
        }
        out.push(build_record(
            ArtifactCategory::Communications,
            "Snapchat Friend",
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
            CREATE TABLE message (
                _id INTEGER PRIMARY KEY,
                sender_id TEXT,
                content TEXT,
                timestamp INTEGER,
                type TEXT
            );
            INSERT INTO message VALUES(1,'alice_snap','Hey!',1609459200000,'text');
            INSERT INTO message VALUES(2,'bob_snap','Snap back',1609459300000,'media');
            INSERT INTO message VALUES(3,'alice_snap','Check this',1609459400000,'text');
            CREATE TABLE friend (
                username TEXT,
                display_name TEXT,
                phone TEXT,
                birthday TEXT,
                added_timestamp INTEGER
            );
            INSERT INTO friend VALUES('alice_snap','Alice','+15551234567','1990-01-15',1609459200000);
            INSERT INTO friend VALUES('bob_snap','Bob',NULL,NULL,1609459300000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_messages_and_friends() {
        let db = make_db();
        let r = parse(db.path());
        let msgs: Vec<_> = r.iter().filter(|a| a.subcategory == "Snapchat Message").collect();
        let friends: Vec<_> = r.iter().filter(|a| a.subcategory == "Snapchat Friend").collect();
        assert_eq!(msgs.len(), 3);
        assert_eq!(friends.len(), 2);
    }

    #[test]
    fn message_sender_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("alice_snap") && a.title.contains("Hey!")));
    }

    #[test]
    fn friend_phone_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let alice = r.iter().find(|a| a.detail.contains("alice_snap") && a.subcategory == "Snapchat Friend").unwrap();
        assert!(alice.detail.contains("phone='+15551234567'"));
        assert!(alice.detail.contains("birthday='1990-01-15'"));
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
