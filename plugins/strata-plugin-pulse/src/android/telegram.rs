//! Telegram — Android message extraction.
//!
//! Source path: `/data/data/org.telegram.messenger/files/cache4.db`.
//!
//! Telegram stores messages in a `messages_v2` table with serialized
//! protobuf blobs. The plaintext-accessible fields are limited but
//! forensically useful: message ID, dialog/chat ID, date, and flags.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "org.telegram.messenger/files/cache4.db",
    "org.telegram.messenger/files/cache",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "messages_v2") {
        out.extend(read_messages(&conn, path));
    } else if table_exists(&conn, "messages") {
        out.extend(read_messages_legacy(&conn, path));
    }
    if table_exists(&conn, "dialogs") {
        out.extend(read_dialogs(&conn, path));
    }
    out
}

fn read_messages(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT mid, uid, date, data \
               FROM messages_v2 ORDER BY date DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (mid, uid, date) in rows.flatten() {
        let msg_id = mid.unwrap_or(0);
        let dialog_id = uid.unwrap_or(0);
        let ts = date; // Telegram uses Unix seconds directly
        let title = format!("Telegram msg #{} in dialog {}", msg_id, dialog_id);
        let detail = format!(
            "Telegram message mid={} dialog_id={}",
            msg_id, dialog_id
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Telegram Message",
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

fn read_messages_legacy(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT mid, uid, date \
               FROM messages ORDER BY date DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (mid, uid, date) in rows.flatten() {
        let msg_id = mid.unwrap_or(0);
        let dialog_id = uid.unwrap_or(0);
        let title = format!("Telegram msg #{} in dialog {}", msg_id, dialog_id);
        let detail = format!(
            "Telegram message mid={} dialog_id={}",
            msg_id, dialog_id
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Telegram Message",
            title,
            detail,
            path,
            date,
            ForensicValue::High,
            false,
        ));
    }
    out
}

fn read_dialogs(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT did, date, unread_count \
               FROM dialogs ORDER BY date DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (did, date, unread) in rows.flatten() {
        let dialog_id = did.unwrap_or(0);
        let unread_count = unread.unwrap_or(0);
        let title = format!("Telegram dialog {} ({} unread)", dialog_id, unread_count);
        let detail = format!(
            "Telegram dialog did={} unread_count={}",
            dialog_id, unread_count
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Telegram Dialog",
            title,
            detail,
            path,
            date,
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
            CREATE TABLE messages_v2 (
                mid INTEGER,
                uid INTEGER,
                date INTEGER,
                data BLOB
            );
            INSERT INTO messages_v2 VALUES(1001,500001,1609459200,NULL);
            INSERT INTO messages_v2 VALUES(1002,500001,1609459300,NULL);
            INSERT INTO messages_v2 VALUES(1003,500002,1609459400,NULL);
            CREATE TABLE dialogs (
                did INTEGER,
                date INTEGER,
                unread_count INTEGER
            );
            INSERT INTO dialogs VALUES(500001,1609459300,2);
            INSERT INTO dialogs VALUES(500002,1609459400,0);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_messages_and_dialogs() {
        let db = make_db();
        let r = parse(db.path());
        let msgs: Vec<_> = r.iter().filter(|a| a.subcategory == "Telegram Message").collect();
        let dialogs: Vec<_> = r.iter().filter(|a| a.subcategory == "Telegram Dialog").collect();
        assert_eq!(msgs.len(), 3);
        assert_eq!(dialogs.len(), 2);
    }

    #[test]
    fn message_ids_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("#1001")));
        assert!(r.iter().any(|a| a.title.contains("#1003")));
    }

    #[test]
    fn dialog_unread_count_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let d = r.iter().find(|a| a.detail.contains("did=500001")).unwrap();
        assert!(d.detail.contains("unread_count=2"));
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
