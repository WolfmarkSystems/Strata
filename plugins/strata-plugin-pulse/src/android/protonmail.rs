//! ProtonMail — encrypted email message extraction.
//!
//! Source path: `/data/data/ch.protonmail.android/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. ProtonMail stores message
//! metadata locally (sender, subject, timestamp, labels). Body text
//! is encrypted client-side, but metadata is plaintext in the local
//! database. Also cached contacts.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["ch.protonmail.android/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["message", "messages", "MessageEntity"] {
        if table_exists(&conn, table) {
            out.extend(read_messages(&conn, path, table));
            break;
        }
    }
    if table_exists(&conn, "contact") {
        out.extend(read_contacts(&conn, path));
    }
    out
}

fn read_messages(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, sender_name, sender_email, subject, time, \
         num_attachments, is_starred, label_ids, unread \
         FROM \"{table}\" ORDER BY time DESC LIMIT 10000",
        table = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
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
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<i64>>(6).unwrap_or(None),
            row.get::<_, Option<String>>(7).unwrap_or(None),
            row.get::<_, Option<i64>>(8).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (
        id,
        sender_name,
        sender_email,
        subject,
        ts_raw,
        num_attachments,
        is_starred,
        labels,
        unread,
    ) in rows.flatten()
    {
        let id = id.unwrap_or_default();
        let sender_name = sender_name.unwrap_or_default();
        let sender_email = sender_email.unwrap_or_default();
        let subject = subject.unwrap_or_default();
        let num_attachments = num_attachments.unwrap_or(0);
        let is_starred = is_starred.unwrap_or(0) != 0;
        let labels = labels.unwrap_or_default();
        let unread = unread.unwrap_or(0) != 0;
        let ts = ts_raw;
        let title = format!("ProtonMail: {} — {}", sender_email, subject);
        let detail = format!(
            "ProtonMail message id='{}' sender_name='{}' sender_email='{}' subject='{}' num_attachments={} starred={} unread={} labels='{}'",
            id, sender_name, sender_email, subject, num_attachments, is_starred, unread, labels
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "ProtonMail Message",
            title,
            detail,
            path,
            ts,
            ForensicValue::Critical,
            false,
        ));
    }
    out
}

fn read_contacts(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, name, email, created_at \
               FROM contact LIMIT 5000";
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
    for (id, name, email, ts_ms) in rows.flatten() {
        let id = id.unwrap_or_default();
        let name = name.unwrap_or_else(|| "(unknown)".to_string());
        let email = email.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("ProtonMail contact: {} ({})", name, email);
        let detail = format!(
            "ProtonMail contact id='{}' name='{}' email='{}'",
            id, name, email
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "ProtonMail Contact",
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
            CREATE TABLE message (id TEXT, sender_name TEXT, sender_email TEXT, subject TEXT, time INTEGER, num_attachments INTEGER, is_starred INTEGER, label_ids TEXT, unread INTEGER);
            INSERT INTO message VALUES('m1','Alice','alice@protonmail.com','Encrypted doc',1609459200,1,1,'0,5',0);
            INSERT INTO message VALUES('m2','Bob','bob@protonmail.com','Meeting notes',1609459300,0,0,'0',1);
            CREATE TABLE contact (id TEXT, name TEXT, email TEXT, created_at INTEGER);
            INSERT INTO contact VALUES('c1','Alice','alice@protonmail.com',1609459100000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_messages_and_contacts() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "ProtonMail Message"));
        assert!(r.iter().any(|a| a.subcategory == "ProtonMail Contact"));
    }

    #[test]
    fn attachment_count_and_starred() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("num_attachments=1") && a.detail.contains("starred=true")));
    }

    #[test]
    fn subject_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("Encrypted doc")));
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
