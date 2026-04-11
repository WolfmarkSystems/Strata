//! Badoo — dating app message extraction.
//!
//! ALEAPP reference: `scripts/artifacts/BadooChat.py`. Source path:
//! `/data/data/com.badoo.mobile/databases/ChatComDatabase*`.
//!
//! Key tables: `message`, `conversation_info`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.badoo.mobile/databases/chatcomdatabase"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "message") {
        out.extend(read_messages(&conn, path));
    }
    if table_exists(&conn, "conversation_info") {
        out.extend(read_conversations(&conn, path));
    }
    out
}

fn read_messages(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT sender_id, recipient_id, created_timestamp, \
               payload, payload_type \
               FROM message \
               ORDER BY created_timestamp DESC LIMIT 10000";
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
            row.get::<_, Option<String>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (sender, recipient, ts_ms, payload, payload_type) in rows.flatten() {
        let sender = sender.unwrap_or_else(|| "(unknown)".to_string());
        let recipient = recipient.unwrap_or_else(|| "(unknown)".to_string());
        let payload = payload.unwrap_or_default();
        let payload_type = payload_type.unwrap_or_else(|| "text".to_string());
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let preview: String = payload.chars().take(120).collect();
        let title = format!("Badoo {}→{}: {}", sender, recipient, preview);
        let detail = format!(
            "Badoo message sender='{}' recipient='{}' type='{}' payload='{}'",
            sender, recipient, payload_type, payload
        );
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "Badoo Message",
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
    let sql = "SELECT user_id, user_name, age, gender, work, education \
               FROM conversation_info LIMIT 5000";
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
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (uid, name, age, gender, work, education) in rows.flatten() {
        let uid = uid.unwrap_or_else(|| "(unknown)".to_string());
        let name = name.unwrap_or_else(|| "(no name)".to_string());
        let title = format!("Badoo contact: {} ({})", name, uid);
        let mut detail = format!("Badoo contact id='{}' name='{}'", uid, name);
        if let Some(a) = age {
            detail.push_str(&format!(" age={}", a));
        }
        if let Some(g) = gender.filter(|g| !g.is_empty()) {
            detail.push_str(&format!(" gender='{}'", g));
        }
        if let Some(w) = work.filter(|w| !w.is_empty()) {
            detail.push_str(&format!(" work='{}'", w));
        }
        if let Some(e) = education.filter(|e| !e.is_empty()) {
            detail.push_str(&format!(" education='{}'", e));
        }
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "Badoo Contact",
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
            CREATE TABLE message (
                sender_id TEXT,
                recipient_id TEXT,
                created_timestamp INTEGER,
                payload TEXT,
                payload_type TEXT
            );
            INSERT INTO message VALUES('u1','u2',1609459200000,'Hey there!','text');
            INSERT INTO message VALUES('u2','u1',1609459300000,'Hi back','text');
            CREATE TABLE conversation_info (
                user_id TEXT,
                user_name TEXT,
                age INTEGER,
                gender TEXT,
                work TEXT,
                education TEXT,
                user_image_url TEXT
            );
            INSERT INTO conversation_info VALUES('u2','Alice',28,'female','Engineer','University',NULL);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_messages_and_contacts() {
        let db = make_db();
        let r = parse(db.path());
        let msgs: Vec<_> = r.iter().filter(|a| a.subcategory == "Badoo Message").collect();
        let contacts: Vec<_> = r.iter().filter(|a| a.subcategory == "Badoo Contact").collect();
        assert_eq!(msgs.len(), 2);
        assert_eq!(contacts.len(), 1);
    }

    #[test]
    fn contact_details_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let alice = r.iter().find(|a| a.subcategory == "Badoo Contact").unwrap();
        assert!(alice.detail.contains("age=28"));
        assert!(alice.detail.contains("work='Engineer'"));
    }

    #[test]
    fn message_direction_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("u1→u2")));
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
