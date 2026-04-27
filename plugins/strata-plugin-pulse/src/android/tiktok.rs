//! TikTok — Android message and user extraction.
//!
//! ALEAPP reference: `scripts/artifacts/tikTok.py`. Source path:
//! `/data/data/com.zhiliaoapp.musically/databases/db_im_xx`.
//!
//! TikTok stores DM messages in `msg` table and user info in `user` table.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.zhiliaoapp.musically/databases/db_im",
    "com.ss.android.ugc.trill/databases/db_im",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "msg") {
        out.extend(read_messages(&conn, path));
    }
    if table_exists(&conn, "SIMPLE_USER") {
        out.extend(read_users(&conn, path));
    }
    out
}

fn read_messages(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT sender, content, created_time, type, conversation_id \
               FROM msg WHERE content IS NOT NULL \
               ORDER BY created_time DESC LIMIT 10000";
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
            row.get::<_, Option<String>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (sender, content, created_ms, msg_type, conv) in rows.flatten() {
        let sender = sender.unwrap_or_else(|| "(unknown)".to_string());
        let body = content.unwrap_or_default();
        let ts = created_ms.and_then(unix_ms_to_i64);
        let kind = msg_type.unwrap_or(0);
        let conv = conv.unwrap_or_default();
        let preview: String = body.chars().take(120).collect();
        let title = format!("TikTok DM {}: {}", sender, preview);
        let detail = format!(
            "TikTok message sender='{}' type={} conversation='{}' body='{}'",
            sender, kind, conv, body
        );
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "TikTok Message",
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

fn read_users(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT UID, NICK_NAME, UNIQUE_ID \
               FROM SIMPLE_USER LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (uid, nickname, unique_id) in rows.flatten() {
        let uid = uid.unwrap_or_else(|| "(unknown)".to_string());
        let nickname = nickname.unwrap_or_else(|| "(no name)".to_string());
        let unique_id = unique_id.unwrap_or_default();
        let title = format!("TikTok user: {} (@{})", nickname, unique_id);
        let detail = format!(
            "TikTok user uid='{}' nickname='{}' unique_id='{}'",
            uid, nickname, unique_id
        );
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "TikTok User",
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
            CREATE TABLE msg (
                _id INTEGER PRIMARY KEY,
                sender TEXT,
                content TEXT,
                created_time INTEGER,
                type INTEGER,
                conversation_id TEXT
            );
            INSERT INTO msg VALUES(1,'user123','Hey check this video!',1609459200000,0,'conv_a');
            INSERT INTO msg VALUES(2,'user456','LOL 😂',1609459300000,0,'conv_a');
            INSERT INTO msg VALUES(3,'user123','New video',1609459400000,1,'conv_b');
            CREATE TABLE SIMPLE_USER (
                UID TEXT,
                NICK_NAME TEXT,
                UNIQUE_ID TEXT
            );
            INSERT INTO SIMPLE_USER VALUES('user123','Alice','alice_tiktok');
            INSERT INTO SIMPLE_USER VALUES('user456','Bob','bob_tiktok');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_messages_and_users() {
        let db = make_db();
        let r = parse(db.path());
        let msgs: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "TikTok Message")
            .collect();
        let users: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "TikTok User")
            .collect();
        assert_eq!(msgs.len(), 3);
        assert_eq!(users.len(), 2);
    }

    #[test]
    fn sender_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.title.contains("user123") && a.title.contains("Hey check")));
    }

    #[test]
    fn user_unique_id_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("@alice_tiktok")));
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
