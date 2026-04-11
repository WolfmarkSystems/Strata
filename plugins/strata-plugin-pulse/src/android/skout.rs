//! Skout — dating chat message extraction.
//!
//! ALEAPP reference: `scripts/artifacts/skout.py`. Source path:
//! `/data/data/com.skout.android/databases/skoutDatabase*`.
//!
//! Key tables: `skoutMessagesTable`, `skoutUsersTable`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.skout.android/databases/skoutdatabase"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "skoutMessagesTable") {
        out.extend(read_messages(&conn, path));
    }
    if table_exists(&conn, "skoutUsersTable") {
        out.extend(read_users(&conn, path));
    }
    out
}

fn read_messages(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT MessageTime, SkoutUser, message, type, \
               pictureUrl, giftUrl, ThreadID \
               FROM skoutMessagesTable \
               ORDER BY MessageTime DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
            row.get::<_, Option<String>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (ts_ms, user, msg, kind, pic, gift, thread) in rows.flatten() {
        let user = user.unwrap_or_else(|| "(unknown)".to_string());
        let body = msg.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let kind = kind.unwrap_or_else(|| "text".to_string());
        let thread = thread.unwrap_or_default();
        let preview: String = body.chars().take(120).collect();
        let title = format!("Skout {}: {}", user, preview);
        let mut detail = format!(
            "Skout message user='{}' type='{}' thread='{}' body='{}'",
            user, kind, thread, body
        );
        if let Some(p) = pic.filter(|p| !p.is_empty()) {
            detail.push_str(&format!(" picture='{}'", p));
        }
        if let Some(g) = gift.filter(|g| !g.is_empty()) {
            detail.push_str(&format!(" gift='{}'", g));
        }
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "Skout Message",
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
    let sql = "SELECT LastMessageTime, userName, picUrl, UserID \
               FROM skoutUsersTable \
               ORDER BY LastMessageTime DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (last_ms, name, pic, uid) in rows.flatten() {
        let name = name.unwrap_or_else(|| "(unknown)".to_string());
        let uid = uid.unwrap_or_else(|| "(unknown)".to_string());
        let ts = last_ms.and_then(unix_ms_to_i64);
        let pic = pic.unwrap_or_default();
        let title = format!("Skout user: {} ({})", name, uid);
        let mut detail = format!("Skout user id='{}' name='{}'", uid, name);
        if !pic.is_empty() {
            detail.push_str(&format!(" picture='{}'", pic));
        }
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "Skout User",
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
            CREATE TABLE skoutMessagesTable (
                MessageTime INTEGER,
                SkoutUser TEXT,
                message TEXT,
                type TEXT,
                pictureUrl TEXT,
                giftUrl TEXT,
                ThreadID TEXT
            );
            INSERT INTO skoutMessagesTable VALUES(1609459200000,'alice_s','Hi Skout!','text',NULL,NULL,'thread_1');
            INSERT INTO skoutMessagesTable VALUES(1609459300000,'alice_s','Pic','image','http://pic.jpg',NULL,'thread_1');
            CREATE TABLE skoutUsersTable (
                LastMessageTime INTEGER,
                userName TEXT,
                picUrl TEXT,
                UserID TEXT
            );
            INSERT INTO skoutUsersTable VALUES(1609459300000,'alice_s','http://profile.jpg','u1');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_messages_and_users() {
        let db = make_db();
        let r = parse(db.path());
        let msgs: Vec<_> = r.iter().filter(|a| a.subcategory == "Skout Message").collect();
        let users: Vec<_> = r.iter().filter(|a| a.subcategory == "Skout User").collect();
        assert_eq!(msgs.len(), 2);
        assert_eq!(users.len(), 1);
    }

    #[test]
    fn picture_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("picture='http://pic.jpg'")));
    }

    #[test]
    fn user_profile_pic_captured() {
        let db = make_db();
        let r = parse(db.path());
        let u = r.iter().find(|a| a.subcategory == "Skout User").unwrap();
        assert!(u.detail.contains("picture='http://profile.jpg'"));
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
