//! Words with Friends — in-game chat extraction.
//!
//! ALEAPP reference: `scripts/artifacts/WordsWithFriends.py`. Source path:
//! `/data/data/com.zynga.words/db/wf_database.sqlite`.
//!
//! Key tables: `messages`, `users`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.zynga.words/db/wf_database.sqlite"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "messages") {
        return Vec::new();
    }
    read_messages(&conn, path)
}

fn read_messages(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let has_users = table_exists(conn, "users");
    let sql = if has_users {
        "SELECT messages.created_at, messages.conv_id, users.name, \
         users.email_address, messages.text \
         FROM messages \
         LEFT JOIN users ON messages.user_zynga_id = users.zynga_account_id \
         ORDER BY messages.created_at DESC LIMIT 10000"
    } else {
        "SELECT created_at, conv_id, NULL, NULL, text \
         FROM messages ORDER BY created_at DESC LIMIT 10000"
    };
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
            row.get::<_, Option<String>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (created_ms, conv_id, name, email, body) in rows.flatten() {
        let ts = created_ms.and_then(unix_ms_to_i64);
        let conv = conv_id.unwrap_or(0);
        let name = name.unwrap_or_else(|| "(unknown)".to_string());
        let email = email.unwrap_or_default();
        let body = body.unwrap_or_default();
        let preview: String = body.chars().take(120).collect();
        let title = format!("WordsWF {}: {}", name, preview);
        let mut detail = format!(
            "Words with Friends message user='{}' conv_id={} body='{}'",
            name, conv, body
        );
        if !email.is_empty() {
            detail.push_str(&format!(" email='{}'", email));
        }
        out.push(build_record(
            ArtifactCategory::Communications,
            "WordsWF Message",
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
            CREATE TABLE users (
                zynga_account_id INTEGER,
                name TEXT,
                email_address TEXT
            );
            INSERT INTO users VALUES(50,'Carol','carol@example.com');
            INSERT INTO users VALUES(60,'Dave','dave@example.com');
            CREATE TABLE messages (
                user_zynga_id INTEGER,
                conv_id INTEGER,
                text TEXT,
                created_at INTEGER
            );
            INSERT INTO messages VALUES(50,1,'Nice word!',1609459200000);
            INSERT INTO messages VALUES(60,1,'Thanks Carol',1609459300000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_two_messages() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|a| a.subcategory == "WordsWF Message"));
    }

    #[test]
    fn email_captured_via_join() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("email='carol@example.com'")));
    }

    #[test]
    fn body_preserved_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("body='Nice word!'")));
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
