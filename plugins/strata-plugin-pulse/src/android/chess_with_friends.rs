//! Chess with Friends — in-game chat extraction.
//!
//! ALEAPP reference: `scripts/artifacts/ChessWithFriends.py`. Source path:
//! `/data/data/com.zynga.chess.googleplay/databases/wf_database.sqlite`.
//!
//! Key tables: `chat_messages`, `users`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.zynga.chess.googleplay/databases/wf_database.sqlite"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "chat_messages") {
        return Vec::new();
    }
    read_chats(&conn, path)
}

fn read_chats(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    // Join with users table if available for name + email enrichment
    let has_users = table_exists(conn, "users");
    let sql = if has_users {
        "SELECT cm.chat_message_id, u.name, u.email_address, \
         cm.message, cm.created_at \
         FROM chat_messages cm \
         LEFT JOIN users u ON cm.user_zynga_id = u.zynga_account_id \
         ORDER BY cm.created_at DESC LIMIT 10000"
    } else {
        "SELECT chat_message_id, NULL, NULL, message, created_at \
         FROM chat_messages \
         ORDER BY created_at DESC LIMIT 10000"
    };
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
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (msg_id, name, email, body, created) in rows.flatten() {
        let msg_id = msg_id.unwrap_or(0);
        let name = name.unwrap_or_else(|| "(unknown)".to_string());
        let email = email.unwrap_or_default();
        let body = body.unwrap_or_default();
        let ts = created.and_then(unix_ms_to_i64);
        let preview: String = body.chars().take(120).collect();
        let title = format!("ChessWF {}: {}", name, preview);
        let mut detail = format!(
            "Chess with Friends message msg_id={} user='{}' body='{}'",
            msg_id, name, body
        );
        if !email.is_empty() {
            detail.push_str(&format!(" email='{}'", email));
        }
        out.push(build_record(
            ArtifactCategory::Communications,
            "ChessWF Message",
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
            INSERT INTO users VALUES(100,'Alice','alice@example.com');
            INSERT INTO users VALUES(200,'Bob','bob@example.com');
            CREATE TABLE chat_messages (
                chat_message_id INTEGER,
                user_zynga_id INTEGER,
                message TEXT,
                created_at INTEGER
            );
            INSERT INTO chat_messages VALUES(1,100,'Good move!',1609459200000);
            INSERT INTO chat_messages VALUES(2,200,'Thanks',1609459300000);
            INSERT INTO chat_messages VALUES(3,100,'GG',1609459400000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_three_messages() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|a| a.subcategory == "ChessWF Message"));
    }

    #[test]
    fn user_name_and_email_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("user='Alice'")
                && a.detail.contains("email='alice@example.com'")));
    }

    #[test]
    fn message_body_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("Good move!")));
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
