//! OfferUp — Android messaging and conversation extraction.
//!
//! Source path: `/data/data/com.offerup/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. OfferUp stores buyer/seller
//! messages in a `messages` table with `text`, `sender`, and
//! `created_at` columns. Some versions use a `conversations` table
//! for thread metadata.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.offerup/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "messages") {
        out.extend(read_messages(&conn, path));
    } else if table_exists(&conn, "conversations") {
        out.extend(read_conversations(&conn, path));
    }
    out
}

fn read_messages(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT text, sender, created_at \
               FROM messages WHERE text IS NOT NULL \
               ORDER BY created_at DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (text, sender, ts_ms) in rows.flatten() {
        let body = text.unwrap_or_default();
        let sender = sender.unwrap_or_else(|| "(unknown)".to_string());
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let preview: String = body.chars().take(120).collect();
        let title = format!("OfferUp {}: {}", sender, preview);
        let detail = format!(
            "OfferUp message sender='{}' text='{}'",
            sender, body
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "OfferUp Message",
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
    let sql = "SELECT snippet, other_user, updated_at \
               FROM conversations \
               ORDER BY updated_at DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (snippet, other_user, ts_ms) in rows.flatten() {
        let snippet = snippet.unwrap_or_default();
        let other_user = other_user.unwrap_or_else(|| "(unknown)".to_string());
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let preview: String = snippet.chars().take(120).collect();
        let title = format!("OfferUp {}: {}", other_user, preview);
        let detail = format!(
            "OfferUp conversation other_user='{}' snippet='{}'",
            other_user, snippet
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "OfferUp Message",
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
                id INTEGER PRIMARY KEY,
                text TEXT,
                sender TEXT,
                created_at INTEGER
            );
            INSERT INTO messages VALUES(1,'Is this still available?','buyer42',1609459200000);
            INSERT INTO messages VALUES(2,'Yes, $50 firm','seller99',1609459300000);
            INSERT INTO messages VALUES(3,'I can pick up today','buyer42',1609459400000);
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
        assert!(r.iter().all(|a| a.subcategory == "OfferUp Message"));
    }

    #[test]
    fn sender_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("sender='buyer42'")));
        assert!(r.iter().any(|a| a.title.contains("seller99")));
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
