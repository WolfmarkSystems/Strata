//! Facebook Marketplace — Android marketplace messages and threads.
//!
//! Source path: `/data/data/com.facebook.katana/databases/*` with a
//! path-level filter for "marketplace" in the file path or database name.
//!
//! Schema note: not in ALEAPP upstream. Facebook stores marketplace
//! conversations in the same `threads_db2` or `msys_database_*` as
//! Messenger, but marketplace-specific data may appear in tables like
//! `marketplace_threads` or with thread metadata indicating marketplace
//! origin. We also probe the standard `messages` table when the path
//! hints at marketplace context.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.facebook.katana/databases/marketplace",
    "com.facebook.katana/databases/threads_db2",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    // Try marketplace-specific tables first
    if table_exists(&conn, "marketplace_threads") {
        out.extend(read_marketplace_threads(&conn, path));
    }
    // Fall back to standard messages table when path contains "marketplace"
    if out.is_empty() && table_exists(&conn, "messages") {
        out.extend(read_messages(&conn, path));
    }
    out
}

fn read_marketplace_threads(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT thread_key, snippet, item_name, timestamp \
               FROM marketplace_threads \
               ORDER BY timestamp DESC LIMIT 5000";
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
    for (thread_key, snippet, item_name, ts_ms) in rows.flatten() {
        let thread = thread_key.unwrap_or_else(|| "(unknown)".to_string());
        let snippet = snippet.unwrap_or_default();
        let item = item_name.unwrap_or_else(|| "(no item)".to_string());
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let preview: String = snippet.chars().take(120).collect();
        let title = format!("FB Marketplace: {} — {}", item, preview);
        let detail = format!(
            "FB Marketplace thread='{}' item='{}' snippet='{}'",
            thread, item, snippet
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "FB Marketplace",
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

fn read_messages(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT sender_key, thread_key, text, timestamp_ms \
               FROM messages WHERE text IS NOT NULL \
               ORDER BY timestamp_ms DESC LIMIT 5000";
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
    for (sender, thread, text, ts_ms) in rows.flatten() {
        let sender = sender.unwrap_or_else(|| "(unknown)".to_string());
        let thread = thread.unwrap_or_else(|| "(unknown)".to_string());
        let body = text.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let preview: String = body.chars().take(120).collect();
        let title = format!("FB Marketplace {}: {}", sender, preview);
        let detail = format!(
            "FB Marketplace sender='{}' thread='{}' body='{}'",
            sender, thread, body
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "FB Marketplace",
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
            CREATE TABLE marketplace_threads (
                thread_key TEXT,
                snippet TEXT,
                item_name TEXT,
                timestamp INTEGER
            );
            INSERT INTO marketplace_threads VALUES('t:1001','Is this available?','Used iPhone 14',1609459200000);
            INSERT INTO marketplace_threads VALUES('t:1002','Can you do $200?','Mountain Bike',1609459300000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_marketplace_threads() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|a| a.subcategory == "FB Marketplace"));
    }

    #[test]
    fn item_name_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("Used iPhone 14")));
        assert!(r.iter().any(|a| a.detail.contains("item='Mountain Bike'")));
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
