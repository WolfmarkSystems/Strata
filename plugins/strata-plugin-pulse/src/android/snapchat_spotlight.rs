//! Snapchat Spotlight — Android Spotlight and conversation messages.
//!
//! Source paths:
//! - `/data/data/com.snapchat.android/databases/arroyo.db`
//! - `/data/data/com.snapchat.android/databases/spotlight*.db`
//!
//! Schema note: not in ALEAPP upstream. Snapchat Spotlight is a TikTok-like
//! feed within Snapchat. Interaction data may be stored in the `arroyo.db`
//! database's `conversation_message` table or in a dedicated
//! `spotlight_stories` table. We probe both patterns defensively.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.snapchat.android/databases/arroyo.db",
    "com.snapchat.android/databases/spotlight",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "spotlight_stories") {
        out.extend(read_spotlight(&conn, path));
    }
    if table_exists(&conn, "conversation_message") {
        out.extend(read_arroyo(&conn, path));
    }
    out
}

fn read_spotlight(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT creator_id, media_type, view_count, timestamp \
               FROM spotlight_stories \
               ORDER BY timestamp DESC LIMIT 5000";
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
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (creator, media_type, views, ts_ms) in rows.flatten() {
        let creator = creator.unwrap_or_else(|| "(unknown)".to_string());
        let media = media_type.unwrap_or_else(|| "video".to_string());
        let views = views.unwrap_or(0);
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Snapchat Spotlight: {} ({}, {} views)", creator, media, views);
        let detail = format!(
            "Snapchat Spotlight creator='{}' type='{}' view_count={}",
            creator, media, views
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Snapchat Spotlight",
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

fn read_arroyo(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT sender_id, message_type, content, creation_timestamp \
               FROM conversation_message \
               ORDER BY creation_timestamp DESC LIMIT 5000";
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
    for (sender, msg_type, content, ts_ms) in rows.flatten() {
        let sender = sender.unwrap_or_else(|| "(unknown)".to_string());
        let kind = msg_type.unwrap_or_else(|| "unknown".to_string());
        let body = content.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let preview: String = body.chars().take(120).collect();
        let title = if body.is_empty() {
            format!("Snapchat Spotlight {}: [{}]", sender, kind)
        } else {
            format!("Snapchat Spotlight {}: {}", sender, preview)
        };
        let detail = format!(
            "Snapchat Spotlight sender='{}' type='{}' content='{}'",
            sender, kind, body
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Snapchat Spotlight",
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
            CREATE TABLE spotlight_stories (
                id INTEGER PRIMARY KEY,
                creator_id TEXT,
                media_type TEXT,
                view_count INTEGER,
                timestamp INTEGER
            );
            INSERT INTO spotlight_stories VALUES(1,'creator_a','video',15000,1609459200000);
            INSERT INTO spotlight_stories VALUES(2,'creator_b','image',8200,1609459300000);
            CREATE TABLE conversation_message (
                id INTEGER PRIMARY KEY,
                sender_id TEXT,
                message_type TEXT,
                content TEXT,
                creation_timestamp INTEGER
            );
            INSERT INTO conversation_message VALUES(1,'user_x','snap','',1609459400000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_spotlight_and_arroyo() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|a| a.subcategory == "Snapchat Spotlight"));
    }

    #[test]
    fn creator_and_views_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("creator='creator_a'") && a.detail.contains("view_count=15000")));
        // Arroyo message with empty content gets [type] in title
        assert!(r.iter().any(|a| a.title.contains("user_x") && a.title.contains("[snap]")));
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
