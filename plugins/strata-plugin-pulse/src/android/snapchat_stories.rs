//! Snapchat Stories — Story posts and views.
//!
//! Source path: `/data/data/com.snapchat.android/databases/main.db` or
//! `stories.db`. Separate from the broad `snapchat.rs` parser which
//! handles chat messages and friends.
//!
//! Schema note: not in ALEAPP upstream. Snapchat stores story posts in
//! `story` or `story_snap` tables, with `user_id`, `timestamp`,
//! `media_id`, and viewer tracking. Column names vary across versions.

use crate::android::helpers::{build_record, column_exists, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.snapchat.android/databases/main.db",
    "com.snapchat.android/databases/stories.db",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["story", "story_snap", "stories"] {
        if table_exists(&conn, table) {
            out.extend(read_stories(&conn, path, table));
            break;
        }
    }
    for table in &["story_note", "story_views"] {
        if table_exists(&conn, table) {
            out.extend(read_views(&conn, path, table));
            break;
        }
    }
    out
}

fn read_stories(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let ts_col = if column_exists(conn, table, "timestamp") {
        "timestamp"
    } else {
        "post_time"
    };
    let sql = format!(
        "SELECT user_id, {ts_col}, media_id, media_type, viewer_count, expired \
         FROM \"{table}\" ORDER BY {ts_col} DESC LIMIT 5000",
        ts_col = ts_col,
        table = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (user_id, ts_ms, media_id, media_type, viewer_count, expired) in rows.flatten() {
        let user_id = user_id.unwrap_or_else(|| "(unknown)".to_string());
        let media_id = media_id.unwrap_or_default();
        let media_type = media_type.unwrap_or_else(|| "unknown".to_string());
        let viewer_count = viewer_count.unwrap_or(0);
        let expired = expired.unwrap_or(0) != 0;
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Snapchat story: {} ({} viewers)", user_id, viewer_count);
        let detail = format!(
            "Snapchat story user_id='{}' media_id='{}' media_type='{}' viewer_count={} expired={}",
            user_id, media_id, media_type, viewer_count, expired
        );
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "Snapchat Story",
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

fn read_views(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT story_id, viewer_id, view_time FROM \"{table}\" \
         ORDER BY view_time DESC LIMIT 10000",
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
            row.get::<_, Option<i64>>(2).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (story_id, viewer_id, view_ms) in rows.flatten() {
        let story_id = story_id.unwrap_or_else(|| "(unknown)".to_string());
        let viewer_id = viewer_id.unwrap_or_else(|| "(unknown)".to_string());
        let ts = view_ms.and_then(unix_ms_to_i64);
        let title = format!("Snap story view: {} by {}", story_id, viewer_id);
        let detail = format!(
            "Snapchat story view story_id='{}' viewer_id='{}'",
            story_id, viewer_id
        );
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "Snapchat Story View",
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
            CREATE TABLE story (
                user_id TEXT,
                timestamp INTEGER,
                media_id TEXT,
                media_type TEXT,
                viewer_count INTEGER,
                expired INTEGER
            );
            INSERT INTO story VALUES('alice',1609459200000,'m1','image',15,0);
            INSERT INTO story VALUES('alice',1609545600000,'m2','video',8,0);
            INSERT INTO story VALUES('bob',1609632000000,'m3','image',22,1);
            CREATE TABLE story_note (
                story_id TEXT,
                viewer_id TEXT,
                view_time INTEGER
            );
            INSERT INTO story_note VALUES('m1','charlie',1609459300000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_stories_and_views() {
        let db = make_db();
        let r = parse(db.path());
        let stories: Vec<_> = r.iter().filter(|a| a.subcategory == "Snapchat Story").collect();
        let views: Vec<_> = r.iter().filter(|a| a.subcategory == "Snapchat Story View").collect();
        assert_eq!(stories.len(), 3);
        assert_eq!(views.len(), 1);
    }

    #[test]
    fn viewer_count_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("22 viewers")));
    }

    #[test]
    fn expired_flag_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("expired=true")));
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
