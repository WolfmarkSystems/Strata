//! SoundCloud — track listening history and metadata.
//!
//! Source: /data/data/com.soundcloud.android/databases/soundcloud.db

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.soundcloud.android/databases/",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "tracks") {
        return Vec::new();
    }
    read_tracks(&conn, path)
}

fn read_tracks(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT title, username, duration, playback_count \
               FROM tracks LIMIT 5000";
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
    for (title, username, duration, playback_count) in rows.flatten() {
        let title_str = title.unwrap_or_else(|| "(untitled)".to_string());
        let username_str = username.unwrap_or_else(|| "(unknown)".to_string());
        let duration_s = duration.unwrap_or(0) / 1000;
        let plays = playback_count.unwrap_or(0);
        let display = format!("SoundCloud Track: {} — {}", username_str, title_str);
        let detail = format!(
            "SoundCloud track title='{}' username='{}' duration={}s playback_count={}",
            title_str, username_str, duration_s, plays
        );
        out.push(build_record(
            ArtifactCategory::Media,
            "SoundCloud Track",
            display,
            detail,
            path,
            None,
            ForensicValue::Low,
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
            CREATE TABLE tracks (
                _id INTEGER PRIMARY KEY,
                title TEXT,
                username TEXT,
                duration INTEGER,
                playback_count INTEGER
            );
            INSERT INTO tracks VALUES(1,'Lo-fi Beats','ChillHop',180000,1500);
            INSERT INTO tracks VALUES(2,'Midnight Jazz','JazzCat',240000,3200);
            INSERT INTO tracks VALUES(3,'Podcast Episode 42','TechTalk',3600000,800);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_three_tracks() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|a| a.subcategory == "SoundCloud Track"));
    }

    #[test]
    fn username_and_playback_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("username='JazzCat'") && a.detail.contains("playback_count=3200")));
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
