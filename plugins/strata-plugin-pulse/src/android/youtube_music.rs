//! YouTube Music — listening history and offline song extraction.
//!
//! Source: /data/data/com.google.android.apps.youtube.music/databases/ytmusic.db
//!
//! Schema note: YouTube Music stores history in either a `watch_history`
//! or `offline_songs` table depending on app version and usage.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.google.android.apps.youtube.music/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if table_exists(&conn, "watch_history") {
        read_history(&conn, path, "watch_history")
    } else if table_exists(&conn, "offline_songs") {
        read_history(&conn, path, "offline_songs")
    } else {
        Vec::new()
    }
}

fn read_history(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT title, artist, timestamp \
         FROM \"{}\" \
         ORDER BY timestamp DESC LIMIT 5000",
        table.replace('"', "\"\"")
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
    for (title, artist, timestamp) in rows.flatten() {
        let title_str = title.unwrap_or_else(|| "(untitled)".to_string());
        let artist_str = artist.unwrap_or_else(|| "(unknown)".to_string());
        let ts = timestamp.and_then(unix_ms_to_i64);
        let display = format!("YouTube Music: {} — {}", artist_str, title_str);
        let detail = format!(
            "YouTube Music title='{}' artist='{}' source='{}'",
            title_str, artist_str, table
        );
        out.push(build_record(
            ArtifactCategory::Media,
            "YouTube Music",
            display,
            detail,
            path,
            ts,
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
            CREATE TABLE watch_history (
                _id INTEGER PRIMARY KEY,
                title TEXT,
                artist TEXT,
                timestamp INTEGER
            );
            INSERT INTO watch_history VALUES(1,'Blinding Lights','The Weeknd',1609459200000);
            INSERT INTO watch_history VALUES(2,'Levitating','Dua Lipa',1609459300000);
            INSERT INTO watch_history VALUES(3,'Save Your Tears','The Weeknd',1609459400000);
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
        assert!(r.iter().all(|a| a.subcategory == "YouTube Music"));
    }

    #[test]
    fn artist_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("artist='Dua Lipa'")));
        assert!(r.iter().any(|a| a.title.contains("The Weeknd")));
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
