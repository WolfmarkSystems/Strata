//! Chrome Media History — Android Chrome media playback tracking.
//!
//! ALEAPP reference: `scripts/artifacts/chromeMediaHistory.py`. Source path:
//! `/data/data/com.android.chrome/app_chrome/Default/Media History`.
//!
//! Key tables: `playbackSession`, `origin`.

use crate::android::helpers::{build_record, chrome_to_unix, open_sqlite_ro, table_exists};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "app_chrome/default/media history",
    "app_sbrowser/default/media history",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "playbackSession") {
        out.extend(read_sessions(&conn, path));
    }
    out
}

fn read_sessions(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT url, duration_ms, position_ms, title, \
               source_title, last_updated_time_s \
               FROM playbackSession \
               ORDER BY last_updated_time_s DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (url, duration, position, title, source, last_updated) in rows.flatten() {
        let url = url.unwrap_or_else(|| "(unknown)".to_string());
        let title = title.unwrap_or_default();
        let source = source.unwrap_or_default();
        let dur_s = duration.unwrap_or(0) / 1000;
        let pos_s = position.unwrap_or(0) / 1000;
        // last_updated_time_s is Chrome/WebKit microseconds
        let ts = last_updated.and_then(chrome_to_unix);
        let display = if title.is_empty() { &source } else { &title };
        let title_str = format!("Media: {} ({}s watched)", display, pos_s);
        let detail = format!(
            "Chrome media url='{}' title='{}' source='{}' duration={}s position={}s",
            url, title, source, dur_s, pos_s
        );
        out.push(build_record(
            ArtifactCategory::Media,
            "Chrome Media History",
            title_str,
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
        // WebKit time for 2021-01-01: (1609459200 + 11644473600) * 1000000
        let webkit_us: i64 = (1_609_459_200i64 + 11_644_473_600i64) * 1_000_000;
        c.execute_batch(&format!(
            r#"
            CREATE TABLE playbackSession (
                id INTEGER PRIMARY KEY,
                url TEXT,
                duration_ms INTEGER,
                position_ms INTEGER,
                title TEXT,
                source_title TEXT,
                last_updated_time_s INTEGER
            );
            INSERT INTO playbackSession VALUES(1,'https://youtube.com/watch?v=abc',300000,120000,'Funny Video','YouTube',{webkit_us});
            INSERT INTO playbackSession VALUES(2,'https://spotify.com/track/xyz',240000,240000,'Song Title','Spotify',{next_us});
            "#,
            webkit_us = webkit_us,
            next_us = webkit_us + 100_000_000,
        ))
        .unwrap();
        tmp
    }

    #[test]
    fn parses_two_sessions() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|a| a.subcategory == "Chrome Media History"));
    }

    #[test]
    fn duration_and_position_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let yt = r.iter().find(|a| a.detail.contains("youtube")).unwrap();
        assert!(yt.detail.contains("duration=300s"));
        assert!(yt.detail.contains("position=120s"));
    }

    #[test]
    fn title_in_display() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("Funny Video")));
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
