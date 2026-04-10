//! VLC — Android VLC media player history.
//!
//! ALEAPP reference: `scripts/artifacts/vlcMedia.py`. Source path:
//! `/data/data/org.videolan.vlc/databases/vlc_database`.
//!
//! Key table: `media_table` — played media paths and metadata.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["org.videolan.vlc/databases/vlc_database"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "media_table") {
        return Vec::new();
    }
    read_media(&conn, path)
}

fn read_media(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT title, filename, uri, length, type, \
               last_modified \
               FROM media_table \
               ORDER BY last_modified DESC LIMIT 10000";
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
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (title, filename, uri, length, media_type, modified) in rows.flatten() {
        let title_str = title.unwrap_or_else(|| "(untitled)".to_string());
        let filename = filename.unwrap_or_default();
        let uri = uri.unwrap_or_default();
        let dur_s = length.unwrap_or(0) / 1000;
        let media = match media_type.unwrap_or(0) {
            0 => "video",
            1 => "audio",
            _ => "unknown",
        };
        let ts = modified.and_then(unix_ms_to_i64);
        let display = if title_str == "(untitled)" { &filename } else { &title_str };
        let title_out = format!("VLC {}: {} ({}s)", media, display, dur_s);
        let detail = format!(
            "VLC media title='{}' file='{}' uri='{}' type={} duration={}s",
            title_str, filename, uri, media, dur_s
        );
        out.push(build_record(
            ArtifactCategory::Media,
            "VLC Media",
            title_out,
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
            CREATE TABLE media_table (
                _id INTEGER PRIMARY KEY,
                title TEXT,
                filename TEXT,
                uri TEXT,
                length INTEGER,
                type INTEGER,
                last_modified INTEGER
            );
            INSERT INTO media_table VALUES(1,'Summer Video','summer.mp4','file:///sdcard/DCIM/summer.mp4',120000,0,1609459200000);
            INSERT INTO media_table VALUES(2,'Podcast Episode','podcast.mp3','file:///sdcard/Music/podcast.mp3',3600000,1,1609459300000);
            INSERT INTO media_table VALUES(3,NULL,'clip.avi','file:///sdcard/Downloads/clip.avi',60000,0,1609459400000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_three_entries() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|a| a.subcategory == "VLC Media"));
    }

    #[test]
    fn media_type_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("video") && a.title.contains("Summer Video")));
        assert!(r.iter().any(|a| a.title.contains("audio") && a.title.contains("Podcast")));
    }

    #[test]
    fn uri_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("uri='file:///sdcard/DCIM/summer.mp4'")));
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
