//! Pandora — internet radio stations and listening history.
//!
//! Source path: `/data/data/com.pandora.android/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Pandora caches stations,
//! played tracks, and thumbs up/down feedback.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.pandora.android/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "station") {
        out.extend(read_stations(&conn, path));
    }
    for table in &["play_history", "track_history"] {
        if table_exists(&conn, table) {
            out.extend(read_history(&conn, path, table));
            break;
        }
    }
    if table_exists(&conn, "feedback") {
        out.extend(read_feedback(&conn, path));
    }
    out
}

fn read_stations(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT station_id, name, seed_name, is_quickmix, \
               last_played_at, total_plays \
               FROM station LIMIT 1000";
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
    for (station_id, name, seed_name, is_quickmix, last_played_ms, total_plays) in rows.flatten() {
        let station_id = station_id.unwrap_or_default();
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let seed_name = seed_name.unwrap_or_default();
        let is_quickmix = is_quickmix.unwrap_or(0) != 0;
        let total_plays = total_plays.unwrap_or(0);
        let ts = last_played_ms.and_then(unix_ms_to_i64);
        let title = format!("Pandora station: {} ({} plays)", name, total_plays);
        let detail = format!(
            "Pandora station id='{}' name='{}' seed_name='{}' is_quickmix={} total_plays={}",
            station_id, name, seed_name, is_quickmix, total_plays
        );
        out.push(build_record(
            ArtifactCategory::Media,
            "Pandora Station",
            title,
            detail,
            path,
            ts,
            ForensicValue::Low,
            false,
        ));
    }
    out
}

fn read_history(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT track_id, title, artist, album, station_id, played_at \
         FROM \"{table}\" ORDER BY played_at DESC LIMIT 10000",
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
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (track_id, track_title, artist, album, station_id, ts_ms) in rows.flatten() {
        let track_id = track_id.unwrap_or_default();
        let track_title = track_title.unwrap_or_else(|| "(unknown)".to_string());
        let artist = artist.unwrap_or_default();
        let album = album.unwrap_or_default();
        let station_id = station_id.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title_str = format!("Pandora: {} — {}", artist, track_title);
        let detail = format!(
            "Pandora play history track_id='{}' title='{}' artist='{}' album='{}' station_id='{}'",
            track_id, track_title, artist, album, station_id
        );
        out.push(build_record(
            ArtifactCategory::Media,
            "Pandora Play",
            title_str,
            detail,
            path,
            ts,
            ForensicValue::Low,
            false,
        ));
    }
    out
}

fn read_feedback(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT track_id, track_title, artist, station_id, \
               is_positive, created_at \
               FROM feedback LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
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
    for (track_id, track_title, artist, station_id, is_positive, ts_ms) in rows.flatten() {
        let track_id = track_id.unwrap_or_default();
        let track_title = track_title.unwrap_or_else(|| "(unknown)".to_string());
        let artist = artist.unwrap_or_default();
        let station_id = station_id.unwrap_or_default();
        let is_positive = is_positive.unwrap_or(0) != 0;
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let thumb = if is_positive { "thumbs_up" } else { "thumbs_down" };
        let title = format!("Pandora {}: {} — {}", thumb, artist, track_title);
        let detail = format!(
            "Pandora feedback track_id='{}' title='{}' artist='{}' station_id='{}' is_positive={}",
            track_id, track_title, artist, station_id, is_positive
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Pandora Feedback",
            title,
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
            CREATE TABLE station (
                station_id TEXT,
                name TEXT,
                seed_name TEXT,
                is_quickmix INTEGER,
                last_played_at INTEGER,
                total_plays INTEGER
            );
            INSERT INTO station VALUES('s1','Rock Radio','Queen',0,1609459200000,250);
            CREATE TABLE play_history (
                track_id TEXT,
                title TEXT,
                artist TEXT,
                album TEXT,
                station_id TEXT,
                played_at INTEGER
            );
            INSERT INTO play_history VALUES('t1','We Will Rock You','Queen','News of the World','s1',1609459300000);
            CREATE TABLE feedback (
                track_id TEXT,
                track_title TEXT,
                artist TEXT,
                station_id TEXT,
                is_positive INTEGER,
                created_at INTEGER
            );
            INSERT INTO feedback VALUES('t1','We Will Rock You','Queen','s1',1,1609459400000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_station_play_feedback() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Pandora Station"));
        assert!(r.iter().any(|a| a.subcategory == "Pandora Play"));
        assert!(r.iter().any(|a| a.subcategory == "Pandora Feedback"));
    }

    #[test]
    fn thumbs_up_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("thumbs_up")));
    }

    #[test]
    fn station_total_plays_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("total_plays=250")));
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
