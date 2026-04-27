//! Spotify — detailed listening history and playlists.
//!
//! Source path: `/data/data/com.spotify.music/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Spotify caches playback
//! history, playlists, and downloaded tracks for offline play.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.spotify.music/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["play_history", "listen_history", "track_history"] {
        if table_exists(&conn, table) {
            out.extend(read_history(&conn, path, table));
            break;
        }
    }
    if table_exists(&conn, "playlist") {
        out.extend(read_playlists(&conn, path));
    }
    for table in &["offline_track", "downloaded_track"] {
        if table_exists(&conn, table) {
            out.extend(read_offline(&conn, path, table));
            break;
        }
    }
    out
}

fn read_history(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT track_uri, track_name, artist_name, album_name, \
         played_at, duration_played_ms, completed \
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
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<i64>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (track_uri, track_name, artist_name, album_name, ts_ms, duration_ms, completed) in
        rows.flatten()
    {
        let track_uri = track_uri.unwrap_or_default();
        let track_name = track_name.unwrap_or_else(|| "(unknown)".to_string());
        let artist_name = artist_name.unwrap_or_default();
        let album_name = album_name.unwrap_or_default();
        let dur_s = duration_ms.unwrap_or(0) / 1000;
        let completed = completed.unwrap_or(0) != 0;
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Spotify: {} — {}", artist_name, track_name);
        let detail = format!(
            "Spotify play history track_uri='{}' track_name='{}' artist_name='{}' album_name='{}' duration_played={}s completed={}",
            track_uri, track_name, artist_name, album_name, dur_s, completed
        );
        out.push(build_record(
            ArtifactCategory::Media,
            "Spotify Play",
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

fn read_playlists(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT uri, name, owner, num_tracks, is_collaborative, \
               created_at \
               FROM playlist LIMIT 5000";
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
    for (uri, name, owner, num_tracks, is_collaborative, ts_ms) in rows.flatten() {
        let uri = uri.unwrap_or_default();
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let owner = owner.unwrap_or_default();
        let num_tracks = num_tracks.unwrap_or(0);
        let is_collaborative = is_collaborative.unwrap_or(0) != 0;
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Spotify playlist: {} ({} tracks)", name, num_tracks);
        let detail = format!(
            "Spotify playlist uri='{}' name='{}' owner='{}' num_tracks={} is_collaborative={}",
            uri, name, owner, num_tracks, is_collaborative
        );
        out.push(build_record(
            ArtifactCategory::Media,
            "Spotify Playlist",
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

fn read_offline(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT track_uri, track_name, artist_name, downloaded_at, size_bytes \
         FROM \"{table}\" ORDER BY downloaded_at DESC LIMIT 5000",
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
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (track_uri, track_name, artist_name, ts_ms, size_bytes) in rows.flatten() {
        let track_uri = track_uri.unwrap_or_default();
        let track_name = track_name.unwrap_or_else(|| "(unknown)".to_string());
        let artist_name = artist_name.unwrap_or_default();
        let size_bytes = size_bytes.unwrap_or(0);
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Spotify offline: {} — {}", artist_name, track_name);
        let detail = format!(
            "Spotify offline track track_uri='{}' track_name='{}' artist_name='{}' size_bytes={}",
            track_uri, track_name, artist_name, size_bytes
        );
        out.push(build_record(
            ArtifactCategory::Media,
            "Spotify Offline Track",
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
            CREATE TABLE play_history (
                track_uri TEXT,
                track_name TEXT,
                artist_name TEXT,
                album_name TEXT,
                played_at INTEGER,
                duration_played_ms INTEGER,
                completed INTEGER
            );
            INSERT INTO play_history VALUES('spotify:track:abc','Bohemian Rhapsody','Queen','A Night at the Opera',1609459200000,355000,1);
            CREATE TABLE playlist (
                uri TEXT,
                name TEXT,
                owner TEXT,
                num_tracks INTEGER,
                is_collaborative INTEGER,
                created_at INTEGER
            );
            INSERT INTO playlist VALUES('spotify:playlist:xyz','Road Trip','user1',45,0,1609459000000);
            CREATE TABLE offline_track (
                track_uri TEXT,
                track_name TEXT,
                artist_name TEXT,
                downloaded_at INTEGER,
                size_bytes INTEGER
            );
            INSERT INTO offline_track VALUES('spotify:track:def','Imagine','John Lennon',1609459300000,5242880);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_history_playlist_offline() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Spotify Play"));
        assert!(r.iter().any(|a| a.subcategory == "Spotify Playlist"));
        assert!(r.iter().any(|a| a.subcategory == "Spotify Offline Track"));
    }

    #[test]
    fn track_uri_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("track_uri='spotify:track:abc'")));
    }

    #[test]
    fn playlist_num_tracks_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.title.contains("Road Trip") && a.title.contains("45 tracks")));
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
