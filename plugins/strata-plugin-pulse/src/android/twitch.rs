//! Twitch — streamer follows, clips, and watch history.
//!
//! Source path: `/data/data/tv.twitch.android.app/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Twitch uses Room databases with
//! tables like `follow`, `recent_channel`, `clip`, `watch_history`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["tv.twitch.android.app/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["follow", "follows", "followed_channel"] {
        if table_exists(&conn, table) {
            out.extend(read_follows(&conn, path, table));
            break;
        }
    }
    for table in &["recent_channel", "watch_history", "recent_watched"] {
        if table_exists(&conn, table) {
            out.extend(read_watch_history(&conn, path, table));
            break;
        }
    }
    for table in &["clip", "saved_clip"] {
        if table_exists(&conn, table) {
            out.extend(read_clips(&conn, path, table));
            break;
        }
    }
    out
}

fn read_follows(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT channel_id, channel_name, display_name, followed_at \
         FROM \"{table}\" ORDER BY followed_at DESC LIMIT 5000",
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
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (channel_id, channel_name, display_name, followed_ms) in rows.flatten() {
        let channel_id = channel_id.unwrap_or_default();
        let channel_name = channel_name.unwrap_or_else(|| "(unknown)".to_string());
        let display_name = display_name.unwrap_or_default();
        let ts = followed_ms.and_then(unix_ms_to_i64);
        let title = format!("Twitch follow: {}", display_name);
        let detail = format!(
            "Twitch follow channel_id='{}' channel_name='{}' display_name='{}'",
            channel_id, channel_name, display_name
        );
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "Twitch Follow",
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

fn read_watch_history(
    conn: &rusqlite::Connection,
    path: &Path,
    table: &str,
) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT channel_name, game_name, view_time, duration \
         FROM \"{table}\" ORDER BY view_time DESC LIMIT 5000",
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
            row.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (channel_name, game_name, view_ms, duration_ms) in rows.flatten() {
        let channel_name = channel_name.unwrap_or_else(|| "(unknown)".to_string());
        let game_name = game_name.unwrap_or_default();
        let dur_s = duration_ms.unwrap_or(0) / 1000;
        let ts = view_ms.and_then(unix_ms_to_i64);
        let title = format!("Twitch watched: {} ({})", channel_name, game_name);
        let detail = format!(
            "Twitch watch history channel='{}' game='{}' duration={}s",
            channel_name, game_name, dur_s
        );
        out.push(build_record(
            ArtifactCategory::Media,
            "Twitch Watch",
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

fn read_clips(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, title, broadcaster_name, creator_name, \
         video_url, view_count, created_at \
         FROM \"{table}\" ORDER BY created_at DESC LIMIT 5000",
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
            row.get::<_, Option<i64>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, title, broadcaster, creator, video_url, view_count, created_ms) in rows.flatten() {
        let id = id.unwrap_or_default();
        let clip_title = title.unwrap_or_else(|| "(untitled)".to_string());
        let broadcaster = broadcaster.unwrap_or_default();
        let creator = creator.unwrap_or_default();
        let video_url = video_url.unwrap_or_default();
        let view_count = view_count.unwrap_or(0);
        let ts = created_ms.and_then(unix_ms_to_i64);
        let title_str = format!("Twitch clip: {}", clip_title);
        let detail = format!(
            "Twitch clip id='{}' title='{}' broadcaster='{}' creator='{}' video_url='{}' view_count={}",
            id, clip_title, broadcaster, creator, video_url, view_count
        );
        out.push(build_record(
            ArtifactCategory::Media,
            "Twitch Clip",
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
        c.execute_batch(
            r#"
            CREATE TABLE follow (
                channel_id TEXT,
                channel_name TEXT,
                display_name TEXT,
                followed_at INTEGER
            );
            INSERT INTO follow VALUES('ch1','shroud','Shroud',1609459200000);
            CREATE TABLE watch_history (
                channel_name TEXT,
                game_name TEXT,
                view_time INTEGER,
                duration INTEGER
            );
            INSERT INTO watch_history VALUES('shroud','Valorant',1609459300000,3600000);
            CREATE TABLE clip (
                id TEXT,
                title TEXT,
                broadcaster_name TEXT,
                creator_name TEXT,
                video_url TEXT,
                view_count INTEGER,
                created_at INTEGER
            );
            INSERT INTO clip VALUES('clip1','Epic Play','shroud','fan1','https://clips.twitch.tv/xyz',50000,1609459400000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_follows_watch_clips() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Twitch Follow"));
        assert!(r.iter().any(|a| a.subcategory == "Twitch Watch"));
        assert!(r.iter().any(|a| a.subcategory == "Twitch Clip"));
    }

    #[test]
    fn watch_duration_captured() {
        let db = make_db();
        let r = parse(db.path());
        let w = r.iter().find(|a| a.subcategory == "Twitch Watch").unwrap();
        assert!(w.detail.contains("duration=3600s"));
        assert!(w.detail.contains("game='Valorant'"));
    }

    #[test]
    fn clip_view_count_captured() {
        let db = make_db();
        let r = parse(db.path());
        let c = r.iter().find(|a| a.subcategory == "Twitch Clip").unwrap();
        assert!(c.detail.contains("view_count=50000"));
        assert!(c.detail.contains("broadcaster='shroud'"));
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
