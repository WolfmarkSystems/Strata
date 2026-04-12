//! Calm — meditation app session history.
//!
//! Source path: `/data/data/com.calm.android/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Calm caches played meditation
//! sessions, sleep stories, favorites, and mood check-ins.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.calm.android/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["play_history", "session_history", "listen_history"] {
        if table_exists(&conn, table) {
            out.extend(read_history(&conn, path, table));
            break;
        }
    }
    if table_exists(&conn, "mood_check_in") {
        out.extend(read_moods(&conn, path));
    }
    out
}

fn read_history(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, content_title, content_type, played_at, \
         duration_played, completed \
         FROM \"{table}\" ORDER BY played_at DESC LIMIT 5000",
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
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, content_title, content_type, ts_ms, duration, completed) in rows.flatten() {
        let id = id.unwrap_or_default();
        let content_title = content_title.unwrap_or_else(|| "(unknown)".to_string());
        let content_type = content_type.unwrap_or_default();
        let duration = duration.unwrap_or(0);
        let completed = completed.unwrap_or(0) != 0;
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Calm: {} ({}s)", content_title, duration);
        let detail = format!(
            "Calm play history id='{}' content_title='{}' content_type='{}' duration_played={} completed={}",
            id, content_title, content_type, duration, completed
        );
        out.push(build_record(
            ArtifactCategory::Media,
            "Calm Session",
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

fn read_moods(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, timestamp, mood, note \
               FROM mood_check_in ORDER BY timestamp DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, ts_ms, mood, note) in rows.flatten() {
        let id = id.unwrap_or_default();
        let mood = mood.unwrap_or_else(|| "(unknown)".to_string());
        let note = note.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Calm mood: {}", mood);
        let detail = format!(
            "Calm mood check-in id='{}' mood='{}' note='{}'",
            id, mood, note
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Calm Mood",
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
            CREATE TABLE play_history (
                id TEXT,
                content_title TEXT,
                content_type TEXT,
                played_at INTEGER,
                duration_played INTEGER,
                completed INTEGER
            );
            INSERT INTO play_history VALUES('p1','Daily Calm','meditation',1609459200000,600,1);
            INSERT INTO play_history VALUES('p2','Sleep Story: Blue Gold','sleep_story',1609459300000,1500,0);
            CREATE TABLE mood_check_in (
                id TEXT,
                timestamp INTEGER,
                mood TEXT,
                note TEXT
            );
            INSERT INTO mood_check_in VALUES('m1',1609459400000,'anxious','Big presentation tomorrow');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_history_and_moods() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Calm Session"));
        assert!(r.iter().any(|a| a.subcategory == "Calm Mood"));
    }

    #[test]
    fn completed_flag_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("completed=true")));
        assert!(r.iter().any(|a| a.detail.contains("completed=false")));
    }

    #[test]
    fn mood_note_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("note='Big presentation tomorrow'")));
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
