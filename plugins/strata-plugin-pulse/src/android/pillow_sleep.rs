//! Pillow — sleep sessions and audio recordings.
//!
//! Source path: `/data/data/com.neybox.pillow/databases/`.
//!
//! Schema note: not in ALEAPP upstream. Pillow tracks sleep sessions with
//! biometric data and records ambient audio during sleep. Session data
//! establishes presence/absence (alibi); audio recordings prove physical
//! presence at the device and may capture conversations.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.neybox.pillow/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["sleep_sessions", "sleepsession", "session"] {
        if table_exists(&conn, table) {
            out.extend(read_sessions(&conn, path, table));
            break;
        }
    }
    for table in &["sleep_audio", "sleepaudio", "audio_recordings"] {
        if table_exists(&conn, table) {
            out.extend(read_audio(&conn, path, table));
            break;
        }
    }
    out
}

fn read_sessions(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT bedtime, wake_time, duration, quality_score, \
         heart_rate_avg, movement_count, notes \
         FROM \"{t}\" ORDER BY bedtime DESC LIMIT 5000",
        t = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<f64>>(3).unwrap_or(None),
            row.get::<_, Option<f64>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<String>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (bedtime_ms, wake_ms, duration_s, quality, hr_avg, movement, notes) in rows.flatten() {
        let ts = bedtime_ms.and_then(unix_ms_to_i64);
        let wake_epoch = wake_ms.and_then(unix_ms_to_i64).unwrap_or(0);
        let duration_s = duration_s.unwrap_or(0);
        let quality = quality.unwrap_or(0.0);
        let hr_avg = hr_avg.unwrap_or(0.0);
        let movement = movement.unwrap_or(0);
        let notes = notes.unwrap_or_default();
        let hours = duration_s / 3600;
        let mins = (duration_s % 3600) / 60;
        let title = format!("Pillow sleep: {}h {}m quality={:.0}", hours, mins, quality);
        let mut detail = format!(
            "Pillow sleep_session duration={}s quality_score={:.1} heart_rate_avg={:.1} movement_count={}",
            duration_s, quality, hr_avg, movement
        );
        detail.push_str(&format!(" wake_time={}", wake_epoch));
        if !notes.is_empty() {
            detail.push_str(&format!(" notes='{}'", notes));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Pillow Sleep Session",
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

fn read_audio(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT recording_path, duration, snore_count, talk_count, timestamp \
         FROM \"{t}\" ORDER BY timestamp DESC LIMIT 5000",
        t = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (recording_path, duration_s, snore_count, talk_count, ts_ms) in rows.flatten() {
        let recording_path = recording_path.unwrap_or_default();
        let duration_s = duration_s.unwrap_or(0);
        let snore_count = snore_count.unwrap_or(0);
        let talk_count = talk_count.unwrap_or(0);
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!(
            "Pillow audio: {}s snores={} talk={}",
            duration_s, snore_count, talk_count
        );
        let detail = format!(
            "Pillow sleep_audio recording_path='{}' duration={}s snore_count={} talk_count={}",
            recording_path, duration_s, snore_count, talk_count
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Pillow Sleep Audio",
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
            CREATE TABLE sleep_sessions (
                bedtime INTEGER,
                wake_time INTEGER,
                duration INTEGER,
                quality_score REAL,
                heart_rate_avg REAL,
                movement_count INTEGER,
                notes TEXT
            );
            INSERT INTO sleep_sessions VALUES(1609416000000,1609444800000,28800,82.5,58.3,14,'Felt rested');
            CREATE TABLE sleep_audio (
                recording_path TEXT,
                duration INTEGER,
                snore_count INTEGER,
                talk_count INTEGER,
                timestamp INTEGER
            );
            INSERT INTO sleep_audio VALUES('/storage/emulated/0/Pillow/rec001.m4a',45,3,1,1609430000000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_session_and_audio() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Pillow Sleep Session"));
        assert!(r.iter().any(|a| a.subcategory == "Pillow Sleep Audio"));
    }

    #[test]
    fn session_quality_in_title() {
        let db = make_db();
        let r = parse(db.path());
        let s = r
            .iter()
            .find(|a| a.subcategory == "Pillow Sleep Session")
            .unwrap();
        assert!(s.title.contains("quality=82"));
        assert!(s.detail.contains("heart_rate_avg=58.3"));
    }

    #[test]
    fn audio_recording_path_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let a = r
            .iter()
            .find(|a| a.subcategory == "Pillow Sleep Audio")
            .unwrap();
        assert!(a
            .detail
            .contains("recording_path='/storage/emulated/0/Pillow/rec001.m4a'"));
        assert!(a.detail.contains("talk_count=1"));
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
