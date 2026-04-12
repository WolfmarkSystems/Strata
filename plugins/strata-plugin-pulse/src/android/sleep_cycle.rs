//! Sleep Cycle — sleep session and health metrics extraction.
//!
//! Source path: `/data/data/com.northcube.sleepcycle/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Sleep Cycle stores sleep sessions
//! in SQLite with tables like `sleep_session`, `sleep_data`, or `sessions`.
//! Sleep timestamps can establish alibi evidence or corroborate timelines.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.northcube.sleepcycle/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["sleep_session", "sleep_data", "sessions", "session"] {
        if table_exists(&conn, table) {
            out.extend(read_sessions(&conn, path, table));
            break;
        }
    }
    out
}

fn read_sessions(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT bedtime, wake_time, quality_score, snoring_minutes, notes \
         FROM \"{table}\" ORDER BY bedtime DESC LIMIT 5000",
        table = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<f64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (bedtime_ms, wake_ms, quality, snoring_min, notes) in rows.flatten() {
        let quality = quality.unwrap_or(0.0);
        let snoring = snoring_min.unwrap_or(0);
        let notes = notes.unwrap_or_default();
        let ts = bedtime_ms.and_then(unix_ms_to_i64);
        let title = format!("Sleep Cycle session: quality {:.0}%", quality);
        let mut detail = format!(
            "Sleep Cycle session quality_score={:.1} snoring_minutes={}",
            quality, snoring
        );
        if let Some(wake) = wake_ms.and_then(unix_ms_to_i64) {
            detail.push_str(&format!(" wake_time={}", wake));
        }
        if !notes.is_empty() {
            detail.push_str(&format!(" notes='{}'", notes));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Sleep Cycle Session",
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
            CREATE TABLE sleep_session (
                bedtime INTEGER,
                wake_time INTEGER,
                quality_score REAL,
                snoring_minutes INTEGER,
                notes TEXT
            );
            INSERT INTO sleep_session VALUES(1609394400000,1609423200000,82.5,12,'Felt rested');
            INSERT INTO sleep_session VALUES(1609480800000,1609509600000,65.0,0,NULL);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_sessions() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.iter().filter(|a| a.subcategory == "Sleep Cycle Session").count(), 2);
    }

    #[test]
    fn quality_score_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("quality_score=82.5")));
    }

    #[test]
    fn notes_captured_when_present() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("notes='Felt rested'")));
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
