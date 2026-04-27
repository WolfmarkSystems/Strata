//! Runkeeper — trip (activity) extraction.
//!
//! ALEAPP reference: `scripts/artifacts/RunkeeperActivities.py`. Source path:
//! `/data/data/com.fitnesskeeper.runkeeper.pro/databases/RunKeeper.sqlite`.
//!
//! Key tables: `trips`, `points`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.fitnesskeeper.runkeeper.pro/databases/runkeeper.sqlite"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "trips") {
        return Vec::new();
    }
    read_trips(&conn, path)
}

fn read_trips(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT _id, start_date, activity_type, distance, \
               elapsed_time, calories, heart_rate, totalClimb, \
               uuid, nickname \
               FROM trips \
               ORDER BY start_date DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<f64>>(3).unwrap_or(None),
            row.get::<_, Option<f64>>(4).unwrap_or(None),
            row.get::<_, Option<f64>>(5).unwrap_or(None),
            row.get::<_, Option<f64>>(6).unwrap_or(None),
            row.get::<_, Option<f64>>(7).unwrap_or(None),
            row.get::<_, Option<String>>(8).unwrap_or(None),
            row.get::<_, Option<String>>(9).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, start, kind, distance, elapsed, calories, hr, climb, uuid, nickname) in rows.flatten()
    {
        let id = id.unwrap_or(0);
        let kind = kind.unwrap_or_else(|| "activity".to_string());
        // RunKeeper uses milliseconds
        let ts = start.and_then(unix_ms_to_i64);
        let nickname = nickname.unwrap_or_else(|| "(unnamed)".to_string());
        let title = format!("Runkeeper {}: {}", kind, nickname);
        let mut detail = format!(
            "Runkeeper trip id={} type='{}' nickname='{}'",
            id, kind, nickname
        );
        if let Some(d) = distance {
            detail.push_str(&format!(" distance={:.0}m", d));
        }
        if let Some(e) = elapsed {
            detail.push_str(&format!(" elapsed={:.0}s", e));
        }
        if let Some(c) = calories {
            detail.push_str(&format!(" calories={:.0}", c));
        }
        if let Some(h) = hr {
            detail.push_str(&format!(" avg_hr={:.0}", h));
        }
        if let Some(c) = climb {
            detail.push_str(&format!(" total_climb={:.0}m", c));
        }
        if let Some(u) = uuid.filter(|u| !u.is_empty()) {
            detail.push_str(&format!(" uuid='{}'", u));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Runkeeper Trip",
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
            CREATE TABLE trips (
                _id INTEGER PRIMARY KEY,
                start_date INTEGER,
                device_sync_time INTEGER,
                distance REAL,
                elapsed_time REAL,
                activity_type TEXT,
                calories REAL,
                heart_rate REAL,
                totalClimb REAL,
                uuid TEXT,
                nickname TEXT
            );
            INSERT INTO trips VALUES(1,1609459200000,1609459200000,5000.0,1800.0,'Running',420.0,145.0,50.0,'abc-123','Morning run');
            INSERT INTO trips VALUES(2,1609545600000,1609545600000,20000.0,3600.0,'Cycling',700.0,135.0,200.0,'def-456','Weekend ride');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_two_trips() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|a| a.subcategory == "Runkeeper Trip"));
    }

    #[test]
    fn nickname_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("Morning run")));
    }

    #[test]
    fn uuid_and_climb_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let t1 = r.iter().find(|a| a.detail.contains("id=1")).unwrap();
        assert!(t1.detail.contains("uuid='abc-123'"));
        assert!(t1.detail.contains("total_climb=50m"));
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
