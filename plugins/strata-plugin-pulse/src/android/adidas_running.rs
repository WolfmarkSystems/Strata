//! Adidas Running (Runtastic) — session extraction.
//!
//! ALEAPP reference: `scripts/artifacts/AdidasActivities.py`. Source path:
//! `/data/data/com.runtastic.android/databases/db*`.
//!
//! Key table: `session`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.runtastic.android/databases/db"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "session") {
        return Vec::new();
    }
    read_sessions(&conn, path)
}

fn read_sessions(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT sampleId, userId, distance, startTime, endTime, \
               runtime, maxSpeed, calories, avgPulse, maxPulse, \
               firstLatitude, firstLongitude, note \
               FROM session \
               ORDER BY startTime DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<f64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<f64>>(6).unwrap_or(None),
            row.get::<_, Option<f64>>(7).unwrap_or(None),
            row.get::<_, Option<f64>>(8).unwrap_or(None),
            row.get::<_, Option<f64>>(9).unwrap_or(None),
            row.get::<_, Option<f64>>(10).unwrap_or(None),
            row.get::<_, Option<f64>>(11).unwrap_or(None),
            row.get::<_, Option<String>>(12).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (sample, user, distance, start_ms, _end_ms, runtime_ms, _max_speed, calories, avg_pulse, max_pulse, lat, lon, note) in rows.flatten() {
        let sample = sample.unwrap_or_else(|| "(unknown)".to_string());
        let user = user.unwrap_or_default();
        let ts = start_ms.and_then(unix_ms_to_i64);
        let runtime_s = runtime_ms.unwrap_or(0) / 1000;
        let distance_m = distance.unwrap_or(0.0);
        let title = format!("Adidas run {} ({:.0}m, {}s)", sample, distance_m, runtime_s);
        let mut detail = format!(
            "Adidas Runtastic session sample='{}' user='{}' distance={:.0}m runtime={}s",
            sample, user, distance_m, runtime_s
        );
        if let Some(c) = calories {
            detail.push_str(&format!(" calories={:.0}", c));
        }
        if let (Some(a), Some(m)) = (avg_pulse, max_pulse) {
            detail.push_str(&format!(" hr_avg={:.0} hr_max={:.0}", a, m));
        }
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" start_lat={:.6} start_lon={:.6}", la, lo));
        }
        if let Some(n) = note.filter(|n| !n.is_empty()) {
            detail.push_str(&format!(" note='{}'", n));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Adidas Running",
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
            CREATE TABLE session (
                sampleId TEXT PRIMARY KEY,
                userId TEXT,
                distance REAL,
                startTime INTEGER,
                endTime INTEGER,
                runtime INTEGER,
                maxSpeed REAL,
                calories REAL,
                avgPulse REAL,
                maxPulse REAL,
                firstLatitude REAL,
                firstLongitude REAL,
                note TEXT,
                encodedTrace TEXT,
                temperature REAL,
                maxElevation REAL,
                minElevation REAL,
                humidity REAL
            );
            INSERT INTO session VALUES('run_001','user_42',5000.0,1609459200000,1609461000000,1800000,4.2,420.0,145.0,170.0,37.7749,-122.4194,'Morning jog',NULL,15.0,50.0,10.0,60.0);
            INSERT INTO session VALUES('run_002','user_42',10000.0,1609545600000,1609549200000,3600000,5.5,800.0,150.0,175.0,37.7700,-122.4000,NULL,NULL,18.0,100.0,20.0,55.0);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_two_sessions() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|a| a.subcategory == "Adidas Running"));
    }

    #[test]
    fn heart_rate_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let s1 = r.iter().find(|a| a.detail.contains("run_001")).unwrap();
        assert!(s1.detail.contains("hr_avg=145 hr_max=170"));
        assert!(s1.detail.contains("note='Morning jog'"));
    }

    #[test]
    fn distance_and_runtime_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("10000m") && a.title.contains("3600s")));
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
