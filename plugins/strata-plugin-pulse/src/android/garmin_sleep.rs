//! Garmin Connect — sleep tracking extraction.
//!
//! ALEAPP reference: `scripts/artifacts/GarminSleep.py`. Source path:
//! `/data/data/com.garmin.android.apps.connectmobile/databases/cache-database`.
//!
//! Key table: `sleep_detail`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.garmin.android.apps.connectmobile/databases/cache-database"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "sleep_detail") {
        return Vec::new();
    }
    read_sleep(&conn, path)
}

fn read_sleep(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT calendarDate, sleepStartTimeGMT, sleepEndTimeGMT, \
               sleepTimeInSeconds, deepSleepSeconds, lightSleepSeconds, \
               remSleepSeconds, awakeSleepSeconds, averageSpO2Value \
               FROM sleep_detail \
               ORDER BY sleepStartTimeGMT DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
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
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<i64>>(6).unwrap_or(None),
            row.get::<_, Option<i64>>(7).unwrap_or(None),
            row.get::<_, Option<f64>>(8).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (date, start, _end, total, deep, light, rem, awake, spo2) in rows.flatten() {
        let date = date.unwrap_or_else(|| "(unknown)".to_string());
        let ts = start; // Unix epoch seconds
        let hours = total.unwrap_or(0) as f64 / 3600.0;
        let title = format!("Garmin sleep {} ({:.1}h)", date, hours);
        let mut detail = format!("Garmin sleep date='{}' total={}s", date, total.unwrap_or(0));
        if let Some(d) = deep {
            detail.push_str(&format!(" deep={}s", d));
        }
        if let Some(l) = light {
            detail.push_str(&format!(" light={}s", l));
        }
        if let Some(r) = rem {
            detail.push_str(&format!(" rem={}s", r));
        }
        if let Some(a) = awake {
            detail.push_str(&format!(" awake={}s", a));
        }
        if let Some(o) = spo2 {
            detail.push_str(&format!(" spo2={:.0}", o));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Garmin Sleep",
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
            CREATE TABLE sleep_detail (
                calendarDate TEXT,
                sleepStartTimeGMT INTEGER,
                sleepEndTimeGMT INTEGER,
                sleepTimeInSeconds INTEGER,
                deepSleepSeconds INTEGER,
                lightSleepSeconds INTEGER,
                remSleepSeconds INTEGER,
                awakeSleepSeconds INTEGER,
                averageSpO2Value REAL,
                averageSpO2HRSleep REAL
            );
            INSERT INTO sleep_detail VALUES('2021-01-01',1609459200,1609487200,28000,5400,15000,7200,400,96.5,95.0);
            INSERT INTO sleep_detail VALUES('2021-01-02',1609545600,1609572000,26400,4800,14400,6800,400,97.0,96.0);
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
        assert!(r.iter().all(|a| a.subcategory == "Garmin Sleep"));
    }

    #[test]
    fn hours_in_title() {
        let db = make_db();
        let r = parse(db.path());
        // 28000 / 3600 = 7.78h
        assert!(r.iter().any(|a| a.title.contains("7.8h")));
    }

    #[test]
    fn sleep_phases_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let d1 = r.iter().find(|a| a.detail.contains("2021-01-01")).unwrap();
        assert!(d1.detail.contains("deep=5400s"));
        assert!(d1.detail.contains("rem=7200s"));
        assert!(d1.detail.contains("spo2="));
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
