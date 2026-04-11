//! Garmin Connect — activity history extraction.
//!
//! ALEAPP reference: `scripts/artifacts/GarminActivities.py`. Source path:
//! `/data/data/com.garmin.android.apps.connectmobile/databases/cache-database`.
//!
//! Key tables: `activity_summaries`, `activity_details`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.garmin.android.apps.connectmobile/databases/cache-database"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "activity_summaries") {
        return Vec::new();
    }
    read_activities(&conn, path)
}

fn read_activities(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT activityId, activityName, activityTypeKey, \
               startTimeGMT, distance, duration, \
               startLatitude, startLongitude, calories, averageHR, steps \
               FROM activity_summaries \
               ORDER BY startTimeGMT DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<f64>>(4).unwrap_or(None),
            row.get::<_, Option<f64>>(5).unwrap_or(None),
            row.get::<_, Option<f64>>(6).unwrap_or(None),
            row.get::<_, Option<f64>>(7).unwrap_or(None),
            row.get::<_, Option<f64>>(8).unwrap_or(None),
            row.get::<_, Option<f64>>(9).unwrap_or(None),
            row.get::<_, Option<i64>>(10).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, name, kind, start_gmt, distance, duration, lat, lon, calories, avg_hr, steps) in rows.flatten() {
        let id = id.unwrap_or(0);
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let kind = kind.unwrap_or_else(|| "activity".to_string());
        let ts = start_gmt; // Unix epoch seconds
        let title = format!("Garmin {}: {}", kind, name);
        let mut detail = format!(
            "Garmin activity id={} type='{}' name='{}'",
            id, kind, name
        );
        if let Some(d) = distance {
            detail.push_str(&format!(" distance={:.2}m", d));
        }
        if let Some(d) = duration {
            detail.push_str(&format!(" duration={:.0}s", d));
        }
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" start_lat={:.6} start_lon={:.6}", la, lo));
        }
        if let Some(c) = calories {
            detail.push_str(&format!(" calories={:.0}", c));
        }
        if let Some(hr) = avg_hr {
            detail.push_str(&format!(" avg_hr={:.0}", hr));
        }
        if let Some(s) = steps {
            detail.push_str(&format!(" steps={}", s));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Garmin Activity",
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
            CREATE TABLE activity_summaries (
                activityId INTEGER PRIMARY KEY,
                activityName TEXT,
                activityTypeKey TEXT,
                startTimeGMT INTEGER,
                distance REAL,
                duration REAL,
                startLatitude REAL,
                startLongitude REAL,
                calories REAL,
                averageHR REAL,
                maxHR REAL,
                steps INTEGER,
                averageRunningCadenceInStepsPerMinute REAL,
                maxRunningCadenceInStepsPerMinute REAL,
                averageSpeed REAL,
                maxSpeed REAL,
                vO2MaxValue REAL,
                movingDuration REAL,
                elevationGain REAL,
                elevationLoss REAL
            );
            INSERT INTO activity_summaries VALUES(1001,'Morning Run','running',1609459200,5000.0,1800.0,37.7749,-122.4194,450.0,145.0,170.0,6500,165.0,180.0,2.77,3.5,45.0,1700.0,50.0,45.0);
            INSERT INTO activity_summaries VALUES(1002,'Bike Loop','cycling',1609545600,15000.0,3600.0,37.7700,-122.4000,600.0,135.0,160.0,0,NULL,NULL,4.16,6.5,NULL,3500.0,250.0,240.0);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_two_activities() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|a| a.subcategory == "Garmin Activity"));
    }

    #[test]
    fn activity_type_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("running") && a.title.contains("Morning Run")));
        assert!(r.iter().any(|a| a.title.contains("cycling")));
    }

    #[test]
    fn gps_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let run = r.iter().find(|a| a.detail.contains("Morning Run")).unwrap();
        assert!(run.detail.contains("start_lat=37.774900"));
        assert!(run.detail.contains("distance=5000.00m"));
        assert!(run.detail.contains("steps=6500"));
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
