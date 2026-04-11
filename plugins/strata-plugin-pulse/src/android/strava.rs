//! Strava — GPS activity and segment extraction.
//!
//! ALEAPP reference: `scripts/artifacts/StravaGPS.py`. Source path:
//! `/data/data/com.strava/databases/strava.db*`.
//!
//! Key tables: `activity`, `segments`, `athletes`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.strava/databases/strava.db",
    "com.strava/databases/activity",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "activity") {
        out.extend(read_activities(&conn, path));
    }
    if table_exists(&conn, "segments") {
        out.extend(read_segments(&conn, path));
    }
    out
}

fn read_activities(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT _id, name, activity_type, start_timestamp, \
               distance, moving_time, start_latitude, start_longitude, \
               total_elevation_gain \
               FROM activity \
               ORDER BY start_timestamp DESC LIMIT 5000";
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
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<f64>>(6).unwrap_or(None),
            row.get::<_, Option<f64>>(7).unwrap_or(None),
            row.get::<_, Option<f64>>(8).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, name, kind, ts_ms, distance, moving, lat, lon, elev) in rows.flatten() {
        let id = id.unwrap_or(0);
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let kind = kind.unwrap_or_else(|| "activity".to_string());
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Strava {}: {}", kind, name);
        let mut detail = format!(
            "Strava activity id={} type='{}' name='{}'",
            id, kind, name
        );
        if let Some(d) = distance {
            detail.push_str(&format!(" distance={:.0}m", d));
        }
        if let Some(m) = moving {
            detail.push_str(&format!(" moving_time={}s", m));
        }
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" start_lat={:.6} start_lon={:.6}", la, lo));
        }
        if let Some(e) = elev {
            detail.push_str(&format!(" elevation_gain={:.0}m", e));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Strava Activity",
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

fn read_segments(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT _id, name, activity_type, distance, \
               start_latitude, start_longitude \
               FROM segments LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<f64>>(3).unwrap_or(None),
            row.get::<_, Option<f64>>(4).unwrap_or(None),
            row.get::<_, Option<f64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, name, kind, distance, lat, lon) in rows.flatten() {
        let id = id.unwrap_or(0);
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let kind = kind.unwrap_or_default();
        let title = format!("Strava segment: {}", name);
        let mut detail = format!("Strava segment id={} name='{}' type='{}'", id, name, kind);
        if let Some(d) = distance {
            detail.push_str(&format!(" distance={:.0}m", d));
        }
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" lat={:.6} lon={:.6}", la, lo));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Strava Segment",
            title,
            detail,
            path,
            None,
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
            CREATE TABLE activity (
                _id INTEGER PRIMARY KEY,
                name TEXT,
                activity_type TEXT,
                start_timestamp INTEGER,
                distance REAL,
                moving_time INTEGER,
                start_latitude REAL,
                start_longitude REAL,
                total_elevation_gain REAL
            );
            INSERT INTO activity VALUES(1,'Morning Run','Run',1609459200000,5000.0,1800,37.7749,-122.4194,50.0);
            INSERT INTO activity VALUES(2,'Hill Climb','Ride',1609545600000,25000.0,5400,37.7700,-122.4000,350.0);
            CREATE TABLE segments (
                _id INTEGER PRIMARY KEY,
                name TEXT,
                activity_type TEXT,
                distance REAL,
                start_latitude REAL,
                start_longitude REAL
            );
            INSERT INTO segments VALUES(100,'Park Loop','Run',1000.0,37.7749,-122.4194);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_activities_and_segments() {
        let db = make_db();
        let r = parse(db.path());
        let acts: Vec<_> = r.iter().filter(|a| a.subcategory == "Strava Activity").collect();
        let segs: Vec<_> = r.iter().filter(|a| a.subcategory == "Strava Segment").collect();
        assert_eq!(acts.len(), 2);
        assert_eq!(segs.len(), 1);
    }

    #[test]
    fn elevation_and_distance_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let hill = r.iter().find(|a| a.detail.contains("Hill Climb")).unwrap();
        assert!(hill.detail.contains("elevation_gain=350m"));
        assert!(hill.detail.contains("distance=25000m"));
    }

    #[test]
    fn start_coordinates_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("start_lat=37.774900")));
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
