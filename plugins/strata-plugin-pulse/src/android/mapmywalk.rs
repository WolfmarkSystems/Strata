//! Map My Walk — workout GPS trail extraction.
//!
//! ALEAPP reference: `scripts/artifacts/MMWActivities.py`. Source path:
//! `/data/data/com.mapmywalk.android2/databases/workout.db`.
//!
//! Key table: `timeSeries`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.mapmywalk.android2/databases/workout.db"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "timeSeries") {
        return Vec::new();
    }
    read_series(&conn, path)
}

fn read_series(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT localId, timestamp, distance, speed, \
               latitude, longitude, timeOffset \
               FROM timeSeries \
               ORDER BY timestamp DESC LIMIT 20000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<f64>>(2).unwrap_or(None),
            row.get::<_, Option<f64>>(3).unwrap_or(None),
            row.get::<_, Option<f64>>(4).unwrap_or(None),
            row.get::<_, Option<f64>>(5).unwrap_or(None),
            row.get::<_, Option<i64>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (local_id, ts, distance, speed, lat, lon, offset) in rows.flatten() {
        let local_id = local_id.unwrap_or(0);
        // timestamp is commonly seconds in MMW
        let title = format!("MapMyWalk point #{}", local_id);
        let mut detail = format!("MapMyWalk time series local_id={}", local_id);
        if let Some(d) = distance {
            detail.push_str(&format!(" distance={:.2}m", d));
        }
        if let Some(s) = speed {
            detail.push_str(&format!(" speed={:.2}", s));
        }
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" lat={:.6} lon={:.6}", la, lo));
        }
        if let Some(o) = offset {
            detail.push_str(&format!(" offset={}", o));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "MapMyWalk Point",
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
            CREATE TABLE timeSeries (
                localId INTEGER,
                timestamp INTEGER,
                distance REAL,
                speed REAL,
                latitude REAL,
                longitude REAL,
                timeOffset INTEGER
            );
            INSERT INTO timeSeries VALUES(1,1609459200,100.0,1.5,37.7749,-122.4194,0);
            INSERT INTO timeSeries VALUES(2,1609459210,150.5,1.8,37.7750,-122.4195,10);
            INSERT INTO timeSeries VALUES(3,1609459220,210.0,1.6,37.7751,-122.4196,20);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_three_points() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|a| a.subcategory == "MapMyWalk Point"));
    }

    #[test]
    fn gps_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("lat=37.774900")));
    }

    #[test]
    fn distance_and_speed_captured() {
        let db = make_db();
        let r = parse(db.path());
        let p2 = r.iter().find(|a| a.detail.contains("local_id=2")).unwrap();
        assert!(p2.detail.contains("distance=150.50m"));
        assert!(p2.detail.contains("speed=1.80"));
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
