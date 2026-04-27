//! Puma Trac — completed exercise extraction.
//!
//! ALEAPP reference: `scripts/artifacts/PumaActivities.py`. Source path:
//! `/data/data/com.pumapumatrac/databases/pumatrac-db*`.
//!
//! Key tables: `completed_exercises`, `positions`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.pumapumatrac/databases/pumatrac-db"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "completed_exercises") {
        return Vec::new();
    }
    read_exercises(&conn, path)
}

fn read_exercises(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, startTime, endTime, duration, score, calories, \
               city, country, distance, maxSpeed, meanSpeed, \
               averageTimePerKm, runLocationType \
               FROM completed_exercises \
               ORDER BY startTime DESC LIMIT 5000";
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
            row.get::<_, Option<f64>>(4).unwrap_or(None),
            row.get::<_, Option<f64>>(5).unwrap_or(None),
            row.get::<_, Option<String>>(6).unwrap_or(None),
            row.get::<_, Option<String>>(7).unwrap_or(None),
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
    for (
        id,
        start_ms,
        _end_ms,
        dur_ms,
        score,
        calories,
        city,
        country,
        distance,
        _max_speed,
        mean_speed,
        _pace,
        loc_type,
    ) in rows.flatten()
    {
        let id = id.unwrap_or_else(|| "(unknown)".to_string());
        let ts = start_ms.and_then(unix_ms_to_i64);
        let dur_s = dur_ms.unwrap_or(0) / 1000;
        let dist_m = distance.unwrap_or(0.0);
        let city = city.unwrap_or_default();
        let country = country.unwrap_or_default();
        let loc = loc_type.unwrap_or_default();
        let title = format!("Puma exercise {} ({:.0}m, {}s)", id, dist_m, dur_s);
        let mut detail = format!(
            "Puma Trac exercise id='{}' distance={:.0}m duration={}s",
            id, dist_m, dur_s
        );
        if let Some(s) = score {
            detail.push_str(&format!(" score={:.0}", s));
        }
        if let Some(c) = calories {
            detail.push_str(&format!(" calories={:.0}", c));
        }
        if let Some(ms) = mean_speed {
            detail.push_str(&format!(" mean_speed={:.2}", ms));
        }
        if !city.is_empty() {
            detail.push_str(&format!(" city='{}'", city));
        }
        if !country.is_empty() {
            detail.push_str(&format!(" country='{}'", country));
        }
        if !loc.is_empty() {
            detail.push_str(&format!(" location_type='{}'", loc));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Puma Trac",
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
            CREATE TABLE completed_exercises (
                id TEXT PRIMARY KEY,
                startTime INTEGER,
                endTime INTEGER,
                duration INTEGER,
                score REAL,
                calories REAL,
                city TEXT,
                country TEXT,
                distance REAL,
                maxAltitude REAL,
                meanAltitude REAL,
                maxSpeed REAL,
                meanSpeed REAL,
                averageTimePerKm REAL,
                runLocationType TEXT,
                currentPace REAL
            );
            INSERT INTO completed_exercises VALUES('puma_1',1609459200000,1609461000000,1800000,85.5,300.0,'San Francisco','USA',5000.0,50.0,25.0,4.2,2.77,360.0,'outdoor',6.0);
            INSERT INTO completed_exercises VALUES('puma_2',1609545600000,1609548000000,2400000,90.0,450.0,'Oakland','USA',8000.0,80.0,40.0,5.0,3.33,300.0,'outdoor',5.0);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_two_exercises() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|a| a.subcategory == "Puma Trac"));
    }

    #[test]
    fn city_and_country_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let p1 = r.iter().find(|a| a.detail.contains("puma_1")).unwrap();
        assert!(p1.detail.contains("city='San Francisco'"));
        assert!(p1.detail.contains("country='USA'"));
    }

    #[test]
    fn score_and_calories_captured() {
        let db = make_db();
        let r = parse(db.path());
        let p2 = r.iter().find(|a| a.detail.contains("puma_2")).unwrap();
        assert!(p2.detail.contains("score=90"));
        assert!(p2.detail.contains("calories=450"));
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
