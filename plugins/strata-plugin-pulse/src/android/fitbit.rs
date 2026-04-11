//! Fitbit — activity, exercise, and sleep extraction.
//!
//! ALEAPP reference: `scripts/artifacts/fitbit.py`. Source paths:
//! - `/data/data/com.fitbit.FitbitMobile/databases/activity_db`
//! - `/data/data/com.fitbit.FitbitMobile/databases/exercise_db`
//! - `/data/data/com.fitbit.FitbitMobile/databases/heart_rate_db`
//!
//! Key tables: `ACTIVITY_LOG_ENTRY`, `EXERCISE_EVENT`, `HEART_RATE_DAILY_SUMMARY`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.fitbit.fitbitmobile/databases/activity_db",
    "com.fitbit.fitbitmobile/databases/exercise_db",
    "com.fitbit.fitbitmobile/databases/heart_rate_db",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "ACTIVITY_LOG_ENTRY") {
        out.extend(read_activity_log(&conn, path));
    }
    if table_exists(&conn, "EXERCISE_EVENT") {
        out.extend(read_exercise_events(&conn, path));
    }
    if table_exists(&conn, "HEART_RATE_DAILY_SUMMARY") {
        out.extend(read_heart_rate(&conn, path));
    }
    out
}

fn read_activity_log(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT LOG_DATE, TIME_CREATED, NAME, LOG_TYPE, \
               SPEED, PACE, CALORIES, STEPS, DISTANCE, HEART_RATE \
               FROM ACTIVITY_LOG_ENTRY \
               ORDER BY TIME_CREATED DESC LIMIT 5000";
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
            row.get::<_, Option<f64>>(4).unwrap_or(None),
            row.get::<_, Option<f64>>(5).unwrap_or(None),
            row.get::<_, Option<f64>>(6).unwrap_or(None),
            row.get::<_, Option<i64>>(7).unwrap_or(None),
            row.get::<_, Option<f64>>(8).unwrap_or(None),
            row.get::<_, Option<f64>>(9).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (date, created_ms, name, kind, _speed, _pace, calories, steps, distance, hr) in rows.flatten() {
        let date = date.unwrap_or_default();
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let kind = kind.unwrap_or_default();
        let ts = created_ms.and_then(unix_ms_to_i64);
        let title = format!("Fitbit {}: {}", kind, name);
        let mut detail = format!(
            "Fitbit activity date='{}' name='{}' type='{}'",
            date, name, kind
        );
        if let Some(c) = calories {
            detail.push_str(&format!(" calories={:.0}", c));
        }
        if let Some(s) = steps {
            detail.push_str(&format!(" steps={}", s));
        }
        if let Some(d) = distance {
            detail.push_str(&format!(" distance={:.0}m", d));
        }
        if let Some(h) = hr {
            detail.push_str(&format!(" avg_hr={:.0}", h));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Fitbit Activity",
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

fn read_exercise_events(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT TIME, LABEL, LATITUDE, LONGITUDE, ALTITUDE, SPEED, SESSION_ID \
               FROM EXERCISE_EVENT \
               ORDER BY TIME DESC LIMIT 20000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
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
    for (time_ms, label, lat, lon, alt, speed, session) in rows.flatten() {
        let label = label.unwrap_or_else(|| "exercise".to_string());
        let ts = time_ms.and_then(unix_ms_to_i64);
        let session = session.unwrap_or(0);
        let title = format!("Fitbit exercise event: {}", label);
        let mut detail = format!(
            "Fitbit exercise event label='{}' session={}",
            label, session
        );
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" lat={:.6} lon={:.6}", la, lo));
        }
        if let Some(a) = alt {
            detail.push_str(&format!(" altitude={:.1}", a));
        }
        if let Some(s) = speed {
            detail.push_str(&format!(" speed={:.2}", s));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Fitbit Exercise Event",
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

fn read_heart_rate(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT DATE_TIME, AVERAGE_HEART_RATE, RESTING_HEART_RATE \
               FROM HEART_RATE_DAILY_SUMMARY \
               ORDER BY DATE_TIME DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<f64>>(1).unwrap_or(None),
            row.get::<_, Option<f64>>(2).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (date_ms, avg, rest) in rows.flatten() {
        let ts = date_ms.and_then(unix_ms_to_i64);
        let avg = avg.unwrap_or(0.0);
        let rest = rest.unwrap_or(0.0);
        let title = format!("Fitbit HR: avg={:.0} rest={:.0}", avg, rest);
        let detail = format!(
            "Fitbit heart rate daily avg_hr={:.0} resting_hr={:.0}",
            avg, rest
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Fitbit Heart Rate",
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

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn make_db() -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE ACTIVITY_LOG_ENTRY (
                LOG_DATE TEXT,
                TIME_CREATED INTEGER,
                NAME TEXT,
                LOG_TYPE TEXT,
                SPEED REAL,
                PACE REAL,
                CALORIES REAL,
                STEPS INTEGER,
                DISTANCE REAL,
                HEART_RATE REAL
            );
            INSERT INTO ACTIVITY_LOG_ENTRY VALUES('2021-01-01',1609459200000,'Morning Walk','walk',1.5,600.0,150.0,5000,4000.0,90.0);
            CREATE TABLE EXERCISE_EVENT (
                TIME INTEGER,
                LABEL TEXT,
                LATITUDE REAL,
                LONGITUDE REAL,
                ALTITUDE REAL,
                SPEED REAL,
                PACE REAL,
                SESSION_ID INTEGER
            );
            INSERT INTO EXERCISE_EVENT VALUES(1609459200000,'lap_split',37.7749,-122.4194,30.0,2.0,500.0,42);
            CREATE TABLE HEART_RATE_DAILY_SUMMARY (
                DATE_TIME INTEGER,
                AVERAGE_HEART_RATE REAL,
                RESTING_HEART_RATE REAL
            );
            INSERT INTO HEART_RATE_DAILY_SUMMARY VALUES(1609459200000,75.0,60.0);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_all_three_tables() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Fitbit Activity"));
        assert!(r.iter().any(|a| a.subcategory == "Fitbit Exercise Event"));
        assert!(r.iter().any(|a| a.subcategory == "Fitbit Heart Rate"));
    }

    #[test]
    fn exercise_event_captures_gps() {
        let db = make_db();
        let r = parse(db.path());
        let ev = r.iter().find(|a| a.subcategory == "Fitbit Exercise Event").unwrap();
        assert!(ev.detail.contains("lat=37.774900"));
        assert!(ev.detail.contains("session=42"));
    }

    #[test]
    fn activity_steps_and_calories() {
        let db = make_db();
        let r = parse(db.path());
        let a = r.iter().find(|a| a.subcategory == "Fitbit Activity").unwrap();
        assert!(a.detail.contains("steps=5000"));
        assert!(a.detail.contains("calories=150"));
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
