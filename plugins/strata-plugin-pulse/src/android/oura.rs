//! Oura Ring — sleep, readiness, and activity tracking.
//!
//! Source path: `/data/data/com.ouraring.oura/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Oura caches daily readiness
//! scores, sleep stages, HRV, body temperature trends.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.ouraring.oura/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "readiness") {
        out.extend(read_readiness(&conn, path));
    }
    if table_exists(&conn, "sleep") {
        out.extend(read_sleep(&conn, path));
    }
    if table_exists(&conn, "activity") {
        out.extend(read_activity(&conn, path));
    }
    out
}

fn read_readiness(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT day, score, temperature_deviation, resting_hr, \
               hrv_balance FROM readiness ORDER BY day DESC LIMIT 5000";
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
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (ts_ms, score, temp_dev, rest_hr, hrv_balance) in rows.flatten() {
        let score = score.unwrap_or(0);
        let temp_dev = temp_dev.unwrap_or(0.0);
        let rest_hr = rest_hr.unwrap_or(0.0);
        let hrv_balance = hrv_balance.unwrap_or(0.0);
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Oura readiness: {}", score);
        let detail = format!(
            "Oura readiness score={} temperature_deviation={:.2} resting_hr={:.0} hrv_balance={:.1}",
            score, temp_dev, rest_hr, hrv_balance
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Oura Readiness",
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

fn read_sleep(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT day, bedtime_start, bedtime_end, total_seconds, \
               score, deep_seconds, rem_seconds, light_seconds, efficiency \
               FROM sleep ORDER BY day DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
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
    for (ts_ms, bedtime_start, _bedtime_end, total, score, deep, rem, light, efficiency) in
        rows.flatten()
    {
        let total = total.unwrap_or(0);
        let score = score.unwrap_or(0);
        let deep = deep.unwrap_or(0);
        let rem = rem.unwrap_or(0);
        let light = light.unwrap_or(0);
        let efficiency = efficiency.unwrap_or(0.0);
        let hours = total as f64 / 3600.0;
        let ts = bedtime_start.or(ts_ms).and_then(unix_ms_to_i64);
        let title = format!("Oura sleep: score {} ({:.1}h)", score, hours);
        let detail = format!(
            "Oura sleep score={} total_seconds={} deep_seconds={} rem_seconds={} light_seconds={} efficiency={:.1}",
            score, total, deep, rem, light, efficiency
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Oura Sleep",
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

fn read_activity(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT day, score, steps, active_cal, total_cal, \
               medium_activity_time, high_activity_time \
               FROM activity ORDER BY day DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
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
            row.get::<_, Option<i64>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (ts_ms, score, steps, active_cal, total_cal, medium_time, high_time) in rows.flatten() {
        let score = score.unwrap_or(0);
        let steps = steps.unwrap_or(0);
        let active_cal = active_cal.unwrap_or(0.0);
        let total_cal = total_cal.unwrap_or(0.0);
        let medium_time = medium_time.unwrap_or(0);
        let high_time = high_time.unwrap_or(0);
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Oura activity: score {} ({} steps)", score, steps);
        let detail = format!(
            "Oura activity score={} steps={} active_cal={:.0} total_cal={:.0} medium_activity_time={} high_activity_time={}",
            score, steps, active_cal, total_cal, medium_time, high_time
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Oura Activity",
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
            CREATE TABLE readiness (
                day INTEGER,
                score INTEGER,
                temperature_deviation REAL,
                resting_hr REAL,
                hrv_balance REAL
            );
            INSERT INTO readiness VALUES(1609459200000,85,0.2,58.0,75.0);
            CREATE TABLE sleep (
                day INTEGER,
                bedtime_start INTEGER,
                bedtime_end INTEGER,
                total_seconds INTEGER,
                score INTEGER,
                deep_seconds INTEGER,
                rem_seconds INTEGER,
                light_seconds INTEGER,
                efficiency REAL
            );
            INSERT INTO sleep VALUES(1609459200000,1609459000000,1609487000000,28000,88,5400,7200,14400,96.5);
            CREATE TABLE activity (
                day INTEGER,
                score INTEGER,
                steps INTEGER,
                active_cal REAL,
                total_cal REAL,
                medium_activity_time INTEGER,
                high_activity_time INTEGER
            );
            INSERT INTO activity VALUES(1609459200000,90,12000,450.0,2600.0,60,30);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_readiness_sleep_activity() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Oura Readiness"));
        assert!(r.iter().any(|a| a.subcategory == "Oura Sleep"));
        assert!(r.iter().any(|a| a.subcategory == "Oura Activity"));
    }

    #[test]
    fn temperature_deviation_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("temperature_deviation=0.20")));
    }

    #[test]
    fn steps_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("12000 steps")));
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
