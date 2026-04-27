//! WHOOP — fitness band strain/recovery/sleep data.
//!
//! Source path: `/data/data/com.whoop.android/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. WHOOP caches daily strain
//! scores, recovery percentages, sleep stages, and workout sessions.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.whoop.android/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "daily_strain") {
        out.extend(read_strain(&conn, path));
    }
    if table_exists(&conn, "recovery") {
        out.extend(read_recovery(&conn, path));
    }
    if table_exists(&conn, "sleep") {
        out.extend(read_sleep(&conn, path));
    }
    out
}

fn read_strain(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT cycle_id, day, strain_score, max_hr, avg_hr, kilojoules \
               FROM daily_strain ORDER BY day DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<f64>>(2).unwrap_or(None),
            row.get::<_, Option<f64>>(3).unwrap_or(None),
            row.get::<_, Option<f64>>(4).unwrap_or(None),
            row.get::<_, Option<f64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (cycle_id, ts_ms, strain, max_hr, avg_hr, kilojoules) in rows.flatten() {
        let cycle_id = cycle_id.unwrap_or_default();
        let strain = strain.unwrap_or(0.0);
        let max_hr = max_hr.unwrap_or(0.0);
        let avg_hr = avg_hr.unwrap_or(0.0);
        let kilojoules = kilojoules.unwrap_or(0.0);
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("WHOOP strain: {:.1}", strain);
        let detail = format!(
            "WHOOP daily strain cycle_id='{}' strain_score={:.2} max_hr={:.0} avg_hr={:.0} kilojoules={:.0}",
            cycle_id, strain, max_hr, avg_hr, kilojoules
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "WHOOP Strain",
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

fn read_recovery(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT cycle_id, day, recovery_score, hrv_rmssd_ms, \
               resting_heart_rate FROM recovery ORDER BY day DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
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
    for (cycle_id, ts_ms, recovery, hrv, rest_hr) in rows.flatten() {
        let cycle_id = cycle_id.unwrap_or_default();
        let recovery = recovery.unwrap_or(0.0);
        let hrv = hrv.unwrap_or(0.0);
        let rest_hr = rest_hr.unwrap_or(0.0);
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("WHOOP recovery: {:.0}%", recovery);
        let detail = format!(
            "WHOOP recovery cycle_id='{}' recovery_score={:.1} hrv_rmssd_ms={:.1} resting_heart_rate={:.0}",
            cycle_id, recovery, hrv, rest_hr
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "WHOOP Recovery",
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
    let sql = "SELECT cycle_id, started_at, ended_at, sleep_performance, \
               rem_minutes, sws_minutes, light_minutes, awake_minutes, \
               disturbances \
               FROM sleep ORDER BY started_at DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<f64>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<i64>>(6).unwrap_or(None),
            row.get::<_, Option<i64>>(7).unwrap_or(None),
            row.get::<_, Option<i64>>(8).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (cycle_id, started_ms, _ended_ms, performance, rem, sws, light, awake, disturbances) in
        rows.flatten()
    {
        let cycle_id = cycle_id.unwrap_or_default();
        let performance = performance.unwrap_or(0.0);
        let rem = rem.unwrap_or(0);
        let sws = sws.unwrap_or(0);
        let light = light.unwrap_or(0);
        let awake = awake.unwrap_or(0);
        let disturbances = disturbances.unwrap_or(0);
        let ts = started_ms.and_then(unix_ms_to_i64);
        let title = format!("WHOOP sleep: {:.0}%", performance);
        let detail = format!(
            "WHOOP sleep cycle_id='{}' sleep_performance={:.1} rem_minutes={} sws_minutes={} light_minutes={} awake_minutes={} disturbances={}",
            cycle_id, performance, rem, sws, light, awake, disturbances
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "WHOOP Sleep",
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
            CREATE TABLE daily_strain (
                cycle_id TEXT,
                day INTEGER,
                strain_score REAL,
                max_hr REAL,
                avg_hr REAL,
                kilojoules REAL
            );
            INSERT INTO daily_strain VALUES('c1',1609459200000,15.3,165.0,82.0,3200.0);
            CREATE TABLE recovery (
                cycle_id TEXT,
                day INTEGER,
                recovery_score REAL,
                hrv_rmssd_ms REAL,
                resting_heart_rate REAL
            );
            INSERT INTO recovery VALUES('c1',1609459200000,78.0,55.3,58.0);
            CREATE TABLE sleep (
                cycle_id TEXT,
                started_at INTEGER,
                ended_at INTEGER,
                sleep_performance REAL,
                rem_minutes INTEGER,
                sws_minutes INTEGER,
                light_minutes INTEGER,
                awake_minutes INTEGER,
                disturbances INTEGER
            );
            INSERT INTO sleep VALUES('c1',1609459000000,1609487000000,92.0,90,120,180,20,5);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_strain_recovery_sleep() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "WHOOP Strain"));
        assert!(r.iter().any(|a| a.subcategory == "WHOOP Recovery"));
        assert!(r.iter().any(|a| a.subcategory == "WHOOP Sleep"));
    }

    #[test]
    fn hrv_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("hrv_rmssd_ms=55.3")));
    }

    #[test]
    fn sleep_disturbances_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("disturbances=5")));
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
