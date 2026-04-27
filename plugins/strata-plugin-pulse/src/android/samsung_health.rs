//! Samsung Health (SHealth) — step, exercise, sleep extraction.
//!
//! Source path: `/data/data/com.sec.android.app.shealth/databases/*.db`.
//!
//! Samsung Health stores activity data in tables whose names are prefixed
//! with the package scope, e.g. `com_samsung_health_step_count`,
//! `com_samsung_health_exercise`, `com_samsung_health_sleep`. Columns
//! include `create_time`, `update_time`, `count`, `distance`, `calorie`,
//! `exercise_type`, `duration`, `start_time`, `end_time`.
//!
//! Schema note: not in ALEAPP upstream — this parser is written from
//! publicly documented Samsung Health schema. Schema varies across
//! S-Health versions; the parser probes multiple known column names.

use crate::android::helpers::{
    build_record, column_exists, open_sqlite_ro, table_exists, unix_ms_to_i64,
};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.sec.android.app.shealth/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();

    // Try both underscore-prefixed and unprefixed variants.
    for table in &[
        "com_samsung_health_step_count",
        "step_count",
        "stepdaily_trend",
    ] {
        if table_exists(&conn, table) {
            out.extend(read_steps(&conn, path, table));
            break;
        }
    }
    for table in &["com_samsung_health_exercise", "exercise"] {
        if table_exists(&conn, table) {
            out.extend(read_exercise(&conn, path, table));
            break;
        }
    }
    for table in &["com_samsung_health_sleep", "sleep", "sleep_stage"] {
        if table_exists(&conn, table) {
            out.extend(read_sleep(&conn, path, table));
            break;
        }
    }
    out
}

fn read_steps(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let ts_col = if column_exists(conn, table, "create_time") {
        "create_time"
    } else if column_exists(conn, table, "start_time") {
        "start_time"
    } else {
        "time"
    };
    let sql = format!(
        "SELECT {ts_col}, count, distance, calorie FROM \"{table}\" \
         ORDER BY {ts_col} DESC LIMIT 10000",
        ts_col = ts_col,
        table = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<f64>>(2).unwrap_or(None),
            row.get::<_, Option<f64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (ts_ms, count, distance, calorie) in rows.flatten() {
        let count = count.unwrap_or(0);
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("SHealth steps: {}", count);
        let mut detail = format!("Samsung Health step_count count={}", count);
        if let Some(d) = distance {
            detail.push_str(&format!(" distance={:.1}m", d));
        }
        if let Some(c) = calorie {
            detail.push_str(&format!(" calorie={:.1}", c));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Samsung Health Steps",
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

fn read_exercise(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT start_time, end_time, exercise_type, duration, distance, calorie \
         FROM \"{table}\" ORDER BY start_time DESC LIMIT 5000",
        table = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<f64>>(4).unwrap_or(None),
            row.get::<_, Option<f64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (start_ms, _end_ms, ex_type, duration_ms, distance, calorie) in rows.flatten() {
        let ts = start_ms.and_then(unix_ms_to_i64);
        let ex_type = ex_type.unwrap_or(0);
        let dur_s = duration_ms.unwrap_or(0) / 1000;
        let title = format!("SHealth exercise type={} ({}s)", ex_type, dur_s);
        let mut detail = format!(
            "Samsung Health exercise type={} duration={}s",
            ex_type, dur_s
        );
        if let Some(d) = distance {
            detail.push_str(&format!(" distance={:.1}m", d));
        }
        if let Some(c) = calorie {
            detail.push_str(&format!(" calorie={:.1}", c));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Samsung Health Exercise",
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

fn read_sleep(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT start_time, end_time FROM \"{table}\" ORDER BY start_time DESC LIMIT 5000",
        table = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (start_ms, end_ms) in rows.flatten() {
        let ts = start_ms.and_then(unix_ms_to_i64);
        let dur_s = end_ms
            .zip(start_ms)
            .map(|(e, s)| (e - s) / 1000)
            .unwrap_or(0);
        let hours = dur_s as f64 / 3600.0;
        let title = format!("SHealth sleep: {:.1}h", hours);
        let detail = format!(
            "Samsung Health sleep start={} duration={}s",
            start_ms.unwrap_or(0),
            dur_s
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Samsung Health Sleep",
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
            CREATE TABLE com_samsung_health_step_count (
                create_time INTEGER,
                count INTEGER,
                distance REAL,
                calorie REAL
            );
            INSERT INTO com_samsung_health_step_count VALUES(1609459200000,5000,3500.0,180.0);
            INSERT INTO com_samsung_health_step_count VALUES(1609545600000,8000,5600.0,280.0);
            CREATE TABLE com_samsung_health_exercise (
                start_time INTEGER,
                end_time INTEGER,
                exercise_type INTEGER,
                duration INTEGER,
                distance REAL,
                calorie REAL
            );
            INSERT INTO com_samsung_health_exercise VALUES(1609459200000,1609461000000,1001,1800000,5000.0,420.0);
            CREATE TABLE com_samsung_health_sleep (
                start_time INTEGER,
                end_time INTEGER
            );
            INSERT INTO com_samsung_health_sleep VALUES(1609459200000,1609487200000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_all_three_tables() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Samsung Health Steps"));
        assert!(r.iter().any(|a| a.subcategory == "Samsung Health Exercise"));
        assert!(r.iter().any(|a| a.subcategory == "Samsung Health Sleep"));
    }

    #[test]
    fn step_count_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("5000")));
        assert!(r.iter().any(|a| a.title.contains("8000")));
    }

    #[test]
    fn exercise_duration_captured() {
        let db = make_db();
        let r = parse(db.path());
        let ex = r
            .iter()
            .find(|a| a.subcategory == "Samsung Health Exercise")
            .unwrap();
        assert!(ex.detail.contains("duration=1800s"));
        assert!(ex.detail.contains("distance=5000.0m"));
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
