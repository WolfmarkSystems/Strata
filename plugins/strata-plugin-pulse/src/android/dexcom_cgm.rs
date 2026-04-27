//! Dexcom G7 — continuous glucose monitor (CGM) readings.
//!
//! Source path: `/data/data/com.dexcom.g7/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Dexcom CGM apps cache glucose
//! readings (every 5 min), alerts, and calibration events. Readings
//! are in mg/dL and stored in tables like `glucose_reading`, `alert`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.dexcom.g7/databases/",
    "com.dexcom.g6/databases/",
    "com.dexcom.follow/databases/",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["glucose_reading", "egv", "glucose"] {
        if table_exists(&conn, table) {
            out.extend(read_glucose(&conn, path, table));
            break;
        }
    }
    if table_exists(&conn, "alert") {
        out.extend(read_alerts(&conn, path));
    }
    out
}

fn read_glucose(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT timestamp, value_mgdl, trend, source_device \
         FROM \"{table}\" ORDER BY timestamp DESC LIMIT 20000",
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
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (ts_ms, value, trend, device) in rows.flatten() {
        let value = value.unwrap_or(0);
        let trend = trend.unwrap_or_default();
        let device = device.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Dexcom CGM: {} mg/dL ({})", value, trend);
        let detail = format!(
            "Dexcom glucose reading value_mgdl={} trend='{}' source_device='{}'",
            value, trend, device
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Dexcom Glucose",
            title,
            detail,
            path,
            ts,
            ForensicValue::Critical,
            false,
        ));
    }
    out
}

fn read_alerts(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, timestamp, alert_type, glucose_value, severity \
               FROM alert ORDER BY timestamp DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, ts_ms, alert_type, glucose, severity) in rows.flatten() {
        let id = id.unwrap_or_default();
        let alert_type = alert_type.unwrap_or_else(|| "(unknown)".to_string());
        let glucose = glucose.unwrap_or(0);
        let severity = severity.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Dexcom alert: {} ({} mg/dL)", alert_type, glucose);
        let detail = format!(
            "Dexcom alert id='{}' alert_type='{}' glucose_value={} severity='{}'",
            id, alert_type, glucose, severity
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Dexcom Alert",
            title,
            detail,
            path,
            ts,
            ForensicValue::Critical,
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
            CREATE TABLE glucose_reading (
                timestamp INTEGER,
                value_mgdl INTEGER,
                trend TEXT,
                source_device TEXT
            );
            INSERT INTO glucose_reading VALUES(1609459200000,120,'flat','G7');
            INSERT INTO glucose_reading VALUES(1609459500000,180,'rising','G7');
            CREATE TABLE alert (
                id TEXT,
                timestamp INTEGER,
                alert_type TEXT,
                glucose_value INTEGER,
                severity TEXT
            );
            INSERT INTO alert VALUES('a1',1609459600000,'high',200,'warning');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_glucose_and_alerts() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Dexcom Glucose"));
        assert!(r.iter().any(|a| a.subcategory == "Dexcom Alert"));
    }

    #[test]
    fn glucose_value_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.title.contains("120 mg/dL") && a.title.contains("flat")));
        assert!(r
            .iter()
            .any(|a| a.title.contains("180 mg/dL") && a.title.contains("rising")));
    }

    #[test]
    fn alert_severity_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("severity='warning'")));
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
