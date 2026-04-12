//! Blood Pressure Apps — medical readings extraction.
//!
//! Source paths:
//! - `/data/data/com.szyk.bpmonitor/databases/*.db`
//! - `/data/data/com.qardio.*/databases/*.db`
//! - `/data/data/com.omronhealthcare.*/databases/*.db`
//!
//! Schema note: not in ALEAPP upstream. Blood pressure readings are medical
//! evidence and can establish physiological state at a specific time. Multiple
//! BP monitoring apps use similar SQLite schemas; parser probes common table
//! name variants across vendors.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.szyk.bpmonitor/databases/",
    "com.qardio.",
    "com.omronhealthcare.",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["measurements", "measurement", "readings", "reading", "bp_records", "record"] {
        if table_exists(&conn, table) {
            out.extend(read_readings(&conn, path, table));
            break;
        }
    }
    out
}

fn read_readings(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT systolic, diastolic, pulse, timestamp, notes \
         FROM \"{table}\" ORDER BY timestamp DESC LIMIT 10000",
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
            row.get::<_, Option<String>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (systolic, diastolic, pulse, ts_raw, notes) in rows.flatten() {
        let sys = systolic.unwrap_or(0);
        let dia = diastolic.unwrap_or(0);
        let pulse = pulse.unwrap_or(0);
        let notes = notes.unwrap_or_default();
        let ts = ts_raw.and_then(unix_ms_to_i64);
        let title = format!("BP reading: {}/{} mmHg pulse {}", sys, dia, pulse);
        let mut detail = format!(
            "Blood pressure reading systolic={} diastolic={} pulse={}",
            sys, dia, pulse
        );
        if !notes.is_empty() {
            detail.push_str(&format!(" notes='{}'", notes));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Blood Pressure Reading",
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
            CREATE TABLE measurements (
                systolic INTEGER,
                diastolic INTEGER,
                pulse INTEGER,
                timestamp INTEGER,
                notes TEXT
            );
            INSERT INTO measurements VALUES(120,80,72,1609459200000,'Morning reading');
            INSERT INTO measurements VALUES(145,95,88,1609459800000,'After exercise');
            INSERT INTO measurements VALUES(118,78,68,1609545600000,NULL);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_readings() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.iter().filter(|a| a.subcategory == "Blood Pressure Reading").count(), 3);
    }

    #[test]
    fn systolic_diastolic_in_title_and_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("120/80") && a.detail.contains("systolic=120")));
    }

    #[test]
    fn notes_captured_when_present() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("notes='Morning reading'")));
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
