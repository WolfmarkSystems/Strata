//! FreeStyle Libre — continuous glucose monitor (CGM) readings.
//!
//! Source path: `/data/data/com.freestylelibre.app.*/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. FreeStyle Libre apps cache
//! glucose readings, scan events, and food/insulin log entries.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.freestylelibre.app.us/databases/",
    "com.freestylelibre.app.de/databases/",
    "com.freestylelibre.app.gb/databases/",
    "com.librelink/databases/",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["cgm_reading", "historic_glucose", "glucose_reading"] {
        if table_exists(&conn, table) {
            out.extend(read_readings(&conn, path, table));
            break;
        }
    }
    if table_exists(&conn, "food_log") {
        out.extend(read_food(&conn, path));
    }
    if table_exists(&conn, "insulin_log") {
        out.extend(read_insulin(&conn, path));
    }
    out
}

fn read_readings(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT timestamp, value_mgdl, sensor_serial, reading_type \
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
    for (ts_ms, value, sensor_serial, reading_type) in rows.flatten() {
        let value = value.unwrap_or(0);
        let sensor_serial = sensor_serial.unwrap_or_default();
        let reading_type = reading_type.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Libre CGM: {} mg/dL", value);
        let detail = format!(
            "FreeStyle Libre reading value_mgdl={} sensor_serial='{}' reading_type='{}'",
            value, sensor_serial, reading_type
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Libre Glucose",
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

fn read_food(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, timestamp, food_name, carbs_g, calories \
               FROM food_log ORDER BY timestamp DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<f64>>(3).unwrap_or(None),
            row.get::<_, Option<f64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, ts_ms, food_name, carbs, calories) in rows.flatten() {
        let id = id.unwrap_or_default();
        let food_name = food_name.unwrap_or_else(|| "(unknown)".to_string());
        let carbs = carbs.unwrap_or(0.0);
        let calories = calories.unwrap_or(0.0);
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Libre food: {} ({:.0}g carbs)", food_name, carbs);
        let detail = format!(
            "FreeStyle Libre food log id='{}' food_name='{}' carbs_g={:.1} calories={:.0}",
            id, food_name, carbs, calories
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Libre Food Log",
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

fn read_insulin(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, timestamp, insulin_type, units \
               FROM insulin_log ORDER BY timestamp DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<f64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, ts_ms, insulin_type, units) in rows.flatten() {
        let id = id.unwrap_or_default();
        let insulin_type = insulin_type.unwrap_or_else(|| "(unknown)".to_string());
        let units = units.unwrap_or(0.0);
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Libre insulin: {} {:.1}u", insulin_type, units);
        let detail = format!(
            "FreeStyle Libre insulin log id='{}' insulin_type='{}' units={:.2}",
            id, insulin_type, units
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Libre Insulin Log",
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
            CREATE TABLE cgm_reading (
                timestamp INTEGER,
                value_mgdl INTEGER,
                sensor_serial TEXT,
                reading_type TEXT
            );
            INSERT INTO cgm_reading VALUES(1609459200000,135,'SN12345','scan');
            INSERT INTO cgm_reading VALUES(1609459500000,140,'SN12345','historic');
            CREATE TABLE food_log (
                id TEXT,
                timestamp INTEGER,
                food_name TEXT,
                carbs_g REAL,
                calories REAL
            );
            INSERT INTO food_log VALUES('f1',1609459300000,'Apple',25.0,95.0);
            CREATE TABLE insulin_log (
                id TEXT,
                timestamp INTEGER,
                insulin_type TEXT,
                units REAL
            );
            INSERT INTO insulin_log VALUES('i1',1609459400000,'rapid',4.5);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_readings_food_insulin() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Libre Glucose"));
        assert!(r.iter().any(|a| a.subcategory == "Libre Food Log"));
        assert!(r.iter().any(|a| a.subcategory == "Libre Insulin Log"));
    }

    #[test]
    fn sensor_serial_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("sensor_serial='SN12345'")));
    }

    #[test]
    fn insulin_units_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("4.5u")));
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
