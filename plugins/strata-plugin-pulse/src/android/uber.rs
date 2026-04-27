//! Uber — Android rideshare trip history extraction.
//!
//! Source path: `/data/data/com.ubercab/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. Uber uses Room databases with
//! tables like `trips`, `trip_history`, `receipt`. Location columns
//! typically `pickup_lat/lon`, `dropoff_lat/lon`. Schema varies across
//! Uber versions.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.ubercab/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    for table in &["trips", "trip_history", "trip"] {
        if table_exists(&conn, table) {
            return read_trips(&conn, path, table);
        }
    }
    Vec::new()
}

fn read_trips(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT uuid, request_time, pickup_lat, pickup_lon, \
         dropoff_lat, dropoff_lon, pickup_address, dropoff_address, \
         fare, driver_name, vehicle_license_plate, status \
         FROM \"{table}\" ORDER BY request_time DESC LIMIT 5000",
        table = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
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
            row.get::<_, Option<String>>(6).unwrap_or(None),
            row.get::<_, Option<String>>(7).unwrap_or(None),
            row.get::<_, Option<String>>(8).unwrap_or(None),
            row.get::<_, Option<String>>(9).unwrap_or(None),
            row.get::<_, Option<String>>(10).unwrap_or(None),
            row.get::<_, Option<String>>(11).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (uuid, req_ms, p_lat, p_lon, d_lat, d_lon, p_addr, d_addr, fare, driver, plate, status) in
        rows.flatten()
    {
        let uuid = uuid.unwrap_or_else(|| "(unknown)".to_string());
        let p_addr = p_addr.unwrap_or_default();
        let d_addr = d_addr.unwrap_or_default();
        let fare = fare.unwrap_or_default();
        let driver = driver.unwrap_or_default();
        let plate = plate.unwrap_or_default();
        let status = status.unwrap_or_default();
        let ts = req_ms.and_then(unix_ms_to_i64);
        let title = format!("Uber trip: {} → {}", p_addr, d_addr);
        let mut detail = format!(
            "Uber trip uuid='{}' pickup='{}' dropoff='{}' fare='{}' status='{}'",
            uuid, p_addr, d_addr, fare, status
        );
        if let (Some(la), Some(lo)) = (p_lat, p_lon) {
            detail.push_str(&format!(" pickup_lat={:.6} pickup_lon={:.6}", la, lo));
        }
        if let (Some(la), Some(lo)) = (d_lat, d_lon) {
            detail.push_str(&format!(" dropoff_lat={:.6} dropoff_lon={:.6}", la, lo));
        }
        if !driver.is_empty() {
            detail.push_str(&format!(" driver='{}'", driver));
        }
        if !plate.is_empty() {
            detail.push_str(&format!(" plate='{}'", plate));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Uber Trip",
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
            CREATE TABLE trips (
                uuid TEXT,
                request_time INTEGER,
                pickup_lat REAL,
                pickup_lon REAL,
                dropoff_lat REAL,
                dropoff_lon REAL,
                pickup_address TEXT,
                dropoff_address TEXT,
                fare TEXT,
                driver_name TEXT,
                vehicle_license_plate TEXT,
                status TEXT
            );
            INSERT INTO trips VALUES('t-001',1609459200000,37.7749,-122.4194,37.6213,-122.3790,'123 Main St','SFO Airport','$45.50','John D','ABC123','completed');
            INSERT INTO trips VALUES('t-002',1609545600000,37.6213,-122.3790,37.7749,-122.4194,'SFO Airport','123 Main St','$48.25','Jane S','XYZ789','completed');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_two_trips() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|a| a.subcategory == "Uber Trip"));
    }

    #[test]
    fn pickup_and_dropoff_gps() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("pickup_lat=37.774900")
            && a.detail.contains("dropoff_lat=37.621300")));
    }

    #[test]
    fn driver_and_plate_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("driver='John D'") && a.detail.contains("plate='ABC123'")));
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
