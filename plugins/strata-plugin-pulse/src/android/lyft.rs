//! Lyft — Android rideshare trip history extraction.
//!
//! Source path: `/data/data/com.lyft.android/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. Lyft uses Room databases with
//! tables like `rides`, `ride_history`. Column names include `ride_id`,
//! `pickup_location`, `dropoff_location`, `cost`, `driver`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.lyft.android/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    for table in &["rides", "ride_history", "ride"] {
        if table_exists(&conn, table) {
            return read_rides(&conn, path, table);
        }
    }
    Vec::new()
}

fn read_rides(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT ride_id, requested_at, pickup_lat, pickup_lon, \
         dropoff_lat, dropoff_lon, pickup_address, dropoff_address, \
         cost, currency, driver_first_name, vehicle_license_plate, ride_type \
         FROM \"{table}\" ORDER BY requested_at DESC LIMIT 5000",
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
            row.get::<_, Option<String>>(12).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (ride_id, req_ms, p_lat, p_lon, d_lat, d_lon, p_addr, d_addr, cost, currency, driver, plate, ride_type) in rows.flatten() {
        let ride_id = ride_id.unwrap_or_else(|| "(unknown)".to_string());
        let p_addr = p_addr.unwrap_or_default();
        let d_addr = d_addr.unwrap_or_default();
        let cost = cost.unwrap_or_default();
        let currency = currency.unwrap_or_default();
        let driver = driver.unwrap_or_default();
        let plate = plate.unwrap_or_default();
        let ride_type = ride_type.unwrap_or_default();
        let ts = req_ms.and_then(unix_ms_to_i64);
        let title = format!("Lyft {}: {} → {}", ride_type, p_addr, d_addr);
        let mut detail = format!(
            "Lyft ride id='{}' pickup='{}' dropoff='{}' cost='{}' currency='{}' type='{}'",
            ride_id, p_addr, d_addr, cost, currency, ride_type
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
            "Lyft Ride",
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
            CREATE TABLE rides (
                ride_id TEXT,
                requested_at INTEGER,
                pickup_lat REAL,
                pickup_lon REAL,
                dropoff_lat REAL,
                dropoff_lon REAL,
                pickup_address TEXT,
                dropoff_address TEXT,
                cost TEXT,
                currency TEXT,
                driver_first_name TEXT,
                vehicle_license_plate TEXT,
                ride_type TEXT
            );
            INSERT INTO rides VALUES('r-001',1609459200000,37.7749,-122.4194,37.6213,-122.3790,'Home','SFO','$52.00','USD','Alice','XYZ-789','lyft');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_one_ride() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 1);
        assert!(r.iter().all(|a| a.subcategory == "Lyft Ride"));
    }

    #[test]
    fn ride_type_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("Lyft lyft")));
    }

    #[test]
    fn gps_and_driver_captured() {
        let db = make_db();
        let r = parse(db.path());
        let ride = &r[0];
        assert!(ride.detail.contains("pickup_lat=37.774900"));
        assert!(ride.detail.contains("driver='Alice'"));
        assert!(ride.detail.contains("plate='XYZ-789'"));
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
