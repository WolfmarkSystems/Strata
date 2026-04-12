//! SpotHero — parking reservation and vehicle location extraction.
//!
//! Source path: `/data/data/com.spothero.spothero/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. SpotHero stores parking reservations
//! in SQLite Room databases. Parking data establishes physical presence at a
//! specific time and location with vehicle association — high forensic value.
//! Table names vary; parser probes common variants.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.spothero.spothero/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["reservations", "reservation", "bookings", "booking"] {
        if table_exists(&conn, table) {
            out.extend(read_reservations(&conn, path, table));
            break;
        }
    }
    out
}

fn read_reservations(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT facility_name, address, latitude, longitude, \
                start_time, end_time, price, vehicle \
         FROM \"{table}\" ORDER BY start_time DESC LIMIT 5000",
        table = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<f64>>(2).unwrap_or(None),
            row.get::<_, Option<f64>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<String>>(6).unwrap_or(None),
            row.get::<_, Option<String>>(7).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (facility_name, address, lat, lon, start_ms, end_ms, price, vehicle) in rows.flatten() {
        let facility_name = facility_name.unwrap_or_else(|| "(unknown facility)".to_string());
        let address = address.unwrap_or_default();
        let price = price.unwrap_or_default();
        let vehicle = vehicle.unwrap_or_default();
        let ts = start_ms.and_then(unix_ms_to_i64);
        let title = format!("SpotHero reservation: {}", facility_name);
        let mut detail = format!(
            "SpotHero reservation facility_name='{}' address='{}' price='{}' vehicle='{}'",
            facility_name, address, price, vehicle
        );
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" lat={:.6} lon={:.6}", la, lo));
        }
        if let Some(end) = end_ms.and_then(unix_ms_to_i64) {
            detail.push_str(&format!(" end_time={}", end));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "SpotHero Reservation",
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
            CREATE TABLE reservations (
                facility_name TEXT,
                address TEXT,
                latitude REAL,
                longitude REAL,
                start_time INTEGER,
                end_time INTEGER,
                price TEXT,
                vehicle TEXT
            );
            INSERT INTO reservations VALUES(
                'Millennium Park Garage','5 S Michigan Ave, Chicago, IL',
                41.8830,-87.6237,1609459200000,1609466400000,'$20.00','Honda Civic - ABC123'
            );
            INSERT INTO reservations VALUES(
                'Navy Pier Garage','600 E Grand Ave, Chicago, IL',
                41.8918,-87.6095,1609545600000,1609552800000,'$18.00','Toyota Camry - XYZ789'
            );
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_reservations() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.iter().filter(|a| a.subcategory == "SpotHero Reservation").count(), 2);
    }

    #[test]
    fn gps_and_vehicle_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("lat=41.883000") && a.detail.contains("vehicle='Honda Civic - ABC123'")));
    }

    #[test]
    fn facility_name_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("Millennium Park Garage")));
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
