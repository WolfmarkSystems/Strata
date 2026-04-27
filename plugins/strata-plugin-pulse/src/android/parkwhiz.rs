//! ParkWhiz — parking reservation and location extraction.
//!
//! Source path: `/data/data/com.parkwhiz.parkwhiz/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. ParkWhiz stores reservations in
//! SQLite Room databases. Parking reservations establish physical presence
//! at a specific time and location — high forensic value. Table names vary
//! across app versions; parser probes common variants.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.parkwhiz.parkwhiz/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["reservations", "reservation", "booking", "bookings"] {
        if table_exists(&conn, table) {
            out.extend(read_reservations(&conn, path, table));
            break;
        }
    }
    out
}

fn read_reservations(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT location_name, address, latitude, longitude, \
                start_time, end_time, price, confirmation \
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
    for (location_name, address, lat, lon, start_ms, end_ms, price, confirmation) in rows.flatten()
    {
        let location_name = location_name.unwrap_or_else(|| "(unknown location)".to_string());
        let address = address.unwrap_or_default();
        let price = price.unwrap_or_default();
        let confirmation = confirmation.unwrap_or_default();
        let ts = start_ms.and_then(unix_ms_to_i64);
        let title = format!("ParkWhiz reservation: {}", location_name);
        let mut detail = format!(
            "ParkWhiz reservation location_name='{}' address='{}' price='{}' confirmation='{}'",
            location_name, address, price, confirmation
        );
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" lat={:.6} lon={:.6}", la, lo));
        }
        if let Some(end) = end_ms.and_then(unix_ms_to_i64) {
            detail.push_str(&format!(" end_time={}", end));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "ParkWhiz Reservation",
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
                location_name TEXT,
                address TEXT,
                latitude REAL,
                longitude REAL,
                start_time INTEGER,
                end_time INTEGER,
                price TEXT,
                confirmation TEXT
            );
            INSERT INTO reservations VALUES(
                'Downtown Parking Garage','123 Main St, Chicago, IL',
                41.8781,-87.6298,1609459200000,1609466400000,'$15.00','PWZ-123456'
            );
            INSERT INTO reservations VALUES(
                'Airport Long-Term Lot','2400 E Devon Ave, Des Plaines, IL',
                41.9851,-87.9073,1609545600000,1609718400000,'$42.00','PWZ-789012'
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
        assert_eq!(
            r.iter()
                .filter(|a| a.subcategory == "ParkWhiz Reservation")
                .count(),
            2
        );
    }

    #[test]
    fn gps_coordinates_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("lat=41.878100") && a.detail.contains("lon=-87.629800")));
    }

    #[test]
    fn confirmation_number_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("confirmation='PWZ-123456'")));
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
