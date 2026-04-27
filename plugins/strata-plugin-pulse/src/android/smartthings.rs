//! Samsung SmartThings — connected device and event extraction.
//!
//! ALEAPP reference: `scripts/artifacts/samsungSmartThings.py`. Source path:
//! `/data/data/com.samsung.android.oneconnect/databases/QcDb.db`.
//!
//! Key tables: `Device`, `Location`, `history`. SmartThings stores
//! IoT device states, location zones, and activity history.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.samsung.android.oneconnect/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "Device") {
        out.extend(read_devices(&conn, path));
    }
    if table_exists(&conn, "Location") {
        out.extend(read_locations(&conn, path));
    }
    out
}

fn read_devices(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, name, deviceType, manufacturerName, locationId, \
               createdDate, modifiedDate \
               FROM Device LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<i64>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, name, device_type, manufacturer, loc_id, _created, modified_ms) in rows.flatten() {
        let id = id.unwrap_or_else(|| "(unknown)".to_string());
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let device_type = device_type.unwrap_or_default();
        let manufacturer = manufacturer.unwrap_or_default();
        let loc_id = loc_id.unwrap_or_default();
        let ts = modified_ms.and_then(unix_ms_to_i64);
        let title = format!("SmartThings device: {} ({})", name, device_type);
        let mut detail = format!(
            "SmartThings device id='{}' name='{}' type='{}'",
            id, name, device_type
        );
        if !manufacturer.is_empty() {
            detail.push_str(&format!(" manufacturer='{}'", manufacturer));
        }
        if !loc_id.is_empty() {
            detail.push_str(&format!(" location_id='{}'", loc_id));
        }
        out.push(build_record(
            ArtifactCategory::SystemActivity,
            "SmartThings Device",
            title,
            detail,
            path,
            ts,
            ForensicValue::High,
            false,
        ));
    }
    out
}

fn read_locations(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, name, latitude, longitude, regionRadius, locationType \
               FROM Location LIMIT 100";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<f64>>(2).unwrap_or(None),
            row.get::<_, Option<f64>>(3).unwrap_or(None),
            row.get::<_, Option<f64>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, name, lat, lon, radius, loc_type) in rows.flatten() {
        let id = id.unwrap_or_else(|| "(unknown)".to_string());
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let loc_type = loc_type.unwrap_or_default();
        let title = format!("SmartThings location: {}", name);
        let mut detail = format!(
            "SmartThings location id='{}' name='{}' type='{}'",
            id, name, loc_type
        );
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" lat={:.6} lon={:.6}", la, lo));
        }
        if let Some(r) = radius {
            detail.push_str(&format!(" radius={:.0}m", r));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "SmartThings Location",
            title,
            detail,
            path,
            None,
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
            CREATE TABLE Device (
                id TEXT,
                name TEXT,
                deviceType TEXT,
                manufacturerName TEXT,
                locationId TEXT,
                createdDate INTEGER,
                modifiedDate INTEGER
            );
            INSERT INTO Device VALUES('dev1','Living Room Light','Bulb','Philips','loc1',1609459200000,1609545600000);
            INSERT INTO Device VALUES('dev2','Front Door Lock','SmartLock','August','loc1',1609459200000,1609545600000);
            CREATE TABLE Location (
                id TEXT,
                name TEXT,
                latitude REAL,
                longitude REAL,
                regionRadius REAL,
                locationType TEXT
            );
            INSERT INTO Location VALUES('loc1','Home',37.7749,-122.4194,100.0,'HOME');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_devices_and_locations() {
        let db = make_db();
        let r = parse(db.path());
        let devs: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "SmartThings Device")
            .collect();
        let locs: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "SmartThings Location")
            .collect();
        assert_eq!(devs.len(), 2);
        assert_eq!(locs.len(), 1);
    }

    #[test]
    fn device_manufacturer_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("manufacturer='Philips'")));
        assert!(r.iter().any(|a| a.detail.contains("manufacturer='August'")));
    }

    #[test]
    fn home_location_coordinates() {
        let db = make_db();
        let r = parse(db.path());
        let home = r
            .iter()
            .find(|a| a.subcategory == "SmartThings Location")
            .unwrap();
        assert!(home.detail.contains("lat=37.774900"));
        assert!(home.detail.contains("radius=100m"));
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
