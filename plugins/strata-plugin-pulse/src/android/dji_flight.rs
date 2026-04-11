//! DJI Fly / DJI Go — drone flight record extraction.
//!
//! Source paths:
//! - `/sdcard/DJI/com.dji.industry.pilot/FlightRecord/*.txt`
//! - `/sdcard/DJI/com.dji.fly/FlightRecord/*.txt`
//! - `/data/data/dji.go.v*/databases/*.db`
//!
//! Schema note: not in ALEAPP upstream. DJI flight logs are typically
//! stored as binary `.txt` files (encrypted/compressed) but the app
//! also keeps a SQLite index of flight metadata. This parser targets
//! the SQLite variant with common tables like `flight`, `location_record`.
//!
//! For binary FlightRecord files, we emit a lightweight record with
//! file name + size + mtime since the format requires DJI's proprietary
//! decoder.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "dji/com.dji.industry.pilot/flightrecord",
    "dji/com.dji.fly/flightrecord",
    "dji.go.v",
    "dji.pilot/databases",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    // Try SQLite first
    if let Some(conn) = open_sqlite_ro(path) {
        let mut out = Vec::new();
        if table_exists(&conn, "flight") {
            out.extend(read_flights(&conn, path));
        }
        if table_exists(&conn, "location_record") {
            out.extend(read_locations(&conn, path));
        }
        if !out.is_empty() {
            return out;
        }
    }
    // Otherwise treat as binary FlightRecord file
    read_binary_record(path)
}

fn read_flights(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, start_time, duration, distance, max_altitude, \
               home_latitude, home_longitude, aircraft_serial, total_path_km \
               FROM flight ORDER BY start_time DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<f64>>(3).unwrap_or(None),
            row.get::<_, Option<f64>>(4).unwrap_or(None),
            row.get::<_, Option<f64>>(5).unwrap_or(None),
            row.get::<_, Option<f64>>(6).unwrap_or(None),
            row.get::<_, Option<String>>(7).unwrap_or(None),
            row.get::<_, Option<f64>>(8).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, start_ms, duration, distance, max_alt, home_lat, home_lon, serial, path_km) in rows.flatten() {
        let id = id.unwrap_or(0);
        let ts = start_ms.and_then(unix_ms_to_i64);
        let duration_s = duration.unwrap_or(0) / 1000;
        let serial = serial.unwrap_or_default();
        let title = format!("DJI flight #{} ({}s)", id, duration_s);
        let mut detail = format!(
            "DJI flight id={} duration={}s",
            id, duration_s
        );
        if let Some(d) = distance {
            detail.push_str(&format!(" distance={:.0}m", d));
        }
        if let Some(m) = max_alt {
            detail.push_str(&format!(" max_altitude={:.0}m", m));
        }
        if let (Some(la), Some(lo)) = (home_lat, home_lon) {
            detail.push_str(&format!(" home_lat={:.6} home_lon={:.6}", la, lo));
        }
        if !serial.is_empty() {
            detail.push_str(&format!(" aircraft_serial='{}'", serial));
        }
        if let Some(p) = path_km {
            detail.push_str(&format!(" total_path_km={:.2}", p));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "DJI Flight",
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

fn read_locations(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT flight_id, timestamp, latitude, longitude, altitude, \
               velocity_x, velocity_y, velocity_z \
               FROM location_record \
               ORDER BY timestamp DESC LIMIT 50000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<f64>>(2).unwrap_or(None),
            row.get::<_, Option<f64>>(3).unwrap_or(None),
            row.get::<_, Option<f64>>(4).unwrap_or(None),
            row.get::<_, Option<f64>>(5).unwrap_or(None),
            row.get::<_, Option<f64>>(6).unwrap_or(None),
            row.get::<_, Option<f64>>(7).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (flight_id, ts_ms, lat, lon, alt, vx, vy, vz) in rows.flatten() {
        let flight_id = flight_id.unwrap_or(0);
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("DJI waypoint flight={}", flight_id);
        let mut detail = format!("DJI location record flight_id={}", flight_id);
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" lat={:.6} lon={:.6}", la, lo));
        }
        if let Some(a) = alt {
            detail.push_str(&format!(" altitude={:.1}m", a));
        }
        if let (Some(x), Some(y), Some(z)) = (vx, vy, vz) {
            detail.push_str(&format!(" velocity=({:.2},{:.2},{:.2})", x, y, z));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "DJI Waypoint",
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

fn read_binary_record(path: &Path) -> Vec<ArtifactRecord> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };
    if !meta.is_file() {
        return Vec::new();
    }
    let size = meta.len();
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("(unknown)")
        .to_string();
    // Only emit for files that look like FlightRecord files
    let lower = file_name.to_lowercase();
    if !lower.contains("flightrecord") && !lower.ends_with(".txt") && !lower.ends_with(".dat") {
        return Vec::new();
    }
    let title = format!("DJI FlightRecord file: {}", file_name);
    let detail = format!(
        "DJI FlightRecord binary file='{}' size={} bytes (requires DJI decoder for contents)",
        file_name, size
    );
    vec![build_record(
        ArtifactCategory::UserActivity,
        "DJI FlightRecord File",
        title,
        detail,
        path,
        None,
        ForensicValue::Critical,
        false,
    )]
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
            CREATE TABLE flight (
                id INTEGER PRIMARY KEY,
                start_time INTEGER,
                duration INTEGER,
                distance REAL,
                max_altitude REAL,
                home_latitude REAL,
                home_longitude REAL,
                aircraft_serial TEXT,
                total_path_km REAL
            );
            INSERT INTO flight VALUES(1,1609459200000,600000,5000.0,120.0,37.7749,-122.4194,'0TYDH3A0A12345',5.2);
            INSERT INTO flight VALUES(2,1609545600000,900000,8000.0,150.0,37.7700,-122.4000,'0TYDH3A0A12345',8.1);
            CREATE TABLE location_record (
                flight_id INTEGER,
                timestamp INTEGER,
                latitude REAL,
                longitude REAL,
                altitude REAL,
                velocity_x REAL,
                velocity_y REAL,
                velocity_z REAL
            );
            INSERT INTO location_record VALUES(1,1609459260000,37.7750,-122.4195,50.0,1.2,0.5,0.0);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_flights_and_waypoints() {
        let db = make_db();
        let r = parse(db.path());
        let flights: Vec<_> = r.iter().filter(|a| a.subcategory == "DJI Flight").collect();
        let waypoints: Vec<_> = r.iter().filter(|a| a.subcategory == "DJI Waypoint").collect();
        assert_eq!(flights.len(), 2);
        assert_eq!(waypoints.len(), 1);
    }

    #[test]
    fn aircraft_serial_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("aircraft_serial='0TYDH3A0A12345'")));
    }

    #[test]
    fn home_coordinates_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("home_lat=37.774900")));
    }

    #[test]
    fn binary_file_emits_record() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("DJIFlightRecord_2024-01-01.txt");
        std::fs::write(&file, b"fake DJI binary content").unwrap();
        let r = parse(&file);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].subcategory, "DJI FlightRecord File");
        assert!(r[0].detail.contains("size=23"));
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
