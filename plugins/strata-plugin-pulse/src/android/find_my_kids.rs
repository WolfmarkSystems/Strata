//! Find My Kids — child GPS tracking and geofence alert extraction.
//!
//! Source path: `/data/data/com.findmykids.app/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Find My Kids stores child location
//! history, geofence zones, and safety alerts in SQLite. Child location
//! tracking data is critical forensic evidence in child safety investigations.
//! Parser probes common table name variants.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.findmykids.app/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["locations", "location", "child_locations", "position"] {
        if table_exists(&conn, table) {
            out.extend(read_locations(&conn, path, table));
            break;
        }
    }
    for table in &["zones", "geofences", "geofence", "safe_zones"] {
        if table_exists(&conn, table) {
            out.extend(read_geofences(&conn, path, table));
            break;
        }
    }
    for table in &["alerts", "alert", "notifications", "events"] {
        if table_exists(&conn, table) {
            out.extend(read_alerts(&conn, path, table));
            break;
        }
    }
    out
}

fn read_locations(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT latitude, longitude, timestamp, battery, address \
         FROM \"{table}\" ORDER BY timestamp DESC LIMIT 10000",
        table = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<f64>>(0).unwrap_or(None),
            row.get::<_, Option<f64>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (lat, lon, ts_ms, battery, address) in rows.flatten() {
        let address = address.unwrap_or_default();
        let battery = battery.unwrap_or(0);
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Find My Kids location: {}", address.chars().take(60).collect::<String>());
        let mut detail = format!(
            "Find My Kids child location battery={}%",
            battery
        );
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" lat={:.6} lon={:.6}", la, lo));
        }
        if !address.is_empty() {
            detail.push_str(&format!(" address='{}'", address));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Find My Kids Location",
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

fn read_geofences(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT name, latitude, longitude, radius FROM \"{table}\" LIMIT 500",
        table = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<f64>>(1).unwrap_or(None),
            row.get::<_, Option<f64>>(2).unwrap_or(None),
            row.get::<_, Option<f64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (name, lat, lon, radius) in rows.flatten() {
        let name = name.unwrap_or_else(|| "(unnamed zone)".to_string());
        let title = format!("Find My Kids geofence: {}", name);
        let mut detail = format!("Find My Kids geofence zone name='{}'", name);
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" lat={:.6} lon={:.6}", la, lo));
        }
        if let Some(r) = radius {
            detail.push_str(&format!(" radius={:.0}m", r));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Find My Kids Geofence",
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

fn read_alerts(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT type, message, timestamp, latitude, longitude \
         FROM \"{table}\" ORDER BY timestamp DESC LIMIT 5000",
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
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<f64>>(3).unwrap_or(None),
            row.get::<_, Option<f64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (alert_type, message, ts_ms, lat, lon) in rows.flatten() {
        let alert_type = alert_type.unwrap_or_else(|| "(unknown)".to_string());
        let message = message.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Find My Kids alert: {}", alert_type);
        let mut detail = format!(
            "Find My Kids alert type='{}' message='{}'",
            alert_type, message
        );
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" lat={:.6} lon={:.6}", la, lo));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Find My Kids Alert",
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
            CREATE TABLE locations (
                latitude REAL,
                longitude REAL,
                timestamp INTEGER,
                battery INTEGER,
                address TEXT
            );
            INSERT INTO locations VALUES(37.7749,-122.4194,1609459200000,85,'123 Main St, San Francisco');
            INSERT INTO locations VALUES(37.3382,-121.8863,1609466400000,72,'456 Oak Ave, San Jose');
            CREATE TABLE zones (
                name TEXT,
                latitude REAL,
                longitude REAL,
                radius REAL
            );
            INSERT INTO zones VALUES('School',37.7749,-122.4194,200.0);
            CREATE TABLE alerts (
                type TEXT,
                message TEXT,
                timestamp INTEGER,
                latitude REAL,
                longitude REAL
            );
            INSERT INTO alerts VALUES('geofence_exit','Child left School zone',1609459200000,37.7799,-122.4150);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_locations_geofences_alerts() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Find My Kids Location"));
        assert!(r.iter().any(|a| a.subcategory == "Find My Kids Geofence"));
        assert!(r.iter().any(|a| a.subcategory == "Find My Kids Alert"));
    }

    #[test]
    fn location_gps_and_battery_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("lat=37.774900") && a.detail.contains("battery=85%")));
    }

    #[test]
    fn geofence_radius_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("name='School'") && a.detail.contains("radius=200m")));
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
