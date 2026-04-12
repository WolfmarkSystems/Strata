//! Android Auto — session history, connected vehicles, and navigation.
//!
//! Source path: `/data/data/com.google.android.projection.gearhead/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Android Auto caches session
//! logs, paired vehicle head units, and recent destinations.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.google.android.projection.gearhead/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["session", "session_history"] {
        if table_exists(&conn, table) {
            out.extend(read_sessions(&conn, path, table));
            break;
        }
    }
    for table in &["paired_vehicle", "connected_car", "head_unit"] {
        if table_exists(&conn, table) {
            out.extend(read_vehicles(&conn, path, table));
            break;
        }
    }
    for table in &["recent_destination", "navigation_history"] {
        if table_exists(&conn, table) {
            out.extend(read_destinations(&conn, path, table));
            break;
        }
    }
    out
}

fn read_sessions(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, vehicle_id, started_at, ended_at, duration, \
         connection_type \
         FROM \"{table}\" ORDER BY started_at DESC LIMIT 5000",
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
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, vehicle_id, started_ms, _ended_ms, duration_ms, connection_type) in rows.flatten() {
        let id = id.unwrap_or_default();
        let vehicle_id = vehicle_id.unwrap_or_default();
        let dur_s = duration_ms.unwrap_or(0) / 1000;
        let connection_type = connection_type.unwrap_or_default();
        let ts = started_ms.and_then(unix_ms_to_i64);
        let title = format!("Android Auto session: {} ({}s)", vehicle_id, dur_s);
        let detail = format!(
            "Android Auto session id='{}' vehicle_id='{}' duration={}s connection='{}'",
            id, vehicle_id, dur_s, connection_type
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Android Auto Session",
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

fn read_vehicles(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, make, model, head_unit_name, bluetooth_address, \
         last_connected_at \
         FROM \"{table}\" LIMIT 100",
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
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, make, model, head_unit_name, bluetooth_address, last_connected_ms) in rows.flatten() {
        let id = id.unwrap_or_default();
        let make = make.unwrap_or_default();
        let model = model.unwrap_or_default();
        let head_unit_name = head_unit_name.unwrap_or_default();
        let bluetooth_address = bluetooth_address.unwrap_or_default();
        let ts = last_connected_ms.and_then(unix_ms_to_i64);
        let title = format!("Android Auto vehicle: {} {}", make, model);
        let detail = format!(
            "Android Auto vehicle id='{}' make='{}' model='{}' head_unit='{}' bluetooth='{}'",
            id, make, model, head_unit_name, bluetooth_address
        );
        out.push(build_record(
            ArtifactCategory::SystemActivity,
            "Android Auto Vehicle",
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

fn read_destinations(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, name, address, latitude, longitude, \
         navigated_at FROM \"{table}\" ORDER BY navigated_at DESC LIMIT 5000",
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
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<f64>>(3).unwrap_or(None),
            row.get::<_, Option<f64>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, name, address, lat, lon, ts_ms) in rows.flatten() {
        let id = id.unwrap_or_default();
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let address = address.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Android Auto nav: {}", name);
        let mut detail = format!(
            "Android Auto navigation id='{}' name='{}' address='{}'",
            id, name, address
        );
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" lat={:.6} lon={:.6}", la, lo));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Android Auto Navigation",
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
            CREATE TABLE session (
                id TEXT,
                vehicle_id TEXT,
                started_at INTEGER,
                ended_at INTEGER,
                duration INTEGER,
                connection_type TEXT
            );
            INSERT INTO session VALUES('s1','v1',1609459200000,1609462800000,3600000,'USB');
            CREATE TABLE paired_vehicle (
                id TEXT,
                make TEXT,
                model TEXT,
                head_unit_name TEXT,
                bluetooth_address TEXT,
                last_connected_at INTEGER
            );
            INSERT INTO paired_vehicle VALUES('v1','Honda','Civic','Civic Audio','AA:BB:CC:DD:EE:FF',1609459200000);
            CREATE TABLE recent_destination (
                id TEXT,
                name TEXT,
                address TEXT,
                latitude REAL,
                longitude REAL,
                navigated_at INTEGER
            );
            INSERT INTO recent_destination VALUES('d1','Work','456 Office Park',37.7749,-122.4194,1609459300000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_sessions_vehicles_destinations() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Android Auto Session"));
        assert!(r.iter().any(|a| a.subcategory == "Android Auto Vehicle"));
        assert!(r.iter().any(|a| a.subcategory == "Android Auto Navigation"));
    }

    #[test]
    fn vehicle_bluetooth_address_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("bluetooth='AA:BB:CC:DD:EE:FF'")));
    }

    #[test]
    fn destination_gps_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("lat=37.774900")));
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
