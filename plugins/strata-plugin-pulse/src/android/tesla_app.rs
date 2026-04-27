//! Tesla — companion app vehicle state, charging, and drive history.
//!
//! Source path: `/data/data/com.teslamotors.tesla/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Tesla app caches vehicle state
//! (battery, lock, climate), charging sessions, and drive summaries.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.teslamotors.tesla/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "vehicle") {
        out.extend(read_vehicles(&conn, path));
    }
    for table in &["drive_history", "drive_summary", "trip"] {
        if table_exists(&conn, table) {
            out.extend(read_drives(&conn, path, table));
            break;
        }
    }
    for table in &["charging_session", "charge_history"] {
        if table_exists(&conn, table) {
            out.extend(read_charging(&conn, path, table));
            break;
        }
    }
    out
}

fn read_vehicles(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, vin, display_name, model, color, \
               software_version, odometer \
               FROM vehicle LIMIT 10";
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
            row.get::<_, Option<String>>(5).unwrap_or(None),
            row.get::<_, Option<f64>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, vin, display_name, model, color, sw_version, odometer) in rows.flatten() {
        let id = id.unwrap_or_default();
        let vin = vin.unwrap_or_default();
        let display_name = display_name.unwrap_or_else(|| "(unnamed)".to_string());
        let model = model.unwrap_or_default();
        let color = color.unwrap_or_default();
        let sw_version = sw_version.unwrap_or_default();
        let odometer = odometer.unwrap_or(0.0);
        let title = format!("Tesla: {} ({})", display_name, model);
        let detail = format!(
            "Tesla vehicle id='{}' vin='{}' display_name='{}' model='{}' color='{}' software='{}' odometer={:.1}",
            id, vin, display_name, model, color, sw_version, odometer
        );
        out.push(build_record(
            ArtifactCategory::SystemActivity,
            "Tesla Vehicle",
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

fn read_drives(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, vehicle_id, started_at, ended_at, \
         start_address, end_address, start_lat, start_lon, \
         end_lat, end_lon, distance, energy_used \
         FROM \"{table}\" ORDER BY started_at DESC LIMIT 10000",
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
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
            row.get::<_, Option<f64>>(6).unwrap_or(None),
            row.get::<_, Option<f64>>(7).unwrap_or(None),
            row.get::<_, Option<f64>>(8).unwrap_or(None),
            row.get::<_, Option<f64>>(9).unwrap_or(None),
            row.get::<_, Option<f64>>(10).unwrap_or(None),
            row.get::<_, Option<f64>>(11).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (
        id,
        vehicle_id,
        started_ms,
        _ended_ms,
        start_addr,
        end_addr,
        start_lat,
        start_lon,
        end_lat,
        end_lon,
        distance,
        energy,
    ) in rows.flatten()
    {
        let id = id.unwrap_or_default();
        let vehicle_id = vehicle_id.unwrap_or_default();
        let start_addr = start_addr.unwrap_or_default();
        let end_addr = end_addr.unwrap_or_default();
        let distance = distance.unwrap_or(0.0);
        let energy = energy.unwrap_or(0.0);
        let ts = started_ms.and_then(unix_ms_to_i64);
        let title = format!("Tesla drive: {} → {}", start_addr, end_addr);
        let mut detail = format!(
            "Tesla drive id='{}' vehicle_id='{}' start_address='{}' end_address='{}' distance={:.1} energy_used={:.2}",
            id, vehicle_id, start_addr, end_addr, distance, energy
        );
        if let (Some(la), Some(lo)) = (start_lat, start_lon) {
            detail.push_str(&format!(" start_lat={:.6} start_lon={:.6}", la, lo));
        }
        if let (Some(la), Some(lo)) = (end_lat, end_lon) {
            detail.push_str(&format!(" end_lat={:.6} end_lon={:.6}", la, lo));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Tesla Drive",
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

fn read_charging(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, vehicle_id, started_at, ended_at, \
         charger_type, kwh_added, location_name, location_lat, location_lon \
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
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<f64>>(5).unwrap_or(None),
            row.get::<_, Option<String>>(6).unwrap_or(None),
            row.get::<_, Option<f64>>(7).unwrap_or(None),
            row.get::<_, Option<f64>>(8).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, vehicle_id, started_ms, _ended_ms, charger_type, kwh, loc_name, lat, lon) in
        rows.flatten()
    {
        let id = id.unwrap_or_default();
        let vehicle_id = vehicle_id.unwrap_or_default();
        let charger_type = charger_type.unwrap_or_default();
        let kwh = kwh.unwrap_or(0.0);
        let loc_name = loc_name.unwrap_or_default();
        let ts = started_ms.and_then(unix_ms_to_i64);
        let title = format!("Tesla charge: {} ({:.1} kWh)", loc_name, kwh);
        let mut detail = format!(
            "Tesla charging session id='{}' vehicle_id='{}' charger_type='{}' kwh_added={:.2} location='{}'",
            id, vehicle_id, charger_type, kwh, loc_name
        );
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" lat={:.6} lon={:.6}", la, lo));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Tesla Charging",
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
            CREATE TABLE vehicle (
                id TEXT,
                vin TEXT,
                display_name TEXT,
                model TEXT,
                color TEXT,
                software_version TEXT,
                odometer REAL
            );
            INSERT INTO vehicle VALUES('v1','5YJ3E1EA4LF123456','My Model 3','Model 3','Pearl White','2023.44.30.4',15234.5);
            CREATE TABLE drive_history (
                id TEXT,
                vehicle_id TEXT,
                started_at INTEGER,
                ended_at INTEGER,
                start_address TEXT,
                end_address TEXT,
                start_lat REAL,
                start_lon REAL,
                end_lat REAL,
                end_lon REAL,
                distance REAL,
                energy_used REAL
            );
            INSERT INTO drive_history VALUES('d1','v1',1609459200000,1609462800000,'Home','Work',37.7749,-122.4194,37.7900,-122.4100,15.2,5.5);
            CREATE TABLE charging_session (
                id TEXT,
                vehicle_id TEXT,
                started_at INTEGER,
                ended_at INTEGER,
                charger_type TEXT,
                kwh_added REAL,
                location_name TEXT,
                location_lat REAL,
                location_lon REAL
            );
            INSERT INTO charging_session VALUES('c1','v1',1609459000000,1609463000000,'supercharger',45.8,'SF Supercharger',37.7800,-122.4100);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_vehicle_drives_charging() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Tesla Vehicle"));
        assert!(r.iter().any(|a| a.subcategory == "Tesla Drive"));
        assert!(r.iter().any(|a| a.subcategory == "Tesla Charging"));
    }

    #[test]
    fn vin_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("vin='5YJ3E1EA4LF123456'")));
    }

    #[test]
    fn drive_gps_and_energy() {
        let db = make_db();
        let r = parse(db.path());
        let d = r.iter().find(|a| a.subcategory == "Tesla Drive").unwrap();
        assert!(d.detail.contains("start_lat=37.774900"));
        assert!(d.detail.contains("end_lat=37.790000"));
        assert!(d.detail.contains("energy_used=5.50"));
    }

    #[test]
    fn charging_kwh_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("45.8 kWh")));
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
