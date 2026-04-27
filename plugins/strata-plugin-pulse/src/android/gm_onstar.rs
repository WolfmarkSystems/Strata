//! GM OnStar / myChevrolet / myBuick / myGMC — GM connected vehicle apps.
//!
//! Source paths: `/data/data/com.gm.onstar.mychevrolet/databases/*`,
//! `/data/data/com.gm.onstar.mybuick/databases/*`,
//! `/data/data/com.gm.onstar.mygmc/databases/*`,
//! `/data/data/com.gm.onstar.mycadillac/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. GM companion apps share a
//! common schema covering vehicle info, diagnostics, and remote commands.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.gm.onstar.mychevrolet/databases/",
    "com.gm.onstar.mybuick/databases/",
    "com.gm.onstar.mygmc/databases/",
    "com.gm.onstar.mycadillac/databases/",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "vehicle") {
        out.extend(read_vehicles(&conn, path));
    }
    for table in &["diagnostic", "diagnostic_report"] {
        if table_exists(&conn, table) {
            out.extend(read_diagnostics(&conn, path, table));
            break;
        }
    }
    for table in &["command_history", "remote_command"] {
        if table_exists(&conn, table) {
            out.extend(read_commands(&conn, path, table));
            break;
        }
    }
    out
}

fn read_vehicles(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT vin, year, make, model, odometer, \
               last_location_lat, last_location_lon, last_updated_at \
               FROM vehicle LIMIT 10";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<f64>>(4).unwrap_or(None),
            row.get::<_, Option<f64>>(5).unwrap_or(None),
            row.get::<_, Option<f64>>(6).unwrap_or(None),
            row.get::<_, Option<i64>>(7).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (vin, year, make, model, odometer, lat, lon, last_updated_ms) in rows.flatten() {
        let vin = vin.unwrap_or_default();
        let year = year.unwrap_or(0);
        let make = make.unwrap_or_default();
        let model = model.unwrap_or_default();
        let odometer = odometer.unwrap_or(0.0);
        let ts = last_updated_ms.and_then(unix_ms_to_i64);
        let title = format!("GM vehicle: {} {} {}", year, make, model);
        let mut detail = format!(
            "GM OnStar vehicle vin='{}' year={} make='{}' model='{}' odometer={:.1}",
            vin, year, make, model, odometer
        );
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" last_lat={:.6} last_lon={:.6}", la, lo));
        }
        out.push(build_record(
            ArtifactCategory::SystemActivity,
            "GM Vehicle",
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

fn read_diagnostics(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT vin, report_time, oil_life, tire_pressure_fl, \
         tire_pressure_fr, tire_pressure_rl, tire_pressure_rr, fuel_range \
         FROM \"{table}\" ORDER BY report_time DESC LIMIT 1000",
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
            row.get::<_, Option<f64>>(6).unwrap_or(None),
            row.get::<_, Option<f64>>(7).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (vin, ts_ms, oil_life, tp_fl, tp_fr, tp_rl, tp_rr, fuel_range) in rows.flatten() {
        let vin = vin.unwrap_or_default();
        let oil_life = oil_life.unwrap_or(0.0);
        let fuel_range = fuel_range.unwrap_or(0.0);
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!(
            "GM diagnostic: oil={:.0}% range={:.0}mi",
            oil_life, fuel_range
        );
        let mut detail = format!(
            "GM OnStar diagnostic vin='{}' oil_life={:.1} fuel_range={:.1}",
            vin, oil_life, fuel_range
        );
        if let (Some(fl), Some(fr), Some(rl), Some(rr)) = (tp_fl, tp_fr, tp_rl, tp_rr) {
            detail.push_str(&format!(
                " tire_pressure=[FL={:.0},FR={:.0},RL={:.0},RR={:.0}]",
                fl, fr, rl, rr
            ));
        }
        out.push(build_record(
            ArtifactCategory::SystemActivity,
            "GM Diagnostic",
            title,
            detail,
            path,
            ts,
            ForensicValue::Low,
            false,
        ));
    }
    out
}

fn read_commands(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, vin, command_type, issued_at, status \
         FROM \"{table}\" ORDER BY issued_at DESC LIMIT 5000",
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
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, vin, command_type, ts_ms, status) in rows.flatten() {
        let id = id.unwrap_or_default();
        let vin = vin.unwrap_or_default();
        let command_type = command_type.unwrap_or_default();
        let status = status.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("GM command: {} ({})", command_type, status);
        let detail = format!(
            "GM OnStar remote command id='{}' vin='{}' command_type='{}' status='{}'",
            id, vin, command_type, status
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "GM Remote Command",
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
                vin TEXT,
                year INTEGER,
                make TEXT,
                model TEXT,
                odometer REAL,
                last_location_lat REAL,
                last_location_lon REAL,
                last_updated_at INTEGER
            );
            INSERT INTO vehicle VALUES('1G1FB1RX4N0123456',2022,'Chevrolet','Camaro',8500.0,37.7749,-122.4194,1609459200000);
            CREATE TABLE diagnostic (
                vin TEXT,
                report_time INTEGER,
                oil_life REAL,
                tire_pressure_fl REAL,
                tire_pressure_fr REAL,
                tire_pressure_rl REAL,
                tire_pressure_rr REAL,
                fuel_range REAL
            );
            INSERT INTO diagnostic VALUES('1G1FB1RX4N0123456',1609459300000,85.0,34.0,34.0,33.5,33.5,320.0);
            CREATE TABLE command_history (
                id TEXT,
                vin TEXT,
                command_type TEXT,
                issued_at INTEGER,
                status TEXT
            );
            INSERT INTO command_history VALUES('cmd1','1G1FB1RX4N0123456','lock',1609459400000,'success');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_vehicle_diagnostic_commands() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "GM Vehicle"));
        assert!(r.iter().any(|a| a.subcategory == "GM Diagnostic"));
        assert!(r.iter().any(|a| a.subcategory == "GM Remote Command"));
    }

    #[test]
    fn last_location_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("last_lat=37.774900")));
    }

    #[test]
    fn tire_pressure_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("tire_pressure=[FL=34,FR=34,RL=34,RR=34]")));
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
