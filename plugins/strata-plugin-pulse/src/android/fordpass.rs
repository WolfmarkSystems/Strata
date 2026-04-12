//! FordPass — Ford connected vehicle app.
//!
//! Source path: `/data/data/com.ford.fordpass/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. FordPass caches vehicle state,
//! remote start history, and trip summaries.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.ford.fordpass/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "vehicle") {
        out.extend(read_vehicles(&conn, path));
    }
    for table in &["trip_summary", "trip", "trip_history"] {
        if table_exists(&conn, table) {
            out.extend(read_trips(&conn, path, table));
            break;
        }
    }
    for table in &["remote_command", "remote_history"] {
        if table_exists(&conn, table) {
            out.extend(read_remote(&conn, path, table));
            break;
        }
    }
    out
}

fn read_vehicles(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT vin, nickname, year, make, model, odometer, fuel_level \
               FROM vehicle LIMIT 10";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<f64>>(5).unwrap_or(None),
            row.get::<_, Option<f64>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (vin, nickname, year, make, model, odometer, fuel_level) in rows.flatten() {
        let vin = vin.unwrap_or_default();
        let nickname = nickname.unwrap_or_else(|| "(unnamed)".to_string());
        let year = year.unwrap_or(0);
        let make = make.unwrap_or_default();
        let model = model.unwrap_or_default();
        let odometer = odometer.unwrap_or(0.0);
        let fuel_level = fuel_level.unwrap_or(0.0);
        let title = format!("FordPass: {} {} {}", year, make, model);
        let detail = format!(
            "FordPass vehicle vin='{}' nickname='{}' year={} make='{}' model='{}' odometer={:.1} fuel_level={:.1}",
            vin, nickname, year, make, model, odometer, fuel_level
        );
        out.push(build_record(
            ArtifactCategory::SystemActivity,
            "FordPass Vehicle",
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

fn read_trips(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, vin, started_at, ended_at, distance, \
         start_lat, start_lon, end_lat, end_lon, avg_mpg \
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
            row.get::<_, Option<f64>>(4).unwrap_or(None),
            row.get::<_, Option<f64>>(5).unwrap_or(None),
            row.get::<_, Option<f64>>(6).unwrap_or(None),
            row.get::<_, Option<f64>>(7).unwrap_or(None),
            row.get::<_, Option<f64>>(8).unwrap_or(None),
            row.get::<_, Option<f64>>(9).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, vin, started_ms, _ended_ms, distance, s_lat, s_lon, e_lat, e_lon, avg_mpg) in rows.flatten() {
        let id = id.unwrap_or_default();
        let vin = vin.unwrap_or_default();
        let distance = distance.unwrap_or(0.0);
        let avg_mpg = avg_mpg.unwrap_or(0.0);
        let ts = started_ms.and_then(unix_ms_to_i64);
        let title = format!("FordPass trip: {:.1} miles ({:.1} mpg)", distance, avg_mpg);
        let mut detail = format!(
            "FordPass trip id='{}' vin='{}' distance={:.1} avg_mpg={:.1}",
            id, vin, distance, avg_mpg
        );
        if let (Some(la), Some(lo)) = (s_lat, s_lon) {
            detail.push_str(&format!(" start_lat={:.6} start_lon={:.6}", la, lo));
        }
        if let (Some(la), Some(lo)) = (e_lat, e_lon) {
            detail.push_str(&format!(" end_lat={:.6} end_lon={:.6}", la, lo));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "FordPass Trip",
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

fn read_remote(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, vin, command, issued_at, status \
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
    for (id, vin, command, ts_ms, status) in rows.flatten() {
        let id = id.unwrap_or_default();
        let vin = vin.unwrap_or_default();
        let command = command.unwrap_or_else(|| "(unknown)".to_string());
        let status = status.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("FordPass remote: {} ({})", command, status);
        let detail = format!(
            "FordPass remote command id='{}' vin='{}' command='{}' status='{}'",
            id, vin, command, status
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "FordPass Remote",
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
                nickname TEXT,
                year INTEGER,
                make TEXT,
                model TEXT,
                odometer REAL,
                fuel_level REAL
            );
            INSERT INTO vehicle VALUES('1FADP3K20EL987654','My F-150',2022,'Ford','F-150',12500.5,75.0);
            CREATE TABLE trip_summary (
                id TEXT,
                vin TEXT,
                started_at INTEGER,
                ended_at INTEGER,
                distance REAL,
                start_lat REAL,
                start_lon REAL,
                end_lat REAL,
                end_lon REAL,
                avg_mpg REAL
            );
            INSERT INTO trip_summary VALUES('t1','1FADP3K20EL987654',1609459200000,1609462800000,25.3,37.7749,-122.4194,37.7900,-122.4100,22.5);
            CREATE TABLE remote_command (
                id TEXT,
                vin TEXT,
                command TEXT,
                issued_at INTEGER,
                status TEXT
            );
            INSERT INTO remote_command VALUES('rc1','1FADP3K20EL987654','remote_start',1609459300000,'success');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_vehicle_trips_remote() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "FordPass Vehicle"));
        assert!(r.iter().any(|a| a.subcategory == "FordPass Trip"));
        assert!(r.iter().any(|a| a.subcategory == "FordPass Remote"));
    }

    #[test]
    fn remote_start_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("command='remote_start'") && a.detail.contains("status='success'")));
    }

    #[test]
    fn trip_gps_and_mpg() {
        let db = make_db();
        let r = parse(db.path());
        let t = r.iter().find(|a| a.subcategory == "FordPass Trip").unwrap();
        assert!(t.detail.contains("start_lat=37.774900"));
        assert!(t.detail.contains("avg_mpg=22.5"));
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
