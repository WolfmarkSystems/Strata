//! Google Family Link — child device monitoring and parental controls extraction.
//!
//! Source path: `/data/data/com.google.android.apps.kids.familylink*/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Google Family Link tracks child device
//! usage, locations, app limits, and screen time. Child location data and
//! supervision records are critical forensic evidence. Table names vary
//! across Family Link versions and companion app variants.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.google.android.apps.kids.familylink"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["child_devices", "devices", "child_device"] {
        if table_exists(&conn, table) {
            out.extend(read_devices(&conn, path, table));
            break;
        }
    }
    for table in &["location_history", "locations", "location"] {
        if table_exists(&conn, table) {
            out.extend(read_locations(&conn, path, table));
            break;
        }
    }
    for table in &["screen_time", "app_usage", "usage_limits"] {
        if table_exists(&conn, table) {
            out.extend(read_screen_time(&conn, path, table));
            break;
        }
    }
    out
}

fn read_devices(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT device_id, child_name, device_name, last_seen \
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
            row.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (device_id, child_name, device_name, last_seen_ms) in rows.flatten() {
        let device_id = device_id.unwrap_or_else(|| "(unknown)".to_string());
        let child_name = child_name.unwrap_or_else(|| "(unknown child)".to_string());
        let device_name = device_name.unwrap_or_default();
        let ts = last_seen_ms.and_then(unix_ms_to_i64);
        let title = format!("Family Link child device: {} ({})", child_name, device_name);
        let detail = format!(
            "Family Link child device device_id='{}' child_name='{}' device_name='{}'",
            device_id, child_name, device_name
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Family Link Device",
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

fn read_locations(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT latitude, longitude, timestamp, child_name, accuracy \
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
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<f64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (lat, lon, ts_ms, child_name, accuracy) in rows.flatten() {
        let child_name = child_name.unwrap_or_else(|| "(unknown child)".to_string());
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Family Link location: {}", child_name);
        let mut detail = format!("Family Link location child_name='{}'", child_name);
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" lat={:.6} lon={:.6}", la, lo));
        }
        if let Some(acc) = accuracy {
            detail.push_str(&format!(" accuracy={:.1}m", acc));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Family Link Location",
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

fn read_screen_time(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT date, app_name, duration_minutes, child_name \
         FROM \"{table}\" ORDER BY date DESC LIMIT 5000",
        table = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (date_ms, app_name, duration_min, child_name) in rows.flatten() {
        let app_name = app_name.unwrap_or_else(|| "(unknown app)".to_string());
        let child_name = child_name.unwrap_or_else(|| "(unknown child)".to_string());
        let duration = duration_min.unwrap_or(0);
        let ts = date_ms.and_then(unix_ms_to_i64);
        let title = format!(
            "Family Link screen time: {} {}min {}",
            child_name, duration, app_name
        );
        let detail = format!(
            "Family Link screen time child_name='{}' app_name='{}' duration_minutes={}",
            child_name, app_name, duration
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Family Link Screen Time",
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
            CREATE TABLE child_devices (
                device_id TEXT,
                child_name TEXT,
                device_name TEXT,
                last_seen INTEGER
            );
            INSERT INTO child_devices VALUES('dev_001','Emma','Emma Pixel 6',1609459200000);
            CREATE TABLE location_history (
                latitude REAL,
                longitude REAL,
                timestamp INTEGER,
                child_name TEXT,
                accuracy REAL
            );
            INSERT INTO location_history VALUES(37.7749,-122.4194,1609459200000,'Emma',5.0);
            INSERT INTO location_history VALUES(37.7755,-122.4180,1609462800000,'Emma',8.0);
            CREATE TABLE screen_time (
                date INTEGER,
                app_name TEXT,
                duration_minutes INTEGER,
                child_name TEXT
            );
            INSERT INTO screen_time VALUES(1609459200000,'YouTube Kids',45,'Emma');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_devices_locations_screen_time() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Family Link Device"));
        assert!(r.iter().any(|a| a.subcategory == "Family Link Location"));
        assert!(r.iter().any(|a| a.subcategory == "Family Link Screen Time"));
    }

    #[test]
    fn child_location_gps_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("lat=37.774900") && a.detail.contains("child_name='Emma'")));
    }

    #[test]
    fn screen_time_duration_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("duration_minutes=45")
            && a.detail.contains("app_name='YouTube Kids'")));
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
