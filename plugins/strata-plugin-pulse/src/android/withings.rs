//! Withings Health Mate — health device and measurement extraction.
//!
//! ALEAPP reference: `scripts/artifacts/WithingsHealthMate.py`. Source:
//! `/data/data/com.withings.wiscale2/databases/Withings-WiScale*`.
//!
//! Key tables: `users`, `Track`, `WorkoutLocation`, `devices`, `chat`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.withings.wiscale2/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "Track") {
        out.extend(read_tracks(&conn, path));
    }
    if table_exists(&conn, "WorkoutLocation") {
        out.extend(read_locations(&conn, path));
    }
    if table_exists(&conn, "devices") {
        out.extend(read_devices(&conn, path));
    }
    out
}

fn read_tracks(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, userID, startdate, enddate, category \
               FROM Track ORDER BY startdate DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, user, start, end, category) in rows.flatten() {
        let id = id.unwrap_or(0);
        let user = user.unwrap_or(0);
        let category = category.unwrap_or(0);
        let dur_s = end.zip(start).map(|(e, s)| e - s).unwrap_or(0);
        let ts = start;
        let title = format!("Withings track #{}: category={} ({}s)", id, category, dur_s);
        let detail = format!(
            "Withings track id={} user={} category={} duration={}s",
            id, user, category, dur_s
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Withings Track",
            title,
            detail,
            path,
            ts,
            ForensicValue::Medium,
            false,
        ));
    }
    out
}

fn read_locations(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, userID, timestamp, latitude, longitude, altitude, speed \
               FROM WorkoutLocation ORDER BY timestamp DESC LIMIT 10000";
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
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, user, ts, lat, lon, alt, speed) in rows.flatten() {
        let id = id.unwrap_or(0);
        let user = user.unwrap_or(0);
        let title = format!("Withings location {} user={}", id, user);
        let mut detail = format!("Withings workout location id={} user={}", id, user);
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" lat={:.6} lon={:.6}", la, lo));
        }
        if let Some(a) = alt {
            detail.push_str(&format!(" altitude={:.1}m", a));
        }
        if let Some(s) = speed {
            detail.push_str(&format!(" speed={:.2}", s));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Withings Location",
            title,
            detail,
            path,
            ts,
            ForensicValue::Medium,
            false,
        ));
    }
    out
}

fn read_devices(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, userID, associationDate, macAddress, firmware, deviceType, deviceModel \
               FROM devices LIMIT 100";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
            row.get::<_, Option<String>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, user, assoc_ms, mac, firmware, device_type, device_model) in rows.flatten() {
        let id = id.unwrap_or(0);
        let user = user.unwrap_or(0);
        let mac = mac.unwrap_or_default();
        let firmware = firmware.unwrap_or_default();
        let device_type = device_type.unwrap_or_default();
        let device_model = device_model.unwrap_or_default();
        let ts = assoc_ms.and_then(unix_ms_to_i64);
        let title = format!("Withings device: {} {}", device_model, mac);
        let detail = format!(
            "Withings device id={} user={} mac='{}' firmware='{}' type='{}' model='{}'",
            id, user, mac, firmware, device_type, device_model
        );
        out.push(build_record(
            ArtifactCategory::SystemActivity,
            "Withings Device",
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
            CREATE TABLE Track (
                id INTEGER PRIMARY KEY,
                userID INTEGER,
                startdate INTEGER,
                enddate INTEGER,
                category INTEGER
            );
            INSERT INTO Track VALUES(1,100,1609459200,1609462800,1);
            CREATE TABLE WorkoutLocation (
                id INTEGER,
                userID INTEGER,
                timestamp INTEGER,
                latitude REAL,
                longitude REAL,
                altitude REAL,
                speed REAL,
                accuracy REAL
            );
            INSERT INTO WorkoutLocation VALUES(1,100,1609459200,37.7749,-122.4194,30.0,2.5,5.0);
            CREATE TABLE devices (
                id INTEGER PRIMARY KEY,
                userID INTEGER,
                associationDate INTEGER,
                macAddress TEXT,
                firmware TEXT,
                deviceType TEXT,
                deviceModel TEXT
            );
            INSERT INTO devices VALUES(1,100,1609459200000,'AA:BB:CC:DD:EE:FF','1.2.3','Scale','Body+');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_all_three_tables() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Withings Track"));
        assert!(r.iter().any(|a| a.subcategory == "Withings Location"));
        assert!(r.iter().any(|a| a.subcategory == "Withings Device"));
    }

    #[test]
    fn device_mac_address_captured() {
        let db = make_db();
        let r = parse(db.path());
        let d = r
            .iter()
            .find(|a| a.subcategory == "Withings Device")
            .unwrap();
        assert!(d.detail.contains("mac='AA:BB:CC:DD:EE:FF'"));
        assert!(d.detail.contains("model='Body+'"));
    }

    #[test]
    fn workout_location_gps() {
        let db = make_db();
        let r = parse(db.path());
        let l = r
            .iter()
            .find(|a| a.subcategory == "Withings Location")
            .unwrap();
        assert!(l.detail.contains("lat=37.774900"));
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
