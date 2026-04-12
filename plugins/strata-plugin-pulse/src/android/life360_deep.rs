//! Life360 — deeper driving event, crash detection, and circle member parsing.
//!
//! Source path: `/data/data/com.life360.android.safetymapd/databases/`.
//!
//! Schema note: not in ALEAPP upstream. Complements the existing `life360.rs`
//! parser (messages, places, events). This module targets driving telemetry,
//! crash detection records, and circle member location snapshots — all of
//! which are Critical forensic value for accident reconstruction and alibi.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.life360.android.safetymapd/databases/l360localstoreroomdatabase",
    "com.life360.android.safetymapd/databases/l360eventstore.db",
    "com.life360.android.safetymapd/databases/life360.db",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["driving_events", "drivingevent", "driving_event"] {
        if table_exists(&conn, table) {
            out.extend(read_driving_events(&conn, path, table));
            break;
        }
    }
    for table in &["crash_detection", "crash", "crashevent"] {
        if table_exists(&conn, table) {
            out.extend(read_crash_detection(&conn, path, table));
            break;
        }
    }
    for table in &["circle_members", "circlemember", "members"] {
        if table_exists(&conn, table) {
            out.extend(read_circle_members(&conn, path, table));
            break;
        }
    }
    out
}

fn read_driving_events(
    conn: &rusqlite::Connection,
    path: &Path,
    table: &str,
) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT event_type, lat, lon, speed_mph, timestamp \
         FROM \"{t}\" ORDER BY timestamp DESC LIMIT 10000",
        t = table.replace('"', "\"\"")
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
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (event_type, lat, lon, speed_mph, ts_ms) in rows.flatten() {
        let event_type = event_type.unwrap_or_else(|| "(unknown)".to_string());
        let speed_mph = speed_mph.unwrap_or(0.0);
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Life360 driving event: {}", event_type);
        let mut detail = format!(
            "Life360 driving_event event_type='{}' speed_mph={:.1}",
            event_type, speed_mph
        );
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" lat={:.6} lon={:.6}", la, lo));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Life360 Driving Event",
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

fn read_crash_detection(
    conn: &rusqlite::Connection,
    path: &Path,
    table: &str,
) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT crash_id, lat, lon, severity, detected_at, emergency_dispatched \
         FROM \"{t}\" ORDER BY detected_at DESC LIMIT 1000",
        t = table.replace('"', "\"\"")
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
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (crash_id, lat, lon, severity, ts_ms, emergency) in rows.flatten() {
        let crash_id = crash_id.unwrap_or_default();
        let severity = severity.unwrap_or_else(|| "unknown".to_string());
        let emergency_dispatched = emergency.unwrap_or(0) != 0;
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Life360 crash detection: {} severity={}", crash_id, severity);
        let mut detail = format!(
            "Life360 crash_detection crash_id='{}' severity='{}' emergency_dispatched={}",
            crash_id, severity, emergency_dispatched
        );
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" lat={:.6} lon={:.6}", la, lo));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Life360 Crash",
            title,
            detail,
            path,
            ts,
            ForensicValue::Critical,
            true,
        ));
    }
    out
}

fn read_circle_members(
    conn: &rusqlite::Connection,
    path: &Path,
    table: &str,
) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT member_name, phone, email, battery_level, \
         last_seen_lat, last_seen_lon, last_seen_at \
         FROM \"{t}\" LIMIT 5000",
        t = table.replace('"', "\"\"")
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
            row.get::<_, Option<f64>>(4).unwrap_or(None),
            row.get::<_, Option<f64>>(5).unwrap_or(None),
            row.get::<_, Option<i64>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (name, phone, email, battery, lat, lon, ts_ms) in rows.flatten() {
        let name = name.unwrap_or_else(|| "(unknown)".to_string());
        let phone = phone.unwrap_or_default();
        let email = email.unwrap_or_default();
        let battery = battery.unwrap_or(-1);
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Life360 member: {}", name);
        let mut detail = format!(
            "Life360 circle_member member_name='{}' phone='{}' email='{}' battery_level={}",
            name, phone, email, battery
        );
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" last_seen_lat={:.6} last_seen_lon={:.6}", la, lo));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Life360 Circle Member",
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
            CREATE TABLE driving_events (
                event_type TEXT,
                lat REAL,
                lon REAL,
                speed_mph REAL,
                timestamp INTEGER
            );
            INSERT INTO driving_events VALUES('hard_brake',37.7749,-122.4194,45.5,1609459200000);
            INSERT INTO driving_events VALUES('phone_use',37.7800,-122.4100,62.0,1609459300000);
            CREATE TABLE crash_detection (
                crash_id TEXT,
                lat REAL,
                lon REAL,
                severity TEXT,
                detected_at INTEGER,
                emergency_dispatched INTEGER
            );
            INSERT INTO crash_detection VALUES('CR001',37.7749,-122.4194,'high',1609459400000,1);
            CREATE TABLE circle_members (
                member_name TEXT,
                phone TEXT,
                email TEXT,
                battery_level INTEGER,
                last_seen_lat REAL,
                last_seen_lon REAL,
                last_seen_at INTEGER
            );
            INSERT INTO circle_members VALUES('John Doe','555-1234','john@example.com',72,37.7749,-122.4194,1609459500000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_driving_crash_members() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Life360 Driving Event"));
        assert!(r.iter().any(|a| a.subcategory == "Life360 Crash"));
        assert!(r.iter().any(|a| a.subcategory == "Life360 Circle Member"));
    }

    #[test]
    fn driving_event_speed_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let ev = r.iter().find(|a| a.subcategory == "Life360 Driving Event" && a.detail.contains("hard_brake")).unwrap();
        assert!(ev.detail.contains("speed_mph=45.5"));
        assert!(ev.detail.contains("lat=37.774900"));
    }

    #[test]
    fn crash_emergency_flag_set() {
        let db = make_db();
        let r = parse(db.path());
        let crash = r.iter().find(|a| a.subcategory == "Life360 Crash").unwrap();
        assert!(crash.detail.contains("emergency_dispatched=true"));
        assert!(crash.is_suspicious);
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
