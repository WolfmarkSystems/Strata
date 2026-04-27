//! Ring Doorbell — video doorbell events and motion alerts.
//!
//! Source path: `/data/data/com.ringapp/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Ring stores doorbell ding,
//! motion, and live view events in tables like `ding_history`, `event`,
//! `device`. Forensic interest: establishes presence/absence at a
//! residence via motion detection timestamps.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.ringapp/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["ding_history", "event_history", "event"] {
        if table_exists(&conn, table) {
            out.extend(read_events(&conn, path, table));
            break;
        }
    }
    if table_exists(&conn, "device") {
        out.extend(read_devices(&conn, path));
    }
    out
}

fn read_events(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, device_id, kind, created_at, answered, \
         recording_url, motion_zone \
         FROM \"{table}\" ORDER BY created_at DESC LIMIT 10000",
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
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
            row.get::<_, Option<String>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, device_id, kind, ts_ms, answered, recording_url, motion_zone) in rows.flatten() {
        let id = id.unwrap_or_else(|| "(unknown)".to_string());
        let device_id = device_id.unwrap_or_default();
        let kind = kind.unwrap_or_else(|| "unknown".to_string());
        let answered = answered.unwrap_or(0) != 0;
        let recording_url = recording_url.unwrap_or_default();
        let motion_zone = motion_zone.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Ring {}: device {}", kind, device_id);
        let mut detail = format!(
            "Ring event id='{}' device_id='{}' kind='{}' answered={}",
            id, device_id, kind, answered
        );
        if !recording_url.is_empty() {
            detail.push_str(&format!(" recording_url='{}'", recording_url));
        }
        if !motion_zone.is_empty() {
            detail.push_str(&format!(" motion_zone='{}'", motion_zone));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Ring Event",
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

fn read_devices(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, description, kind, firmware_version, battery_life \
               FROM device LIMIT 100";
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
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, description, kind, firmware, battery) in rows.flatten() {
        let id = id.unwrap_or_default();
        let description = description.unwrap_or_else(|| "(unnamed)".to_string());
        let kind = kind.unwrap_or_default();
        let firmware = firmware.unwrap_or_default();
        let battery = battery.unwrap_or_default();
        let title = format!("Ring device: {} ({})", description, kind);
        let detail = format!(
            "Ring device id='{}' description='{}' kind='{}' firmware='{}' battery='{}'",
            id, description, kind, firmware, battery
        );
        out.push(build_record(
            ArtifactCategory::SystemActivity,
            "Ring Device",
            title,
            detail,
            path,
            None,
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
            CREATE TABLE ding_history (
                id TEXT,
                device_id TEXT,
                kind TEXT,
                created_at INTEGER,
                answered INTEGER,
                recording_url TEXT,
                motion_zone TEXT
            );
            INSERT INTO ding_history VALUES('e1','d1','ding',1609459200000,1,'https://ring.com/rec/e1.mp4','front_door');
            INSERT INTO ding_history VALUES('e2','d1','motion',1609459300000,0,'https://ring.com/rec/e2.mp4','porch');
            CREATE TABLE device (
                id TEXT,
                description TEXT,
                kind TEXT,
                firmware_version TEXT,
                battery_life TEXT
            );
            INSERT INTO device VALUES('d1','Front Door','doorbell_v3','1.8.9','85');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_events_and_devices() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Ring Event"));
        assert!(r.iter().any(|a| a.subcategory == "Ring Device"));
    }

    #[test]
    fn answered_flag_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("kind='ding'") && a.detail.contains("answered=true")));
        assert!(r
            .iter()
            .any(|a| a.detail.contains("kind='motion'") && a.detail.contains("answered=false")));
    }

    #[test]
    fn motion_zone_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("motion_zone='front_door'")));
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
