//! Google Home — smart home device control and activity history.
//!
//! Source path: `/data/data/com.google.android.apps.chromecast.app/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Google Home uses Room databases
//! to cache linked devices, rooms, and recent activity. Tables include
//! `device`, `room`, `home_graph`, `activity`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.google.android.apps.chromecast.app/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "device") {
        out.extend(read_devices(&conn, path));
    }
    for table in &["activity", "activity_history"] {
        if table_exists(&conn, table) {
            out.extend(read_activity(&conn, path, table));
            break;
        }
    }
    if table_exists(&conn, "room") {
        out.extend(read_rooms(&conn, path));
    }
    out
}

fn read_devices(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, name, device_type, manufacturer, model, \
               room_id, ip_address, last_seen_at \
               FROM device LIMIT 5000";
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
            row.get::<_, Option<String>>(6).unwrap_or(None),
            row.get::<_, Option<i64>>(7).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, name, device_type, manufacturer, model, room_id, ip, last_seen_ms) in rows.flatten() {
        let id = id.unwrap_or_else(|| "(unknown)".to_string());
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let device_type = device_type.unwrap_or_default();
        let manufacturer = manufacturer.unwrap_or_default();
        let model = model.unwrap_or_default();
        let room_id = room_id.unwrap_or_default();
        let ip = ip.unwrap_or_default();
        let ts = last_seen_ms.and_then(unix_ms_to_i64);
        let title = format!("Google Home device: {} ({})", name, device_type);
        let mut detail = format!(
            "Google Home device id='{}' name='{}' type='{}' manufacturer='{}' model='{}'",
            id, name, device_type, manufacturer, model
        );
        if !room_id.is_empty() {
            detail.push_str(&format!(" room_id='{}'", room_id));
        }
        if !ip.is_empty() {
            detail.push_str(&format!(" ip='{}'", ip));
        }
        out.push(build_record(
            ArtifactCategory::SystemActivity,
            "Google Home Device",
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

fn read_activity(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, device_id, action, timestamp, actor \
         FROM \"{table}\" ORDER BY timestamp DESC LIMIT 10000",
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
    for (id, device_id, action, ts_ms, actor) in rows.flatten() {
        let id = id.unwrap_or_default();
        let device_id = device_id.unwrap_or_default();
        let action = action.unwrap_or_else(|| "(unknown)".to_string());
        let actor = actor.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Google Home activity: {} on {}", action, device_id);
        let detail = format!(
            "Google Home activity id='{}' device_id='{}' action='{}' actor='{}'",
            id, device_id, action, actor
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Google Home Activity",
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

fn read_rooms(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, name, home_id FROM room LIMIT 100";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, name, home_id) in rows.flatten() {
        let id = id.unwrap_or_default();
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let home_id = home_id.unwrap_or_default();
        let title = format!("Google Home room: {}", name);
        let detail = format!("Google Home room id='{}' name='{}' home_id='{}'", id, name, home_id);
        out.push(build_record(
            ArtifactCategory::SystemActivity,
            "Google Home Room",
            title,
            detail,
            path,
            None,
            ForensicValue::Medium,
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
            CREATE TABLE device (
                id TEXT,
                name TEXT,
                device_type TEXT,
                manufacturer TEXT,
                model TEXT,
                room_id TEXT,
                ip_address TEXT,
                last_seen_at INTEGER
            );
            INSERT INTO device VALUES('d1','Living Room Speaker','nest.audio','Google','Nest Audio','r1','192.168.1.100',1609459200000);
            INSERT INTO device VALUES('d2','Front Door Cam','camera','Google','Nest Cam','r2','192.168.1.101',1609459300000);
            CREATE TABLE activity (
                id TEXT,
                device_id TEXT,
                action TEXT,
                timestamp INTEGER,
                actor TEXT
            );
            INSERT INTO activity VALUES('a1','d1','play_music',1609459400000,'user@example.com');
            CREATE TABLE room (
                id TEXT,
                name TEXT,
                home_id TEXT
            );
            INSERT INTO room VALUES('r1','Living Room','h1');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_devices_activity_rooms() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Google Home Device"));
        assert!(r.iter().any(|a| a.subcategory == "Google Home Activity"));
        assert!(r.iter().any(|a| a.subcategory == "Google Home Room"));
    }

    #[test]
    fn device_ip_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("ip='192.168.1.100'")));
    }

    #[test]
    fn activity_actor_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("actor='user@example.com'")));
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
