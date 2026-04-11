//! Life360 — family location tracking and messaging.
//!
//! ALEAPP reference: `scripts/artifacts/Life360.py`. Source paths:
//! - `/data/data/com.life360.android.safetymapd/databases/messaging.db`
//! - `/data/data/com.life360.android.safetymapd/databases/L360LocalStoreRoomDatabase`
//! - `/data/data/com.life360.android.safetymapd/databases/L360EventStore.db`
//!
//! Key tables: `message`, `places`, `event`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.life360.android.safetymapd/databases/messaging.db",
    "com.life360.android.safetymapd/databases/l360localstoreroomdatabase",
    "com.life360.android.safetymapd/databases/l360eventstore.db",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "message") {
        out.extend(read_messages(&conn, path));
    }
    if table_exists(&conn, "places") {
        out.extend(read_places(&conn, path));
    }
    if table_exists(&conn, "event") {
        out.extend(read_events(&conn, path));
    }
    out
}

fn read_messages(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT created_at, thread_id, sender_id, content, \
               has_location, location_latitude, location_longitude, location_name \
               FROM message \
               ORDER BY created_at DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<f64>>(5).unwrap_or(None),
            row.get::<_, Option<f64>>(6).unwrap_or(None),
            row.get::<_, Option<String>>(7).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (ts_ms, thread, sender, content, has_loc, lat, lon, loc_name) in rows.flatten() {
        let sender = sender.unwrap_or_else(|| "(unknown)".to_string());
        let thread = thread.unwrap_or_default();
        let body = content.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let has_location = has_loc.unwrap_or(0) != 0;
        let preview: String = body.chars().take(120).collect();
        let title = format!("Life360 {}: {}", sender, preview);
        let mut detail = format!(
            "Life360 message sender='{}' thread='{}' body='{}'",
            sender, thread, body
        );
        if has_location {
            if let (Some(la), Some(lo)) = (lat, lon) {
                detail.push_str(&format!(" lat={:.6} lon={:.6}", la, lo));
            }
            if let Some(n) = loc_name.filter(|n| !n.is_empty()) {
                detail.push_str(&format!(" location_name='{}'", n));
            }
        }
        out.push(build_record(
            ArtifactCategory::Communications,
            "Life360 Message",
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

fn read_places(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT name, latitude, longitude, radius, source, owner_id \
               FROM places LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<f64>>(1).unwrap_or(None),
            row.get::<_, Option<f64>>(2).unwrap_or(None),
            row.get::<_, Option<f64>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (name, lat, lon, radius, source, owner) in rows.flatten() {
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let source = source.unwrap_or_default();
        let owner = owner.unwrap_or_default();
        let title = format!("Life360 place: {}", name);
        let mut detail = format!("Life360 place name='{}' owner='{}'", name, owner);
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" lat={:.6} lon={:.6}", la, lo));
        }
        if let Some(r) = radius {
            detail.push_str(&format!(" radius={:.0}m", r));
        }
        if !source.is_empty() {
            detail.push_str(&format!(" source='{}'", source));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Life360 Place",
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

fn read_events(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT timestamp, id, data FROM event \
               ORDER BY timestamp DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (ts_ms, id, data) in rows.flatten() {
        let id = id.unwrap_or_default();
        let data = data.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let preview: String = data.chars().take(120).collect();
        let title = format!("Life360 event {}: {}", id, preview);
        let detail = format!("Life360 event id='{}' data='{}'", id, data);
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Life360 Event",
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

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn make_db() -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE message (
                created_at INTEGER,
                thread_id TEXT,
                sender_id TEXT,
                content TEXT,
                has_location INTEGER,
                location_latitude REAL,
                location_longitude REAL,
                location_name TEXT
            );
            INSERT INTO message VALUES(1609459200000,'t1','alice','On my way',1,37.7749,-122.4194,'Home');
            INSERT INTO message VALUES(1609459300000,'t1','bob','OK thanks',0,NULL,NULL,NULL);
            CREATE TABLE places (
                name TEXT,
                latitude REAL,
                longitude REAL,
                radius REAL,
                source TEXT,
                owner_id TEXT
            );
            INSERT INTO places VALUES('Home',37.7749,-122.4194,100.0,'user','user_1');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_messages_and_places() {
        let db = make_db();
        let r = parse(db.path());
        let msgs: Vec<_> = r.iter().filter(|a| a.subcategory == "Life360 Message").collect();
        let places: Vec<_> = r.iter().filter(|a| a.subcategory == "Life360 Place").collect();
        assert_eq!(msgs.len(), 2);
        assert_eq!(places.len(), 1);
    }

    #[test]
    fn message_with_location_captures_gps() {
        let db = make_db();
        let r = parse(db.path());
        let m = r.iter().find(|a| a.detail.contains("On my way")).unwrap();
        assert!(m.detail.contains("lat=37.774900"));
        assert!(m.detail.contains("location_name='Home'"));
    }

    #[test]
    fn place_radius_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let home = r.iter().find(|a| a.subcategory == "Life360 Place").unwrap();
        assert!(home.detail.contains("radius=100m"));
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
