//! Philips Hue — smart lighting bridge and scene history.
//!
//! Source path: `/data/data/com.philips.lighting.hue2/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Hue app caches bridge info,
//! lights, groups, and scene activations.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.philips.lighting.hue2/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "bridge") {
        out.extend(read_bridges(&conn, path));
    }
    if table_exists(&conn, "light") {
        out.extend(read_lights(&conn, path));
    }
    for table in &["scene_activation", "scene_history"] {
        if table_exists(&conn, table) {
            out.extend(read_scenes(&conn, path, table));
            break;
        }
    }
    out
}

fn read_bridges(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, name, ip_address, mac_address, api_version, \
               software_version FROM bridge LIMIT 10";
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
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, name, ip, mac, api_ver, sw_ver) in rows.flatten() {
        let id = id.unwrap_or_default();
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let ip = ip.unwrap_or_default();
        let mac = mac.unwrap_or_default();
        let api_ver = api_ver.unwrap_or_default();
        let sw_ver = sw_ver.unwrap_or_default();
        let title = format!("Hue bridge: {} ({})", name, mac);
        let detail = format!(
            "Philips Hue bridge id='{}' name='{}' ip='{}' mac='{}' api_version='{}' software='{}'",
            id, name, ip, mac, api_ver, sw_ver
        );
        out.push(build_record(
            ArtifactCategory::SystemActivity,
            "Hue Bridge",
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

fn read_lights(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, name, model, room, on_state \
               FROM light LIMIT 1000";
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
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, name, model, room, on_state) in rows.flatten() {
        let id = id.unwrap_or_default();
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let model = model.unwrap_or_default();
        let room = room.unwrap_or_default();
        let on_state = on_state.unwrap_or(0) != 0;
        let title = format!(
            "Hue light: {} ({})",
            name,
            if on_state { "on" } else { "off" }
        );
        let detail = format!(
            "Philips Hue light id='{}' name='{}' model='{}' room='{}' on={}",
            id, name, model, room, on_state
        );
        out.push(build_record(
            ArtifactCategory::SystemActivity,
            "Hue Light",
            title,
            detail,
            path,
            None,
            ForensicValue::Low,
            false,
        ));
    }
    out
}

fn read_scenes(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, scene_name, activated_at, actor \
         FROM \"{table}\" ORDER BY activated_at DESC LIMIT 5000",
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
            row.get::<_, Option<String>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, scene_name, ts_ms, actor) in rows.flatten() {
        let id = id.unwrap_or_default();
        let scene_name = scene_name.unwrap_or_else(|| "(unnamed)".to_string());
        let actor = actor.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Hue scene: {}", scene_name);
        let detail = format!(
            "Philips Hue scene activation id='{}' scene_name='{}' actor='{}'",
            id, scene_name, actor
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Hue Scene",
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
            CREATE TABLE bridge (
                id TEXT,
                name TEXT,
                ip_address TEXT,
                mac_address TEXT,
                api_version TEXT,
                software_version TEXT
            );
            INSERT INTO bridge VALUES('b1','Philips hue','192.168.1.5','00:17:88:AA:BB:CC','1.41','1.52.1950111030');
            CREATE TABLE light (
                id TEXT,
                name TEXT,
                model TEXT,
                room TEXT,
                on_state INTEGER
            );
            INSERT INTO light VALUES('l1','Kitchen','LCT015','Kitchen',1);
            INSERT INTO light VALUES('l2','Bedroom','LCT015','Bedroom',0);
            CREATE TABLE scene_activation (
                id TEXT,
                scene_name TEXT,
                activated_at INTEGER,
                actor TEXT
            );
            INSERT INTO scene_activation VALUES('s1','Movie Night',1609459200000,'app');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_bridge_lights_scenes() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Hue Bridge"));
        assert!(r.iter().any(|a| a.subcategory == "Hue Light"));
        assert!(r.iter().any(|a| a.subcategory == "Hue Scene"));
    }

    #[test]
    fn bridge_mac_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("mac='00:17:88:AA:BB:CC'")));
    }

    #[test]
    fn light_on_state_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.title.contains("Kitchen") && a.title.contains("on")));
        assert!(r
            .iter()
            .any(|a| a.title.contains("Bedroom") && a.title.contains("off")));
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
