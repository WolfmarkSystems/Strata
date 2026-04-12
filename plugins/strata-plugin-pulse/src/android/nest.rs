//! Nest — thermostat and camera activity extraction.
//!
//! Source path: `/data/data/com.nest.android/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Nest app stores thermostat
//! setpoint history, camera events, and away/home status in Room
//! databases.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.nest.android/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "thermostat_history") {
        out.extend(read_thermostat(&conn, path));
    }
    if table_exists(&conn, "camera_event") {
        out.extend(read_camera(&conn, path));
    }
    for table in &["structure_mode", "home_away_history"] {
        if table_exists(&conn, table) {
            out.extend(read_away(&conn, path, table));
            break;
        }
    }
    out
}

fn read_thermostat(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT device_id, timestamp, current_temp, target_temp, \
               mode, hvac_state \
               FROM thermostat_history ORDER BY timestamp DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
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
    for (device_id, ts_ms, current_temp, target_temp, mode, hvac_state) in rows.flatten() {
        let device_id = device_id.unwrap_or_else(|| "(unknown)".to_string());
        let current_temp = current_temp.unwrap_or(0.0);
        let target_temp = target_temp.unwrap_or(0.0);
        let mode = mode.unwrap_or_default();
        let hvac_state = hvac_state.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Nest thermostat: {:.1}°→{:.1}° ({})", current_temp, target_temp, mode);
        let detail = format!(
            "Nest thermostat device_id='{}' current_temp={:.1} target_temp={:.1} mode='{}' hvac_state='{}'",
            device_id, current_temp, target_temp, mode, hvac_state
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Nest Thermostat",
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

fn read_camera(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, device_id, event_type, started_at, ended_at, \
               zone_name, has_person, has_sound \
               FROM camera_event ORDER BY started_at DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
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
            row.get::<_, Option<i64>>(6).unwrap_or(None),
            row.get::<_, Option<i64>>(7).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, device_id, event_type, started_ms, _ended_ms, zone, has_person, has_sound) in rows.flatten() {
        let id = id.unwrap_or_default();
        let device_id = device_id.unwrap_or_else(|| "(unknown)".to_string());
        let event_type = event_type.unwrap_or_default();
        let zone = zone.unwrap_or_default();
        let has_person = has_person.unwrap_or(0) != 0;
        let has_sound = has_sound.unwrap_or(0) != 0;
        let ts = started_ms.and_then(unix_ms_to_i64);
        let title = format!("Nest cam event: {} ({})", event_type, zone);
        let detail = format!(
            "Nest camera event id='{}' device_id='{}' event_type='{}' zone='{}' has_person={} has_sound={}",
            id, device_id, event_type, zone, has_person, has_sound
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Nest Camera Event",
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

fn read_away(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT structure_id, mode, changed_at, changed_by \
         FROM \"{table}\" ORDER BY changed_at DESC LIMIT 5000",
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
    for (structure_id, mode, ts_ms, changed_by) in rows.flatten() {
        let structure_id = structure_id.unwrap_or_default();
        let mode = mode.unwrap_or_else(|| "unknown".to_string());
        let changed_by = changed_by.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Nest structure mode: {}", mode);
        let detail = format!(
            "Nest structure mode change structure_id='{}' mode='{}' changed_by='{}'",
            structure_id, mode, changed_by
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Nest Home/Away",
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
            CREATE TABLE thermostat_history (
                device_id TEXT,
                timestamp INTEGER,
                current_temp REAL,
                target_temp REAL,
                mode TEXT,
                hvac_state TEXT
            );
            INSERT INTO thermostat_history VALUES('t1',1609459200000,68.5,72.0,'heat','heating');
            CREATE TABLE camera_event (
                id TEXT,
                device_id TEXT,
                event_type TEXT,
                started_at INTEGER,
                ended_at INTEGER,
                zone_name TEXT,
                has_person INTEGER,
                has_sound INTEGER
            );
            INSERT INTO camera_event VALUES('c1','cam1','motion',1609459300000,1609459330000,'driveway',1,0);
            CREATE TABLE structure_mode (
                structure_id TEXT,
                mode TEXT,
                changed_at INTEGER,
                changed_by TEXT
            );
            INSERT INTO structure_mode VALUES('s1','away',1609459100000,'user@example.com');
            INSERT INTO structure_mode VALUES('s1','home',1609459400000,'user@example.com');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_thermostat_camera_mode() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Nest Thermostat"));
        assert!(r.iter().any(|a| a.subcategory == "Nest Camera Event"));
        assert!(r.iter().any(|a| a.subcategory == "Nest Home/Away"));
    }

    #[test]
    fn camera_has_person_flag() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("has_person=true")));
    }

    #[test]
    fn away_and_home_transitions_captured() {
        let db = make_db();
        let r = parse(db.path());
        let modes: Vec<_> = r.iter().filter(|a| a.subcategory == "Nest Home/Away").collect();
        assert_eq!(modes.len(), 2);
        assert!(modes.iter().any(|a| a.detail.contains("mode='away'")));
        assert!(modes.iter().any(|a| a.detail.contains("mode='home'")));
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
