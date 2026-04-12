//! SmartThings Events — deeper automation and motion event history.
//!
//! Source path: `/data/data/com.samsung.android.oneconnect/databases/*`.
//!
//! Schema note: complements `smartthings.rs` (devices/locations) by
//! targeting `device_event` and `automation_run` tables which capture
//! motion sensor triggers, door open/close, and automation executions.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.samsung.android.oneconnect/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["device_event", "event_history", "events"] {
        if table_exists(&conn, table) {
            out.extend(read_events(&conn, path, table));
            break;
        }
    }
    for table in &["automation_run", "automation_history", "rule_run"] {
        if table_exists(&conn, table) {
            out.extend(read_automation(&conn, path, table));
            break;
        }
    }
    out
}

fn read_events(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, device_id, capability, attribute, value, timestamp \
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
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, device_id, capability, attribute, value, ts_ms) in rows.flatten() {
        let id = id.unwrap_or_default();
        let device_id = device_id.unwrap_or_else(|| "(unknown)".to_string());
        let capability = capability.unwrap_or_default();
        let attribute = attribute.unwrap_or_default();
        let value = value.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("SmartThings event: {} {}={}", device_id, attribute, value);
        let detail = format!(
            "SmartThings device event id='{}' device_id='{}' capability='{}' attribute='{}' value='{}'",
            id, device_id, capability, attribute, value
        );
        let suspicious = attribute == "motion" && value == "active"
            || attribute == "contact" && value == "open";
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "SmartThings Event",
            title,
            detail,
            path,
            ts,
            if suspicious { ForensicValue::High } else { ForensicValue::Medium },
            false,
        ));
    }
    out
}

fn read_automation(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, automation_name, triggered_at, trigger_type, \
         action_summary, status \
         FROM \"{table}\" ORDER BY triggered_at DESC LIMIT 5000",
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
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, name, ts_ms, trigger_type, action_summary, status) in rows.flatten() {
        let id = id.unwrap_or_default();
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let trigger_type = trigger_type.unwrap_or_default();
        let action_summary = action_summary.unwrap_or_default();
        let status = status.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("SmartThings automation: {} ({})", name, status);
        let detail = format!(
            "SmartThings automation run id='{}' name='{}' trigger_type='{}' action='{}' status='{}'",
            id, name, trigger_type, action_summary, status
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "SmartThings Automation",
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
            CREATE TABLE device_event (
                id TEXT,
                device_id TEXT,
                capability TEXT,
                attribute TEXT,
                value TEXT,
                timestamp INTEGER
            );
            INSERT INTO device_event VALUES('e1','dev1','motionSensor','motion','active',1609459200000);
            INSERT INTO device_event VALUES('e2','dev2','contactSensor','contact','open',1609459300000);
            INSERT INTO device_event VALUES('e3','dev3','switch','switch','on',1609459400000);
            CREATE TABLE automation_run (
                id TEXT,
                automation_name TEXT,
                triggered_at INTEGER,
                trigger_type TEXT,
                action_summary TEXT,
                status TEXT
            );
            INSERT INTO automation_run VALUES('a1','Goodnight',1609459500000,'schedule','Turn off all lights','completed');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_events_and_automation() {
        let db = make_db();
        let r = parse(db.path());
        let events: Vec<_> = r.iter().filter(|a| a.subcategory == "SmartThings Event").collect();
        let automations: Vec<_> = r.iter().filter(|a| a.subcategory == "SmartThings Automation").collect();
        assert_eq!(events.len(), 3);
        assert_eq!(automations.len(), 1);
    }

    #[test]
    fn motion_and_contact_events_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("attribute='motion'") && a.detail.contains("value='active'")));
        assert!(r.iter().any(|a| a.detail.contains("attribute='contact'") && a.detail.contains("value='open'")));
    }

    #[test]
    fn automation_trigger_type_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("trigger_type='schedule'")));
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
