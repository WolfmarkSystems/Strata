//! Digital Wellbeing — Android screen time and app usage.
//!
//! ALEAPP reference: `scripts/artifacts/wellbeing.py`. Source path:
//! `/data/data/com.google.android.apps.wellbeing/databases/app_usage`.
//!
//! Key tables: `events` joined with `packages`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.google.android.apps.wellbeing/databases/app_usage"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "events") || !table_exists(&conn, "packages") {
        return Vec::new();
    }
    read_events(&conn, path)
}

fn event_type_name(code: i64) -> &'static str {
    match code {
        1 => "ACTIVITY_RESUMED",
        2 => "ACTIVITY_PAUSED",
        7 => "USER_INTERACTION",
        15 => "SCREEN_INTERACTIVE",
        16 => "SCREEN_NON_INTERACTIVE",
        17 => "KEYGUARD_SHOWN",
        18 => "KEYGUARD_HIDDEN",
        23 => "DEVICE_STARTUP",
        24 => "DEVICE_SHUTDOWN",
        26 => "ACTIVITY_STOPPED",
        _ => "UNKNOWN",
    }
}

fn read_events(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT e.timestamp, p.package_name, e.type \
               FROM events e \
               JOIN packages p ON e.package_id = p._id \
               ORDER BY e.timestamp DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (ts_ms, package, event_type) in rows.flatten() {
        let package = package.unwrap_or_else(|| "(unknown)".to_string());
        let type_code = event_type.unwrap_or(0);
        let type_name = event_type_name(type_code);
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Wellbeing: {} — {}", package, type_name);
        let detail = format!(
            "Digital Wellbeing package='{}' event='{}' type_code={}",
            package, type_name, type_code
        );
        let suspicious = type_code == 23 || type_code == 24; // startup/shutdown
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Digital Wellbeing",
            title,
            detail,
            path,
            ts,
            if suspicious {
                ForensicValue::High
            } else {
                ForensicValue::Low
            },
            suspicious,
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
            CREATE TABLE packages (_id INTEGER PRIMARY KEY, package_name TEXT);
            INSERT INTO packages VALUES(1,'com.whatsapp');
            INSERT INTO packages VALUES(2,'com.android.chrome');
            CREATE TABLE events (_id INTEGER PRIMARY KEY, timestamp INTEGER, package_id INTEGER, type INTEGER);
            INSERT INTO events VALUES(1,1609459200000,1,1);
            INSERT INTO events VALUES(2,1609459300000,1,2);
            INSERT INTO events VALUES(3,1609459400000,2,1);
            INSERT INTO events VALUES(4,1609459500000,2,23);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_four_events() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 4);
        assert!(r.iter().all(|a| a.subcategory == "Digital Wellbeing"));
    }

    #[test]
    fn event_types_mapped() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("event='ACTIVITY_RESUMED'")));
        assert!(r
            .iter()
            .any(|a| a.detail.contains("event='DEVICE_STARTUP'")));
    }

    #[test]
    fn startup_is_suspicious() {
        let db = make_db();
        let r = parse(db.path());
        let startup = r
            .iter()
            .find(|a| a.detail.contains("DEVICE_STARTUP"))
            .unwrap();
        assert!(startup.is_suspicious);
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
