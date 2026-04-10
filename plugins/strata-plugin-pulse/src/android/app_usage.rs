//! App Usage / UsageStats — Android app execution history.
//!
//! ALEAPP reference: `scripts/artifacts/usagestats.py` plus a handful
//! of vendor-specific variants. The canonical source is
//! `/data/system/usagestats/0/...` which was XML on older Android and
//! protobuf on Android 9+. Vendors also write a SQLite view; Samsung
//! in particular ships
//! `/data/data/com.samsung.android.svcmanager/databases/ProcStatsService.db`
//! and `/data/system_ce/0/usagestats/events`.
//!
//! Pulse ports the SQLite path. We accept any `usagestats` database
//! with a recognisable schema containing package-name and timestamp
//! columns — specifically the consolidated `events` table with
//! columns `package`, `timestamp`, and `type`.
//!
//! The `type` column encodes the event kind (Android
//! `UsageEvents$Event`):
//!
//! | value | meaning                |
//! |-------|------------------------|
//! | 1     | MOVE_TO_FOREGROUND     |
//! | 2     | MOVE_TO_BACKGROUND     |
//! | 5     | CONFIGURATION_CHANGE   |
//! | 7     | USER_INTERACTION       |
//! | 23    | DEVICE_SHUTDOWN        |

use crate::android::helpers::{build_record, column_exists, open_sqlite_ro, table_exists, unix_ms_to_i64};
use rusqlite::Connection;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["usagestats", "procstatsservice.db", "events.db"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "events")
        && column_exists(&conn, "events", "package")
        && column_exists(&conn, "events", "timestamp")
    {
        read_events(&conn, path, &mut out);
    }
    out
}

fn event_type_name(code: i64) -> &'static str {
    match code {
        1 => "MOVE_TO_FOREGROUND",
        2 => "MOVE_TO_BACKGROUND",
        5 => "CONFIGURATION_CHANGE",
        6 => "SYSTEM_INTERACTION",
        7 => "USER_INTERACTION",
        8 => "SHORTCUT_INVOCATION",
        23 => "DEVICE_SHUTDOWN",
        _ => "OTHER",
    }
}

fn read_events(conn: &Connection, path: &Path, out: &mut Vec<ArtifactRecord>) {
    let has_type = column_exists(conn, "events", "type");
    let sql = if has_type {
        "SELECT package, timestamp, type FROM events ORDER BY timestamp DESC LIMIT 20000"
    } else {
        "SELECT package, timestamp, 0 FROM events ORDER BY timestamp DESC LIMIT 20000"
    };
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return,
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return;
    };
    for (pkg, ts_ms, type_code) in rows.flatten() {
        let pkg = pkg.unwrap_or_else(|| "(unknown)".to_string());
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let code = type_code.unwrap_or(0);
        let event = event_type_name(code);
        let title = format!("App Usage: {} — {}", pkg, event);
        let detail = format!(
            "Android UsageStats event for package '{}' type={} ({})",
            pkg, code, event
        );
        out.push(build_record(
            ArtifactCategory::ExecutionHistory,
            "Android App Usage",
            title,
            detail,
            path,
            ts,
            ForensicValue::Medium,
            false,
        ));
    }
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
            CREATE TABLE events (
                _id INTEGER PRIMARY KEY,
                package TEXT,
                timestamp INTEGER,
                type INTEGER
            );
            INSERT INTO events(package, timestamp, type) VALUES ('com.whatsapp', 1609459200000, 1);
            INSERT INTO events(package, timestamp, type) VALUES ('com.whatsapp', 1609459300000, 2);
            INSERT INTO events(package, timestamp, type) VALUES ('com.google.android.gm', 1609459400000, 7);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn reads_events_ordered() {
        let db = make_db();
        let records = parse(db.path());
        assert_eq!(records.len(), 3);
        assert!(records.iter().all(|r| r.category == ArtifactCategory::ExecutionHistory));
        assert!(records.iter().all(|r| r.subcategory == "Android App Usage"));
    }

    #[test]
    fn event_type_names_are_mapped() {
        let db = make_db();
        let records = parse(db.path());
        assert!(records
            .iter()
            .any(|r| r.title.contains("MOVE_TO_FOREGROUND")));
        assert!(records
            .iter()
            .any(|r| r.title.contains("MOVE_TO_BACKGROUND")));
        assert!(records
            .iter()
            .any(|r| r.title.contains("USER_INTERACTION")));
    }

    #[test]
    fn timestamps_are_converted_to_seconds() {
        let db = make_db();
        let records = parse(db.path());
        let r = records
            .iter()
            .find(|r| r.title.contains("com.google.android.gm"))
            .unwrap();
        assert_eq!(r.timestamp, Some(1_609_459_400));
    }

    #[test]
    fn missing_events_table_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE other (x INTEGER);").unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}
