//! Factory Reset — Android factory reset detection (anti-forensics).
//!
//! ALEAPP reference: `scripts/artifacts/factory_reset.py`. Source path:
//! `/data/system/users/0/settings_secure.xml` — checks for last factory
//! reset timestamp, or `/data/system/uiderrors.txt` for reset evidence.
//!
//! We also parse `/data/misc/bootstat/factory_reset` timestamp files
//! and the `android_id` re-generation as reset indicators.
//!
//! Key tables (if SQLite): `secure` with `name` and `value` columns.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "factory_reset",
    "poweroffreset",
    "shutdown_checkpoints",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    // Try as SQLite first
    if let Some(conn) = open_sqlite_ro(path) {
        if table_exists(&conn, "secure") {
            return read_secure_settings(&conn, path);
        }
        if table_exists(&conn, "checkpoints") {
            return read_checkpoints(&conn, path);
        }
    }
    // Fallback: read as plaintext log
    read_text_file(path)
}

fn read_secure_settings(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT name, value FROM secure \
               WHERE name IN ('android_id', 'bluetooth_address', 'bluetooth_name') \
               ORDER BY name LIMIT 100";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (name, value) in rows.flatten() {
        let name = name.unwrap_or_else(|| "(unknown)".to_string());
        let value = value.unwrap_or_default();
        let title = format!("Secure setting: {} = {}", name, value);
        let detail = format!(
            "Android secure setting name='{}' value='{}'",
            name, value
        );
        out.push(build_record(
            ArtifactCategory::SystemActivity,
            "Device Settings",
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

fn read_checkpoints(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT timestamp, reason, system_server \
               FROM checkpoints ORDER BY timestamp DESC LIMIT 1000";
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
    for (ts, reason, _server) in rows.flatten() {
        let reason = reason.unwrap_or_else(|| "(unknown)".to_string());
        let is_reset = reason.to_lowercase().contains("factory")
            || reason.to_lowercase().contains("wipe");
        let title = format!("Shutdown: {}", reason);
        let detail = format!("Shutdown checkpoint reason='{}' factory_reset={}", reason, is_reset);
        out.push(build_record(
            ArtifactCategory::SystemActivity,
            "Shutdown Checkpoint",
            title,
            detail,
            path,
            ts,
            ForensicValue::Critical,
            is_reset,
        ));
    }
    out
}

fn read_text_file(path: &Path) -> Vec<ArtifactRecord> {
    let data = match std::fs::read_to_string(path) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    if data.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for line in data.lines().filter(|l| !l.trim().is_empty()) {
        let lower = line.to_lowercase();
        let is_reset = lower.contains("factory") || lower.contains("wipe") || lower.contains("reset");
        let title = if is_reset {
            "FACTORY RESET DETECTED".to_string()
        } else {
            format!("Power event: {}", line.chars().take(80).collect::<String>())
        };
        let detail = format!("Device event log='{}'", line);
        out.push(build_record(
            ArtifactCategory::SystemActivity,
            if is_reset { "Factory Reset" } else { "Power Event" },
            title,
            detail,
            path,
            None,
            if is_reset { ForensicValue::Critical } else { ForensicValue::Medium },
            is_reset,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn make_checkpoint_db() -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE checkpoints (
                timestamp INTEGER,
                reason TEXT,
                system_server TEXT
            );
            INSERT INTO checkpoints VALUES(1609459200,'reboot','system_server');
            INSERT INTO checkpoints VALUES(1609459300,'factory_reset','system_server');
            INSERT INTO checkpoints VALUES(1609459400,'shutdown','system_server');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_checkpoints() {
        let db = make_checkpoint_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn factory_reset_is_suspicious() {
        let db = make_checkpoint_db();
        let r = parse(db.path());
        let reset = r.iter().find(|a| a.detail.contains("factory_reset=true")).unwrap();
        assert!(reset.is_suspicious);
        assert!(matches!(reset.forensic_value, ForensicValue::Critical));
    }

    #[test]
    fn text_file_detects_reset() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "2021-01-01 00:00:00 factory reset initiated\nnormal boot\n").unwrap();
        let r = parse(tmp.path());
        assert_eq!(r.len(), 2);
        assert!(r.iter().any(|a| a.subcategory == "Factory Reset"));
    }

    #[test]
    fn empty_file_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "").unwrap();
        assert!(parse(tmp.path()).is_empty());
    }
}
