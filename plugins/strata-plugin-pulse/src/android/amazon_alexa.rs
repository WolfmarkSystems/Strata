//! Amazon Alexa — voice history, routines, and device control.
//!
//! Source path: `/data/data/com.amazon.dee.app/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Alexa caches voice interaction
//! history locally in Room databases with tables like `voice_history`,
//! `card`, `routine`, `device`. Transcripts are especially valuable —
//! they capture the exact words spoken to an Alexa device.

use crate::android::helpers::{
    build_record, column_exists, open_sqlite_ro, table_exists, unix_ms_to_i64,
};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.amazon.dee.app/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["voice_history", "voice_activity", "activity_dialog"] {
        if table_exists(&conn, table) {
            out.extend(read_voice_history(&conn, path, table));
            break;
        }
    }
    if table_exists(&conn, "device") {
        out.extend(read_devices(&conn, path));
    }
    if table_exists(&conn, "routine") {
        out.extend(read_routines(&conn, path));
    }
    out
}

fn read_voice_history(
    conn: &rusqlite::Connection,
    path: &Path,
    table: &str,
) -> Vec<ArtifactRecord> {
    let transcript_col = if column_exists(conn, table, "transcript") {
        "transcript"
    } else if column_exists(conn, table, "summary") {
        "summary"
    } else {
        "utterance"
    };
    let sql = format!(
        "SELECT id, {transcript_col}, timestamp, device_id, device_name, response \
         FROM \"{table}\" ORDER BY timestamp DESC LIMIT 10000",
        transcript_col = transcript_col,
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
    for (id, transcript, ts_ms, device_id, device_name, response) in rows.flatten() {
        let id = id.unwrap_or_default();
        let transcript = transcript.unwrap_or_default();
        let device_id = device_id.unwrap_or_default();
        let device_name = device_name.unwrap_or_default();
        let response = response.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let preview: String = transcript.chars().take(120).collect();
        let title = format!("Alexa voice: \"{}\"", preview);
        let mut detail = format!(
            "Alexa voice history id='{}' transcript='{}' device_name='{}' device_id='{}'",
            id, transcript, device_name, device_id
        );
        if !response.is_empty() {
            let resp_preview: String = response.chars().take(200).collect();
            detail.push_str(&format!(" response='{}'", resp_preview));
        }
        out.push(build_record(
            ArtifactCategory::Communications,
            "Alexa Voice History",
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
    let sql = "SELECT serial_number, account_name, device_type, name, \
               software_version, mac_address \
               FROM device LIMIT 1000";
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
    for (serial, account, device_type, name, sw_version, mac) in rows.flatten() {
        let serial = serial.unwrap_or_default();
        let account = account.unwrap_or_default();
        let device_type = device_type.unwrap_or_default();
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let sw_version = sw_version.unwrap_or_default();
        let mac = mac.unwrap_or_default();
        let title = format!("Alexa device: {} ({})", name, device_type);
        let detail = format!(
            "Alexa device serial='{}' account='{}' type='{}' name='{}' software='{}' mac='{}'",
            serial, account, device_type, name, sw_version, mac
        );
        out.push(build_record(
            ArtifactCategory::SystemActivity,
            "Alexa Device",
            title,
            detail,
            path,
            None,
            ForensicValue::Critical,
            false,
        ));
    }
    out
}

fn read_routines(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, name, trigger_utterance, enabled, created_at \
               FROM routine LIMIT 1000";
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
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, name, trigger, enabled, created_ms) in rows.flatten() {
        let id = id.unwrap_or_default();
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let trigger = trigger.unwrap_or_default();
        let enabled = enabled.unwrap_or(0) != 0;
        let ts = created_ms.and_then(unix_ms_to_i64);
        let title = format!("Alexa routine: {}", name);
        let detail = format!(
            "Alexa routine id='{}' name='{}' trigger_utterance='{}' enabled={}",
            id, name, trigger, enabled
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Alexa Routine",
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
            CREATE TABLE voice_history (
                id TEXT,
                transcript TEXT,
                timestamp INTEGER,
                device_id TEXT,
                device_name TEXT,
                response TEXT
            );
            INSERT INTO voice_history VALUES('v1','alexa play jazz',1609459200000,'d1','Echo Dot','Playing jazz from Spotify');
            INSERT INTO voice_history VALUES('v2','alexa turn off the lights',1609459300000,'d1','Echo Dot','OK');
            CREATE TABLE device (
                serial_number TEXT,
                account_name TEXT,
                device_type TEXT,
                name TEXT,
                software_version TEXT,
                mac_address TEXT
            );
            INSERT INTO device VALUES('G0912345','primary','echo_dot','Echo Dot','1234','AA:BB:CC:DD:EE:FF');
            CREATE TABLE routine (
                id TEXT,
                name TEXT,
                trigger_utterance TEXT,
                enabled INTEGER,
                created_at INTEGER
            );
            INSERT INTO routine VALUES('r1','Good Morning','alexa good morning',1,1609459000000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_voice_devices_routines() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Alexa Voice History"));
        assert!(r.iter().any(|a| a.subcategory == "Alexa Device"));
        assert!(r.iter().any(|a| a.subcategory == "Alexa Routine"));
    }

    #[test]
    fn transcript_captured_in_title_and_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("alexa play jazz")));
        assert!(r
            .iter()
            .any(|a| a.detail.contains("response='Playing jazz from Spotify'")));
    }

    #[test]
    fn device_mac_captured() {
        let db = make_db();
        let r = parse(db.path());
        let d = r.iter().find(|a| a.subcategory == "Alexa Device").unwrap();
        assert!(d.detail.contains("mac='AA:BB:CC:DD:EE:FF'"));
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
