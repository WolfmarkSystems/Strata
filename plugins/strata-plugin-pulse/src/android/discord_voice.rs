//! Discord Voice — voice channel sessions and call history.
//!
//! Source path: `/data/data/com.discord/databases/*`.
//!
//! Schema note: complements `discord.rs` (text messages). Discord
//! stores voice session data in tables like `voice_session`,
//! `voice_channel_history`, `call_history`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.discord/databases/", "com.discord/files/kv-storage/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["voice_session", "voice_channel_history"] {
        if table_exists(&conn, table) {
            out.extend(read_voice_sessions(&conn, path, table));
        }
    }
    for table in &["call_history", "call_log"] {
        if table_exists(&conn, table) {
            out.extend(read_calls(&conn, path, table));
        }
    }
    out
}

fn read_voice_sessions(
    conn: &rusqlite::Connection,
    path: &Path,
    table: &str,
) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT channel_id, guild_id, joined_at, left_at, duration \
         FROM \"{table}\" ORDER BY joined_at DESC LIMIT 5000",
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
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (channel_id, guild_id, joined_ms, _left_ms, duration_ms) in rows.flatten() {
        let channel_id = channel_id.unwrap_or_else(|| "(unknown)".to_string());
        let guild_id = guild_id.unwrap_or_default();
        let dur_s = duration_ms.unwrap_or(0) / 1000;
        let ts = joined_ms.and_then(unix_ms_to_i64);
        let title = format!("Discord voice: channel {} ({}s)", channel_id, dur_s);
        let detail = format!(
            "Discord voice session channel_id='{}' guild_id='{}' duration={}s",
            channel_id, guild_id, dur_s
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Discord Voice Session",
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

fn read_calls(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, caller_id, recipient_id, call_type, started_at, \
         ended_at, duration, status \
         FROM \"{table}\" ORDER BY started_at DESC LIMIT 5000",
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
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<i64>>(6).unwrap_or(None),
            row.get::<_, Option<String>>(7).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, caller_id, recipient_id, call_type, started_ms, _ended_ms, duration_ms, status) in
        rows.flatten()
    {
        let id = id.unwrap_or_else(|| "(unknown)".to_string());
        let caller_id = caller_id.unwrap_or_default();
        let recipient_id = recipient_id.unwrap_or_default();
        let call_type = call_type.unwrap_or_else(|| "voice".to_string());
        let dur_s = duration_ms.unwrap_or(0) / 1000;
        let status = status.unwrap_or_default();
        let ts = started_ms.and_then(unix_ms_to_i64);
        let title = format!(
            "Discord call: {} → {} ({}s)",
            caller_id, recipient_id, dur_s
        );
        let detail = format!(
            "Discord call id='{}' caller='{}' recipient='{}' type='{}' duration={}s status='{}'",
            id, caller_id, recipient_id, call_type, dur_s, status
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Discord Call",
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
            CREATE TABLE voice_session (
                channel_id TEXT,
                guild_id TEXT,
                joined_at INTEGER,
                left_at INTEGER,
                duration INTEGER
            );
            INSERT INTO voice_session VALUES('ch1','g1',1609459200000,1609462800000,3600000);
            CREATE TABLE call_history (
                id TEXT,
                caller_id TEXT,
                recipient_id TEXT,
                call_type TEXT,
                started_at INTEGER,
                ended_at INTEGER,
                duration INTEGER,
                status TEXT
            );
            INSERT INTO call_history VALUES('c1','u1','u2','video',1609459500000,1609460100000,600000,'ended');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_voice_and_calls() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Discord Voice Session"));
        assert!(r.iter().any(|a| a.subcategory == "Discord Call"));
    }

    #[test]
    fn voice_duration_captured() {
        let db = make_db();
        let r = parse(db.path());
        let v = r
            .iter()
            .find(|a| a.subcategory == "Discord Voice Session")
            .unwrap();
        assert!(v.detail.contains("duration=3600s"));
    }

    #[test]
    fn call_type_captured() {
        let db = make_db();
        let r = parse(db.path());
        let c = r.iter().find(|a| a.subcategory == "Discord Call").unwrap();
        assert!(c.detail.contains("type='video'"));
        assert!(c.detail.contains("duration=600s"));
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
