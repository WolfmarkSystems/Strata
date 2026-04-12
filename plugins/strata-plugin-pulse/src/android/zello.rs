//! Zello — Android push-to-talk / walkie-talkie messaging.
//!
//! Source path: `/data/data/com.loudtalks/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. Zello (formerly Loudtalks) stores
//! messages and channel activity in `messages` or `channels` tables with
//! `sender`, `channel`, and `timestamp` columns.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.loudtalks/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "messages") {
        out.extend(read_messages(&conn, path));
    }
    if table_exists(&conn, "channels") {
        out.extend(read_channels(&conn, path));
    }
    out
}

fn read_messages(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT sender, channel, type, duration, timestamp \
               FROM messages \
               ORDER BY timestamp DESC LIMIT 5000";
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
    for (sender, channel, msg_type, duration, ts_ms) in rows.flatten() {
        let sender = sender.unwrap_or_else(|| "(unknown)".to_string());
        let channel = channel.unwrap_or_else(|| "(direct)".to_string());
        let kind = msg_type.unwrap_or_else(|| "voice".to_string());
        let dur = duration.unwrap_or(0);
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Zello {}: {} on {}", kind, sender, channel);
        let detail = format!(
            "Zello message sender='{}' channel='{}' type='{}' duration_ms={}",
            sender, channel, kind, dur
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Zello Message",
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

fn read_channels(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT name, owner, member_count, created_at \
               FROM channels \
               ORDER BY created_at DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (name, owner, member_count, ts_ms) in rows.flatten() {
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let owner = owner.unwrap_or_else(|| "(unknown)".to_string());
        let members = member_count.unwrap_or(0);
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Zello channel: {} ({} members)", name, members);
        let detail = format!(
            "Zello channel name='{}' owner='{}' member_count={}",
            name, owner, members
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Zello Message",
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
            CREATE TABLE messages (
                id INTEGER PRIMARY KEY,
                sender TEXT,
                channel TEXT,
                type TEXT,
                duration INTEGER,
                timestamp INTEGER
            );
            INSERT INTO messages VALUES(1,'dispatch','Ops Channel','voice',5200,1609459200000);
            INSERT INTO messages VALUES(2,'unit_7','Ops Channel','voice',3100,1609459300000);
            CREATE TABLE channels (
                name TEXT,
                owner TEXT,
                member_count INTEGER,
                created_at INTEGER
            );
            INSERT INTO channels VALUES('Ops Channel','dispatch',12,1609000000000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_messages_and_channels() {
        let db = make_db();
        let r = parse(db.path());
        let msgs: Vec<_> = r.iter().filter(|a| a.title.starts_with("Zello voice") || a.title.starts_with("Zello text")).collect();
        let chs: Vec<_> = r.iter().filter(|a| a.title.starts_with("Zello channel")).collect();
        assert_eq!(msgs.len(), 2);
        assert_eq!(chs.len(), 1);
    }

    #[test]
    fn channel_name_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("channel='Ops Channel'") && a.detail.contains("sender='dispatch'")));
        assert!(r.iter().any(|a| a.detail.contains("owner='dispatch'") && a.detail.contains("member_count=12")));
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
