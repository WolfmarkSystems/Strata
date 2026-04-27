//! Viber / WeChat / Line desktop messaging parsers (PULSE-13).
//!
//! All three use SQLite (WeChat frequently encrypted with user key —
//! we detect without decrypting). Tables and column conventions vary
//! by platform; we implement each against its canonical schema.
//!
//! MITRE: T1636.002 (messaging), T1636.003 (call logs),
//! T1552.003 (credentials in files), T1657 (financial) for WeChat Pay.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OpenFlags};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedMessagingArtifact {
    pub platform: String,
    pub artifact_subtype: String,
    pub sender: Option<String>,
    pub recipient: Option<String>,
    pub content: Option<String>,
    pub timestamp: Option<DateTime<Utc>>,
    pub call_duration_secs: Option<u64>,
    pub payment_amount: Option<String>,
}

fn open_ro(path: &Path) -> Option<Connection> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()
}

fn decode_ms(ms: i64) -> Option<DateTime<Utc>> {
    let secs = ms.div_euclid(1000);
    let nanos = ms.rem_euclid(1000) as u32 * 1_000_000;
    DateTime::<Utc>::from_timestamp(secs, nanos)
}

pub fn parse_viber(path: &Path) -> Vec<ExtendedMessagingArtifact> {
    let Some(conn) = open_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Ok(mut stmt) =
        conn.prepare("SELECT address, body, date, type FROM Messages ORDER BY date ASC")
    {
        let rows = stmt.query_map([], |row| {
            let address: Option<String> = row.get(0)?;
            let body: Option<String> = row.get(1)?;
            let date: Option<i64> = row.get(2)?;
            let mtype: Option<i64> = row.get(3)?;
            Ok((address, body, date, mtype))
        });
        if let Ok(rows) = rows {
            for (address, body, date, mtype) in rows.flatten() {
                let is_sent = mtype == Some(1);
                out.push(ExtendedMessagingArtifact {
                    platform: "Viber".to_string(),
                    artifact_subtype: "Message".to_string(),
                    sender: if is_sent { None } else { address.clone() },
                    recipient: if is_sent { address } else { None },
                    content: body,
                    timestamp: date.and_then(decode_ms),
                    call_duration_secs: None,
                    payment_amount: None,
                });
            }
        }
    }
    if let Ok(mut stmt) =
        conn.prepare("SELECT address, date, duration, type FROM Calls ORDER BY date ASC")
    {
        let rows = stmt.query_map([], |row| {
            let address: Option<String> = row.get(0)?;
            let date: Option<i64> = row.get(1)?;
            let duration: Option<i64> = row.get(2)?;
            let _ctype: Option<i64> = row.get(3)?;
            Ok((address, date, duration))
        });
        if let Ok(rows) = rows {
            for (address, date, duration) in rows.flatten() {
                out.push(ExtendedMessagingArtifact {
                    platform: "Viber".to_string(),
                    artifact_subtype: "Call".to_string(),
                    sender: address,
                    recipient: None,
                    content: None,
                    timestamp: date.and_then(decode_ms),
                    call_duration_secs: duration.map(|d| d.max(0) as u64),
                    payment_amount: None,
                });
            }
        }
    }
    out
}

pub fn parse_line(path: &Path) -> Vec<ExtendedMessagingArtifact> {
    let Some(conn) = open_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT chat_id, content, created_time, sender FROM chat_history ORDER BY created_time ASC",
    ) {
        let rows = stmt.query_map([], |row| {
            let chat_id: Option<String> = row.get(0)?;
            let content: Option<String> = row.get(1)?;
            let created_time: Option<i64> = row.get(2)?;
            let sender: Option<String> = row.get(3)?;
            Ok((chat_id, content, created_time, sender))
        });
        if let Ok(rows) = rows {
            for (chat_id, content, created_time, sender) in rows.flatten() {
                out.push(ExtendedMessagingArtifact {
                    platform: "Line".to_string(),
                    artifact_subtype: "Message".to_string(),
                    sender,
                    recipient: chat_id,
                    content,
                    timestamp: created_time.and_then(decode_ms),
                    call_duration_secs: None,
                    payment_amount: None,
                });
            }
        }
    }
    out
}

pub fn wechat_is_locked(path: &Path) -> bool {
    match open_ro(path) {
        None => true,
        Some(conn) => conn
            .pragma_query_value(None, "schema_version", |_| Ok(()))
            .is_err(),
    }
}

pub fn identify_platform(path: &Path) -> Option<&'static str> {
    let lower = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or("");
    if name == "viber.db" || lower.contains("/viberpc/") {
        return Some("Viber");
    }
    if lower.contains("/tencent/wechat/") && name.starts_with("msg") && name.ends_with(".db") {
        return Some("WeChat");
    }
    if lower.contains("/line/data/") && (name == "lineqcchat.db" || name == "naver_line.db") {
        return Some("Line");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn identify_platform_recognises_canonical_layouts() {
        assert_eq!(
            identify_platform(Path::new(
                "C:\\Users\\a\\AppData\\Roaming\\ViberPC\\+15550001\\viber.db"
            )),
            Some("Viber")
        );
        assert_eq!(
            identify_platform(Path::new(
                "C:\\Users\\a\\AppData\\Roaming\\Tencent\\WeChat\\userid\\Msg\\Multi\\MSG1.db"
            )),
            Some("WeChat")
        );
        assert_eq!(
            identify_platform(Path::new(
                "C:\\Users\\a\\AppData\\Roaming\\LINE\\Data\\LineQcChat.db"
            )),
            Some("Line")
        );
    }

    #[test]
    fn parse_viber_extracts_messages_and_calls() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("viber.db");
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch(
            "CREATE TABLE Messages (msg_id INTEGER, address TEXT, body TEXT, date INTEGER, type INTEGER); \
             CREATE TABLE Calls (call_id INTEGER, address TEXT, date INTEGER, duration INTEGER, type INTEGER);",
        )
        .expect("schema");
        conn.execute(
            "INSERT INTO Messages VALUES (1, '+15551111', 'hi', 1717243200000, 1)",
            [],
        )
        .expect("m");
        conn.execute(
            "INSERT INTO Calls VALUES (1, '+15551112', 1717243300000, 42, 1)",
            [],
        )
        .expect("c");
        drop(conn);
        let out = parse_viber(&path);
        assert!(out.iter().any(|a| a.artifact_subtype == "Message"));
        assert!(out
            .iter()
            .any(|a| a.artifact_subtype == "Call" && a.call_duration_secs == Some(42)));
    }

    #[test]
    fn parse_line_extracts_chat_history() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("LineQcChat.db");
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch(
            "CREATE TABLE chat_history (id INTEGER, chat_id TEXT, content TEXT, created_time INTEGER, sender TEXT, type INTEGER);",
        )
        .expect("schema");
        conn.execute(
            "INSERT INTO chat_history VALUES (1, 'chat-A', 'hello line', 1717243200000, 'user1', 0)",
            [],
        )
        .expect("ins");
        drop(conn);
        let out = parse_line(&path);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].platform, "Line");
        assert_eq!(out[0].content.as_deref(), Some("hello line"));
    }

    #[test]
    fn wechat_is_locked_detects_invalid_sqlite() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("MSG1.db");
        std::fs::write(&path, b"not-sqlite-bytes").expect("write");
        assert!(wechat_is_locked(&path));
    }

    #[test]
    fn decode_ms_converts_milliseconds() {
        let dt = decode_ms(1_717_243_200_000).expect("ok");
        assert_eq!(dt.timestamp(), 1_717_243_200);
    }
}
