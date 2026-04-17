//! Ephemeral-messaging indicators across platforms (PULSE-15).
//!
//! Disappearing messages leave metadata even when content is gone.
//! This module surfaces timer settings, expired-message slots, and
//! WAL-file fragments across WhatsApp, Telegram, Signal, Snapchat.
//!
//! MITRE: T1070.003, T1485.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OpenFlags};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EphemeralIndicator {
    pub platform: String,
    pub indicator_type: String,
    pub timer_seconds: Option<u64>,
    pub deleted_message_count: Option<u64>,
    pub wal_fragment: Option<String>,
    pub setting_timestamp: Option<DateTime<Utc>>,
}

pub fn scan_whatsapp(path: &Path) -> Vec<EphemeralIndicator> {
    let Some(conn) = open_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT DISTINCT ephemeral_duration FROM message WHERE ephemeral_duration > 0",
    ) {
        let rows = stmt.query_map([], |row| row.get::<_, i64>(0));
        if let Ok(rows) = rows {
            for d in rows.flatten() {
                out.push(EphemeralIndicator {
                    platform: "WhatsApp".to_string(),
                    indicator_type: "DisappearingTimer".to_string(),
                    timer_seconds: Some(d.max(0) as u64),
                    deleted_message_count: None,
                    wal_fragment: None,
                    setting_timestamp: None,
                });
            }
        }
    }
    if let Ok(expired) = conn.query_row(
        "SELECT COUNT(*) FROM message WHERE message_expiry_timestamp IS NOT NULL \
         AND message_expiry_timestamp > 0 AND message_expiry_timestamp < strftime('%s','now')*1000",
        [],
        |row| row.get::<_, i64>(0),
    ) {
        if expired > 0 {
            out.push(EphemeralIndicator {
                platform: "WhatsApp".to_string(),
                indicator_type: "ExpiredMessages".to_string(),
                timer_seconds: None,
                deleted_message_count: Some(expired.max(0) as u64),
                wal_fragment: None,
                setting_timestamp: None,
            });
        }
    }
    out
}

pub fn scan_telegram(path: &Path) -> Vec<EphemeralIndicator> {
    let Some(conn) = open_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='secret_chats'",
            [],
            |_| Ok(()),
        )
        .is_ok()
    {
        out.push(EphemeralIndicator {
            platform: "Telegram".to_string(),
            indicator_type: "SecretChatPresent".to_string(),
            timer_seconds: None,
            deleted_message_count: None,
            wal_fragment: None,
            setting_timestamp: None,
        });
    }
    if let Ok(deleted) = conn.query_row(
        "SELECT COUNT(*) FROM messages WHERE content IS NULL AND id IS NOT NULL",
        [],
        |row| row.get::<_, i64>(0),
    ) {
        if deleted > 0 {
            out.push(EphemeralIndicator {
                platform: "Telegram".to_string(),
                indicator_type: "DeletedMessageSlots".to_string(),
                timer_seconds: None,
                deleted_message_count: Some(deleted.max(0) as u64),
                wal_fragment: None,
                setting_timestamp: None,
            });
        }
    }
    out
}

pub fn scan_wal_file(path: &Path, platform: &str) -> Vec<EphemeralIndicator> {
    let Ok(bytes) = fs::read(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Ok(text) = std::str::from_utf8(&bytes) {
        for run in text.split(|c: char| c.is_control()) {
            let t = run.trim();
            if t.len() >= 20
                && t.len() <= 512
                && t.chars().filter(|c| c.is_ascii_alphabetic()).count() > 5
                && (t.contains(' ') || t.contains('.'))
            {
                out.push(EphemeralIndicator {
                    platform: platform.to_string(),
                    indicator_type: "WalFragment".to_string(),
                    timer_seconds: None,
                    deleted_message_count: None,
                    wal_fragment: Some(t.chars().take(512).collect()),
                    setting_timestamp: None,
                });
                if out.len() >= 128 {
                    break;
                }
            }
        }
    }
    out
}

fn open_ro(path: &Path) -> Option<Connection> {
    let c = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()?;
    if c.pragma_query_value(None, "schema_version", |_| Ok(())).is_ok() {
        Some(c)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn scan_whatsapp_recovers_timer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("msgstore.db");
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch(
            "CREATE TABLE message (id INTEGER, ephemeral_duration INTEGER, message_expiry_timestamp INTEGER);",
        )
        .expect("schema");
        conn.execute(
            "INSERT INTO message VALUES (1, 86400, 1)",
            [],
        )
        .expect("i");
        drop(conn);
        let out = scan_whatsapp(&path);
        assert!(out
            .iter()
            .any(|i| i.indicator_type == "DisappearingTimer" && i.timer_seconds == Some(86400)));
    }

    #[test]
    fn scan_telegram_detects_secret_chats_table() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cache4.db");
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch(
            "CREATE TABLE secret_chats (id INTEGER); CREATE TABLE messages (id INTEGER, content TEXT);",
        )
        .expect("schema");
        conn.execute("INSERT INTO messages VALUES (1, NULL)", [])
            .expect("m");
        drop(conn);
        let out = scan_telegram(&path);
        assert!(out
            .iter()
            .any(|i| i.indicator_type == "SecretChatPresent"));
    }

    #[test]
    fn scan_wal_file_extracts_text_fragments() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("msgstore.db-wal");
        std::fs::write(
            &path,
            b"\x00\x00This is a recovered message fragment from the WAL file.\x00\x00",
        )
        .expect("w");
        let out = scan_wal_file(&path, "WhatsApp");
        assert!(out.iter().any(|i| i.indicator_type == "WalFragment"));
    }

    #[test]
    fn open_ro_rejects_non_sqlite() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("garbage.db");
        std::fs::write(&path, b"not-sqlite-bytes").expect("w");
        assert!(open_ro(&path).is_none());
    }

    #[test]
    fn scan_whatsapp_returns_empty_on_invalid_db() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("empty.db");
        std::fs::write(&path, b"garbage").expect("w");
        assert!(scan_whatsapp(&path).is_empty());
    }
}
