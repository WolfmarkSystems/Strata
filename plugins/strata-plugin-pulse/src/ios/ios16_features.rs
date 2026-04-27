//! LEGACY-IOS-2 — iOS 16 unsent messages + AirDrop "Boop" transfers.
//!
//! Two distinct forensic wins from iOS 16:
//!
//! 1. **Unsend messages** left behind in `chat.db` when a user
//!    deleted a message in the Messages app. The unsend timestamp,
//!    original timestamp, and (when preserved) original text all
//!    remain queryable, and the time delta between send-and-unsend
//!    is itself probative.
//!
//! 2. **AirDrop "Boop"** non-contact transfers surfaced in the
//!    sharingd defaults plus the unified log. The transfer records
//!    flag recipient devices that are *not* in the device's
//!    contacts — high signal for clandestine communication.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, TimeZone, Utc};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnsentMessage {
    pub message_id: i64,
    pub chat_id: i64,
    pub original_text: Option<String>,
    pub sent_timestamp: DateTime<Utc>,
    pub unsent_timestamp: DateTime<Utc>,
    pub time_before_unsent_seconds: u64,
    pub sender: String,
    pub recipient: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AirDropBoopTransfer {
    pub timestamp: DateTime<Utc>,
    pub direction: String,
    pub file_name: Option<String>,
    pub file_size: Option<u64>,
    pub recipient_or_sender_device: String,
    pub transfer_type: String,
}

pub fn parse_unsent_messages(conn: &Connection) -> Vec<UnsentMessage> {
    let cols = column_names(conn, "message");
    let deleted_col = match cols
        .iter()
        .find(|c| c.contains("deleted_at") || c.contains("unsent"))
    {
        Some(c) => c.clone(),
        None => return Vec::new(),
    };
    let sql = format!(
        "SELECT ROWID, cache_roomnames, text, date, {}, handle_id FROM message WHERE {} IS NOT NULL",
        deleted_col, deleted_col
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0).unwrap_or(0),
            r.get::<_, Option<String>>(1).unwrap_or(None),
            r.get::<_, Option<String>>(2).unwrap_or(None),
            r.get::<_, i64>(3).unwrap_or(0),
            r.get::<_, i64>(4).unwrap_or(0),
            r.get::<_, i64>(5).unwrap_or(0),
        ))
    });
    let Ok(rows) = rows else { return Vec::new() };
    let mut out = Vec::new();
    for (id, chat_room, text, sent_raw, unsent_raw, handle) in rows.flatten() {
        let sent = cocoa_to_utc(sent_raw).unwrap_or_else(unix_epoch);
        let unsent = cocoa_to_utc(unsent_raw).unwrap_or(sent);
        let delta = (unsent - sent).num_seconds().max(0) as u64;
        out.push(UnsentMessage {
            message_id: id,
            chat_id: handle,
            original_text: text,
            sent_timestamp: sent,
            unsent_timestamp: unsent,
            time_before_unsent_seconds: delta,
            sender: String::new(),
            recipient: chat_room.unwrap_or_default(),
        });
    }
    out
}

fn column_names(conn: &Connection, table: &str) -> Vec<String> {
    let sql = format!("PRAGMA table_info({table})");
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    stmt.query_map([], |r| r.get::<_, String>(1))
        .ok()
        .map(|r| r.flatten().collect())
        .unwrap_or_default()
}

fn cocoa_to_utc(ts: i64) -> Option<DateTime<Utc>> {
    if ts == 0 {
        return None;
    }
    let cocoa_epoch_offset = 978_307_200i64;
    let secs = if ts > 1_000_000_000_000 {
        ts / 1_000_000_000
    } else {
        ts
    };
    Utc.timestamp_opt(secs + cocoa_epoch_offset, 0).single()
}

/// Parse a single sharingd defaults plist row into an
/// AirDropBoopTransfer record. The callers walk the plist and hand
/// each transfer entry to this function.
pub fn classify_airdrop_transfer(
    timestamp_secs_since_cocoa: i64,
    direction: &str,
    file_name: Option<&str>,
    file_size: Option<u64>,
    device: &str,
    recipient_in_contacts: bool,
) -> AirDropBoopTransfer {
    let transfer_type = if recipient_in_contacts {
        "Standard"
    } else {
        "Boop"
    };
    AirDropBoopTransfer {
        timestamp: cocoa_to_utc(timestamp_secs_since_cocoa).unwrap_or_else(unix_epoch),
        direction: direction.into(),
        file_name: file_name.map(|s| s.into()),
        file_size,
        recipient_or_sender_device: device.into(),
        transfer_type: transfer_type.into(),
    }
}

fn unix_epoch() -> DateTime<Utc> {
    DateTime::<Utc>::from(std::time::UNIX_EPOCH)
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_unsent_message_with_time_delta() {
        let c = Connection::open_in_memory().expect("open");
        c.execute_batch(
            "CREATE TABLE message (\
                ROWID INTEGER PRIMARY KEY,\
                cache_roomnames TEXT,\
                text TEXT,\
                date INTEGER,\
                deleted_at INTEGER,\
                handle_id INTEGER);",
        )
        .expect("schema");
        // 100 -> Cocoa 2001-01-01 00:01:40; 160 -> 1 min later.
        c.execute(
            "INSERT INTO message VALUES (1, 'chat1', 'oops', 100, 160, 5)",
            [],
        )
        .expect("ins");
        let msgs = parse_unsent_messages(&c);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].time_before_unsent_seconds, 60);
        assert_eq!(msgs[0].original_text.as_deref(), Some("oops"));
    }

    #[test]
    fn missing_deleted_column_returns_empty() {
        let c = Connection::open_in_memory().expect("open");
        c.execute_batch("CREATE TABLE message (ROWID INTEGER);")
            .expect("s");
        assert!(parse_unsent_messages(&c).is_empty());
    }

    #[test]
    fn classify_airdrop_as_boop_when_not_in_contacts() {
        let t = classify_airdrop_transfer(
            500_000_000,
            "Incoming",
            Some("secret.pdf"),
            Some(12345),
            "alice's iPhone",
            false,
        );
        assert_eq!(t.transfer_type, "Boop");
    }

    #[test]
    fn classify_airdrop_as_standard_when_in_contacts() {
        let t = classify_airdrop_transfer(
            500_000_000,
            "Outgoing",
            Some("doc.txt"),
            Some(256),
            "Bob's MacBook",
            true,
        );
        assert_eq!(t.transfer_type, "Standard");
    }
}
