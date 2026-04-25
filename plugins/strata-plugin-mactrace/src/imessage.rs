//! Enhanced iMessage / SMS parser (MOB-3).
//!
//! Locations:
//! * macOS — `~/Library/Messages/chat.db`
//! * iOS — `/private/var/mobile/Library/SMS/sms.db`
//!
//! Both are SQLite with the same schema. Existing MacTrace coverage
//! emitted a single row-count artifact; MOB-3 asks for per-message
//! records with the fields iOS 16 + macOS Ventura added to the
//! `message` and `attachment` tables.
//!
//! ## Fields this parser extracts
//! * `text` — plain message text (pre-iOS 16 the canonical column).
//! * `attributedBody` — NSArchiver-serialized `NSAttributedString`.
//!   On iOS 16+ the `text` column is frequently NULL and the real
//!   message content lives here. We extract the plain-string portion
//!   by scanning for the NSString byte preamble `"NSString" [0x01]
//!   [len]`.
//! * `thread_originator_guid` — thread tracking.
//! * `associated_message_guid` — tapback / reaction target.
//! * `expressive_send_style_id` — message effect (`"slam"`, `"loud"`).
//! * `was_downgraded` — iMessage → SMS fallback indicator.
//!
//! From the `attachment` table (joined via `message_attachment_join`):
//! * `transfer_name` — original filename.
//! * `mime_type`.
//! * `total_bytes`.
//! * `is_sticker`.
//!
//! ## MITRE ATT&CK
//! * **T1636.002** — Protected User Data: SMS/messages.
//! * **T1530** — Data from Cloud Storage (for cloud-synced attachments).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OpenFlags};
use std::path::Path;

const APPLE_EPOCH_OFFSET: i64 = 978_307_200;

/// iMessage / SMS schema keeps `date` as CoreData seconds on macOS
/// 10.x and earlier, then switched to CoreData nanoseconds on macOS
/// 11+ / iOS 14+. We normalise both.
fn decode_message_date(raw: i64) -> Option<DateTime<Utc>> {
    // Values above this threshold are clearly nanoseconds.
    const NS_THRESHOLD: i64 = 1_000_000_000_000; // ~31k CoreData secs
    let seconds = if raw.abs() >= NS_THRESHOLD {
        raw / 1_000_000_000
    } else {
        raw
    };
    DateTime::<Utc>::from_timestamp(seconds.saturating_add(APPLE_EPOCH_OFFSET), 0)
}

/// One decoded message row plus its (possibly empty) attachment list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageRecord {
    /// `message.ROWID`.
    pub rowid: i64,
    /// Message send/receive time.
    pub date: DateTime<Utc>,
    /// Handle identifier (phone / email) of the peer.
    pub handle: Option<String>,
    /// Plain text body if present.
    pub text: Option<String>,
    /// Extracted body from `attributedBody` when `text` is NULL.
    pub attributed_text: Option<String>,
    /// Thread originator GUID.
    pub thread_originator_guid: Option<String>,
    /// Tapback / reaction target GUID.
    pub associated_message_guid: Option<String>,
    /// Expressive send style (e.g. `"com.apple.messages.effect.CKSlamEffect"`).
    pub expressive_send_style_id: Option<String>,
    /// True when the message fell back from iMessage to SMS.
    pub was_downgraded: bool,
    /// Attachments attached to this message.
    pub attachments: Vec<AttachmentRecord>,
    /// Sprint-11 P1 — `message.is_from_me`. `true` = the examiner's
    /// account sent it, `false` = inbound from the peer. Drives the
    /// conversation-view direction indicator.
    pub is_from_me: bool,
    /// Sprint-11 P1 — `message.service`. Typically `"iMessage"` or
    /// `"SMS"`. Empty string when missing; the conversation view
    /// uses this to badge each row.
    pub service: String,
    /// Sprint-11 follow-up — `chat.chat_identifier` resolved via
    /// `chat_message_join`. The authoritative thread identifier
    /// for both 1:1 and group conversations: a message with
    /// `is_from_me=1` and `handle_id=NULL` (the examiner's reply
    /// in their own thread) joins back to its chat through this
    /// path even though the `handle` column is empty. Falls back
    /// to `None` when the message has no chat-membership row.
    pub chat_identifier: Option<String>,
}

/// One row from the `attachment` table, joined to a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentRecord {
    pub transfer_name: Option<String>,
    pub mime_type: Option<String>,
    pub total_bytes: i64,
    pub is_sticker: bool,
}

pub fn parse(path: &Path) -> Vec<MessageRecord> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let Ok(conn) = Connection::open_with_flags(path, flags) else {
        return Vec::new();
    };
    query_messages(&conn).unwrap_or_default()
}

fn query_messages(conn: &Connection) -> rusqlite::Result<Vec<MessageRecord>> {
    // Some older fixtures lack the newer columns; we tolerate that by
    // probing for each and substituting NULL when missing.
    let has_column = |table: &str, col: &str| -> bool {
        let sql = format!("PRAGMA table_info({})", table);
        let Ok(mut stmt) = conn.prepare(&sql) else {
            return false;
        };
        let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(1)) else {
            return false;
        };
        for r in rows.flatten() {
            if r.eq_ignore_ascii_case(col) {
                return true;
            }
        }
        false
    };
    let has_thread = has_column("message", "thread_originator_guid");
    let has_assoc = has_column("message", "associated_message_guid");
    let has_style = has_column("message", "expressive_send_style_id");
    let has_downgraded = has_column("message", "was_downgraded");
    let has_attrbody = has_column("message", "attributedBody");
    let has_isfromme = has_column("message", "is_from_me");
    let has_service = has_column("message", "service");
    let sql = format!(
        "SELECT m.ROWID, m.date, h.id, m.text, \
                {attr}, {thread}, {assoc}, {style}, {down}, {ifm}, {svc} \
         FROM message m \
         LEFT JOIN handle h ON m.handle_id = h.ROWID \
         ORDER BY m.date ASC",
        attr = if has_attrbody { "m.attributedBody" } else { "NULL" },
        thread = if has_thread { "m.thread_originator_guid" } else { "NULL" },
        assoc = if has_assoc { "m.associated_message_guid" } else { "NULL" },
        style = if has_style { "m.expressive_send_style_id" } else { "NULL" },
        down = if has_downgraded { "m.was_downgraded" } else { "0" },
        ifm = if has_isfromme { "m.is_from_me" } else { "0" },
        svc = if has_service { "m.service" } else { "NULL" },
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], |row| {
        let rowid: i64 = row.get(0)?;
        let date: Option<i64> = row.get(1)?;
        let handle: Option<String> = row.get(2)?;
        let text: Option<String> = row.get(3)?;
        let attr_body: Option<Vec<u8>> = row.get(4)?;
        let thread_originator_guid: Option<String> = row.get(5)?;
        let associated_message_guid: Option<String> = row.get(6)?;
        let expressive_send_style_id: Option<String> = row.get(7)?;
        let was_downgraded: Option<i64> = row.get(8)?;
        let is_from_me: Option<i64> = row.get(9)?;
        let service: Option<String> = row.get(10)?;
        Ok((
            rowid,
            date,
            handle,
            text,
            attr_body,
            thread_originator_guid,
            associated_message_guid,
            expressive_send_style_id,
            was_downgraded,
            is_from_me,
            service,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let Ok((
            rowid,
            date,
            handle,
            text,
            attr_body,
            thread_originator_guid,
            associated_message_guid,
            expressive_send_style_id,
            was_downgraded,
            is_from_me,
            service,
        )) = row
        else {
            continue;
        };
        let Some(date) = date.and_then(decode_message_date) else {
            continue;
        };
        let attributed_text =
            attr_body.as_deref().and_then(extract_attributed_string);
        let attachments = load_attachments(conn, rowid).unwrap_or_default();
        let chat_identifier = load_chat_identifier(conn, rowid);
        out.push(MessageRecord {
            rowid,
            date,
            handle,
            text,
            attributed_text,
            thread_originator_guid,
            associated_message_guid,
            expressive_send_style_id,
            was_downgraded: was_downgraded.unwrap_or(0) != 0,
            attachments,
            is_from_me: is_from_me.unwrap_or(0) != 0,
            service: service.unwrap_or_default(),
            chat_identifier,
        });
    }
    Ok(out)
}

/// Sprint-11 follow-up — resolve a message's chat membership.
///
/// Joins `chat_message_join` → `chat` to recover the
/// `chat_identifier` (typically the peer phone / handle for 1:1
/// chats, or a synthesized GUID for group chats). This is the
/// authoritative thread key: a message can have `handle_id=NULL`
/// (e.g. the examiner replying in a thread their own account
/// owns) and still resolve to the right thread through this join.
///
/// Returns `None` when:
///   * the join tables are missing (stripped fixtures), or
///   * the message has no chat-membership row.
///
/// In either case the caller falls back to handle / thread_originator_guid.
fn load_chat_identifier(conn: &Connection, message_rowid: i64) -> Option<String> {
    let sql = "SELECT c.chat_identifier \
               FROM chat_message_join cmj \
               JOIN chat c ON cmj.chat_id = c.ROWID \
               WHERE cmj.message_id = ?1 \
               LIMIT 1";
    let mut stmt = conn.prepare(sql).ok()?;
    stmt.query_row([message_rowid], |row| row.get::<_, String>(0)).ok()
}

fn load_attachments(conn: &Connection, message_rowid: i64) -> rusqlite::Result<Vec<AttachmentRecord>> {
    let sql = "SELECT a.transfer_name, a.mime_type, a.total_bytes, \
                      COALESCE(a.is_sticker, 0) \
               FROM attachment a \
               JOIN message_attachment_join j ON j.attachment_id = a.ROWID \
               WHERE j.message_id = ?1";
    let Ok(mut stmt) = conn.prepare(sql) else {
        // attachment table may not exist in a stripped fixture.
        return Ok(Vec::new());
    };
    let rows = stmt.query_map([message_rowid], |row| {
        let transfer_name: Option<String> = row.get(0)?;
        let mime_type: Option<String> = row.get(1)?;
        let total_bytes: i64 = row.get::<_, Option<i64>>(2)?.unwrap_or(0);
        let is_sticker: i64 = row.get(3)?;
        Ok(AttachmentRecord {
            transfer_name,
            mime_type,
            total_bytes,
            is_sticker: is_sticker != 0,
        })
    })?;
    let mut out = Vec::new();
    for a in rows.flatten() {
        out.push(a);
    }
    Ok(out)
}

/// Extract the plain-text portion of a serialized NSAttributedString.
///
/// The archive format is NSKeyedArchiver; a minimal decoder looks for
/// the `+` + `NSString` marker followed by a length-prefixed UTF-8
/// run. This is a heuristic — returns `None` when no text could be
/// recovered. Sufficient for the common iOS 16 case where the message
/// body is simple unformatted text.
pub fn extract_attributed_string(bytes: &[u8]) -> Option<String> {
    // Look for the NSString class marker.
    let needle = b"NSString";
    let pos = bytes.windows(needle.len()).position(|w| w == needle)?;
    // From `NSString` onward, find the first 0x01 byte that appears
    // immediately before a plausible length prefix.
    let mut i = pos + needle.len();
    while i + 2 < bytes.len() {
        let marker = bytes[i];
        if marker == 0x01 {
            // Next byte is length when <= 0x7F, or length-prefix tag.
            let len_tag = bytes[i + 1];
            let (length, skip) = if len_tag < 0x80 {
                (len_tag as usize, 1)
            } else if len_tag == 0x8F {
                if i + 3 > bytes.len() {
                    break;
                }
                (bytes[i + 2] as usize, 2)
            } else {
                i += 1;
                continue;
            };
            let start = i + 1 + skip;
            let end = start + length;
            if end <= bytes.len() && length > 0 && length <= 8192 {
                if let Ok(s) = std::str::from_utf8(&bytes[start..end]) {
                    if s.chars().all(|c| !c.is_control() || c == '\n' || c == '\t') {
                        return Some(s.to_string());
                    }
                }
            }
        }
        i += 1;
    }
    // Final fallback: scan for a long printable-ASCII run (>= 4 chars).
    let mut current: Vec<u8> = Vec::new();
    let mut best: Option<String> = None;
    for &b in bytes {
        if (0x20..=0x7E).contains(&b) {
            current.push(b);
        } else {
            if current.len() >= 4 {
                if let Ok(s) = std::str::from_utf8(&current) {
                    if best.as_deref().is_none_or(|prev| prev.len() < s.len()) {
                        best = Some(s.to_string());
                    }
                }
            }
            current.clear();
        }
    }
    best
}

/// True when `path` looks like an iMessage / SMS database.
pub fn is_imessage_path(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    name == "sms.db" || name == "chat.db"
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn build_message_db() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("chat.db");
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch(
            "CREATE TABLE handle ( \
                 ROWID INTEGER PRIMARY KEY, id TEXT \
             ); \
             CREATE TABLE message ( \
                 ROWID INTEGER PRIMARY KEY, date INTEGER, handle_id INTEGER, \
                 text TEXT, attributedBody BLOB, \
                 thread_originator_guid TEXT, associated_message_guid TEXT, \
                 expressive_send_style_id TEXT, was_downgraded INTEGER, \
                 is_from_me INTEGER, service TEXT \
             ); \
             CREATE TABLE attachment ( \
                 ROWID INTEGER PRIMARY KEY, transfer_name TEXT, \
                 mime_type TEXT, total_bytes INTEGER, is_sticker INTEGER \
             ); \
             CREATE TABLE message_attachment_join ( \
                 message_id INTEGER, attachment_id INTEGER \
             ); \
             CREATE TABLE chat ( \
                 ROWID INTEGER PRIMARY KEY, chat_identifier TEXT \
             ); \
             CREATE TABLE chat_message_join ( \
                 chat_id INTEGER, message_id INTEGER \
             );",
        )
        .expect("create schema");
        conn.execute(
            "INSERT INTO handle (ROWID, id) VALUES (1, '+15551234567')",
            [],
        )
        .expect("handle");
        // Message 1: inbound iMessage with text, date in CoreData seconds.
        conn.execute(
            "INSERT INTO message (ROWID, date, handle_id, text, was_downgraded, \
                                  is_from_me, service) \
             VALUES (1, 738936000, 1, 'hello world', 0, 0, 'iMessage')",
            [],
        )
        .expect("msg1");
        // Message 2: outbound SMS-fallback (was_downgraded), NULL text +
        // attributedBody containing 'secret payload'.
        let mut attr = Vec::new();
        attr.extend_from_slice(b"\x00\x00NSString\x01\x0e");
        attr.extend_from_slice(b"secret payload");
        conn.execute(
            "INSERT INTO message (ROWID, date, handle_id, text, attributedBody, \
                                  thread_originator_guid, associated_message_guid, \
                                  expressive_send_style_id, was_downgraded, \
                                  is_from_me, service) \
             VALUES (2, 738936060000000000, 1, NULL, ?1, 'THREAD-1', 'TAP-1', \
                     'com.apple.messages.effect.CKSlamEffect', 1, 1, 'SMS')",
            [rusqlite::types::Value::Blob(attr)],
        )
        .expect("msg2");
        conn.execute(
            "INSERT INTO attachment (ROWID, transfer_name, mime_type, total_bytes, is_sticker) \
             VALUES (1, 'photo.jpg', 'image/jpeg', 1048576, 0)",
            [],
        )
        .expect("attachment");
        conn.execute(
            "INSERT INTO message_attachment_join (message_id, attachment_id) VALUES (2, 1)",
            [],
        )
        .expect("join");
        // Sprint-11 follow-up — both messages live in the same
        // chat with chat_identifier "+15551234567". Mirrors the
        // MacBookPro Mint Mobile (6700) thread on the CTF image.
        conn.execute(
            "INSERT INTO chat (ROWID, chat_identifier) VALUES (1, '+15551234567')",
            [],
        )
        .expect("chat");
        conn.execute(
            "INSERT INTO chat_message_join (chat_id, message_id) VALUES (1, 1), (1, 2)",
            [],
        )
        .expect("chat_message_join");
        drop(conn);
        dir
    }

    #[test]
    fn parse_empty_on_missing_file() {
        assert!(parse(Path::new("/no/such/chat.db")).is_empty());
    }

    #[test]
    fn parse_returns_messages_with_attachments_and_attr_body() {
        let dir = build_message_db();
        let records = parse(&dir.path().join("chat.db"));
        assert_eq!(records.len(), 2);

        let m1 = records
            .iter()
            .find(|r| r.rowid == 1)
            .expect("msg 1");
        assert_eq!(m1.text.as_deref(), Some("hello world"));
        assert_eq!(m1.date.timestamp(), 1_717_243_200);
        assert!(m1.attachments.is_empty());
        assert!(!m1.is_from_me);
        assert_eq!(m1.service, "iMessage");

        let m2 = records
            .iter()
            .find(|r| r.rowid == 2)
            .expect("msg 2");
        assert!(m2.text.is_none());
        assert_eq!(m2.attributed_text.as_deref(), Some("secret payload"));
        assert_eq!(m2.thread_originator_guid.as_deref(), Some("THREAD-1"));
        assert_eq!(m2.associated_message_guid.as_deref(), Some("TAP-1"));
        assert_eq!(
            m2.expressive_send_style_id.as_deref(),
            Some("com.apple.messages.effect.CKSlamEffect")
        );
        assert!(m2.was_downgraded);
        assert!(m2.is_from_me);
        assert_eq!(m2.service, "SMS");
        assert_eq!(m2.attachments.len(), 1);
        assert_eq!(m2.attachments[0].transfer_name.as_deref(), Some("photo.jpg"));
        assert_eq!(m2.attachments[0].mime_type.as_deref(), Some("image/jpeg"));
        assert_eq!(m2.attachments[0].total_bytes, 1_048_576);

        // Sprint-11 follow-up — chat_identifier resolves through
        // chat_message_join for both messages, including the one
        // that would otherwise have been an orphan.
        assert_eq!(m1.chat_identifier.as_deref(), Some("+15551234567"));
        assert_eq!(m2.chat_identifier.as_deref(), Some("+15551234567"));
    }

    #[test]
    fn sprint11_followup_chat_identifier_recovers_thread_for_null_handle() {
        // Mirror the MacBookPro Mint Mobile (handle="6700") shape:
        // 4 messages with handle="6700" + 1 outbound STOP with
        // handle_id=NULL. All must share the same chat_identifier
        // so the conversation view groups them into one thread.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("chat.db");
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch(
            "CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT); \
             CREATE TABLE message ( \
                 ROWID INTEGER PRIMARY KEY, date INTEGER, handle_id INTEGER, \
                 text TEXT, attributedBody BLOB, \
                 thread_originator_guid TEXT, associated_message_guid TEXT, \
                 expressive_send_style_id TEXT, was_downgraded INTEGER, \
                 is_from_me INTEGER, service TEXT \
             ); \
             CREATE TABLE chat (ROWID INTEGER PRIMARY KEY, chat_identifier TEXT); \
             CREATE TABLE chat_message_join (chat_id INTEGER, message_id INTEGER);",
        )
        .expect("schema");
        conn.execute("INSERT INTO handle (ROWID, id) VALUES (1, '6700')", [])
            .expect("handle");
        // Outbound STOP — handle_id NULL.
        conn.execute(
            "INSERT INTO message (ROWID, date, handle_id, text, was_downgraded, is_from_me, service) \
             VALUES (1, 738936000, NULL, 'STOP', 0, 1, 'SMS')",
            [],
        )
        .expect("msg1");
        // Inbound from 6700.
        conn.execute(
            "INSERT INTO message (ROWID, date, handle_id, text, was_downgraded, is_from_me, service) \
             VALUES (2, 738936060, 1, 'Nice! Your phone is setup', 0, 0, 'SMS')",
            [],
        )
        .expect("msg2");
        conn.execute("INSERT INTO chat (ROWID, chat_identifier) VALUES (1, '6700')", [])
            .expect("chat");
        conn.execute(
            "INSERT INTO chat_message_join (chat_id, message_id) VALUES (1, 1), (1, 2)",
            [],
        )
        .expect("cmj");
        drop(conn);

        let records = parse(&path);
        assert_eq!(records.len(), 2);
        let m1 = records.iter().find(|r| r.rowid == 1).expect("STOP row");
        assert!(m1.handle.is_none(), "STOP row must reproduce NULL handle");
        assert!(m1.is_from_me);
        assert_eq!(
            m1.chat_identifier.as_deref(),
            Some("6700"),
            "chat_message_join must recover the thread for handle-NULL outbound messages"
        );
        let m2 = records.iter().find(|r| r.rowid == 2).expect("inbound row");
        assert_eq!(m2.chat_identifier.as_deref(), Some("6700"));
    }

    #[test]
    fn extract_attributed_string_finds_plain_text() {
        let mut blob = Vec::new();
        blob.extend_from_slice(b"junk\x00prefix");
        blob.extend_from_slice(b"NSString\x01\x05hello");
        blob.extend_from_slice(b"\x00trailing");
        assert_eq!(
            extract_attributed_string(&blob).as_deref(),
            Some("hello")
        );
    }

    #[test]
    fn decode_message_date_handles_both_schemas() {
        // Seconds-form.
        let d1 = decode_message_date(738_936_000).expect("seconds");
        assert_eq!(d1.timestamp(), 1_717_243_200);
        // Nanoseconds-form (macOS 11+ / iOS 14+).
        let d2 = decode_message_date(738_936_000_000_000_000).expect("nanos");
        assert_eq!(d2.timestamp(), 1_717_243_200);
    }

    #[test]
    fn sprint11_p3_apple_timestamp_converts_correctly() {
        // Apple epoch 0 = 2001-01-01 00:00:00 UTC = unix 978_307_200.
        let dt = decode_message_date(0).expect("apple_epoch_0");
        assert_eq!(dt.timestamp(), 978_307_200);
        // 1762276748 (decimal) — a real CoreData seconds value from
        // 2025-11-04 ~17:39 UTC. Apple epoch + 1762276748 seconds.
        let dt = decode_message_date(1_762_276_748).expect("ref");
        assert_eq!(dt.timestamp(), 1_762_276_748 + 978_307_200);
    }

    #[test]
    fn sprint11_p3_imessage_nanosecond_timestamp_converts_correctly() {
        // 738_936_000_000_000_000 ns since 2001-01-01 = 738_936_000 s.
        // Adding the Apple → Unix offset gives 1_717_243_200 (a known
        // 2024-06-01 12:00:00 UTC fixture used elsewhere in this
        // module).
        let dt = decode_message_date(738_936_000_000_000_000).expect("nanos");
        assert_eq!(dt.timestamp(), 1_717_243_200);
        // Heuristic boundary: anything below 1e12 must be treated
        // as seconds (not nanoseconds).
        let dt = decode_message_date(999_999_999_999).expect("boundary");
        // The threshold is `>= 1_000_000_000_000`, so this stays as
        // seconds: apple-epoch 999_999_999_999 + offset.
        assert_eq!(
            dt.timestamp(),
            999_999_999_999_i64.saturating_add(978_307_200)
        );
    }

    #[test]
    fn is_imessage_path_recognises_filenames() {
        assert!(is_imessage_path(Path::new("/x/Messages/chat.db")));
        assert!(is_imessage_path(Path::new("/x/SMS/sms.db")));
        assert!(!is_imessage_path(Path::new("/x/other.db")));
    }
}
