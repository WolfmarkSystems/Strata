//! APPLE26-1 — iOS 26 iMessage schema extensions.
//!
//! iOS 26 adds three new kinds of evidence to `chat.db`:
//!   1. per-chat wallpapers / backgrounds stored in
//!      `chat.chat_properties` as a binary PLIST with a
//!      `backgroundProperties` key;
//!   2. a per-message encryption-state column
//!      (`message.encryption_state` — exact name varies with
//!      point-release, so we probe for any column containing
//!      "encryption");
//!   3. Live Translation flags (`attachment.is_translated`,
//!      `message.translation_source_language`,
//!      `message.translation_target_language`).
//!
//! This module parses all three via `rusqlite`. Validation against a
//! real iOS 26 `chat.db` requires an iOS 26 extraction — none of the
//! images in `~/Wolfmark/Test Material/` are iOS 26 yet, so tests
//! drive synthetic in-memory fixtures that model the documented
//! schema shape.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use std::path::{Path, PathBuf};

use chrono::{DateTime, TimeZone, Utc};
use rusqlite::Connection;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

/// Per-chat background discovered in `chat.chat_properties`.
#[derive(Debug, Clone, PartialEq)]
pub struct ImessageBackground {
    pub chat_id: i64,
    pub background_type: String,
    pub color_primary: Option<String>,
    pub color_secondary: Option<String>,
    pub image_ktx_data: Option<Vec<u8>>,
    pub modified_date: Option<DateTime<Utc>>,
}

/// Live Translation event observed on a single message.
#[derive(Debug, Clone, PartialEq)]
pub struct LiveTranslationEvent {
    pub message_id: i64,
    pub source_language: Option<String>,
    pub target_language: Option<String>,
    pub showed_original: bool,
    pub timestamp: Option<DateTime<Utc>>,
}

/// Encryption state transition for a single message.
#[derive(Debug, Clone, PartialEq)]
pub struct MessageEncryptionState {
    pub message_id: i64,
    pub state: String,
}

/// Detect whether `path` looks like an iOS 26 `chat.db` by probing for
/// the iOS 26-specific column names. Safe on older schemas — returns
/// `false` and the caller falls back to the existing sms.rs parser.
pub fn matches_ios26(path: &Path) -> bool {
    if !util::name_is(path, &["chat.db", "sms.db"]) {
        return false;
    }
    let Some(conn) = util::open_sqlite_ro(path) else {
        return false;
    };
    has_ios26_columns(&conn)
}

fn has_ios26_columns(conn: &Connection) -> bool {
    if column_names(conn, "chat").iter().any(|c| c == "chat_properties") {
        return true;
    }
    let msg_cols = column_names(conn, "message");
    msg_cols.iter().any(|c| c.contains("encryption") || c.contains("translat"))
}

fn column_names(conn: &Connection, table: &str) -> Vec<String> {
    let sql = format!("PRAGMA table_info({table})");
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = match stmt.query_map([], |r| r.get::<_, String>(1)) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    rows.flatten().collect()
}

// ── Backgrounds ────────────────────────────────────────────────────────

/// Parse every row in `chat` with a non-null `chat_properties` column,
/// decode the embedded PLIST, and emit an `ImessageBackground` per
/// chat. Unknown / mis-shaped PLISTs are skipped silently.
pub fn parse_backgrounds(conn: &Connection) -> Vec<ImessageBackground> {
    let mut out = Vec::new();
    if !column_names(conn, "chat").iter().any(|c| c == "chat_properties") {
        return out;
    }
    let mut stmt = match conn
        .prepare("SELECT ROWID, chat_properties FROM chat WHERE chat_properties IS NOT NULL")
    {
        Ok(s) => s,
        Err(_) => return out,
    };
    let rows = match stmt.query_map([], |r| {
        Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
    }) {
        Ok(r) => r,
        Err(_) => return out,
    };
    for row in rows.flatten() {
        if let Some(b) = extract_background_from_plist(row.0, &row.1) {
            out.push(b);
        }
    }
    out
}

/// Walk an arbitrary `plist::Value` and pull out the first
/// `backgroundProperties` dictionary we find. Apple nests it inside a
/// wrapper dict so we recurse defensively.
fn extract_background_from_plist(chat_id: i64, bytes: &[u8]) -> Option<ImessageBackground> {
    let value = plist::Value::from_reader(std::io::Cursor::new(bytes)).ok()?;
    let dict = find_dict_with_key(&value, "backgroundProperties")?;
    let bg_type = string_key(dict, "backgroundType").unwrap_or_else(|| "unknown".into());
    let color_primary = string_key(dict, "colorPrimary");
    let color_secondary = string_key(dict, "colorSecondary");
    let image_ktx_data = dict
        .get("imageData")
        .and_then(|v| v.as_data().map(|d| d.to_vec()));
    let modified_date = dict
        .get("modifiedDate")
        .and_then(|v| v.as_date())
        .and_then(|d| {
            let secs = d.to_xml_format().parse::<DateTime<Utc>>().ok()?;
            Some(secs)
        });
    Some(ImessageBackground {
        chat_id,
        background_type: bg_type,
        color_primary,
        color_secondary,
        image_ktx_data,
        modified_date,
    })
}

fn find_dict_with_key<'a>(v: &'a plist::Value, key: &str) -> Option<&'a plist::Dictionary> {
    match v {
        plist::Value::Dictionary(d) => {
            if let Some(inner) = d.get(key).and_then(|x| x.as_dictionary()) {
                return Some(inner);
            }
            for val in d.values() {
                if let Some(found) = find_dict_with_key(val, key) {
                    return Some(found);
                }
            }
            None
        }
        plist::Value::Array(arr) => arr.iter().find_map(|e| find_dict_with_key(e, key)),
        _ => None,
    }
}

fn string_key(d: &plist::Dictionary, k: &str) -> Option<String> {
    d.get(k).and_then(|v| v.as_string()).map(|s| s.to_string())
}

// ── Encryption state ───────────────────────────────────────────────────

pub fn parse_encryption_states(conn: &Connection) -> Vec<MessageEncryptionState> {
    let mut out = Vec::new();
    let cols = column_names(conn, "message");
    let Some(enc_col) = cols.iter().find(|c| c.contains("encryption")).cloned() else {
        return out;
    };
    let sql = format!("SELECT ROWID, COALESCE({enc_col}, '') FROM message WHERE {enc_col} IS NOT NULL");
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return out,
    };
    let rows = match stmt.query_map([], |r| {
        Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
    }) {
        Ok(r) => r,
        Err(_) => return out,
    };
    for (id, state) in rows.flatten() {
        if !state.is_empty() {
            out.push(MessageEncryptionState { message_id: id, state });
        }
    }
    out
}

// ── Live Translation ───────────────────────────────────────────────────

pub fn parse_translation_events(conn: &Connection) -> Vec<LiveTranslationEvent> {
    let mut out = Vec::new();
    let cols = column_names(conn, "message");
    let has_src = cols.iter().any(|c| c == "translation_source_language");
    let has_tgt = cols.iter().any(|c| c == "translation_target_language");
    if !has_src && !has_tgt {
        return out;
    }
    let sql = "SELECT ROWID, \
               COALESCE(translation_source_language, ''), \
               COALESCE(translation_target_language, ''), \
               COALESCE(showed_original, 0), \
               COALESCE(date, 0) \
               FROM message WHERE \
               translation_source_language IS NOT NULL OR \
               translation_target_language IS NOT NULL";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return out,
    };
    let rows = match stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, i64>(3)?,
            r.get::<_, i64>(4)?,
        ))
    }) {
        Ok(r) => r,
        Err(_) => return out,
    };
    for (id, src, tgt, orig, ts) in rows.flatten() {
        let timestamp = if ts > 0 {
            // iOS uses Cocoa epoch (2001-01-01); messages in iOS 13+
            // store nanoseconds. Dividing by 1e9 handles both order-
            // of-magnitude variants without losing precision.
            cocoa_to_utc(ts)
        } else {
            None
        };
        out.push(LiveTranslationEvent {
            message_id: id,
            source_language: opt(&src),
            target_language: opt(&tgt),
            showed_original: orig != 0,
            timestamp,
        });
    }
    out
}

fn opt(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn cocoa_to_utc(ts: i64) -> Option<DateTime<Utc>> {
    let cocoa_epoch_offset = 978_307_200i64;
    let secs = if ts > 1_000_000_000_000 { ts / 1_000_000_000 } else { ts };
    Utc.timestamp_opt(secs + cocoa_epoch_offset, 0).single()
}

// ── KTX header probing ─────────────────────────────────────────────────

/// Minimal KTX (v1) header sanity check — Apple's chat background
/// thumbnails are stored in this format. We expose a strict magic
/// check for test fixtures; deeper format parsing stays out of scope
/// until we have real samples.
pub fn is_ktx_v1(bytes: &[u8]) -> bool {
    // «KTX 11» — 0xAB, 0x4B, 0x54, 0x58, 0x20, 0x31, 0x31, 0xBB, 0x0D, 0x0A, 0x1A, 0x0A
    const MAGIC: [u8; 12] = [0xAB, 0x4B, 0x54, 0x58, 0x20, 0x31, 0x31, 0xBB, 0x0D, 0x0A, 0x1A, 0x0A];
    bytes.len() >= MAGIC.len() && bytes[..MAGIC.len()] == MAGIC
}

// ── Artifact emission ──────────────────────────────────────────────────

/// Convert a background + translation inventory into the plugin
/// `ArtifactRecord` surface.
pub fn emit_artifacts(
    path: &Path,
    backgrounds: &[ImessageBackground],
    translations: &[LiveTranslationEvent],
    encryption: &[MessageEncryptionState],
) -> Vec<ArtifactRecord> {
    let source = path.to_string_lossy().to_string();
    let mut out: Vec<ArtifactRecord> = Vec::new();
    for bg in backgrounds {
        out.push(ArtifactRecord {
            category: ArtifactCategory::Communications,
            subcategory: "ios26.imessage.background".into(),
            title: "iOS 26 iMessage Background".into(),
            detail: format!(
                "Chat {} background: {} ({}{})",
                bg.chat_id,
                bg.background_type,
                bg.color_primary.clone().unwrap_or_default(),
                if bg.image_ktx_data.is_some() { ", with image" } else { "" }
            ),
            source_path: source.clone(),
            timestamp: bg.modified_date.map(|t| t.timestamp()),
            mitre_technique: Some("T1005".into()),
            is_suspicious: false,
            confidence: 80,
            forensic_value: ForensicValue::Medium,
            raw_data: None,
        });
    }
    for ev in translations {
        out.push(ArtifactRecord {
            category: ArtifactCategory::Communications,
            subcategory: "ios26.imessage.translation".into(),
            title: "iOS 26 Live Translation Event".into(),
            detail: format!(
                "Message {}: {} -> {}, showed_original={}",
                ev.message_id,
                ev.source_language.clone().unwrap_or_else(|| "?".into()),
                ev.target_language.clone().unwrap_or_else(|| "?".into()),
                ev.showed_original,
            ),
            source_path: source.clone(),
            timestamp: ev.timestamp.map(|t| t.timestamp()),
            mitre_technique: Some("T1005".into()),
            is_suspicious: false,
            confidence: 85,
            forensic_value: ForensicValue::High,
            raw_data: None,
        });
    }
    for s in encryption {
        out.push(ArtifactRecord {
            category: ArtifactCategory::Communications,
            subcategory: "ios26.imessage.encryption".into(),
            title: "iOS 26 iMessage Encryption State".into(),
            detail: format!("Message {}: {}", s.message_id, s.state),
            source_path: source.clone(),
            timestamp: None,
            mitre_technique: Some("T1005".into()),
            is_suspicious: false,
            confidence: 70,
            forensic_value: ForensicValue::Medium,
            raw_data: None,
        });
    }
    out
}

/// Full-parse entrypoint used by the pulse plugin host when this
/// module wins the `matches_ios26()` probe.
pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = util::open_sqlite_ro(path) else {
        return Vec::new();
    };
    let bg = parse_backgrounds(&conn);
    let tr = parse_translation_events(&conn);
    let enc = parse_encryption_states(&conn);
    emit_artifacts(path, &bg, &tr, &enc)
}

// Silence the unused-import on PathBuf if future changes need it.
#[allow(dead_code)]
fn _ensure_pathbuf_used(_p: PathBuf) {}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn mem() -> Connection {
        Connection::open_in_memory().expect("open")
    }

    fn plist_with_background() -> Vec<u8> {
        // Minimal binary PLIST with a nested `backgroundProperties` dict.
        let mut inner = plist::Dictionary::new();
        inner.insert("backgroundType".into(), plist::Value::String("Gradient".into()));
        inner.insert("colorPrimary".into(), plist::Value::String("#FF00AA".into()));
        inner.insert("colorSecondary".into(), plist::Value::String("#110055".into()));
        let mut outer = plist::Dictionary::new();
        outer.insert(
            "backgroundProperties".into(),
            plist::Value::Dictionary(inner),
        );
        let mut bytes: Vec<u8> = Vec::new();
        plist::to_writer_binary(std::io::Cursor::new(&mut bytes), &plist::Value::Dictionary(outer))
            .expect("write plist");
        bytes
    }

    #[test]
    fn parses_gradient_background_from_chat_properties() {
        let c = mem();
        c.execute_batch(
            "CREATE TABLE chat (ROWID INTEGER PRIMARY KEY, chat_properties BLOB);",
        )
        .expect("schema");
        let p = plist_with_background();
        c.execute(
            "INSERT INTO chat (ROWID, chat_properties) VALUES (7, ?1)",
            rusqlite::params![p],
        )
        .expect("ins");
        let bg = parse_backgrounds(&c);
        assert_eq!(bg.len(), 1);
        assert_eq!(bg[0].chat_id, 7);
        assert_eq!(bg[0].background_type, "Gradient");
        assert_eq!(bg[0].color_primary.as_deref(), Some("#FF00AA"));
    }

    #[test]
    fn missing_chat_properties_column_returns_empty() {
        let c = mem();
        c.execute_batch("CREATE TABLE chat (ROWID INTEGER PRIMARY KEY, name TEXT);")
            .expect("schema");
        assert!(parse_backgrounds(&c).is_empty());
    }

    #[test]
    fn parses_encryption_state_when_column_present() {
        let c = mem();
        c.execute_batch(
            "CREATE TABLE message (ROWID INTEGER PRIMARY KEY, encryption_state TEXT);",
        )
        .expect("schema");
        c.execute(
            "INSERT INTO message (ROWID, encryption_state) VALUES (3, 'E2EE')",
            [],
        )
        .expect("ins");
        let states = parse_encryption_states(&c);
        assert_eq!(states, vec![MessageEncryptionState { message_id: 3, state: "E2EE".into() }]);
    }

    #[test]
    fn parses_live_translation_events() {
        let c = mem();
        c.execute_batch(
            "CREATE TABLE message (\
                ROWID INTEGER PRIMARY KEY,\
                translation_source_language TEXT,\
                translation_target_language TEXT,\
                showed_original INTEGER,\
                date INTEGER);",
        )
        .expect("schema");
        c.execute(
            "INSERT INTO message VALUES (9, 'es', 'en', 0, 0)",
            [],
        )
        .expect("ins");
        let ev = parse_translation_events(&c);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].source_language.as_deref(), Some("es"));
        assert_eq!(ev[0].target_language.as_deref(), Some("en"));
        assert!(!ev[0].showed_original);
    }

    #[test]
    fn ktx_magic_check() {
        let good = [
            0xAB, 0x4B, 0x54, 0x58, 0x20, 0x31, 0x31, 0xBB, 0x0D, 0x0A, 0x1A, 0x0A, 0x00,
        ];
        assert!(is_ktx_v1(&good));
        let bad = [0u8; 12];
        assert!(!is_ktx_v1(&bad));
    }

    #[test]
    fn matches_ios26_false_on_empty_db() {
        let tmp = tempfile::tempdir().expect("tmp");
        let p = tmp.path().join("chat.db");
        let conn = Connection::open(&p).expect("create");
        conn.execute_batch("CREATE TABLE message (ROWID INTEGER);").expect("s");
        drop(conn);
        assert!(!matches_ios26(&p));
    }

    #[test]
    fn matches_ios26_true_when_chat_properties_present() {
        let tmp = tempfile::tempdir().expect("tmp");
        let p = tmp.path().join("chat.db");
        let conn = Connection::open(&p).expect("create");
        conn.execute_batch(
            "CREATE TABLE chat (ROWID INTEGER, chat_properties BLOB);\
             CREATE TABLE message (ROWID INTEGER);",
        )
        .expect("s");
        drop(conn);
        assert!(matches_ios26(&p));
    }
}
