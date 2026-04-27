//! APPLE26-3 — macOS Tahoe 26 persistent Clipboard History.
//!
//! macOS 26 elevated the pasteboard from memory-only to a disk-backed,
//! Spotlight-indexed history. The exact schema has not stabilised
//! across public betas, so this module parses any SQLite database
//! whose table layout matches the documented-for-research shape:
//! a main `clipboard_entries` (or `entries`) table with at least
//! `timestamp`, a content-type column, and a text-content column.
//!
//! Sensitive-content detection uses regex-free pattern matching so we
//! don't pull the regex crate into mactrace purely for this module —
//! the checks are all direct predicates (Luhn for card numbers, byte
//! ranges for ASCII-printable passwords, etc.).
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use std::path::Path;

use chrono::{DateTime, TimeZone, Utc};
use rusqlite::Connection;

#[derive(Debug, Clone, PartialEq)]
pub struct ClipboardEntry {
    pub timestamp: DateTime<Utc>,
    pub content_type: String,
    pub content_text: Option<String>,
    pub source_app: Option<String>,
    pub source_context: Option<String>,
    pub size: u64,
    pub sensitive_detected: bool,
}

/// File-name predicate for dispatch from the macOS plugin host. Kept
/// permissive because Apple has shuffled the database between
/// `ClipboardHistory.db` and `pboard.db` across developer previews.
pub fn matches(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    let n = name.to_ascii_lowercase();
    n == "clipboardhistory.db" || n == "pboard.db" || n.contains("clipboard")
}

/// Parse the clipboard history database at `path`. Returns an empty
/// Vec if the database is missing expected tables rather than erroring
/// so plugin callers can chain.
pub fn parse(path: &Path) -> Vec<ClipboardEntry> {
    let conn = match Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    parse_conn(&conn)
}

pub fn parse_conn(conn: &Connection) -> Vec<ClipboardEntry> {
    let Some(table) = detect_table(conn) else {
        return Vec::new();
    };
    let cols = column_names(conn, &table);
    let ts_col = pick_col(&cols, &["timestamp", "copied_at", "date"]).unwrap_or("timestamp".into());
    let type_col =
        pick_col(&cols, &["content_type", "type", "kind"]).unwrap_or("content_type".into());
    let text_col = pick_col(&cols, &["content_text", "content", "text"]);
    let app_col = pick_col(&cols, &["source_app", "app", "application"]);
    let ctx_col = pick_col(&cols, &["source_context", "context", "document"]);
    let size_col = pick_col(&cols, &["size", "byte_size", "content_size"]);

    let projection = format!(
        "{},{},{},{},{},{}",
        ts_col,
        type_col,
        text_col.clone().unwrap_or_else(|| "NULL".into()),
        app_col.clone().unwrap_or_else(|| "NULL".into()),
        ctx_col.clone().unwrap_or_else(|| "NULL".into()),
        size_col.clone().unwrap_or_else(|| "0".into()),
    );
    let sql = format!("SELECT {projection} FROM {table}");

    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = match stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0).unwrap_or(0),
            r.get::<_, String>(1).unwrap_or_default(),
            r.get::<_, Option<String>>(2).unwrap_or(None),
            r.get::<_, Option<String>>(3).unwrap_or(None),
            r.get::<_, Option<String>>(4).unwrap_or(None),
            r.get::<_, i64>(5).unwrap_or(0),
        ))
    }) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for (ts, ctype, text, app, ctx, size) in rows.flatten() {
        let timestamp = cocoa_or_unix(ts).unwrap_or_else(unix_epoch);
        let sensitive = text.as_deref().map(is_sensitive).unwrap_or(false);
        out.push(ClipboardEntry {
            timestamp,
            content_type: ctype,
            content_text: text,
            source_app: app,
            source_context: ctx,
            size: size.max(0) as u64,
            sensitive_detected: sensitive,
        });
    }
    out
}

fn unix_epoch() -> DateTime<Utc> {
    DateTime::<Utc>::from(std::time::UNIX_EPOCH)
}

fn detect_table(conn: &Connection) -> Option<String> {
    for t in [
        "clipboard_entries",
        "entries",
        "ClipboardHistory",
        "pboard_items",
    ] {
        let sql =
            format!("SELECT name FROM sqlite_master WHERE type='table' AND name='{t}' LIMIT 1");
        if conn.query_row(&sql, [], |r| r.get::<_, String>(0)).is_ok() {
            return Some(t.into());
        }
    }
    None
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

fn pick_col(cols: &[String], candidates: &[&str]) -> Option<String> {
    for c in candidates {
        if cols.iter().any(|x| x.eq_ignore_ascii_case(c)) {
            return Some((*c).into());
        }
    }
    None
}

fn cocoa_or_unix(ts: i64) -> Option<DateTime<Utc>> {
    if ts == 0 {
        return None;
    }
    // If it looks like a reasonable UNIX epoch (> 1970-01-02) use it
    // directly; otherwise treat as Cocoa (seconds since 2001-01-01).
    if ts > 86_400 {
        Utc.timestamp_opt(ts, 0).single()
    } else {
        let cocoa = 978_307_200i64;
        Utc.timestamp_opt(ts + cocoa, 0).single()
    }
}

// ── Sensitive-content heuristics ───────────────────────────────────────

pub fn is_sensitive(text: &str) -> bool {
    has_private_key_marker(text)
        || has_api_key_prefix(text)
        || has_credentials_url(text)
        || looks_like_password(text)
        || has_ssn_shape(text)
        || has_credit_card(text)
}

fn has_private_key_marker(t: &str) -> bool {
    t.contains("BEGIN PRIVATE KEY")
        || t.contains("BEGIN RSA PRIVATE KEY")
        || t.starts_with("ssh-rsa ")
        || t.starts_with("ssh-ed25519 ")
}

fn has_api_key_prefix(t: &str) -> bool {
    t.starts_with("AKIA") || t.starts_with("sk-") || t.starts_with("ghp_") || t.starts_with("xoxb-")
}

fn has_credentials_url(t: &str) -> bool {
    // https://user:pass@host/...
    if let Some(rest) = t
        .strip_prefix("http://")
        .or_else(|| t.strip_prefix("https://"))
    {
        if let Some(at_idx) = rest.find('@') {
            let userinfo = &rest[..at_idx];
            if userinfo.contains(':') && !userinfo.contains('/') {
                return true;
            }
        }
    }
    false
}

fn looks_like_password(t: &str) -> bool {
    if t.len() < 8 || t.len() > 64 {
        return false;
    }
    let mut upper = false;
    let mut lower = false;
    let mut digit = false;
    let mut symbol = false;
    for c in t.chars() {
        if c.is_ascii_uppercase() {
            upper = true;
        } else if c.is_ascii_lowercase() {
            lower = true;
        } else if c.is_ascii_digit() {
            digit = true;
        } else if c.is_ascii_punctuation() {
            symbol = true;
        } else if c.is_whitespace() {
            return false;
        }
    }
    upper && lower && digit && symbol
}

fn has_ssn_shape(t: &str) -> bool {
    // xxx-xx-xxxx where x is digit
    let bytes = t.as_bytes();
    if bytes.len() < 11 {
        return false;
    }
    for i in 0..=bytes.len() - 11 {
        let w = &bytes[i..i + 11];
        if w[0].is_ascii_digit()
            && w[1].is_ascii_digit()
            && w[2].is_ascii_digit()
            && w[3] == b'-'
            && w[4].is_ascii_digit()
            && w[5].is_ascii_digit()
            && w[6] == b'-'
            && w[7].is_ascii_digit()
            && w[8].is_ascii_digit()
            && w[9].is_ascii_digit()
            && w[10].is_ascii_digit()
        {
            return true;
        }
    }
    false
}

fn has_credit_card(t: &str) -> bool {
    // Any 13-19 consecutive digits (allowing spaces/dashes) that Luhn-validates.
    let digits: String = t.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    luhn_valid(&digits)
}

fn luhn_valid(digits: &str) -> bool {
    let mut sum = 0u32;
    let mut alt = false;
    for c in digits.chars().rev() {
        let Some(d) = c.to_digit(10) else {
            return false;
        };
        let v = if alt { d * 2 } else { d };
        sum += if v > 9 { v - 9 } else { v };
        alt = !alt;
    }
    sum.is_multiple_of(10)
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_detects_aws_key() {
        assert!(is_sensitive("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn sensitive_detects_credentials_url() {
        assert!(is_sensitive("https://admin:hunter2@example.com/api"));
    }

    #[test]
    fn sensitive_detects_luhn_valid_card() {
        // Luhn-valid test card number.
        assert!(is_sensitive("4532015112830366"));
    }

    #[test]
    fn sensitive_detects_ssn_shape() {
        assert!(is_sensitive("SSN: 123-45-6789 on file"));
    }

    #[test]
    fn sensitive_detects_strong_password() {
        assert!(is_sensitive("P@ssw0rd!"));
        assert!(!is_sensitive("short"));
    }

    #[test]
    fn non_sensitive_text_passes() {
        assert!(!is_sensitive("the quick brown fox"));
        assert!(!is_sensitive("just a sentence of words"));
    }

    #[test]
    fn matches_filename_candidates() {
        use std::path::PathBuf;
        assert!(matches(&PathBuf::from("/x/ClipboardHistory.db")));
        assert!(matches(&PathBuf::from("/y/pboard.db")));
        assert!(!matches(&PathBuf::from("/z/unrelated.sqlite")));
    }

    #[test]
    fn parses_synthetic_entry_from_in_memory_db() {
        let c = Connection::open_in_memory().expect("open");
        c.execute_batch(
            "CREATE TABLE clipboard_entries (\
                timestamp INTEGER,\
                content_type TEXT,\
                content_text TEXT,\
                source_app TEXT,\
                source_context TEXT,\
                size INTEGER);",
        )
        .expect("schema");
        c.execute(
            "INSERT INTO clipboard_entries VALUES (1700000000, 'Text', 'AKIAEXAMPLE', 'Notes', 'note-1', 12)",
            [],
        )
        .expect("ins");
        let entries = parse_conn(&c);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].content_type, "Text");
        assert!(entries[0].sensitive_detected);
        assert_eq!(entries[0].source_app.as_deref(), Some("Notes"));
    }
}
