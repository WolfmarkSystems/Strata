//! Outlook PST/OST string-carving fallback (W-12).
//!
//! Full PST parsing (NDB + messages) requires a libpff binding which is
//! not available in the workspace. Per the sprint spec's fallback path,
//! this module validates the `!BDN` magic, then carves email addresses
//! and common subject-line prefixes from the file's UTF-16LE content
//! for examiner triage.
//!
//! The carved data is annotated as `PST String Carve` so downstream
//! consumers understand the coverage limitation.
//!
//! MITRE: T1114 (email collection), T1530.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use std::path::Path;

const PST_MAGIC: &[u8; 4] = b"!BDN";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutlookMessage {
    pub subject: String,
    pub sender_name: Option<String>,
    pub sender_email: Option<String>,
    pub recipients: Vec<String>,
    pub sent_time: Option<DateTime<Utc>>,
    pub received_time: Option<DateTime<Utc>>,
    pub has_attachments: bool,
    pub attachment_names: Vec<String>,
    pub folder_path: String,
    pub message_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PstCarveHit {
    pub kind: &'static str,
    pub value: String,
    pub offset: u64,
}

/// True if `bytes` carries the PST/OST file magic.
pub fn has_pst_magic(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && &bytes[..4] == PST_MAGIC
}

/// Carve email-shaped UTF-16LE runs and obvious subject strings.
pub fn carve(bytes: &[u8]) -> Vec<PstCarveHit> {
    if !has_pst_magic(bytes) {
        return Vec::new();
    }
    let utf8_runs = extract_utf16le_strings(bytes, 5);
    let mut out = Vec::new();
    for (offset, s) in utf8_runs {
        if looks_like_email(&s) {
            out.push(PstCarveHit {
                kind: "email",
                value: s,
                offset,
            });
        } else if looks_like_subject(&s) {
            out.push(PstCarveHit {
                kind: "subject",
                value: s,
                offset,
            });
        }
        if out.len() >= 50_000 {
            break;
        }
    }
    out
}

/// UTF-16LE printable-ASCII run extractor. Returns each run's byte
/// offset and decoded string.
fn extract_utf16le_strings(bytes: &[u8], min_chars: usize) -> Vec<(u64, String)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 2 <= bytes.len() {
        let start = i;
        let mut run: Vec<u8> = Vec::new();
        while i + 2 <= bytes.len() {
            let lo = bytes[i];
            let hi = bytes[i + 1];
            if hi != 0x00 || !(0x20..=0x7E).contains(&lo) {
                break;
            }
            run.push(lo);
            i += 2;
        }
        if run.len() >= min_chars {
            if let Ok(s) = std::str::from_utf8(&run) {
                out.push((start as u64, s.to_string()));
            }
        }
        if i == start {
            i += 2;
        }
    }
    out
}

fn looks_like_email(s: &str) -> bool {
    if !s.contains('@') {
        return false;
    }
    let Some((local, domain)) = s.rsplit_once('@') else {
        return false;
    };
    if local.is_empty() || !domain.contains('.') {
        return false;
    }
    local.chars().all(|c| c.is_ascii_graphic())
        && domain.chars().all(|c| c.is_ascii_graphic())
}

fn looks_like_subject(s: &str) -> bool {
    let lc = s.to_ascii_lowercase();
    (lc.starts_with("re:") || lc.starts_with("fwd:") || lc.starts_with("fw:"))
        && s.len() >= 6
        && s.len() < 256
}

pub fn is_outlook_path(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    name.ends_with(".pst") || name.ends_with(".ost")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le(s: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for u in s.encode_utf16() {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out
    }

    #[test]
    fn has_pst_magic_check() {
        assert!(has_pst_magic(b"!BDNxxxxxx"));
        assert!(!has_pst_magic(b"XXXXBDN"));
        assert!(!has_pst_magic(b""));
    }

    #[test]
    fn carve_returns_empty_on_non_pst() {
        assert!(carve(b"notapst").is_empty());
    }

    #[test]
    fn carve_extracts_emails_and_subjects() {
        let mut blob = Vec::new();
        blob.extend_from_slice(PST_MAGIC);
        blob.extend_from_slice(&[0u8; 128]);
        blob.extend_from_slice(&utf16le("alice@example.com"));
        blob.extend_from_slice(&[0u8; 8]);
        blob.extend_from_slice(&utf16le("RE: Quarterly Review"));
        blob.extend_from_slice(&[0u8; 8]);
        blob.extend_from_slice(&utf16le("garbage not email"));
        let hits = carve(&blob);
        assert!(hits.iter().any(|h| h.kind == "email" && h.value == "alice@example.com"));
        assert!(hits.iter().any(|h| h.kind == "subject" && h.value.starts_with("RE:")));
    }

    #[test]
    fn is_outlook_path_accepts_both_extensions() {
        assert!(is_outlook_path(Path::new("/a/archive.pst")));
        assert!(is_outlook_path(Path::new("/b/mail.OST")));
        assert!(!is_outlook_path(Path::new("/c/notes.txt")));
    }

    #[test]
    fn looks_like_email_rejects_invalid_shapes() {
        assert!(looks_like_email("alice@example.com"));
        assert!(!looks_like_email("@example.com"));
        assert!(!looks_like_email("no-at-sign"));
        assert!(!looks_like_email("alice@nodot"));
    }
}
