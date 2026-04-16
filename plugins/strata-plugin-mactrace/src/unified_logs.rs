//! Apple Unified Logging parser — `.tracev3` indicator extractor.
//!
//! The Unified Logging System (ULS) stores log records in binary
//! `.tracev3` files under `/private/var/db/diagnostics/` (and
//! `/private/var/db/uuidtext/` for the string-resolution side tables).
//! Full decoding requires chunkset inflation (LZ4), firehose preamble
//! parsing, UUID-text resolution, and format-string reconstruction —
//! out of scope for this crate.
//!
//! ## Crate evaluation — `macos-unifiedlogs`
//! Mandiant's `macos-unifiedlogs` crate is **not** present in our
//! workspace and is not available to us here. Per CLAUDE.md
//! ("No unnecessary dependencies") we do not add a new heavy crate
//! on speculation. This module therefore implements the documented
//! fallback path — a minimal indicator-level reader.
//!
//! ## What this reader does
//! 1. Validates the file opens as a tracev3 chunkset (first chunk tag
//!    `0x00001000`).
//! 2. Extracts printable-ASCII runs from the raw bytes.
//! 3. Emits one [`UnifiedLogEntry`] per forensically-significant
//!    process or subsystem token discovered (`sudo`, `SecurityAgent`,
//!    `sshd`, `screensharingd`, `com.apple.securityd`,
//!    `com.apple.ManagedClient`, or the literal `authentication`).
//! 4. Uses the file's mtime as the entry timestamp so the artifact can
//!    be timelined, acknowledging that per-record times are not
//!    recoverable without a full tracev3 decoder.
//!
//! This is deliberately conservative: callers get coverage for the
//! high-value signals listed in SPRINT M-5 without the risk of a
//! half-implemented binary decoder producing wrong data.
//!
//! ## MITRE ATT&CK
//! * **T1548.003** — `sudo` invocations (Sudo and Sudo Caching).
//! * **T1078** — `SecurityAgent`, `com.apple.securityd`, and any
//!   `authentication` message (Valid Accounts).
//! * **T1021.004** — `sshd` (Remote Services: SSH).
//! * **T1021.005** — `screensharingd` (Remote Services: VNC).
//! * **T1072** — `com.apple.ManagedClient` (Remote Services: MDM).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use std::path::Path;

/// First-chunk tag value for a valid tracev3 file. Chunkset header
/// chunks start with this little-endian `u32`.
const TRACEV3_FIRST_CHUNK_TAG: [u8; 4] = [0x00, 0x10, 0x00, 0x00];

/// Minimum run length for a printable-ASCII token to be considered a
/// candidate indicator. Short runs produce too many false positives
/// (padding bytes that happen to land in the printable range).
const MIN_TOKEN_RUN: usize = 4;

/// Hard cap on entries emitted from a single tracev3 file.
const MAX_ENTRIES: usize = 10_000;

/// One log entry surfaced by the indicator reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnifiedLogEntry {
    /// Event timestamp in UTC. With the indicator reader this is the
    /// tracev3 file's mtime (best available approximation); a full
    /// decoder would populate per-record firehose timestamps.
    pub timestamp: DateTime<Utc>,
    /// Process name that generated the log (for example `"sudo"`,
    /// `"sshd"`).
    pub process: String,
    /// Process ID. `0` when not recoverable — the indicator reader
    /// cannot decode firehose PID tags, so all entries carry `0`
    /// unless a caller constructs the entry manually.
    pub pid: u32,
    /// Apple subsystem identifier (for example
    /// `"com.apple.securityd"`). `None` when the entry was indexed by
    /// process name rather than subsystem token.
    pub subsystem: Option<String>,
    /// Log category within the subsystem. `None` with the indicator
    /// reader; populated by callers that construct entries manually.
    pub category: Option<String>,
    /// Human-readable log message. With the indicator reader this is
    /// a synthetic "presence" message naming the token found.
    pub message: String,
    /// Log level string — one of `"Default"`, `"Info"`, `"Debug"`,
    /// `"Error"`, or `"Fault"`.
    pub log_level: String,
}

impl UnifiedLogEntry {
    /// True if this entry represents a forensically high-value signal
    /// per SPRINT M-5 (sudo, auth, remote access, MDM). Used by the
    /// MacTrace plugin to avoid emitting one artifact per log line.
    pub fn is_forensically_significant(&self) -> bool {
        match_significance(&self.process, self.subsystem.as_deref(), &self.message).is_some()
    }

    /// MITRE ATT&CK technique ID for this entry. Falls back to
    /// `"T1005"` (Data from Local System) for entries that reach this
    /// parser but don't map to a specific sub-technique.
    pub fn mitre_technique(&self) -> &'static str {
        match_significance(&self.process, self.subsystem.as_deref(), &self.message)
            .map(|s| s.mitre)
            .unwrap_or("T1005")
    }

    /// Forensic value tier (`"High"` or `"Medium"`). Privilege /
    /// authentication / remote-access signals are `"High"`; anything
    /// else routed through this module is `"Medium"`.
    pub fn forensic_value(&self) -> &'static str {
        match_significance(&self.process, self.subsystem.as_deref(), &self.message)
            .map(|s| s.severity)
            .unwrap_or("Medium")
    }
}

/// Per-token significance metadata.
struct Significance {
    mitre: &'static str,
    severity: &'static str,
    label: &'static str,
}

fn match_significance(
    process: &str,
    subsystem: Option<&str>,
    message: &str,
) -> Option<Significance> {
    // Process-name matches first — most specific.
    match process {
        "sudo" => {
            return Some(Significance {
                mitre: "T1548.003",
                severity: "High",
                label: "sudo",
            });
        }
        "SecurityAgent" => {
            return Some(Significance {
                mitre: "T1078",
                severity: "High",
                label: "SecurityAgent",
            });
        }
        "sshd" => {
            return Some(Significance {
                mitre: "T1021.004",
                severity: "High",
                label: "sshd",
            });
        }
        "screensharingd" => {
            return Some(Significance {
                mitre: "T1021.005",
                severity: "High",
                label: "screensharingd",
            });
        }
        _ => {}
    }
    match subsystem {
        Some("com.apple.securityd") => {
            return Some(Significance {
                mitre: "T1078",
                severity: "High",
                label: "com.apple.securityd",
            });
        }
        Some("com.apple.ManagedClient") => {
            return Some(Significance {
                mitre: "T1072",
                severity: "High",
                label: "com.apple.ManagedClient",
            });
        }
        _ => {}
    }
    if message.to_ascii_lowercase().contains("authentication") {
        return Some(Significance {
            mitre: "T1078",
            severity: "High",
            label: "authentication",
        });
    }
    None
}

/// Parse a tracev3 file's raw bytes and return every forensically
/// significant indicator entry found. Empty vec on magic mismatch,
/// truncated input, or absence of known tokens. Never panics.
pub fn parse(path: &Path, bytes: &[u8]) -> Vec<UnifiedLogEntry> {
    if !has_tracev3_magic(bytes) {
        return Vec::new();
    }
    let timestamp =
        mtime_of(path).unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).unwrap_or_default());
    let tokens = extract_ascii_tokens(bytes);
    let mut seen: Vec<(&'static str, bool)> = Vec::new();
    let mut out = Vec::new();
    for token in &tokens {
        if out.len() >= MAX_ENTRIES {
            break;
        }
        let entry = classify_token(token, timestamp);
        if let Some(entry) = entry {
            let key = significance_label(&entry);
            let is_subsystem = entry.subsystem.is_some();
            if seen
                .iter()
                .any(|(k, sub)| *k == key && *sub == is_subsystem)
            {
                continue;
            }
            seen.push((key, is_subsystem));
            out.push(entry);
        }
    }
    out
}

fn significance_label(entry: &UnifiedLogEntry) -> &'static str {
    match_significance(&entry.process, entry.subsystem.as_deref(), &entry.message)
        .map(|s| s.label)
        .unwrap_or("unknown")
}

/// True when the first chunk tag matches the tracev3 format.
fn has_tracev3_magic(bytes: &[u8]) -> bool {
    bytes.len() >= TRACEV3_FIRST_CHUNK_TAG.len()
        && bytes[..TRACEV3_FIRST_CHUNK_TAG.len()] == TRACEV3_FIRST_CHUNK_TAG
}

fn mtime_of(path: &Path) -> Option<DateTime<Utc>> {
    let meta = std::fs::metadata(path).ok()?;
    let sys = meta.modified().ok()?;
    Some(sys.into())
}

/// Extract printable-ASCII runs of at least [`MIN_TOKEN_RUN`] bytes.
fn extract_ascii_tokens(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    for &b in bytes {
        if (0x20..0x7F).contains(&b) {
            current.push(b);
        } else {
            if current.len() >= MIN_TOKEN_RUN {
                if let Ok(s) = std::str::from_utf8(&current) {
                    out.push(s.to_string());
                }
            }
            current.clear();
        }
    }
    if current.len() >= MIN_TOKEN_RUN {
        if let Ok(s) = std::str::from_utf8(&current) {
            out.push(s.to_string());
        }
    }
    out
}

fn classify_token(token: &str, timestamp: DateTime<Utc>) -> Option<UnifiedLogEntry> {
    for proc in ["sudo", "SecurityAgent", "sshd", "screensharingd"] {
        if token_contains_word(token, proc) {
            return Some(UnifiedLogEntry {
                timestamp,
                process: proc.to_string(),
                pid: 0,
                subsystem: None,
                category: None,
                message: format!("Indicator: process token '{}' present in tracev3", proc),
                log_level: "Default".to_string(),
            });
        }
    }
    for sub in ["com.apple.securityd", "com.apple.ManagedClient"] {
        if token.contains(sub) {
            return Some(UnifiedLogEntry {
                timestamp,
                process: "<unresolved>".to_string(),
                pid: 0,
                subsystem: Some(sub.to_string()),
                category: None,
                message: format!("Indicator: subsystem '{}' present in tracev3", sub),
                log_level: "Default".to_string(),
            });
        }
    }
    if token.to_ascii_lowercase().contains("authentication") {
        return Some(UnifiedLogEntry {
            timestamp,
            process: "<unresolved>".to_string(),
            pid: 0,
            subsystem: None,
            category: None,
            message: "Indicator: 'authentication' keyword present in tracev3".to_string(),
            log_level: "Default".to_string(),
        });
    }
    None
}

/// Word-boundary check: returns true when `needle` appears in `haystack`
/// surrounded by characters outside the identifier class
/// `[A-Za-z0-9._-]`. Prevents `"sudo"` matching inside `"pseudonym"`
/// or `"sshd"` matching `"xsshdy"`.
fn token_contains_word(haystack: &str, needle: &str) -> bool {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || h.len() < n.len() {
        return false;
    }
    for i in 0..=(h.len() - n.len()) {
        if h[i..i + n.len()] != *n {
            continue;
        }
        let left_ok = i == 0 || !is_ident_byte(h[i - 1]);
        let right_idx = i + n.len();
        let right_ok = right_idx == h.len() || !is_ident_byte(h[right_idx]);
        if left_ok && right_ok {
            return true;
        }
    }
    false
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-'
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_tracev3(payload: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(&TRACEV3_FIRST_CHUNK_TAG).expect("write magic");
        // Minimal plausible header remainder (subtag, reserved, length).
        f.write_all(&[0x11, 0x00, 0x00, 0x00]).expect("subtag");
        f.write_all(&[0x00; 8]).expect("length");
        f.write_all(payload).expect("payload");
        f
    }

    #[test]
    fn parse_returns_empty_on_wrong_magic() {
        let blob = vec![0xFFu8; 64];
        let f = NamedTempFile::new().expect("tempfile");
        assert!(parse(f.path(), &blob).is_empty());
    }

    #[test]
    fn parse_returns_empty_on_truncated_file() {
        let blob = vec![0x00u8; 2];
        let f = NamedTempFile::new().expect("tempfile");
        assert!(parse(f.path(), &blob).is_empty());
    }

    #[test]
    fn parse_surfaces_sudo_and_sshd_indicators() {
        let body = b"\x00 sudo session opened for root \x00 /usr/sbin/sshd listening \x00";
        let f = write_tracev3(body);
        let bytes = std::fs::read(f.path()).expect("read");
        let entries = parse(f.path(), &bytes);
        assert!(entries.iter().any(|e| e.process == "sudo"));
        assert!(entries.iter().any(|e| e.process == "sshd"));
        for e in &entries {
            assert!(e.is_forensically_significant());
        }
    }

    #[test]
    fn parse_surfaces_subsystem_and_authentication_tokens() {
        let body = b"\x00 com.apple.ManagedClient pushed policy \x00 \
                     com.apple.securityd evaluated trust \x00 \
                     failed authentication for user \x00";
        let f = write_tracev3(body);
        let bytes = std::fs::read(f.path()).expect("read");
        let entries = parse(f.path(), &bytes);
        assert!(entries
            .iter()
            .any(|e| e.subsystem.as_deref() == Some("com.apple.ManagedClient")));
        assert!(entries
            .iter()
            .any(|e| e.subsystem.as_deref() == Some("com.apple.securityd")));
        assert!(entries
            .iter()
            .any(|e| e.message.contains("'authentication'")));
    }

    #[test]
    fn parse_deduplicates_repeated_process_tokens() {
        let body = b"\x00 sudo A \x00 sudo B \x00 sudo C \x00";
        let f = write_tracev3(body);
        let bytes = std::fs::read(f.path()).expect("read");
        let entries = parse(f.path(), &bytes);
        assert_eq!(
            entries.iter().filter(|e| e.process == "sudo").count(),
            1,
            "expected a single deduplicated sudo indicator"
        );
    }

    #[test]
    fn parse_ignores_substring_false_positives() {
        // "pseudonym" contains "sudo" as a substring; the word-boundary
        // check must reject it. "xsshdy" likewise must not match sshd.
        let body = b"\x00 pseudonym exchange \x00 xsshdy things \x00";
        let f = write_tracev3(body);
        let bytes = std::fs::read(f.path()).expect("read");
        let entries = parse(f.path(), &bytes);
        assert!(entries.is_empty(), "got unexpected entries: {:?}", entries);
    }

    #[test]
    fn mitre_and_severity_map_per_category() {
        let ts = DateTime::<Utc>::from_timestamp(1_717_243_200, 0).expect("ts");
        let sudo = UnifiedLogEntry {
            timestamp: ts,
            process: "sudo".to_string(),
            pid: 501,
            subsystem: None,
            category: None,
            message: "sudo: session opened".to_string(),
            log_level: "Default".to_string(),
        };
        assert!(sudo.is_forensically_significant());
        assert_eq!(sudo.mitre_technique(), "T1548.003");
        assert_eq!(sudo.forensic_value(), "High");

        let ssh = UnifiedLogEntry {
            timestamp: ts,
            process: "sshd".to_string(),
            pid: 0,
            subsystem: None,
            category: None,
            message: "accepted publickey".to_string(),
            log_level: "Default".to_string(),
        };
        assert_eq!(ssh.mitre_technique(), "T1021.004");

        let screen = UnifiedLogEntry {
            timestamp: ts,
            process: "screensharingd".to_string(),
            pid: 0,
            subsystem: None,
            category: None,
            message: "client connected".to_string(),
            log_level: "Default".to_string(),
        };
        assert_eq!(screen.mitre_technique(), "T1021.005");

        let auth = UnifiedLogEntry {
            timestamp: ts,
            process: "loginwindow".to_string(),
            pid: 0,
            subsystem: None,
            category: None,
            message: "failed authentication attempt".to_string(),
            log_level: "Default".to_string(),
        };
        assert!(auth.is_forensically_significant());
        assert_eq!(auth.mitre_technique(), "T1078");

        let noise = UnifiedLogEntry {
            timestamp: ts,
            process: "WindowServer".to_string(),
            pid: 0,
            subsystem: None,
            category: None,
            message: "vsync".to_string(),
            log_level: "Default".to_string(),
        };
        assert!(!noise.is_forensically_significant());
        assert_eq!(noise.mitre_technique(), "T1005");
        assert_eq!(noise.forensic_value(), "Medium");
    }

    #[test]
    fn token_word_boundary_matches_edges_but_not_substrings() {
        assert!(token_contains_word("sudo session opened", "sudo"));
        assert!(token_contains_word("ran sudo", "sudo"));
        assert!(token_contains_word("/usr/sbin/sshd", "sshd"));
        assert!(!token_contains_word("pseudonym", "sudo"));
        assert!(!token_contains_word("xsshdy", "sshd"));
    }
}
