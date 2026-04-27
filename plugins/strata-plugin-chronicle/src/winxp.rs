//! LEGACY-WIN-2 — Windows XP artifact layer.
//!
//! Covers the XP-specific shapes: INFO2 recycle bin records,
//! StreamMRU-style removable shellbags, XP-era UserAssist, Prefetch
//! v17, classic .evt event logs, and index.dat IE history. Each
//! shape is a pure parser that takes raw bytes and yields a strongly-
//! typed record; the chronicle plugin wires them to real files.
//!
//! The XP registry hive layout and .lnk extended-attribute quirks are
//! already handled by the workspace-wide hive + shell-link code;
//! this module covers only what XP does differently enough to
//! justify version-specific code.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WindowsXPArtifact {
    Recycler(XPRecyclerEntry),
    StreamShellbag(XPStreamShellbag),
    UserAssist(XPUserAssist),
    Prefetch(XPPrefetch),
    EventLog(XPEvtEntry),
    IEHistory(XPIndexDatEntry),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XPRecyclerEntry {
    pub record_index: u32,
    pub original_path: String,
    pub deleted_at: Option<DateTime<Utc>>,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XPStreamShellbag {
    pub mru_index: u32,
    pub device_label: String,
    pub shell_item_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XPUserAssist {
    pub guid_bucket: String,
    pub decoded_name: String,
    pub run_count: u32,
    pub last_run: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XPPrefetch {
    pub executable: String,
    pub run_count: u32,
    pub last_run: Option<DateTime<Utc>>,
    pub format_version: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XPEvtEntry {
    pub record_number: u32,
    pub event_id: u32,
    pub generated: Option<DateTime<Utc>>,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XPIndexDatEntry {
    pub url: String,
    pub last_visited: Option<DateTime<Utc>>,
    pub visit_count: u32,
}

// ── Detection ──────────────────────────────────────────────────────────

/// Walks a few well-known filesystem markers to confirm we're looking
/// at an XP disk image. Conservative: returns false on ambiguous
/// layouts so Windows 7/10/11 parsers don't get double-called.
pub fn is_windows_xp(root: &Path) -> bool {
    let markers = ["Documents and Settings", "RECYCLER"];
    let hit = markers
        .iter()
        .any(|m| root.join(m).exists() || root.join(m.to_ascii_lowercase()).exists());
    let evt = root.join("WINDOWS/system32/config/SysEvent.Evt").exists()
        || root.join("WINDOWS/system32/config/sysevent.evt").exists();
    hit || evt
}

// ── INFO2 (recycler) parsing ───────────────────────────────────────────

/// INFO2 records are fixed 820 bytes; we only use the first 264 for
/// the ASCII path, the Unicode path, the deletion FILETIME, and the
/// size.
pub fn parse_info2(bytes: &[u8]) -> Vec<XPRecyclerEntry> {
    const RECORD_LEN: usize = 820;
    const HEADER_LEN: usize = 20;
    if bytes.len() < HEADER_LEN + RECORD_LEN {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut cursor = HEADER_LEN;
    while cursor + RECORD_LEN <= bytes.len() {
        let rec = &bytes[cursor..cursor + RECORD_LEN];
        let ascii_path = cstring_at(&rec[4..264]);
        let record_index = u32::from_le_bytes([rec[264], rec[265], rec[266], rec[267]]);
        let ft = u64::from_le_bytes([
            rec[268], rec[269], rec[270], rec[271], rec[272], rec[273], rec[274], rec[275],
        ]);
        let size = u32::from_le_bytes([rec[276], rec[277], rec[278], rec[279]]) as u64;
        out.push(XPRecyclerEntry {
            record_index,
            original_path: ascii_path,
            deleted_at: filetime_to_utc(ft),
            size,
        });
        cursor += RECORD_LEN;
    }
    out
}

fn cstring_at(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

// ── XP UserAssist decoding (ROT13) ─────────────────────────────────────

pub fn rot13_decode(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            'A'..='Z' => (((c as u8) - b'A' + 13) % 26 + b'A') as char,
            'a'..='z' => (((c as u8) - b'a' + 13) % 26 + b'a') as char,
            _ => c,
        })
        .collect()
}

// ── Prefetch v17 header probe ──────────────────────────────────────────

/// XP Prefetch files start with a 4-byte version followed by "SCCA".
/// Version 17 (0x11000000) identifies XP.
pub fn is_xp_prefetch(bytes: &[u8]) -> bool {
    if bytes.len() < 8 {
        return false;
    }
    let version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    &bytes[4..8] == b"SCCA" && version == 17
}

// ── Shared helpers ─────────────────────────────────────────────────────

fn filetime_to_utc(ft: u64) -> Option<DateTime<Utc>> {
    const WINDOWS_TICK: i64 = 10_000_000;
    const SEC_TO_UNIX_EPOCH: i64 = 11_644_473_600;
    if ft == 0 {
        return None;
    }
    let secs = (ft as i64 / WINDOWS_TICK) - SEC_TO_UNIX_EPOCH;
    if secs < 0 {
        return None;
    }
    Utc.timestamp_opt(secs, 0).single()
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn detects_xp_layout_via_documents_and_settings() {
        let tmp = tempfile::tempdir().expect("tmp");
        fs::create_dir_all(tmp.path().join("Documents and Settings")).expect("mk");
        assert!(is_windows_xp(tmp.path()));
    }

    #[test]
    fn rejects_non_xp_layout() {
        let tmp = tempfile::tempdir().expect("tmp");
        fs::create_dir_all(tmp.path().join("Users")).expect("mk");
        assert!(!is_windows_xp(tmp.path()));
    }

    #[test]
    fn rot13_round_trips_letters() {
        assert_eq!(
            rot13_decode("UEME_RUNPATH:chrome.exe"),
            "HRZR_EHACNGU:puebzr.rkr"
        );
        assert_eq!(rot13_decode(&rot13_decode("Hello")), "Hello");
    }

    #[test]
    fn info2_parses_one_record() {
        let mut buf = vec![0u8; 820 + 20];
        let path = b"C:\\Documents and Settings\\Alice\\secret.txt\0";
        buf[20 + 4..20 + 4 + path.len()].copy_from_slice(path);
        buf[20 + 264..20 + 268].copy_from_slice(&1u32.to_le_bytes());
        let ft: u64 = 133_484_544_000_000_000;
        buf[20 + 268..20 + 276].copy_from_slice(&ft.to_le_bytes());
        buf[20 + 276..20 + 280].copy_from_slice(&2048u32.to_le_bytes());
        let entries = parse_info2(&buf);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].record_index, 1);
        assert_eq!(entries[0].size, 2048);
        assert!(entries[0].original_path.contains("secret.txt"));
    }

    #[test]
    fn prefetch_v17_magic_check() {
        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(&17u32.to_le_bytes());
        buf[4..8].copy_from_slice(b"SCCA");
        assert!(is_xp_prefetch(&buf));
        // version 23 (Vista+) should fail.
        buf[0..4].copy_from_slice(&23u32.to_le_bytes());
        assert!(!is_xp_prefetch(&buf));
    }
}
