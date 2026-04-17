//! Telegram Desktop artifact parser (PULSE-12).
//!
//! Opportunistic extraction from `tdata/` — we do not attempt to
//! decrypt TDF blobs. Recovers phone numbers and message fragments
//! from plaintext dumps, detects local-passcode presence via
//! `key_data` / `key_datas`.
//!
//! MITRE: T1552.003, T1636.002.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use regex::Regex;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelegramArtifact {
    pub artifact_type: String,
    pub phone_number: Option<String>,
    pub username: Option<String>,
    pub local_passcode_set: bool,
    pub message_fragments: Vec<String>,
    pub media_cache_count: Option<u64>,
    pub tdata_path: String,
    pub timestamp: Option<DateTime<Utc>>,
}

pub fn is_tdata_path(path: &Path) -> bool {
    let lower = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    lower.contains("telegram desktop/tdata/")
}

pub fn passcode_state(tdata_dir: &Path) -> Option<bool> {
    let has_key_data = tdata_dir.join("key_data").exists();
    let has_key_datas = tdata_dir.join("key_datas").exists();
    if has_key_datas {
        Some(true)
    } else if has_key_data {
        Some(false)
    } else {
        None
    }
}

pub fn scan_dumps(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(s) = std::str::from_utf8(bytes) {
        for word in s.split(|c: char| c.is_control()) {
            let t = word.trim();
            if t.len() >= 10 && t.len() <= 512 && t.chars().any(|c| c.is_ascii_alphabetic()) {
                out.push(t.to_string());
            }
            if out.len() >= 256 {
                break;
            }
        }
    }
    out
}

pub fn scan_settings_s(bytes: &[u8]) -> (Option<String>, Option<String>) {
    let mut phone = None;
    let mut username = None;
    if let Ok(s) = std::str::from_utf8(bytes) {
        if let Ok(re) = Regex::new(r"\+[0-9]{7,15}") {
            if let Some(m) = re.find(s) {
                phone = Some(m.as_str().to_string());
            }
        }
        if let Ok(re) = Regex::new(r"@[a-zA-Z][a-zA-Z0-9_]{4,31}") {
            if let Some(m) = re.find(s) {
                username = Some(m.as_str().to_string());
            }
        }
    }
    (phone, username)
}

pub fn parse(path: &Path) -> Option<TelegramArtifact> {
    if !is_tdata_path(path) {
        return None;
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let parent = path.parent().map(|p| p.to_path_buf()).unwrap_or_default();
    let local_passcode_set = passcode_state(&parent).unwrap_or(false);
    let mut art = TelegramArtifact {
        artifact_type: "Telegram Desktop".to_string(),
        phone_number: None,
        username: None,
        local_passcode_set,
        message_fragments: Vec::new(),
        media_cache_count: None,
        tdata_path: parent.to_string_lossy().to_string(),
        timestamp: None,
    };
    if name == "s" {
        if let Ok(body) = fs::read(path) {
            let (phone, user) = scan_settings_s(&body);
            art.phone_number = phone;
            art.username = user;
        }
    } else if name.starts_with("dump") || name.ends_with(".dmp") {
        if let Ok(body) = fs::read(path) {
            art.message_fragments = scan_dumps(&body);
        }
    }
    Some(art)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_tdata_path_matches_telegram_desktop_layout() {
        assert!(is_tdata_path(Path::new(
            "C:\\Users\\a\\AppData\\Roaming\\Telegram Desktop\\tdata\\key_data"
        )));
        assert!(!is_tdata_path(Path::new("/tmp/other/key_data")));
    }

    #[test]
    fn passcode_state_detects_key_data_variants() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("key_data"), b"").expect("w");
        assert_eq!(passcode_state(dir.path()), Some(false));
        std::fs::write(dir.path().join("key_datas"), b"").expect("w");
        assert_eq!(passcode_state(dir.path()), Some(true));
    }

    #[test]
    fn scan_settings_s_recovers_phone_and_username() {
        let body = b"garbage +15551234567 stuff @alice_username more";
        let (p, u) = scan_settings_s(body);
        assert_eq!(p.as_deref(), Some("+15551234567"));
        assert_eq!(u.as_deref(), Some("@alice_username"));
    }

    #[test]
    fn parse_returns_some_for_tdata_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tdata = dir.path().join("Telegram Desktop").join("tdata");
        std::fs::create_dir_all(&tdata).expect("mkdirs");
        let path = tdata.join("s");
        std::fs::write(&path, b"+15551234567 @bob").expect("w");
        let out = parse(&path).expect("some");
        assert_eq!(out.phone_number.as_deref(), Some("+15551234567"));
    }

    #[test]
    fn parse_returns_none_for_non_tdata_path() {
        assert!(parse(Path::new("/tmp/random")).is_none());
    }
}
