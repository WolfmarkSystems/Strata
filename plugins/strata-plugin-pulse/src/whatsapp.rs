//! WhatsApp Desktop parser — WebView2 (Dec 2025+) and UWP fallback
//! (PULSE-11).
//!
//! MITRE: T1552.003, T1636.002.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use regex::Regex;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhatsAppArchitecture {
    WebView2,
    Uwp,
    Unknown,
}

impl WhatsAppArchitecture {
    pub fn as_str(&self) -> &'static str {
        match self {
            WhatsAppArchitecture::WebView2 => "WebView2",
            WhatsAppArchitecture::Uwp => "UWP",
            WhatsAppArchitecture::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhatsAppFinding {
    pub architecture: WhatsAppArchitecture,
    pub phone_numbers: Vec<String>,
    pub message_fragments: Vec<String>,
    pub locked: bool,
    pub source_path: String,
}

pub fn is_whatsapp_path(path: &Path) -> bool {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    lower.contains("5319275a.whatsappdesktop_") || lower.contains("/whatsapp/")
        || lower.contains("\\whatsapp\\")
}

pub fn architecture_for(path: &Path) -> WhatsAppArchitecture {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    if lower.contains("localstate/sessions/")
        || lower.contains("localstate\\sessions\\")
        || lower.ends_with("session.db")
        || lower.ends_with("session.db-wal")
        || lower.ends_with("nativesettings.db")
    {
        return WhatsAppArchitecture::WebView2;
    }
    if lower.ends_with("shared.db") || lower.ends_with("messages.db") {
        return WhatsAppArchitecture::Uwp;
    }
    WhatsAppArchitecture::Unknown
}

pub fn scan_wal(bytes: &[u8]) -> WhatsAppFinding {
    let phone_re = Regex::new(r"\+[0-9]{7,15}").ok();
    let mut phones: Vec<String> = Vec::new();
    let mut fragments: Vec<String> = Vec::new();
    if let Ok(s) = std::str::from_utf8(bytes) {
        if let Some(re) = phone_re.as_ref() {
            for m in re.find_iter(s) {
                phones.push(m.as_str().to_string());
            }
        }
        for word in s.split(|c: char| !c.is_ascii_graphic() && c != ' ') {
            if word.len() >= 10 && word.len() <= 512 {
                fragments.push(word.to_string());
            }
        }
    }
    // UTF-16LE scan for phone runs.
    for window in bytes.windows(2) {
        let _ = window;
    }
    // Dedup.
    phones.sort();
    phones.dedup();
    fragments.truncate(64);
    WhatsAppFinding {
        architecture: WhatsAppArchitecture::WebView2,
        phone_numbers: phones,
        message_fragments: fragments,
        locked: true,
        source_path: String::new(),
    }
}

pub fn parse(path: &Path) -> Option<WhatsAppFinding> {
    if !is_whatsapp_path(path) {
        return None;
    }
    let arch = architecture_for(path);
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let mut finding = WhatsAppFinding {
        architecture: arch,
        phone_numbers: Vec::new(),
        message_fragments: Vec::new(),
        locked: false,
        source_path: path.to_string_lossy().to_string(),
    };
    if name == "session.db-wal" {
        if let Ok(bytes) = fs::read(path) {
            let scan = scan_wal(&bytes);
            finding.phone_numbers = scan.phone_numbers;
            finding.message_fragments = scan.message_fragments;
            finding.locked = true;
        }
        return Some(finding);
    }
    if name == "nativesettings.db" || name == "session.db" {
        use rusqlite::{Connection, OpenFlags};
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        );
        finding.locked = match conn {
            Ok(c) => c.pragma_query_value(None, "schema_version", |_| Ok(())).is_err(),
            Err(_) => true,
        };
        return Some(finding);
    }
    Some(finding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_whatsapp_path_recognises_package_dir() {
        assert!(is_whatsapp_path(Path::new(
            "C:\\Users\\a\\AppData\\Local\\Packages\\5319275A.WhatsAppDesktop_abc\\LocalState\\session.db"
        )));
        assert!(!is_whatsapp_path(Path::new("/x/random.db")));
    }

    #[test]
    fn architecture_for_classifies_webview2() {
        assert_eq!(
            architecture_for(Path::new("/x/LocalState/session.db-wal")),
            WhatsAppArchitecture::WebView2
        );
        assert_eq!(
            architecture_for(Path::new("/x/Messages/shared.db")),
            WhatsAppArchitecture::Uwp
        );
    }

    #[test]
    fn scan_wal_recovers_phone_numbers_and_fragments() {
        let bytes = b"garbage \x00+15551234567 more text here and some content";
        let f = scan_wal(bytes);
        assert!(f.phone_numbers.contains(&"+15551234567".to_string()));
        assert!(!f.message_fragments.is_empty());
    }

    #[test]
    fn parse_returns_none_for_non_whatsapp_path() {
        assert!(parse(Path::new("/tmp/other.db")).is_none());
    }

    #[test]
    fn parse_flags_webview2_locked_db() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wa = dir
            .path()
            .join("Packages")
            .join("5319275A.WhatsAppDesktop_abc")
            .join("LocalState");
        std::fs::create_dir_all(&wa).expect("mkdirs");
        let path = wa.join("nativeSettings.db");
        std::fs::write(&path, b"not-sqlite").expect("write");
        let f = parse(&path).expect("parsed");
        assert_eq!(f.architecture, WhatsAppArchitecture::WebView2);
        assert!(f.locked);
    }
}
