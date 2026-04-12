//! iOS Universal Clipboard — `com.apple.UIKit.pboard/`.
//!
//! When Handoff is enabled, clipboard contents sync between devices.
//! May contain copied passwords, addresses, phone numbers, or text
//! from secure messaging apps.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::path_contains(path, "uipasteboard") || util::path_contains(path, "pboard")
        && {
            let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
            n.ends_with(".db") || n.ends_with(".plist")
        }
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 { return Vec::new(); }
    let source = path.to_string_lossy().to_string();
    vec![ArtifactRecord {
        category: ArtifactCategory::UserActivity,
        subcategory: "Universal Clipboard".to_string(), timestamp: None,
        title: "iOS clipboard / pasteboard".to_string(),
        detail: format!("Pasteboard data ({} bytes) — copied text, images, URLs (may cross-device sync)", size),
        source_path: source, forensic_value: ForensicValue::High,
        mitre_technique: Some("T1115".to_string()), is_suspicious: false, raw_data: None,
        confidence: 0,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    #[test]
    fn matches_clipboard() {
        assert!(matches(Path::new("/var/mobile/Library/Caches/com.apple.UIKit.pboard/pasteboard.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses_presence() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("com.apple.UIKit.pboard");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("pasteboard.db");
        std::fs::write(&p, b"data").unwrap();
        assert_eq!(parse(&p).len(), 1);
    }
    #[test]
    fn empty_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("UIPasteboard");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("pasteboard.db");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
