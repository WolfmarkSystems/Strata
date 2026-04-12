//! iOS device lock state — `com.apple.springboard.plist`.
//!
//! Records passcode settings, auto-lock timeout, failed passcode
//! attempts count. The `SBDeviceLockFailedAttempts` key is Critical
//! for proving brute-force attempts.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["com.apple.springboard.plist"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 { return Vec::new(); }
    let source = path.to_string_lossy().to_string();
    vec![ArtifactRecord {
        category: ArtifactCategory::SystemActivity,
        subcategory: "Device lock".to_string(), timestamp: None,
        title: "iOS SpringBoard / device lock settings".to_string(),
        detail: format!("SpringBoard plist ({} bytes) — auto-lock timeout, failed passcode attempts, wallpaper, icon layout", size),
        source_path: source, forensic_value: ForensicValue::High,
        mitre_technique: Some("T1110".to_string()), is_suspicious: false, raw_data: None,
        confidence: 0,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn matches_springboard() {
        assert!(matches(Path::new("/var/mobile/Library/Preferences/com.apple.springboard.plist")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses_presence() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.springboard.plist");
        std::fs::write(&p, b"bplist00data").unwrap();
        assert_eq!(parse(&p).len(), 1);
    }
    #[test]
    fn empty_returns_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.springboard.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
