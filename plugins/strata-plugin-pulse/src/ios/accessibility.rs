//! iOS Accessibility settings — `com.apple.Accessibility.plist`.
//!
//! Indicates VoiceOver, AssistiveTouch, BoldText, etc. May help
//! characterise the device user (visual/motor impairment indicators).

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["com.apple.accessibility.plist"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 { return Vec::new(); }
    let source = path.to_string_lossy().to_string();
    vec![ArtifactRecord {
        category: ArtifactCategory::SystemActivity,
        subcategory: "Accessibility".to_string(),
        timestamp: None,
        title: "iOS Accessibility settings".to_string(),
        detail: format!("Accessibility plist ({} bytes) — VoiceOver, AssistiveTouch, BoldText, display settings", size),
        source_path: source,
        forensic_value: ForensicValue::Medium,
        mitre_technique: None,
        is_suspicious: false,
        raw_data: None,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn matches_accessibility_plist() {
        assert!(matches(Path::new("/var/mobile/Library/Preferences/com.apple.Accessibility.plist")));
        assert!(!matches(Path::new("/var/mobile/Library/Preferences/com.apple.wifi.plist")));
    }

    #[test]
    fn parses_presence() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.Accessibility.plist");
        std::fs::write(&p, b"bplist00fake").unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].detail.contains("VoiceOver"));
    }

    #[test]
    fn empty_file_returns_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.Accessibility.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
