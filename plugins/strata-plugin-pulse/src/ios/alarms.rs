//! iOS Alarms / Clock — `com.apple.mobiletimerd.plist`.
//!
//! Alarm settings reveal the user's daily schedule (wake time,
//! recurring patterns). Bedtime/Sleep timer data is also here.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["com.apple.mobiletimerd.plist"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 { return Vec::new(); }
    let source = path.to_string_lossy().to_string();
    vec![ArtifactRecord {
        category: ArtifactCategory::UserActivity,
        subcategory: "Alarms".to_string(), timestamp: None,
        title: "iOS alarm / timer settings".to_string(),
        detail: format!("mobiletimerd plist ({} bytes) — alarm schedule, bedtime, sleep focus, timers", size),
        source_path: source, forensic_value: ForensicValue::Medium,
        mitre_technique: None, is_suspicious: false, raw_data: None,
        confidence: 0,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    #[test]
    fn matches_alarm() {
        assert!(matches(Path::new("/var/mobile/Library/Preferences/com.apple.mobiletimerd.plist")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.mobiletimerd.plist");
        std::fs::write(&p, b"data").unwrap();
        assert_eq!(parse(&p).len(), 1);
    }
    #[test]
    fn empty_returns_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.mobiletimerd.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
