//! iOS Restrictions / Parental Controls — `restrictionspassword.plist`,
//! `com.apple.restrictionspassword.plist`.
//!
//! Indicates parental controls or device restrictions were set.
//! Relevant in cases involving minors.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    util::name_is(
        path,
        &[
            "com.apple.restrictionspassword.plist",
            "restrictionspassword.plist",
        ],
    )
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 {
        return Vec::new();
    }
    let source = path.to_string_lossy().to_string();
    vec![ArtifactRecord {
        category: ArtifactCategory::SystemActivity,
        subcategory: "Restrictions passcode".to_string(),
        timestamp: None,
        title: "iOS Restrictions / Screen Time passcode".to_string(),
        detail: format!(
            "Restrictions password plist ({} bytes) — parental controls were active",
            size
        ),
        source_path: source,
        forensic_value: ForensicValue::High,
        mitre_technique: None,
        is_suspicious: false,
        raw_data: None,
        confidence: 0,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn matches_restrictions_plist() {
        assert!(matches(Path::new(
            "/var/mobile/Library/Preferences/com.apple.restrictionspassword.plist"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_presence() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.restrictionspassword.plist");
        std::fs::write(&p, b"bplist00fake").unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].detail.contains("parental controls"));
    }

    #[test]
    fn empty_file_returns_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.restrictionspassword.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
