//! iOS MobileBackup settings — `com.apple.MobileBackup.plist`.
//!
//! Shows when the device was last backed up to iTunes/Finder and
//! iCloud. Gaps in backup schedule can indicate awareness of
//! investigation.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["com.apple.mobilebackup.plist"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 { return Vec::new(); }
    let source = path.to_string_lossy().to_string();
    vec![ArtifactRecord {
        category: ArtifactCategory::SystemActivity,
        subcategory: "Mobile backup".to_string(),
        timestamp: None,
        title: "iOS backup settings".to_string(),
        detail: format!("MobileBackup plist ({} bytes) — last iTunes/iCloud backup date, backup enabled state", size),
        source_path: source,
        forensic_value: ForensicValue::High,
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
    fn matches_mobilebackup_plist() {
        assert!(matches(Path::new("/var/mobile/Library/Preferences/com.apple.MobileBackup.plist")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_presence() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.MobileBackup.plist");
        std::fs::write(&p, b"bplist00fake").unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].detail.contains("backup"));
    }

    #[test]
    fn empty_file_returns_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.MobileBackup.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
