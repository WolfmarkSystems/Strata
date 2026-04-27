//! iOS Focus Filters (iOS 16+) — per-app filter configurations.
//!
//! Focus Filters customize which accounts, tabs, and calendars are
//! visible in each Focus mode. Reveals user intent about information
//! compartmentalization.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    util::path_contains(path, "focusconfig") && {
        let n = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        n.ends_with(".db") || n.ends_with(".sqlite") || n.ends_with(".plist")
    }
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 {
        return Vec::new();
    }
    let source = path.to_string_lossy().to_string();
    vec![ArtifactRecord {
        category: ArtifactCategory::UserActivity,
        subcategory: "Focus Filters".to_string(),
        timestamp: None,
        title: "iOS Focus Filters configuration".to_string(),
        detail: format!(
            "Focus filter data ({} bytes) — per-Focus account/tab/calendar visibility rules",
            size
        ),
        source_path: source,
        forensic_value: ForensicValue::Medium,
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
    fn matches_focusconfig() {
        assert!(matches(Path::new(
            "/var/mobile/Library/FocusConfig/store.db"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("FocusConfig");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("config.plist");
        std::fs::write(&p, b"data").unwrap();
        assert_eq!(parse(&p).len(), 1);
    }
    #[test]
    fn empty_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("FocusConfig");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("config.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
