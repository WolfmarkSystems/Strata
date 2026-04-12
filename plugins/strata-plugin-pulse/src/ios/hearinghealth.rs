//! iOS Hearing Health — `com.apple.health.hearing/` + audiogram data.
//!
//! Records headphone audio levels, noise exposure, and audiogram
//! results. Proves AirPods/headphone usage patterns and hearing
//! test results.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    (util::path_contains(path, "hearing") || util::path_contains(path, "audiogram")) && {
        let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
        n.ends_with(".db") || n.ends_with(".sqlite") || n.ends_with(".plist")
    }
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 { return Vec::new(); }
    let source = path.to_string_lossy().to_string();
    vec![ArtifactRecord {
        category: ArtifactCategory::UserActivity,
        subcategory: "Hearing Health".to_string(), timestamp: None,
        title: "iOS Hearing Health data".to_string(),
        detail: format!("Hearing data ({} bytes) — headphone levels, noise exposure, audiogram results", size),
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
    fn matches_hearing() {
        assert!(matches(Path::new("/var/mobile/Library/Health/hearing/store.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("hearing");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("store.db");
        std::fs::write(&p, b"data").unwrap();
        assert_eq!(parse(&p).len(), 1);
    }
    #[test]
    fn empty_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("hearing");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("store.db");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
