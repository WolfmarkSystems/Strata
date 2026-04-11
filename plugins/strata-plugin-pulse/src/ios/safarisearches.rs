//! iOS Safari recent searches — `RecentSearches.plist`.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["recentsearches.plist"]) && util::path_contains(path, "/safari/")
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 { return Vec::new(); }
    let source = path.to_string_lossy().to_string();
    vec![ArtifactRecord {
        category: ArtifactCategory::WebActivity,
        subcategory: "Safari searches".to_string(), timestamp: None,
        title: "Safari recent searches".to_string(),
        detail: format!("RecentSearches.plist ({} bytes) — user search queries from Safari search bar", size),
        source_path: source, forensic_value: ForensicValue::Critical,
        mitre_technique: Some("T1005".to_string()), is_suspicious: false, raw_data: None,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn matches_safari_searches() {
        assert!(matches(Path::new("/var/mobile/Library/Safari/RecentSearches.plist")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/RecentSearches.plist")));
    }
    #[test]
    fn parses_presence() {
        let dir = tempdir().unwrap();
        let safari = dir.path().join("Library").join("Safari");
        std::fs::create_dir_all(&safari).unwrap();
        let p = safari.join("RecentSearches.plist");
        std::fs::write(&p, b"bplist00data").unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].forensic_value, ForensicValue::Critical);
    }
    #[test]
    fn empty_returns_empty() {
        let dir = tempdir().unwrap();
        let safari = dir.path().join("Library").join("Safari");
        std::fs::create_dir_all(&safari).unwrap();
        let p = safari.join("RecentSearches.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
