//! iOS Spotlight — `index.spotlightV2` / `index.spotlightV3`.
//!
//! The Spotlight index catalogs searchable content across the device.
//! iLEAPP uses it as a secondary source for deleted-file metadata.
//! The index is a proprietary binary format; Pulse v1.0 reports
//! presence + size.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
    n.starts_with("index.spotlightv") || n == ".store.db"
        && util::path_contains(path, "spotlight")
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 { return Vec::new(); }
    let source = path.to_string_lossy().to_string();
    vec![ArtifactRecord {
        category: ArtifactCategory::SystemActivity,
        subcategory: "Spotlight index".to_string(),
        timestamp: None,
        title: "iOS Spotlight search index".to_string(),
        detail: format!("Spotlight index at {} ({} bytes) — searchable metadata for all apps", source, size),
        source_path: source,
        forensic_value: ForensicValue::High,
        mitre_technique: Some("T1005".to_string()),
        is_suspicious: false,
        raw_data: None,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn matches_spotlight_index() {
        assert!(matches(Path::new("/var/mobile/Library/Spotlight/index.spotlightV3")));
        assert!(matches(Path::new("/var/mobile/Library/Spotlight/index.spotlightV2")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_presence() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("index.spotlightV3");
        std::fs::write(&p, b"spotlight binary").unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].detail.contains("Spotlight"));
    }

    #[test]
    fn empty_file_returns_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("index.spotlightV3");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
