//! iOS Magnifier — `com.apple.Magnifier/` saved snapshots metadata.
//! Magnifier captures are often used to photograph documents, signs,
//! or small text — the metadata reveals what was being examined.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    util::path_contains(path, "com.apple.magnifier") && {
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
        subcategory: "Magnifier".to_string(),
        timestamp: None,
        title: "iOS Magnifier saved captures".to_string(),
        detail: format!(
            "Magnifier data ({} bytes) — snapshot metadata (image bytes not read)",
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
    fn matches_magnifier() {
        assert!(matches(Path::new(
            "/var/mobile/Library/com.apple.Magnifier/store.db"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("com.apple.Magnifier");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("store.db");
        std::fs::write(&p, b"data").unwrap();
        assert_eq!(parse(&p).len(), 1);
    }
    #[test]
    fn empty_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("com.apple.Magnifier");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("store.db");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
