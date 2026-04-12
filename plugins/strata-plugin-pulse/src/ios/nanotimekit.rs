//! iOS NanoTimeKit — Apple Watch face configuration + complications.
//!
//! `com.apple.NanoTimeKit/` stores which watch faces the user
//! configured and what complications they chose (weather city,
//! favorite contacts, stock tickers). Reveals user priorities.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::path_contains(path, "nanotimekit") && {
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
        subcategory: "NanoTimeKit".to_string(), timestamp: None,
        title: "Apple Watch face configuration".to_string(),
        detail: format!("NanoTimeKit data ({} bytes) — watch faces, complications (pinned contacts, cities, stocks)", size),
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
    fn matches_nanotimekit() {
        assert!(matches(Path::new("/var/mobile/Library/NanoTimeKit/faces.plist")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("NanoTimeKit");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("faces.plist");
        std::fs::write(&p, b"data").unwrap();
        assert_eq!(parse(&p).len(), 1);
    }
    #[test]
    fn empty_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("NanoTimeKit");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("faces.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
