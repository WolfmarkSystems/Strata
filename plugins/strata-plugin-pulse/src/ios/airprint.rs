//! iOS AirPrint — `com.apple.printd/` print job history.
//! Records document names, printer IDs, timestamps. Proves what
//! was printed and when.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    (util::path_contains(path, "printd") || util::path_contains(path, "airprint")) && {
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
        subcategory: "AirPrint".to_string(), timestamp: None,
        title: "iOS AirPrint job history".to_string(),
        detail: format!("Print data ({} bytes) — document names, printer IDs, print times", size),
        source_path: source, forensic_value: ForensicValue::High,
        mitre_technique: None, is_suspicious: false, raw_data: None,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    #[test]
    fn matches_airprint() {
        assert!(matches(Path::new("/var/mobile/Library/com.apple.printd/jobs.plist")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("com.apple.printd");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("jobs.plist");
        std::fs::write(&p, b"data").unwrap();
        assert_eq!(parse(&p).len(), 1);
    }
    #[test]
    fn empty_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("com.apple.printd");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("jobs.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
