//! iOS Continuity Camera / Sidecar — `com.apple.sidecar.plist`,
//! `com.apple.continuity.plist`.
//!
//! Tracks which nearby Macs/iPads this iPhone has connected to for
//! Continuity Camera, Sidecar display, or Universal Control.
//! Reveals associated devices.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &[
        "com.apple.sidecar.plist",
        "com.apple.continuity.plist",
        "com.apple.universalcontrol.plist",
    ])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 { return Vec::new(); }
    let source = path.to_string_lossy().to_string();
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    vec![ArtifactRecord {
        category: ArtifactCategory::SystemActivity,
        subcategory: "Continuity".to_string(), timestamp: None,
        title: format!("iOS Continuity / Sidecar: {}", name),
        detail: format!("{} ({} bytes) — paired Mac/iPad for Continuity Camera, Sidecar, Universal Control", name, size),
        source_path: source, forensic_value: ForensicValue::High,
        mitre_technique: None, is_suspicious: false, raw_data: None,
        confidence: 0,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    #[test]
    fn matches_continuity() {
        assert!(matches(Path::new("/var/mobile/Library/Preferences/com.apple.sidecar.plist")));
        assert!(matches(Path::new("/var/mobile/Library/Preferences/com.apple.continuity.plist")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.sidecar.plist");
        std::fs::write(&p, b"data").unwrap();
        assert_eq!(parse(&p).len(), 1);
    }
    #[test]
    fn empty_returns_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.sidecar.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
