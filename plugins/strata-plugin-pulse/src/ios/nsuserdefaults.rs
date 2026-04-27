//! iOS NSUserDefaults forensic patterns — per-app preferences plists.
//!
//! Every app writes `<bundle-id>.plist` under `Library/Preferences/`.
//! These often contain user IDs, auth tokens, last-login timestamps,
//! feature flags, and onboarding state. This parser detects and
//! inventories them.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    if !util::path_contains(path, "/preferences/") {
        return false;
    }
    let n = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    // Match reverse-DNS plist names (at least 2 dots = com.xxx.yyy)
    n.ends_with(".plist") && n.matches('.').count() >= 3
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 {
        return Vec::new();
    }
    let source = path.to_string_lossy().to_string();
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    // Extract bundle ID from filename (strip .plist)
    let bundle = name
        .strip_suffix(".plist")
        .or_else(|| name.strip_suffix(".PLIST"))
        .unwrap_or(name);
    vec![ArtifactRecord {
        category: ArtifactCategory::UserActivity,
        subcategory: "NSUserDefaults".to_string(),
        timestamp: None,
        title: format!("App preferences: {}", bundle),
        detail: format!(
            "{} ({} bytes) — user IDs, auth tokens, last-login, feature flags",
            bundle, size
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
    fn matches_reverse_dns_plists_in_preferences() {
        assert!(matches(Path::new(
            "/var/mobile/Library/Preferences/com.example.myapp.plist"
        )));
        assert!(!matches(Path::new(
            "/var/mobile/Library/Preferences/com.apple.plist"
        ))); // only 2 dots
        assert!(!matches(Path::new(
            "/var/mobile/Library/SMS/com.example.myapp.plist"
        ))); // wrong dir
    }

    #[test]
    fn parses_bundle_id() {
        let dir = tempdir().unwrap();
        let prefs = dir.path().join("Library").join("Preferences");
        std::fs::create_dir_all(&prefs).unwrap();
        let p = prefs.join("com.example.myapp.plist");
        std::fs::write(&p, b"bplist00data").unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].title.contains("com.example.myapp"));
    }

    #[test]
    fn empty_returns_empty() {
        let dir = tempdir().unwrap();
        let prefs = dir.path().join("Library").join("Preferences");
        std::fs::create_dir_all(&prefs).unwrap();
        let p = prefs.join("com.example.myapp.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
