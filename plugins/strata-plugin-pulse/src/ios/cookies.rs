//! iOS Cookies — `Cookies.binarycookies`.
//!
//! Apple's binary cookie jar (not SQLite, proprietary binary format).
//! iLEAPP counts the file size as a proxy for cookie volume.
//! Pulse v1.0 follows suit — reports presence + size.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    let n = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_ascii_lowercase(),
        None => return false,
    };
    n == "cookies.binarycookies" || n.ends_with(".binarycookies")
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 { return Vec::new(); }
    let source = path.to_string_lossy().to_string();

    // Infer the owning app from the parent directory path
    let app_hint = path.parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    vec![ArtifactRecord {
        category: ArtifactCategory::WebActivity,
        subcategory: "Cookies".to_string(),
        timestamp: None,
        title: format!("iOS binary cookies ({})", app_hint),
        detail: format!("Cookies.binarycookies ({} bytes) — session tokens, tracking cookies, auth state", size),
        source_path: source,
        forensic_value: ForensicValue::High,
        mitre_technique: Some("T1539".to_string()),
        is_suspicious: false,
        raw_data: None,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn matches_cookie_files() {
        assert!(matches(Path::new("/var/mobile/Containers/Data/Application/UUID/Library/Cookies/Cookies.binarycookies")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_size() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("Cookies.binarycookies");
        std::fs::write(&p, b"cook0000deadbeef").unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].detail.contains("session tokens"));
    }

    #[test]
    fn empty_file_returns_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("Cookies.binarycookies");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
