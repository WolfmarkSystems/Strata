//! iOS AuthKit — Apple ID authentication state.
//!
//! `com.apple.AuthKit*` stores Apple ID tokens, sign-in timestamps,
//! 2FA state. Proves which Apple ID was signed in and when the last
//! authentication occurred.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
    n.starts_with("com.apple.authkit") && (n.ends_with(".db") || n.ends_with(".plist"))
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 { return Vec::new(); }
    let source = path.to_string_lossy().to_string();
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    vec![ArtifactRecord {
        category: ArtifactCategory::AccountsCredentials,
        subcategory: "AuthKit".to_string(), timestamp: None,
        title: "iOS AuthKit Apple ID state".to_string(),
        detail: format!("{} ({} bytes) — Apple ID auth tokens, sign-in time, 2FA enrollment", name, size),
        source_path: source, forensic_value: ForensicValue::Critical,
        mitre_technique: Some("T1078".to_string()), is_suspicious: false, raw_data: None,
        confidence: 0,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn matches_authkit() {
        assert!(matches(Path::new("/var/mobile/Library/Preferences/com.apple.AuthKit.plist")));
        assert!(matches(Path::new("/var/mobile/Library/AuthKit/com.apple.AuthKit.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses_presence() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.AuthKit.plist");
        std::fs::write(&p, b"bplist00data").unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].forensic_value, ForensicValue::Critical);
    }
    #[test]
    fn empty_returns_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.AuthKit.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
