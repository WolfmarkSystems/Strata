//! iOS BiometricKit — Face ID / Touch ID attempt logs.
//!
//! `com.apple.BiometricKit*` plists and databases record biometric
//! enrollment events, failed authentication attempts, and lockout
//! events. Failed attempts prove someone tried to unlock the device.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    let n = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    n.starts_with("com.apple.biometrickit")
        || n == "biometrickittsync.db"
        || (util::path_contains(path, "biometrickit")
            && (n.ends_with(".db") || n.ends_with(".plist")))
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 {
        return Vec::new();
    }
    let source = path.to_string_lossy().to_string();
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    vec![ArtifactRecord {
        category: ArtifactCategory::SystemActivity,
        subcategory: "BiometricKit".to_string(),
        timestamp: None,
        title: "iOS Face ID / Touch ID biometric log".to_string(),
        detail: format!(
            "{} ({} bytes) — enrollment events, auth attempts, lockouts",
            name, size
        ),
        source_path: source,
        forensic_value: ForensicValue::Critical,
        mitre_technique: Some("T1110".to_string()),
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
    fn matches_biometrickit() {
        assert!(matches(Path::new(
            "/var/mobile/Library/BiometricKit/com.apple.BiometricKit.plist"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses_presence() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.BiometricKit.plist");
        std::fs::write(&p, b"bplist00data").unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].forensic_value, ForensicValue::Critical);
    }
    #[test]
    fn empty_returns_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.BiometricKit.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
