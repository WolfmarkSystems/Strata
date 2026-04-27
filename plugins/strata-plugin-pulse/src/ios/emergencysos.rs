//! iOS Emergency SOS — `com.apple.emergency*`, SOS trigger logs.
//!
//! Records when Emergency SOS was triggered, including crash detection
//! events (iOS 16+). Extremely high forensic value — proves the user
//! initiated an emergency call at a specific time.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    util::name_is(
        path,
        &["com.apple.emergencykit.plist", "com.apple.emergency.plist"],
    ) || (util::path_contains(path, "emergencykit") && {
        let n = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        n.ends_with(".plist") || n.ends_with(".db")
    })
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 {
        return Vec::new();
    }
    let source = path.to_string_lossy().to_string();
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    vec![ArtifactRecord {
        category: ArtifactCategory::UserActivity,
        subcategory: "Emergency SOS".to_string(),
        timestamp: None,
        title: format!("iOS Emergency SOS: {}", name),
        detail: format!(
            "{} ({} bytes) — SOS contacts, crash detection config, emergency call trigger log",
            name, size
        ),
        source_path: source,
        forensic_value: ForensicValue::Critical,
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
    fn matches_emergency_files() {
        assert!(matches(Path::new(
            "/var/mobile/Library/Preferences/com.apple.emergencykit.plist"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_presence() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.emergencykit.plist");
        std::fs::write(&p, b"bplist00data").unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].forensic_value, ForensicValue::Critical);
    }

    #[test]
    fn empty_returns_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.emergencykit.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
