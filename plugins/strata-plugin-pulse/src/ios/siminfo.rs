//! iOS SIM card info — `com.apple.commcenter.plist`,
//! `carrier.plist`, `com.apple.commcenter.device_specific_nobackup.plist`.
//!
//! Contains ICCID, IMSI (partial), carrier name, phone number.
//! Extremely high value for attribution.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

const SIM_PLISTS: &[&str] = &[
    "com.apple.commcenter.plist",
    "com.apple.commcenter.device_specific_nobackup.plist",
    "carrier.plist",
];

pub fn matches(path: &Path) -> bool {
    util::name_is(path, SIM_PLISTS)
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 {
        return Vec::new();
    }
    let source = path.to_string_lossy().to_string();
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    vec![ArtifactRecord {
        category: ArtifactCategory::AccountsCredentials,
        subcategory: "SIM info".to_string(),
        timestamp: None,
        title: format!("iOS SIM / carrier info: {}", name),
        detail: format!(
            "{} ({} bytes) — ICCID, carrier name, phone number",
            name, size
        ),
        source_path: source,
        forensic_value: ForensicValue::Critical,
        mitre_technique: Some("T1005".to_string()),
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
    fn matches_sim_plists() {
        assert!(matches(Path::new(
            "/var/wireless/Library/Preferences/com.apple.commcenter.plist"
        )));
        assert!(matches(Path::new(
            "/var/wireless/Library/Preferences/carrier.plist"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_presence() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.commcenter.plist");
        std::fs::write(&p, b"bplist00fake").unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].forensic_value, ForensicValue::Critical);
    }

    #[test]
    fn empty_file_returns_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.commcenter.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
