//! iOS Mobile Activation — `activation_record.plist`.
//!
//! Contains ActivationState, UniqueDeviceID, SerialNumber, PhoneNumber,
//! ICCID, IMEI. Critical for tying physical device to user account.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["activation_record.plist"])
        || (util::name_is(path, &["data_ark.plist"]) && util::path_contains(path, "activation"))
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 { return Vec::new(); }
    let source = path.to_string_lossy().to_string();
    vec![ArtifactRecord {
        category: ArtifactCategory::AccountsCredentials,
        subcategory: "Mobile activation".to_string(),
        timestamp: None,
        title: "iOS activation record".to_string(),
        detail: format!("Activation plist ({} bytes) — UDID, serial, IMEI, ICCID, phone number, activation state", size),
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
    fn matches_activation_record() {
        assert!(matches(Path::new("/var/mobile/Library/mad/activation_record.plist")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_presence() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("activation_record.plist");
        std::fs::write(&p, b"bplist00fake").unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].forensic_value, ForensicValue::Critical);
    }

    #[test]
    fn empty_file_returns_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("activation_record.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
