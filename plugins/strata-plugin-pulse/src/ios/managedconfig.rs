//! iOS Managed Configuration (MDM) — `ManagedConfiguration/` profiles.
//!
//! MDM enrollment and configuration profiles. Reveals if the device
//! was under corporate/institutional management, which apps were
//! force-installed, and what restrictions were applied.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::path_contains(path, "managedconfiguration")
        && util::name_is(path, &["effectiveusersettings.plist", "profiletruth.plist", "profileinstallationresults.plist"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 { return Vec::new(); }
    let source = path.to_string_lossy().to_string();
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    vec![ArtifactRecord {
        category: ArtifactCategory::SystemActivity,
        subcategory: "MDM config".to_string(), timestamp: None,
        title: format!("iOS MDM profile: {}", name),
        detail: format!("{} ({} bytes) — MDM enrollment, managed apps, device restrictions", name, size),
        source_path: source, forensic_value: ForensicValue::High,
        mitre_technique: Some("T1098".to_string()), is_suspicious: false, raw_data: None,
        confidence: 0,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn matches_mdm() {
        assert!(matches(Path::new("/var/mobile/Library/ConfigurationProfiles/ManagedConfiguration/effectiveUserSettings.plist")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses_presence() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("ManagedConfiguration");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("effectiveUserSettings.plist");
        std::fs::write(&p, b"bplist00data").unwrap();
        assert_eq!(parse(&p).len(), 1);
    }
    #[test]
    fn empty_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("ManagedConfiguration");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("effectiveUserSettings.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
