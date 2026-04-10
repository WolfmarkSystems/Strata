//! iOS device info plists — `SystemVersion.plist`,
//! `com.apple.mobile.ldbackup.plist`, `com.apple.MobileDeviceType.plist`.
//!
//! These plists contain iOS version, device model, build, etc.
//! Pulse v1.0 reports presence + size; full plist key extraction is v1.1.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

const DEVICE_PLISTS: &[&str] = &[
    "systemversion.plist",
    "com.apple.mobile.ldbackup.plist",
    "com.apple.mobiledevicetype.plist",
    "buildmanifest.plist",
    "info.plist",
];

pub fn matches(path: &Path) -> bool {
    let n = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_ascii_lowercase(),
        None => return false,
    };
    // info.plist is too generic — only match under System/ or root
    if n == "info.plist" {
        return super::util::path_contains(path, "/system/");
    }
    DEVICE_PLISTS.iter().any(|p| n == *p)
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 { return Vec::new(); }
    let source = path.to_string_lossy().to_string();
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    vec![ArtifactRecord {
        category: ArtifactCategory::SystemActivity,
        subcategory: "Device info".to_string(),
        timestamp: None,
        title: format!("iOS device info: {}", name),
        detail: format!("{} ({} bytes) — device model, iOS version, build info", name, size),
        source_path: source,
        forensic_value: ForensicValue::High,
        mitre_technique: None,
        is_suspicious: false,
        raw_data: None,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn matches_system_plists() {
        assert!(matches(Path::new("/System/Library/CoreServices/SystemVersion.plist")));
        assert!(matches(Path::new("/var/root/Library/Preferences/com.apple.MobileDeviceType.plist")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_plist_presence() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("SystemVersion.plist");
        std::fs::write(&p, b"bplist00fake").unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].detail.contains("SystemVersion.plist"));
    }

    #[test]
    fn empty_file_returns_no_records() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("SystemVersion.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
