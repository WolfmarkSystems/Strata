//! iOS DHCP leases — plist files under `db/dhcpclient/leases/`.
//!
//! Each lease plist records IP address, router, SSID, and lease start.
//! Ties device to specific networks with timestamps.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
    n.ends_with(".plist") && util::path_contains(path, "/dhcpclient/leases")
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 { return Vec::new(); }
    let source = path.to_string_lossy().to_string();
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    vec![ArtifactRecord {
        category: ArtifactCategory::NetworkArtifacts,
        subcategory: "DHCP lease".to_string(),
        timestamp: None,
        title: format!("DHCP lease: {}", name),
        detail: format!("DHCP lease plist ({} bytes) — IP address, router, SSID, lease start time", size),
        source_path: source,
        forensic_value: ForensicValue::High,
        mitre_technique: Some("T1016".to_string()),
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
    fn matches_lease_plists() {
        assert!(matches(Path::new("/var/db/dhcpclient/leases/en0.plist")));
        assert!(!matches(Path::new("/var/mobile/Library/Preferences/en0.plist")));
    }

    #[test]
    fn parses_presence() {
        let dir = tempdir().unwrap();
        let leases = dir.path().join("db").join("dhcpclient").join("leases");
        std::fs::create_dir_all(&leases).unwrap();
        let p = leases.join("en0.plist");
        std::fs::write(&p, b"bplist00fake").unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].detail.contains("DHCP lease"));
    }

    #[test]
    fn empty_file_returns_empty() {
        let dir = tempdir().unwrap();
        let leases = dir.path().join("db").join("dhcpclient").join("leases");
        std::fs::create_dir_all(&leases).unwrap();
        let p = leases.join("en0.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
