//! iOS known Wi-Fi networks — `com.apple.wifi.plist`,
//! `com.apple.wifi.known-networks.plist`, `com.apple.airport.preferences.plist`.
//!
//! iOS persists every joined SSID + last-joined date in one of three
//! plist locations depending on iOS release. v1.0 reports presence and
//! file size; per-SSID extraction (BSSID, lat/lon, last-join time)
//! requires walking nested dicts and is queued for v1.1.

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

const KNOWN_WIFI_PLISTS: &[&str] = &[
    "com.apple.wifi.plist",
    "com.apple.wifi.known-networks.plist",
    "com.apple.airport.preferences.plist",
];

pub fn matches(path: &Path) -> bool {
    util::name_is(path, KNOWN_WIFI_PLISTS)
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 {
        return Vec::new();
    }
    let source = path.to_string_lossy().to_string();
    vec![ArtifactRecord {
        category: ArtifactCategory::NetworkArtifacts,
        subcategory: "Wi-Fi known networks".to_string(),
        timestamp: None,
        title: "iOS Wi-Fi known networks plist".to_string(),
        detail: format!(
            "Wi-Fi network plist present ({} bytes) — contains SSID, BSSID, last-joined time, and (sometimes) Wi-Fi-derived location",
            size
        ),
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

    fn write_fake_plist(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }

    #[test]
    fn matches_known_filenames() {
        assert!(matches(Path::new(
            "/var/preferences/SystemConfiguration/com.apple.wifi.plist"
        )));
        assert!(matches(Path::new(
            "/var/preferences/SystemConfiguration/com.apple.wifi.known-networks.plist"
        )));
        assert!(matches(Path::new(
            "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist"
        )));
        assert!(!matches(Path::new("/var/something/com.example.plist")));
    }

    #[test]
    fn parses_size_into_summary() {
        let dir = tempdir().unwrap();
        let p = write_fake_plist(dir.path(), "com.apple.wifi.plist", b"bplist00fake-payload");
        let records = parse(&p);
        assert_eq!(records.len(), 1);
        assert!(records[0].detail.contains("bytes"));
        assert_eq!(records[0].forensic_value, ForensicValue::High);
    }

    #[test]
    fn empty_file_returns_no_records() {
        let dir = tempdir().unwrap();
        let p = write_fake_plist(dir.path(), "com.apple.wifi.plist", b"");
        let records = parse(&p);
        assert!(records.is_empty());
    }

    #[test]
    fn never_emits_raw_data() {
        let dir = tempdir().unwrap();
        let p = write_fake_plist(dir.path(), "com.apple.wifi.plist", b"x");
        let records = parse(&p);
        assert!(records[0].raw_data.is_none());
    }
}
