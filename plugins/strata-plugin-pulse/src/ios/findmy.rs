//! iOS Find My — `searchpartyd` cache and `Items.data`.
//!
//! Find My persists Bluetooth-tag advertisements (AirTag, Tile, third-
//! party items) under `Library/com.apple.icloud.searchpartyd/`. Two
//! files of forensic interest:
//!   * `OwnedBeacons/Beacons` — owned AirTag/iPhone records
//!   * `Items.data` (or `BeaconNamingRecord`) — friendly names for
//!     paired devices
//!
//! Pulse v1.0 reports presence + size for any matched file. Per-tag
//! decoding (lat/lon, last-seen) requires walking Apple's
//! protobuf+plist hybrid and is queued for v1.1.

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

pub fn matches(path: &Path) -> bool {
    let n = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_ascii_lowercase(),
        None => return false,
    };
    let in_searchparty = util::path_contains(path, "/searchpartyd/")
        || util::path_contains(path, "com.apple.icloud.searchpartyd");
    if !in_searchparty {
        return false;
    }
    n == "items.data"
        || n == "beaconnamingrecord"
        || n == "beacons"
        || n.ends_with(".plist")
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 {
        return Vec::new();
    }
    let source = path.to_string_lossy().to_string();
    vec![ArtifactRecord {
        category: ArtifactCategory::UserActivity,
        subcategory: "Find My".to_string(),
        timestamp: None,
        title: "iOS Find My searchpartyd record".to_string(),
        detail: format!(
            "Find My / searchpartyd file present at {} ({} bytes)",
            source, size
        ),
        source_path: source,
        forensic_value: ForensicValue::High,
        mitre_technique: Some("T1430".to_string()),
        is_suspicious: false,
        raw_data: None,
        confidence: 0,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write(dir: &Path, parts: &[&str], bytes: &[u8]) -> std::path::PathBuf {
        let mut p = dir.to_path_buf();
        for s in parts {
            p = p.join(s);
        }
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, bytes).unwrap();
        p
    }

    #[test]
    fn matches_findmy_files_under_searchpartyd() {
        assert!(matches(Path::new(
            "/var/mobile/Library/com.apple.icloud.searchpartyd/OwnedBeacons/Items.data"
        )));
        assert!(matches(Path::new(
            "/var/mobile/Library/com.apple.icloud.searchpartyd/foo.plist"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/Items.data")));
    }

    #[test]
    fn parses_size_into_record() {
        let dir = tempdir().unwrap();
        let p = write(
            dir.path(),
            &["com.apple.icloud.searchpartyd", "Items.data"],
            b"binary blob",
        );
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].detail.contains("bytes"));
    }

    #[test]
    fn empty_file_returns_no_records() {
        let dir = tempdir().unwrap();
        let p = write(
            dir.path(),
            &["com.apple.icloud.searchpartyd", "Items.data"],
            b"",
        );
        assert!(parse(&p).is_empty());
    }
}
