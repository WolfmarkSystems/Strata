//! iOS Apple Maps — `History.mapsdata`, `GeoHistory.mapsdata`,
//! `MapsSync_*.sqlite`.
//!
//! Apple Maps stores location bookmarks, search history, and route
//! requests in `History.mapsdata` (a CoreData binary plist on iOS 14+
//! and a SQLite store on earlier releases). It also keeps
//! `GeoHistory.mapsdata` for cached geocoding queries.
//!
//! Pulse v1.0 reports presence + size for the binary stores. The
//! per-search extraction is queued for v1.1 once the binary plist
//! variant is mapped.

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

const MAPS_FILES: &[&str] = &[
    "history.mapsdata",
    "geohistory.mapsdata",
    "mapssync_0_5859ba6098f6489c9c69e1a8b0c4f0fd.sqlite",
];

pub fn matches(path: &Path) -> bool {
    if util::name_is(path, MAPS_FILES) {
        return true;
    }
    // Match the per-installation MapsSync_<UUID>.sqlite variant.
    let n = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_ascii_lowercase(),
        None => return false,
    };
    n.starts_with("mapssync_") && n.ends_with(".sqlite")
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let source = path.to_string_lossy().to_string();
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if size == 0 {
        return Vec::new();
    }

    let label = if name.contains("geohistory") {
        "Apple Maps geocoding cache"
    } else if name.contains("history") {
        "Apple Maps search history"
    } else {
        "Apple Maps sync state"
    };

    vec![ArtifactRecord {
        category: ArtifactCategory::UserActivity,
        subcategory: "Apple Maps".to_string(),
        timestamp: None,
        title: label.to_string(),
        detail: format!(
            "{} present at {} ({} bytes) — search and route history",
            label, source, size
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

    fn write(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }

    #[test]
    fn matches_canonical_filenames_and_uuid_variant() {
        assert!(matches(Path::new(
            "/var/mobile/Library/Maps/History.mapsdata"
        )));
        assert!(matches(Path::new(
            "/var/mobile/Library/Maps/GeoHistory.mapsdata"
        )));
        assert!(matches(Path::new(
            "/var/mobile/Library/Maps/MapsSync_DEADBEEF1234.sqlite"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_history_label() {
        let dir = tempdir().unwrap();
        let p = write(dir.path(), "History.mapsdata", b"binary plist payload");
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].title, "Apple Maps search history");
    }

    #[test]
    fn parses_geohistory_label() {
        let dir = tempdir().unwrap();
        let p = write(dir.path(), "GeoHistory.mapsdata", b"binary plist payload");
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].title, "Apple Maps geocoding cache");
    }

    #[test]
    fn empty_file_returns_no_records() {
        let dir = tempdir().unwrap();
        let p = write(dir.path(), "History.mapsdata", b"");
        let recs = parse(&p);
        assert!(recs.is_empty());
    }
}
