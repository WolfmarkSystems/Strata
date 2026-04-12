//! iOS Nearby Interaction — `com.apple.NearbyInteraction/`.
//!
//! Ultra Wideband (UWB) proximity data from U1 chip. Records which
//! other U1-equipped devices (iPhones, AirTags, HomePods) were
//! nearby and at what distance. Proves physical proximity to
//! specific devices.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::path_contains(path, "nearbyinteraction") && {
        let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
        n.ends_with(".db") || n.ends_with(".sqlite") || n.ends_with(".plist")
    }
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 { return Vec::new(); }
    let source = path.to_string_lossy().to_string();
    vec![ArtifactRecord {
        category: ArtifactCategory::NetworkArtifacts,
        subcategory: "Nearby Interaction".to_string(), timestamp: None,
        title: "iOS Ultra Wideband / Nearby Interaction".to_string(),
        detail: format!("NearbyInteraction data ({} bytes) — UWB proximity to other U1 devices (iPhones, AirTags)", size),
        source_path: source, forensic_value: ForensicValue::Critical,
        mitre_technique: Some("T1011".to_string()), is_suspicious: false, raw_data: None,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    #[test]
    fn matches_nearby() {
        assert!(matches(Path::new("/var/mobile/Library/NearbyInteraction/store.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("NearbyInteraction");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("store.db");
        std::fs::write(&p, b"data").unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].forensic_value, ForensicValue::Critical);
    }
    #[test]
    fn empty_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("NearbyInteraction");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("store.db");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
