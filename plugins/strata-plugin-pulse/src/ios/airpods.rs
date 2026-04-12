//! iOS AirPods connection logs — `com.apple.BTServer/` + pairing.
//!
//! AirPods connection history records when the device paired/connected,
//! battery levels, and automatic ear detection state. Proves the user
//! was physically present and wearing the earbuds.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["com.apple.btserver.plist", "com.apple.btserver.le.plist"])
        || (util::path_contains(path, "btserver") && {
            let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
            n.ends_with(".db") || n.ends_with(".plist")
        })
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 { return Vec::new(); }
    let source = path.to_string_lossy().to_string();
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    vec![ArtifactRecord {
        category: ArtifactCategory::NetworkArtifacts,
        subcategory: "AirPods / BT Server".to_string(), timestamp: None,
        title: "iOS Bluetooth server / AirPods connection log".to_string(),
        detail: format!("{} ({} bytes) — AirPods/Beats pairing, connection times, battery levels, ear detection", name, size),
        source_path: source, forensic_value: ForensicValue::High,
        mitre_technique: Some("T1011".to_string()), is_suspicious: false, raw_data: None,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn matches_btserver() {
        assert!(matches(Path::new("/var/mobile/Library/Preferences/com.apple.BTServer.plist")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses_presence() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.BTServer.plist");
        std::fs::write(&p, b"bplist00data").unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].detail.contains("AirPods"));
    }
    #[test]
    fn empty_returns_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.BTServer.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
