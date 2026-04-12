//! iOS VPN Configuration — `com.apple.networkextension.plist`,
//! `NEConfiguration.plist`.
//!
//! VPN profiles reveal which VPN services are/were configured.
//! High forensic value — VPN use during a crime window is significant.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &[
        "com.apple.networkextension.plist",
        "neconfiguration.plist",
        "nehelper.plist",
    ]) || (util::path_contains(path, "networkextension") && {
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
        subcategory: "VPN config".to_string(), timestamp: None,
        title: "iOS VPN configuration".to_string(),
        detail: format!("{} ({} bytes) — VPN profiles, tunnel endpoints, on-demand rules", name, size),
        source_path: source, forensic_value: ForensicValue::High,
        mitre_technique: Some("T1572".to_string()),
        is_suspicious: false, raw_data: None,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    #[test]
    fn matches_vpn() {
        assert!(matches(Path::new("/var/mobile/Library/Preferences/com.apple.networkextension.plist")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.networkextension.plist");
        std::fs::write(&p, b"data").unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].mitre_technique.as_deref() == Some("T1572"));
    }
    #[test]
    fn empty_returns_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.networkextension.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
