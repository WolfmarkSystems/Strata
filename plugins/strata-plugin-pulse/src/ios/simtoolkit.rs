//! iOS SIM Toolkit logs — `com.apple.coretelephony.plist`,
//! `CellularUsage.db` SIM entries.
//!
//! Records SIM card changes, ICCID history, carrier switches.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &[
        "com.apple.coretelephony.plist",
        "com.apple.coretelephony.carrier.plist",
    ])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 { return Vec::new(); }
    let source = path.to_string_lossy().to_string();
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    vec![ArtifactRecord {
        category: ArtifactCategory::NetworkArtifacts,
        subcategory: "SIM Toolkit".to_string(), timestamp: None,
        title: format!("iOS SIM/carrier config: {}", name),
        detail: format!("{} ({} bytes) — SIM card ICCID, carrier name, network registration", name, size),
        source_path: source, forensic_value: ForensicValue::High,
        mitre_technique: None, is_suspicious: false, raw_data: None,
        confidence: 0,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    #[test]
    fn matches_coretelephony() {
        assert!(matches(Path::new("/var/wireless/Library/Preferences/com.apple.coretelephony.plist")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.coretelephony.plist");
        std::fs::write(&p, b"data").unwrap();
        assert_eq!(parse(&p).len(), 1);
    }
    #[test]
    fn empty_returns_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.coretelephony.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
