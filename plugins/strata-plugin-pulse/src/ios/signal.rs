//! iOS Signal — `signal.sqlite` / `Signal.sqlite`.
//!
//! Signal is end-to-end encrypted with SQLCipher; the on-device
//! database is unreadable without the SQLCipher key extracted from
//! Signal's keychain entry. Pulse v1.0 reports presence + size only —
//! decryption requires keychain access and is queued for the v1.1
//! Cipher integration.

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["signal.sqlite", "signal.db"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 {
        return Vec::new();
    }
    let source = path.to_string_lossy().to_string();
    vec![ArtifactRecord {
        category: ArtifactCategory::Communications,
        subcategory: "Signal (encrypted)".to_string(),
        timestamp: None,
        title: "Signal messenger database".to_string(),
        detail: format!(
            "Signal database present at {} ({} bytes) — SQLCipher-encrypted, key required",
            source, size
        ),
        source_path: source,
        forensic_value: ForensicValue::Critical,
        mitre_technique: Some("T1005".to_string()),
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
    fn matches_signal_filenames() {
        assert!(matches(Path::new(
            "/var/mobile/Library/Signal/signal.sqlite"
        )));
        assert!(matches(Path::new("/var/mobile/Library/Signal/signal.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_size_into_summary() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("signal.sqlite");
        std::fs::write(&p, b"sqlcipher-encrypted-blob").unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].forensic_value, ForensicValue::Critical);
        assert!(recs[0].detail.contains("SQLCipher"));
    }

    #[test]
    fn empty_file_returns_no_records() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("signal.sqlite");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
