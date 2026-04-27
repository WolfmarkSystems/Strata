//! iOS AirDrop — `com.apple.sharingd.plist`, `Recents.db`.
//!
//! AirDrop transfers are logged by `sharingd`. iLEAPP keys off the
//! plist for discovery/transfer records and `Recents.db` for
//! received-item history.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["com.apple.sharingd.plist"])
        || (util::name_is(path, &["recents.db"]) && util::path_contains(path, "sharingd"))
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 {
        return Vec::new();
    }
    let source = path.to_string_lossy().to_string();
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    // Try SQLite for Recents.db
    if name.eq_ignore_ascii_case("recents.db") {
        if let Some(conn) = util::open_sqlite_ro(path) {
            let tables: Vec<String> = conn
                .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
                .and_then(|mut s| { let r = s.query_map([], |row| row.get::<_, String>(0))?; Ok(r.flatten().collect()) })
                .unwrap_or_default();
            if !tables.is_empty() {
                let mut total = 0_i64;
                for t in &tables {
                    total += util::count_rows(&conn, t);
                }
                return vec![ArtifactRecord {
                    category: ArtifactCategory::UserActivity,
                    subcategory: "AirDrop".to_string(),
                    timestamp: None,
                    title: "AirDrop transfer history".to_string(),
                    detail: format!(
                        "{} rows across {} tables in Recents.db",
                        total,
                        tables.len()
                    ),
                    source_path: source,
                    forensic_value: ForensicValue::High,
                    mitre_technique: Some("T1011".to_string()),
                    is_suspicious: false,
                    raw_data: None,
                    confidence: 0,
                }];
            }
        }
    }

    vec![ArtifactRecord {
        category: ArtifactCategory::UserActivity,
        subcategory: "AirDrop".to_string(),
        timestamp: None,
        title: "AirDrop sharingd plist".to_string(),
        detail: format!(
            "{} ({} bytes) — AirDrop discovery and transfer records",
            name, size
        ),
        source_path: source,
        forensic_value: ForensicValue::High,
        mitre_technique: Some("T1011".to_string()),
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
    fn matches_airdrop_files() {
        assert!(matches(Path::new(
            "/var/mobile/Library/Preferences/com.apple.sharingd.plist"
        )));
        assert!(matches(Path::new(
            "/var/mobile/Library/Application Support/com.apple.sharingd/Recents.db"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_plist_presence() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.sharingd.plist");
        std::fs::write(&p, b"bplist00data").unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].detail.contains("AirDrop"));
    }

    #[test]
    fn empty_file_returns_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.sharingd.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
