//! iOS Fall Detection — `com.apple.WatchSafetyService/` logs.
//!
//! Apple Watch Series 4+ records fall events with timestamp,
//! location, and whether Emergency SOS was auto-triggered. Proves
//! the user experienced a physical fall at a specific time/place.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    (util::path_contains(path, "watchsafety") || util::path_contains(path, "falldetection")) && {
        let n = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        n.ends_with(".db") || n.ends_with(".sqlite") || n.ends_with(".plist")
    }
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 {
        return Vec::new();
    }
    let source = path.to_string_lossy().to_string();
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    if name.to_ascii_lowercase().ends_with(".db") || name.to_ascii_lowercase().ends_with(".sqlite")
    {
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
                    subcategory: "Fall Detection".to_string(),
                    timestamp: None,
                    title: "Apple Watch fall detection log".to_string(),
                    detail: format!(
                        "{} rows — fall events with timestamp, location, SOS trigger state",
                        total
                    ),
                    source_path: source,
                    forensic_value: ForensicValue::Critical,
                    mitre_technique: None,
                    is_suspicious: false,
                    raw_data: None,
                    confidence: 0,
                }];
            }
        }
        return Vec::new();
    }

    vec![ArtifactRecord {
        category: ArtifactCategory::UserActivity,
        subcategory: "Fall Detection".to_string(),
        timestamp: None,
        title: "Apple Watch fall detection plist".to_string(),
        detail: format!(
            "{} ({} bytes) — fall event records, crash detection config",
            name, size
        ),
        source_path: source,
        forensic_value: ForensicValue::Critical,
        mitre_technique: None,
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
    fn matches_fall_detection() {
        assert!(matches(Path::new(
            "/var/mobile/Library/WatchSafetyService/events.db"
        )));
        assert!(matches(Path::new(
            "/var/mobile/Library/FallDetection/config.plist"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses_plist() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("WatchSafetyService");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("config.plist");
        std::fs::write(&p, b"bplist00data").unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].forensic_value, ForensicValue::Critical);
    }
    #[test]
    fn empty_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("WatchSafetyService");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("config.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
