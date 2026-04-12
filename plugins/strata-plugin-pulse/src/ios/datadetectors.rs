//! iOS DataDetectors — `com.apple.datadetectors.plist` and cache.
//!
//! Data Detectors recognize phone numbers, addresses, dates, and
//! flight numbers in text. The cache retains detected data even after
//! the source message/email is deleted.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::path_contains(path, "datadetectors") && {
        let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
        n.ends_with(".db") || n.ends_with(".sqlite") || n.ends_with(".plist")
    }
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 { return Vec::new(); }
    let source = path.to_string_lossy().to_string();

    if let Some(conn) = util::open_sqlite_ro(path) {
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
            .and_then(|mut s| { let r = s.query_map([], |row| row.get::<_, String>(0))?; Ok(r.flatten().collect()) })
            .unwrap_or_default();
        if !tables.is_empty() {
            let mut total = 0_i64;
            for t in &tables { total += util::count_rows(&conn, t); }
            return vec![ArtifactRecord {
                category: ArtifactCategory::UserActivity,
                subcategory: "DataDetectors".to_string(), timestamp: None,
                title: "iOS DataDetectors cache".to_string(),
                detail: format!("{} rows — detected phone numbers, addresses, dates, flights from messages/email", total),
                source_path: source, forensic_value: ForensicValue::High,
                mitre_technique: Some("T1005".to_string()), is_suspicious: false, raw_data: None,
                confidence: 0,
            }];
        }
    }

    vec![ArtifactRecord {
        category: ArtifactCategory::UserActivity,
        subcategory: "DataDetectors".to_string(), timestamp: None,
        title: "iOS DataDetectors plist".to_string(),
        detail: format!("DataDetectors data ({} bytes) — auto-detected entities cache", size),
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
    fn matches_datadetectors() {
        assert!(matches(Path::new("/var/mobile/Library/DataDetectors/cache.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses_plist() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("DataDetectors");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("cache.plist");
        std::fs::write(&p, b"data").unwrap();
        assert_eq!(parse(&p).len(), 1);
    }
    #[test]
    fn empty_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("DataDetectors");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("cache.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
