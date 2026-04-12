//! iOS MobileAsset — OTA update history.
//!
//! `com.apple.MobileAsset/` databases track which OTA assets (iOS
//! updates, font downloads, ML models) were downloaded and when.
//! Proves the device was on a specific iOS version at a specific time.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::path_contains(path, "mobileasset") && {
        let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
        n.ends_with(".db") || n.ends_with(".sqlite") || n.ends_with(".plist")
    }
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
    let source = path.to_string_lossy().to_string();

    if n.ends_with(".db") || n.ends_with(".sqlite") {
        let Some(conn) = util::open_sqlite_ro(path) else { return Vec::new() };
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
            .and_then(|mut s| { let r = s.query_map([], |row| row.get::<_, String>(0))?; Ok(r.flatten().collect()) })
            .unwrap_or_default();
        if tables.is_empty() { return Vec::new(); }
        let mut total = 0_i64;
        for t in &tables { total += util::count_rows(&conn, t); }
        return vec![ArtifactRecord {
            category: ArtifactCategory::SystemActivity,
            subcategory: "MobileAsset".to_string(), timestamp: None,
            title: "iOS MobileAsset OTA update history".to_string(),
            detail: format!("{} rows — OTA downloads: iOS updates, ML models, fonts", total),
            source_path: source, forensic_value: ForensicValue::High,
            mitre_technique: None, is_suspicious: false, raw_data: None,
        }];
    }

    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 { return Vec::new(); }
    vec![ArtifactRecord {
        category: ArtifactCategory::SystemActivity,
        subcategory: "MobileAsset".to_string(), timestamp: None,
        title: "iOS MobileAsset config".to_string(),
        detail: format!("MobileAsset plist ({} bytes) — OTA update configuration + download history", size),
        source_path: source, forensic_value: ForensicValue::High,
        mitre_technique: None, is_suspicious: false, raw_data: None,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::tempdir;

    #[test]
    fn matches_mobileasset() {
        assert!(matches(Path::new("/var/MobileAsset/AssetsV2/store.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses_db() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("MobileAsset");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("store.db");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE assets (id INTEGER PRIMARY KEY, name TEXT)", []).unwrap();
        c.execute("INSERT INTO assets (name) VALUES ('iOS 18.2')", []).unwrap();
        assert_eq!(parse(&p).len(), 1);
    }
    #[test]
    fn empty_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("MobileAsset");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("config.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
