//! iOS App Clips — `AppClip` metadata.
//!
//! App Clips are lightweight app interactions triggered by NFC tags,
//! QR codes, or Safari links. They record which real-world locations
//! or businesses the user interacted with.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    util::path_contains(path, "appclip") && {
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
                    subcategory: "App Clips".to_string(),
                    timestamp: None,
                    title: "iOS App Clips interaction history".to_string(),
                    detail: format!(
                        "{} rows — NFC/QR/link-triggered app interactions at businesses",
                        total
                    ),
                    source_path: source,
                    forensic_value: ForensicValue::High,
                    mitre_technique: Some("T1430".to_string()),
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
        subcategory: "App Clips".to_string(),
        timestamp: None,
        title: "iOS App Clips config".to_string(),
        detail: format!("{} ({} bytes) — App Clip invocation history", name, size),
        source_path: source,
        forensic_value: ForensicValue::High,
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
    fn matches_appclip() {
        assert!(matches(Path::new("/var/mobile/Library/AppClip/store.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses_plist() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("AppClip");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("config.plist");
        std::fs::write(&p, b"data").unwrap();
        assert_eq!(parse(&p).len(), 1);
    }
    #[test]
    fn empty_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("AppClip");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("config.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
