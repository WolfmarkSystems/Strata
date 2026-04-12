//! iOS Focus Mode (iOS 15+) — `com.apple.donotdisturb.plist`,
//! Focus configuration databases.
//!
//! Tracks when DND / Driving / Sleep / Work focus modes were active.
//! Proves the user set a specific focus (e.g., "Driving" active =
//! device owner was driving at that time).

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &[
        "com.apple.donotdisturb.plist",
        "com.apple.focus.plist",
    ]) || (util::path_contains(path, "focus") && util::name_is(path, &["modeconfigurations.db"]))
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 { return Vec::new(); }
    let source = path.to_string_lossy().to_string();
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    // Try SQLite first for ModeConfigurations.db
    if name.to_ascii_lowercase().ends_with(".db") {
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
                    subcategory: "Focus Mode".to_string(), timestamp: None,
                    title: "iOS Focus Mode configuration".to_string(),
                    detail: format!("{} rows — DND, Driving, Sleep, Work focus mode history", total),
                    source_path: source, forensic_value: ForensicValue::High,
                    mitre_technique: None, is_suspicious: false, raw_data: None,
                    confidence: 0,
                }];
            }
        }
        return Vec::new();
    }

    vec![ArtifactRecord {
        category: ArtifactCategory::UserActivity,
        subcategory: "Focus Mode".to_string(), timestamp: None,
        title: format!("iOS Focus/DND settings: {}", name),
        detail: format!("{} ({} bytes) — Do Not Disturb / Focus mode schedule + activation log", name, size),
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
    fn matches_focus_files() {
        assert!(matches(Path::new("/var/mobile/Library/Preferences/com.apple.donotdisturb.plist")));
        assert!(matches(Path::new("/var/mobile/Library/Preferences/com.apple.focus.plist")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_plist() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.donotdisturb.plist");
        std::fs::write(&p, b"bplist00data").unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].detail.contains("Do Not Disturb"));
    }

    #[test]
    fn empty_returns_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.donotdisturb.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
