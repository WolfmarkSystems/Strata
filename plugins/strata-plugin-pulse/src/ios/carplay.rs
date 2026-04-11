//! iOS CarPlay — `com.apple.carplay.plist`, `CarPlayState.db`.
//!
//! Records which vehicle the device paired with, when, and which
//! apps were used during driving. High forensic value for proving
//! device-in-vehicle at specific times.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["com.apple.carplay.plist"])
        || (util::path_contains(path, "carplay") && {
            let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
            n.ends_with(".db") || n.ends_with(".sqlite") || n.ends_with(".plist")
        })
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let source = path.to_string_lossy().to_string();
    let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();

    if n.ends_with(".db") || n.ends_with(".sqlite") {
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
                    subcategory: "CarPlay".to_string(), timestamp: None,
                    title: "iOS CarPlay database".to_string(),
                    detail: format!("{} rows across {} tables — vehicle pairing, driving session app usage", total, tables.len()),
                    source_path: source, forensic_value: ForensicValue::High,
                    mitre_technique: Some("T1005".to_string()), is_suspicious: false, raw_data: None,
                }];
            }
        }
        return Vec::new();
    }

    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 { return Vec::new(); }
    vec![ArtifactRecord {
        category: ArtifactCategory::UserActivity,
        subcategory: "CarPlay".to_string(), timestamp: None,
        title: "iOS CarPlay configuration".to_string(),
        detail: format!("CarPlay plist ({} bytes) — paired vehicles, app layout, driving sessions", size),
        source_path: source, forensic_value: ForensicValue::High,
        mitre_technique: Some("T1005".to_string()), is_suspicious: false, raw_data: None,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn matches_carplay_files() {
        assert!(matches(Path::new("/var/mobile/Library/Preferences/com.apple.carplay.plist")));
        assert!(matches(Path::new("/var/mobile/Library/CarPlay/state.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_plist_presence() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.carplay.plist");
        std::fs::write(&p, b"bplist00data").unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].detail.contains("paired vehicles"));
    }

    #[test]
    fn empty_file_returns_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.carplay.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
