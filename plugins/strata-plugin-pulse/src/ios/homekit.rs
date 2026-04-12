//! iOS HomeKit — `HomeKit` databases and plists.
//!
//! HomeKit logs every smart-home device interaction: door locks,
//! cameras, lights, thermostats. Proves device proximity + user
//! actions (e.g., "door was unlocked at 2:30 AM").

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::path_contains(path, "homekit") && {
        let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
        n.ends_with(".db") || n.ends_with(".sqlite") || n.ends_with(".plist")
    }
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
                    subcategory: "HomeKit".to_string(), timestamp: None,
                    title: "iOS HomeKit smart home database".to_string(),
                    detail: format!("{} rows across {} tables — device events, automations, scenes", total, tables.len()),
                    source_path: source, forensic_value: ForensicValue::Critical,
                    mitre_technique: Some("T1005".to_string()), is_suspicious: false, raw_data: None,
                    confidence: 0,
                }];
            }
        }
        return Vec::new();
    }

    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 { return Vec::new(); }
    vec![ArtifactRecord {
        category: ArtifactCategory::UserActivity,
        subcategory: "HomeKit".to_string(), timestamp: None,
        title: "iOS HomeKit configuration".to_string(),
        detail: format!("HomeKit plist ({} bytes) — smart home devices, rooms, automations", size),
        source_path: source, forensic_value: ForensicValue::Critical,
        mitre_technique: Some("T1005".to_string()), is_suspicious: false, raw_data: None,
        confidence: 0,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::tempdir;

    #[test]
    fn matches_homekit() {
        assert!(matches(Path::new("/var/mobile/Library/HomeKit/store.db")));
        assert!(matches(Path::new("/var/mobile/Library/HomeKit/config.plist")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_sqlite_rows() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("HomeKit");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("store.db");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, device TEXT, action TEXT, ts REAL)", []).unwrap();
        c.execute("INSERT INTO events (device, action, ts) VALUES ('Front Door Lock', 'unlock', 700000000.0)", []).unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].forensic_value, ForensicValue::Critical);
    }

    #[test]
    fn empty_plist_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("HomeKit");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("config.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
