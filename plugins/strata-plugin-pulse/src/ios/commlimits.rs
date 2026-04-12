//! iOS Communication Limits (Screen Time) — contact allow/block lists.
//!
//! Parents can restrict which contacts a child can communicate with.
//! The allow/deny list is stored in Screen Time's managed
//! configuration. Relevant in child exploitation + custody cases.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &[
        "com.apple.screentime.communicationlimits.plist",
        "communicationlimits.db",
    ]) || (util::path_contains(path, "communicationlimit") && {
        let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
        n.ends_with(".plist") || n.ends_with(".db")
    })
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size == 0 { return Vec::new(); }
    let source = path.to_string_lossy().to_string();
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

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
                    subcategory: "Communication limits".to_string(), timestamp: None,
                    title: "iOS Communication Limits database".to_string(),
                    detail: format!("{} rows — Screen Time allowed/blocked contact lists", total),
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
        subcategory: "Communication limits".to_string(), timestamp: None,
        title: "iOS Communication Limits plist".to_string(),
        detail: format!("{} ({} bytes) — Screen Time allowed/blocked contacts for child accounts", name, size),
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
    fn matches_comm_limits() {
        assert!(matches(Path::new("/var/mobile/Library/Preferences/com.apple.screentime.communicationlimits.plist")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses_plist() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.screentime.communicationlimits.plist");
        std::fs::write(&p, b"bplist00data").unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].detail.contains("allowed/blocked contacts"));
    }
    #[test]
    fn empty_returns_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("com.apple.screentime.communicationlimits.plist");
        std::fs::write(&p, b"").unwrap();
        assert!(parse(&p).is_empty());
    }
}
