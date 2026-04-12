//! iOS CloudKit sync state — `CloudKitSyncState.db`,
//! `com.apple.cloudkit.*/sync*.db`.
//!
//! Tracks which records were synced to iCloud and when. Reveals what
//! data was pushed to the cloud (and therefore discoverable server-side).

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["cloudkitsyncstate.db"])
        || (util::path_contains(path, "cloudkit") && {
            let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
            n.contains("sync") && (n.ends_with(".db") || n.ends_with(".sqlite"))
        })
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else { return out };
    let source = path.to_string_lossy().to_string();
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        .and_then(|mut s| { let r = s.query_map([], |row| row.get::<_, String>(0))?; Ok(r.flatten().collect()) })
        .unwrap_or_default();
    if tables.is_empty() { return out; }
    let mut total = 0_i64;
    for t in &tables { total += util::count_rows(&conn, t); }
    out.push(ArtifactRecord {
        category: ArtifactCategory::CloudSync,
        subcategory: "CloudKit sync state".to_string(), timestamp: None,
        title: "iOS CloudKit sync state".to_string(),
        detail: format!("{} rows — record-level iCloud sync tracking, reveals what was pushed to cloud", total),
        source_path: source, forensic_value: ForensicValue::High,
        mitre_technique: Some("T1530".to_string()), is_suspicious: false, raw_data: None,
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    #[test]
    fn matches_cloudkit_sync() {
        assert!(matches(Path::new("/var/mobile/Library/CloudKit/CloudKitSyncState.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses_rows() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE sync_state (id TEXT PRIMARY KEY, modified DOUBLE)", []).unwrap();
        c.execute("INSERT INTO sync_state VALUES ('r1', 700000000.0)", []).unwrap();
        assert_eq!(parse(tmp.path()).len(), 1);
    }
    #[test]
    fn empty_db_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let _c = Connection::open(tmp.path()).unwrap();
        assert!(parse(tmp.path()).is_empty());
    }
}
