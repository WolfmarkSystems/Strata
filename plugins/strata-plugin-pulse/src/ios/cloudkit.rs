//! iOS CloudKit — `cloudkit_cache.sqlite` / `CloudKitMetadata`.
//!
//! iCloud sharing activity: shared albums, documents, collaboration.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["cloudkit_cache.sqlite", "cloudkitmetadata"])
        && util::path_contains(path, "cloudkit")
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    let source = path.to_string_lossy().to_string();
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        .and_then(|mut s| {
            let r = s.query_map([], |row| row.get::<_, String>(0))?;
            Ok(r.flatten().collect())
        })
        .unwrap_or_default();
    if tables.is_empty() {
        return out;
    }
    let mut total = 0_i64;
    for t in &tables {
        total += util::count_rows(&conn, t);
    }
    out.push(ArtifactRecord {
        category: ArtifactCategory::CloudSync,
        subcategory: "CloudKit".to_string(),
        timestamp: None,
        title: "iOS CloudKit cache".to_string(),
        detail: format!(
            "{} rows across {} tables — iCloud sharing, collaboration records",
            total,
            tables.len()
        ),
        source_path: source,
        forensic_value: ForensicValue::High,
        mitre_technique: Some("T1530".to_string()),
        is_suspicious: false,
        raw_data: None,
        confidence: 0,
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::tempdir;

    #[test]
    fn matches_cloudkit_paths() {
        assert!(matches(Path::new(
            "/var/mobile/Library/Caches/CloudKit/cloudkit_cache.sqlite"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_rows() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("CloudKit");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("cloudkit_cache.sqlite");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE cached_records (id TEXT, recordType TEXT)", [])
            .unwrap();
        c.execute("INSERT INTO cached_records VALUES ('r1', 'Note')", [])
            .unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
    }

    #[test]
    fn empty_db_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("CloudKit");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("cloudkit_cache.sqlite");
        let _c = Connection::open(&p).unwrap();
        assert!(parse(&p).is_empty());
    }
}
