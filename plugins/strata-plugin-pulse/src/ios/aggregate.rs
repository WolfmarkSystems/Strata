//! iOS Aggregate Dictionary — `ADDataStore.sqlitedb`.
//!
//! iLEAPP keys off `scalars` (daily counters: unlock count, keyboard
//! usage, app opens) and `timedscalars` (timestamped counters). These
//! prove the device was in active use at specific times even when
//! per-app artifacts have been wiped.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["addatastore.sqlitedb"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    let source = path.to_string_lossy().to_string();
    let mut emitted = false;

    if util::table_exists(&conn, "scalars") {
        let count = util::count_rows(&conn, "scalars");
        out.push(ArtifactRecord {
            category: ArtifactCategory::UserActivity,
            subcategory: "Aggregate scalars".to_string(),
            timestamp: None,
            title: "iOS Aggregate Dictionary scalars".to_string(),
            detail: format!(
                "{} scalar rows (daily unlock count, keyboard usage, app launches)",
                count
            ),
            source_path: source.clone(),
            forensic_value: ForensicValue::High,
            mitre_technique: Some("T1005".to_string()),
            is_suspicious: false,
            raw_data: None,
            confidence: 0,
        });
        emitted = true;
    }
    if util::table_exists(&conn, "timedscalars") {
        let count = util::count_rows(&conn, "timedscalars");
        out.push(ArtifactRecord {
            category: ArtifactCategory::UserActivity,
            subcategory: "Aggregate timed scalars".to_string(),
            timestamp: None,
            title: "iOS Aggregate Dictionary timed scalars".to_string(),
            detail: format!("{} timedscalar rows (timestamped device counters)", count),
            source_path: source,
            forensic_value: ForensicValue::High,
            mitre_technique: Some("T1005".to_string()),
            is_suspicious: false,
            raw_data: None,
            confidence: 0,
        });
        emitted = true;
    }
    if !emitted {
        return Vec::new();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    fn make_ad(scalars: usize, timed: usize) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute(
            "CREATE TABLE scalars (key TEXT, value REAL, daynumber INTEGER)",
            [],
        )
        .unwrap();
        c.execute(
            "CREATE TABLE timedscalars (key TEXT, value REAL, secondsfromgmt REAL)",
            [],
        )
        .unwrap();
        for i in 0..scalars {
            c.execute(
                "INSERT INTO scalars VALUES (?1, 42.0, 19800)",
                rusqlite::params![format!("key{}", i)],
            )
            .unwrap();
        }
        for i in 0..timed {
            c.execute(
                "INSERT INTO timedscalars VALUES (?1, 1.0, 3600.0)",
                rusqlite::params![format!("ts{}", i)],
            )
            .unwrap();
        }
        tmp
    }

    #[test]
    fn matches_addatastore() {
        assert!(matches(Path::new(
            "/var/mobile/Library/AggregateDictionary/ADDataStore.sqlitedb"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_both_tables() {
        let tmp = make_ad(5, 3);
        let recs = parse(tmp.path());
        let s = recs
            .iter()
            .find(|r| r.subcategory == "Aggregate scalars")
            .unwrap();
        assert!(s.detail.contains("5 scalar"));
        let t = recs
            .iter()
            .find(|r| r.subcategory == "Aggregate timed scalars")
            .unwrap();
        assert!(t.detail.contains("3 timedscalar"));
    }

    #[test]
    fn no_tables_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(tmp.path()).is_empty());
    }
}
