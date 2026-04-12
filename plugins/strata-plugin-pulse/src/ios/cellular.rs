//! iOS cellular data usage — `DataUsage.sqlite` /
//! `dataUsage.sqlite` / `Cellular_Usage.db`.
//!
//! iOS records per-app cellular and Wi-Fi byte counts under
//! `Library/Databases/`. iLEAPP keys off `ZPROCESS` (process name) and
//! `ZLIVEUSAGE` (running totals). Pulse v1.0 reports row counts for
//! both tables.

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(
        path,
        &["datausage.sqlite", "datausage.sqlite-wal", "cellular_usage.db"],
    )
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    let source = path.to_string_lossy().to_string();

    let mut emitted = false;
    for (table, label) in [
        ("ZPROCESS", "data-usage processes"),
        ("ZLIVEUSAGE", "data-usage rolling totals"),
    ] {
        if util::table_exists(&conn, table) {
            let n = util::count_rows(&conn, table);
            out.push(ArtifactRecord {
                category: ArtifactCategory::NetworkArtifacts,
                subcategory: format!("Data usage {}", table),
                timestamp: None,
                title: format!("iOS {}", label),
                detail: format!("{} rows in `{}`", n, table),
                source_path: source.clone(),
                forensic_value: ForensicValue::Medium,
                mitre_technique: Some("T1011".to_string()),
                is_suspicious: false,
                raw_data: None,
                confidence: 0,
            });
            emitted = true;
        }
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

    fn make_db(processes: usize) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE ZPROCESS (Z_PK INTEGER PRIMARY KEY, ZPROCNAME TEXT)", [])
            .unwrap();
        c.execute("CREATE TABLE ZLIVEUSAGE (Z_PK INTEGER PRIMARY KEY, ZWWANIN INTEGER, ZWWANOUT INTEGER)", [])
            .unwrap();
        for i in 0..processes {
            c.execute(
                "INSERT INTO ZPROCESS (ZPROCNAME) VALUES (?1)",
                rusqlite::params![format!("/usr/bin/proc{}", i)],
            )
            .unwrap();
            c.execute(
                "INSERT INTO ZLIVEUSAGE (ZWWANIN, ZWWANOUT) VALUES (?1, ?2)",
                rusqlite::params![1024 * (i as i64 + 1), 256 * (i as i64 + 1)],
            )
            .unwrap();
        }
        tmp
    }

    #[test]
    fn matches_known_filenames() {
        assert!(matches(Path::new("/var/wireless/Library/Databases/DataUsage.sqlite")));
        assert!(matches(Path::new("/copies/Cellular_Usage.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_zprocess_and_zliveusage_counts() {
        let tmp = make_db(3);
        let recs = parse(tmp.path());
        let p = recs.iter().find(|r| r.subcategory == "Data usage ZPROCESS").unwrap();
        assert!(p.detail.contains("3 rows"));
        let l = recs.iter().find(|r| r.subcategory == "Data usage ZLIVEUSAGE").unwrap();
        assert!(l.detail.contains("3 rows"));
    }

    #[test]
    fn unknown_schema_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        {
            let c = Connection::open(tmp.path()).unwrap();
            c.execute("CREATE TABLE other (x INT)", []).unwrap();
        }
        assert!(parse(tmp.path()).is_empty());
    }
}
