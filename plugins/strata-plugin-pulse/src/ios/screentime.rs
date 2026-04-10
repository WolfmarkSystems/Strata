//! iOS Screen Time — `RMAdminStore-Local.sqlite`.
//!
//! Screen Time stores its on-device usage windows in `RMAdminStore`
//! (RemoteManagement) plus per-device CoreDuet stats. iLEAPP keys off:
//!   * `ZUSAGEBLOCK` / `ZUSAGECATEGORY` — daily breakdown by category
//!   * `ZUSAGE` — root row per usage day
//!   * `ZUSAGETIMEDITEM` — per-app/web foreground time
//!
//! Pulse v1.0 emits row counts for each table that exists. Per-app
//! breakdown is queued for v1.1 once the schema variants are mapped.

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

const SCREEN_TIME_DBS: &[&str] = &["rmadminstore-local.sqlite", "rmadminstore-cloud.sqlite"];

pub fn matches(path: &Path) -> bool {
    util::name_is(path, SCREEN_TIME_DBS)
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    let source = path.to_string_lossy().to_string();

    let interesting = [
        "ZUSAGEBLOCK",
        "ZUSAGECATEGORY",
        "ZUSAGE",
        "ZUSAGETIMEDITEM",
        "ZCATEGORY",
    ];

    let mut total = 0_i64;
    let mut hits = 0_usize;
    for table in interesting {
        if !util::table_exists(&conn, table) {
            continue;
        }
        hits += 1;
        let count = util::count_rows(&conn, table);
        total += count;
        out.push(ArtifactRecord {
            category: ArtifactCategory::UserActivity,
            subcategory: format!("Screen Time {}", table),
            timestamp: None,
            title: format!("Screen Time `{}`", table),
            detail: format!("{} rows in `{}`", count, table),
            source_path: source.clone(),
            forensic_value: ForensicValue::High,
            mitre_technique: Some("T1005".to_string()),
            is_suspicious: false,
            raw_data: None,
        });
    }

    if hits > 0 {
        out.push(ArtifactRecord {
            category: ArtifactCategory::UserActivity,
            subcategory: "Screen Time summary".to_string(),
            timestamp: None,
            title: "iOS Screen Time database".to_string(),
            detail: format!(
                "Screen Time database present, {} rows across {} tracked tables",
                total, hits
            ),
            source_path: source,
            forensic_value: ForensicValue::High,
            mitre_technique: None,
            is_suspicious: false,
            raw_data: None,
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    fn make_screen_time(rows: usize) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute(
            "CREATE TABLE ZUSAGEBLOCK (Z_PK INTEGER PRIMARY KEY, ZTOTALDURATION DOUBLE)",
            [],
        )
        .unwrap();
        c.execute(
            "CREATE TABLE ZUSAGETIMEDITEM (Z_PK INTEGER PRIMARY KEY, ZBUNDLEIDENTIFIER TEXT)",
            [],
        )
        .unwrap();
        for i in 0..rows {
            c.execute(
                "INSERT INTO ZUSAGEBLOCK (ZTOTALDURATION) VALUES (?1)",
                rusqlite::params![60.0_f64 + i as f64],
            )
            .unwrap();
            c.execute(
                "INSERT INTO ZUSAGETIMEDITEM (ZBUNDLEIDENTIFIER) VALUES (?1)",
                rusqlite::params![format!("com.example.{}", i)],
            )
            .unwrap();
        }
        tmp
    }

    #[test]
    fn matches_screen_time_filenames() {
        assert!(matches(Path::new(
            "/var/mobile/Library/Application Support/com.apple.remotemanagementd/RMAdminStore-Local.sqlite"
        )));
        assert!(matches(Path::new("/copies/RMAdminStore-Cloud.sqlite")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_known_tables_with_counts() {
        let tmp = make_screen_time(3);
        let records = parse(tmp.path());
        let block = records
            .iter()
            .find(|r| r.subcategory == "Screen Time ZUSAGEBLOCK")
            .expect("block record");
        assert!(block.detail.contains("3 rows"));
        let item = records
            .iter()
            .find(|r| r.subcategory == "Screen Time ZUSAGETIMEDITEM")
            .expect("item record");
        assert!(item.detail.contains("3 rows"));
        let summary = records
            .iter()
            .find(|r| r.subcategory == "Screen Time summary")
            .expect("summary record");
        assert!(summary.detail.contains("6 rows across 2"));
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

    #[test]
    fn empty_known_tables_still_summarises() {
        let tmp = make_screen_time(0);
        let records = parse(tmp.path());
        assert!(records
            .iter()
            .any(|r| r.subcategory == "Screen Time summary"));
    }
}
