//! iOS routined / Significant Locations.
//!
//! `routined` is the iOS daemon that tracks "Significant Locations" /
//! "Frequent Locations". The two databases iLEAPP keys off:
//!   * `Cache.sqlite`            — recent learned visits
//!   * `Local.sqlite`            — local history (iOS 11+)
//!   * `Cloud.sqlite`            — iCloud-synced significant locations
//!
//! All three live under `*/Caches/com.apple.routined/`. The schemas
//! diverge across iOS releases — Pulse v1.0 just enumerates the tables
//! that exist plus their row counts. The lat/lon extraction is queued
//! for v1.1.

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

pub fn matches(path: &Path) -> bool {
    let names = ["cache.sqlite", "local.sqlite", "cloud.sqlite"];
    if !util::name_is(path, &names) {
        return false;
    }
    util::path_contains(path, "/com.apple.routined/")
        || util::path_contains(path, "/routined/")
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    let source = path.to_string_lossy().to_string();

    let interesting = [
        "ZRTLEARNEDLOCATIONOFINTERESTMO",
        "ZRTLEARNEDLOCATIONOFINTERESTVISITMO",
        "ZRTHINTMO",
        "ZRTSIGNIFICANTEVENTMO",
        "ZRTLEARNEDPLACEMO",
    ];

    let mut found_any = false;
    for table in interesting {
        if !util::table_exists(&conn, table) {
            continue;
        }
        found_any = true;
        let count = util::count_rows(&conn, table);
        out.push(ArtifactRecord {
            category: ArtifactCategory::UserActivity,
            subcategory: format!("Location {}", table),
            timestamp: None,
            title: format!("routined `{}`", table),
            detail: format!("{} rows in routined `{}`", count, table),
            source_path: source.clone(),
            forensic_value: ForensicValue::High,
            mitre_technique: Some("T1430".to_string()),
            is_suspicious: false,
            raw_data: None,
        });
    }

    if found_any {
        out.push(ArtifactRecord {
            category: ArtifactCategory::UserActivity,
            subcategory: "Location summary".to_string(),
            timestamp: None,
            title: "iOS Significant Locations database".to_string(),
            detail: format!(
                "routined database present at {} — Significant Locations / Frequent Locations",
                source
            ),
            source_path: source,
            forensic_value: ForensicValue::High,
            mitre_technique: Some("T1430".to_string()),
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
    use tempfile::tempdir;

    fn make_routined(dir: &Path, name: &str, table: &str, rows: usize) -> std::path::PathBuf {
        let routined = dir.join("Library").join("Caches").join("com.apple.routined");
        std::fs::create_dir_all(&routined).unwrap();
        let p = routined.join(name);
        let c = Connection::open(&p).unwrap();
        c.execute(
            &format!(
                "CREATE TABLE {} (Z_PK INTEGER PRIMARY KEY, ZLATITUDE DOUBLE, ZLONGITUDE DOUBLE)",
                table
            ),
            [],
        )
        .unwrap();
        for _ in 0..rows {
            c.execute(
                &format!("INSERT INTO {} (ZLATITUDE, ZLONGITUDE) VALUES (40.7, -74.0)", table),
                [],
            )
            .unwrap();
        }
        p
    }

    #[test]
    fn matches_routined_files_only() {
        assert!(matches(Path::new(
            "/var/mobile/Library/Caches/com.apple.routined/Cache.sqlite"
        )));
        assert!(matches(Path::new(
            "/var/mobile/Library/Caches/com.apple.routined/Cloud.sqlite"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/Other/Cache.sqlite")));
    }

    #[test]
    fn parses_known_table_with_count() {
        let dir = tempdir().unwrap();
        let p = make_routined(dir.path(), "Cache.sqlite", "ZRTLEARNEDLOCATIONOFINTERESTMO", 5);
        let records = parse(&p);
        let table_rec = records
            .iter()
            .find(|r| r.subcategory == "Location ZRTLEARNEDLOCATIONOFINTERESTMO")
            .expect("learned location record");
        assert!(table_rec.detail.contains("5 rows"));
        assert_eq!(table_rec.mitre_technique.as_deref(), Some("T1430"));

        let summary = records
            .iter()
            .find(|r| r.subcategory == "Location summary")
            .expect("summary record");
        assert!(summary.detail.contains("routined database present"));
    }

    #[test]
    fn unrecognised_schema_returns_empty() {
        let dir = tempdir().unwrap();
        let routined = dir.path().join("Library").join("Caches").join("com.apple.routined");
        std::fs::create_dir_all(&routined).unwrap();
        let p = routined.join("Cache.sqlite");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        let records = parse(&p);
        assert!(records.is_empty());
    }

    #[test]
    fn parses_multiple_tables_in_same_db() {
        let dir = tempdir().unwrap();
        let p = make_routined(dir.path(), "Local.sqlite", "ZRTHINTMO", 3);
        // Add a second known table by reopening rw.
        {
            let c = Connection::open(&p).unwrap();
            c.execute(
                "CREATE TABLE ZRTSIGNIFICANTEVENTMO (Z_PK INTEGER PRIMARY KEY)",
                [],
            )
            .unwrap();
            c.execute("INSERT INTO ZRTSIGNIFICANTEVENTMO DEFAULT VALUES", [])
                .unwrap();
        }
        let records = parse(&p);
        assert!(records
            .iter()
            .any(|r| r.subcategory == "Location ZRTHINTMO"));
        assert!(records
            .iter()
            .any(|r| r.subcategory == "Location ZRTSIGNIFICANTEVENTMO"));
    }
}
