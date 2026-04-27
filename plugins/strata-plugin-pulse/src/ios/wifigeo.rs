//! iOS Wi-Fi geolocation cache — `cache_encryptedA.db` /
//! `com.apple.wifid/` databases.
//!
//! Apple's Wi-Fi positioning cache maps BSSIDs to lat/lon. These
//! locations come from Apple's crowd-sourced database and prove the
//! device was in range of specific access points.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["cache_encrypteda.db", "cache_encryptedb.db"])
        || (util::path_contains(path, "wifid") && {
            let n = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            n.ends_with(".db") || n.ends_with(".sqlite")
        })
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    let source = path.to_string_lossy().to_string();

    for table in ["WifiLocation", "ZRTCLLOCATIONMO", "wifi_locations"] {
        if util::table_exists(&conn, table) {
            let count = util::count_rows(&conn, table);
            out.push(ArtifactRecord {
                category: ArtifactCategory::NetworkArtifacts,
                subcategory: "Wi-Fi geolocation".to_string(),
                timestamp: None,
                title: format!("iOS Wi-Fi geolocation cache ({})", table),
                detail: format!(
                    "{} {} rows — BSSID → lat/lon cache from Apple positioning",
                    count, table
                ),
                source_path: source.clone(),
                forensic_value: ForensicValue::Critical,
                mitre_technique: Some("T1430".to_string()),
                is_suspicious: false,
                raw_data: None,
                confidence: 0,
            });
            return out;
        }
    }

    // Fallback: table inventory
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
        category: ArtifactCategory::NetworkArtifacts,
        subcategory: "Wi-Fi geolocation".to_string(),
        timestamp: None,
        title: "iOS Wi-Fi positioning database".to_string(),
        detail: format!(
            "{} rows across {} tables — Wi-Fi BSSID location cache",
            total,
            tables.len()
        ),
        source_path: source,
        forensic_value: ForensicValue::High,
        mitre_technique: Some("T1430".to_string()),
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
    use tempfile::NamedTempFile;

    #[test]
    fn matches_wifi_geo_dbs() {
        assert!(matches(Path::new(
            "/var/root/Library/Caches/locationd/cache_encryptedA.db"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_known_wifi_location_table() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute(
            "CREATE TABLE WifiLocation (MAC TEXT, Latitude REAL, Longitude REAL)",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO WifiLocation VALUES ('aa:bb:cc:dd:ee:ff', 40.7, -74.0)",
            [],
        )
        .unwrap();
        let recs = parse(tmp.path());
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].forensic_value, ForensicValue::Critical);
    }

    #[test]
    fn empty_db_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let _c = Connection::open(tmp.path()).unwrap();
        assert!(parse(tmp.path()).is_empty());
    }
}
