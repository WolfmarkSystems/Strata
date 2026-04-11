//! iOS DataUsage — `com.apple.networkd/DataUsage.sqlite` (extended).
//!
//! Distinct from `cellular.rs` which targets `DataUsage.sqlite` under
//! `/wireless/`. This parser targets the `networkd` variant which has
//! `ZPROCESS` with `ZPROCNAME`, `ZFIRSTTIMESTAMP`, `ZTIMESTAMP`
//! (Cocoa), `ZWIFIIN`, `ZWIFIOUT`, `ZWWANIN`, `ZWWANOUT`. Proves
//! which apps used network and when.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["datausage.sqlite"])
        && util::path_contains(path, "networkd")
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else { return out };
    if !util::table_exists(&conn, "ZPROCESS") { return out; }
    let source = path.to_string_lossy().to_string();
    let count = util::count_rows(&conn, "ZPROCESS");

    let ts = conn
        .prepare("SELECT MIN(ZFIRSTTIMESTAMP), MAX(ZTIMESTAMP) FROM ZPROCESS WHERE ZFIRSTTIMESTAMP IS NOT NULL")
        .and_then(|mut s| s.query_row([], |r| Ok((r.get::<_, Option<f64>>(0)?, r.get::<_, Option<f64>>(1)?))))
        .unwrap_or((None, None));
    let first = ts.0.and_then(util::cf_absolute_to_unix);
    let last = ts.1.and_then(util::cf_absolute_to_unix);

    out.push(ArtifactRecord {
        category: ArtifactCategory::NetworkArtifacts,
        subcategory: "DataUsage networkd".to_string(),
        timestamp: first,
        title: "iOS per-app network usage (networkd)".to_string(),
        detail: format!(
            "{} ZPROCESS rows — per-app WiFi/cellular byte counts, range {:?}..{:?} Unix",
            count, first, last
        ),
        source_path: source,
        forensic_value: ForensicValue::High,
        mitre_technique: Some("T1011".to_string()),
        is_suspicious: false,
        raw_data: None,
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::tempdir;

    #[test]
    fn matches_networkd_datausage() {
        assert!(matches(Path::new("/var/networkd/Library/com.apple.networkd/DataUsage.sqlite")));
        assert!(!matches(Path::new("/var/wireless/Library/Databases/DataUsage.sqlite")));
    }

    #[test]
    fn parses_process_count_and_range() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("com.apple.networkd");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("DataUsage.sqlite");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE ZPROCESS (Z_PK INTEGER PRIMARY KEY, ZPROCNAME TEXT, ZFIRSTTIMESTAMP DOUBLE, ZTIMESTAMP DOUBLE, ZWIFIIN INTEGER, ZWWANIN INTEGER)", []).unwrap();
        c.execute("INSERT INTO ZPROCESS (ZPROCNAME, ZFIRSTTIMESTAMP, ZTIMESTAMP, ZWIFIIN, ZWWANIN) VALUES ('Safari', 700000000.0, 700100000.0, 1024, 512)", []).unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].detail.contains("1 ZPROCESS"));
        assert_eq!(recs[0].timestamp, Some(700_000_000 + util::APPLE_EPOCH_OFFSET));
    }

    #[test]
    fn missing_zprocess_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("com.apple.networkd");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("DataUsage.sqlite");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(&p).is_empty());
    }
}
