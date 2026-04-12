//! iOS iCloud Tabs — `CloudTabs.db`.
//!
//! Synced open tabs from other devices (Mac, iPad). Shows what the
//! user was browsing on all their Apple devices.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["cloudtabs.db"]) && util::path_contains(path, "/safari/")
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else { return out };
    let source = path.to_string_lossy().to_string();

    for table in ["cloud_tabs", "cloud_tab_devices"] {
        if util::table_exists(&conn, table) {
            let count = util::count_rows(&conn, table);
            out.push(ArtifactRecord {
                category: ArtifactCategory::WebActivity,
                subcategory: format!("iCloud Tabs {}", table),
                timestamp: None,
                title: format!("iCloud synced tabs ({})", table),
                detail: format!("{} {} rows — tabs open on other Apple devices", count, table),
                source_path: source.clone(), forensic_value: ForensicValue::High,
                mitre_technique: Some("T1005".to_string()), is_suspicious: false, raw_data: None,
                confidence: 0,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::tempdir;

    #[test]
    fn matches_cloudtabs() {
        assert!(matches(Path::new("/var/mobile/Library/Safari/CloudTabs.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/CloudTabs.db")));
    }
    #[test]
    fn parses_tabs() {
        let dir = tempdir().unwrap();
        let safari = dir.path().join("Library").join("Safari");
        std::fs::create_dir_all(&safari).unwrap();
        let p = safari.join("CloudTabs.db");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE cloud_tabs (tab_uuid TEXT, url TEXT, title TEXT)", []).unwrap();
        c.execute("INSERT INTO cloud_tabs VALUES ('u1', 'https://a.com', 'A')", []).unwrap();
        let recs = parse(&p);
        assert!(recs.iter().any(|r| r.subcategory.contains("cloud_tabs")));
    }
    #[test]
    fn no_tables_returns_empty() {
        let dir = tempdir().unwrap();
        let safari = dir.path().join("Library").join("Safari");
        std::fs::create_dir_all(&safari).unwrap();
        let p = safari.join("CloudTabs.db");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(&p).is_empty());
    }
}
