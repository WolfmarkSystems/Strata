//! iOS deleted app remnants — `com.apple.LaunchServices/`
//! `ApplicationWorkspace.sqlite`, `iTunesMetadata.plist`.
//!
//! Even after an app is uninstalled, metadata remnants persist in
//! LaunchServices and `<BundleMetadata.plist>`. This parser detects
//! those remnants, proving an app was once installed.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["applicationworkspace.sqlite"])
        || (util::path_contains(path, "launchservices") && {
            let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
            n.ends_with(".db") || n.ends_with(".sqlite")
        })
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else { return out };
    let source = path.to_string_lossy().to_string();

    for (table, label) in [
        ("application_identifier", "registered app identifiers (includes deleted)"),
        ("application_state", "app lifecycle states"),
        ("plugin", "app extension plugins"),
    ] {
        if util::table_exists(&conn, table) {
            let count = util::count_rows(&conn, table);
            out.push(ArtifactRecord {
                category: ArtifactCategory::ExecutionHistory,
                subcategory: format!("Deleted app remnants {}", table),
                timestamp: None,
                title: format!("iOS LaunchServices: {}", label),
                detail: format!("{} {} rows — {}", count, table, label),
                source_path: source.clone(), forensic_value: ForensicValue::High,
                mitre_technique: Some("T1070".to_string()), is_suspicious: false, raw_data: None,
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
    fn matches_launchservices() {
        assert!(matches(Path::new("/var/mobile/Library/FrontBoard/ApplicationWorkspace.sqlite")));
        assert!(matches(Path::new("/var/mobile/Library/LaunchServices/data.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_app_identifiers() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("LaunchServices");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("data.db");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE application_identifier (id INTEGER PRIMARY KEY, bundle TEXT)", []).unwrap();
        c.execute("INSERT INTO application_identifier (bundle) VALUES ('com.deleted.app')", []).unwrap();
        let recs = parse(&p);
        assert!(recs.iter().any(|r| r.subcategory.contains("application_identifier")));
    }

    #[test]
    fn no_known_tables_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("LaunchServices");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("data.db");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(&p).is_empty());
    }
}
