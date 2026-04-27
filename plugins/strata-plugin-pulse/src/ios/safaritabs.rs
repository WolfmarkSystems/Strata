//! iOS Safari open/closed tabs — `BrowserState.db`.
//!
//! `BrowserState.db` (iOS 10+) stores the active tab groups and
//! recently closed tabs. iLEAPP keys off `tabs` and `tab_sessions`
//! tables with `url`, `title`, `last_viewed_time` (Cocoa seconds).

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["browserstate.db"]) && util::path_contains(path, "/safari/")
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    let source = path.to_string_lossy().to_string();

    for table in ["tabs", "tab_sessions"] {
        if util::table_exists(&conn, table) {
            let count = util::count_rows(&conn, table);
            out.push(ArtifactRecord {
                category: ArtifactCategory::WebActivity,
                subcategory: format!("Safari {}", table),
                timestamp: None,
                title: format!("Safari open/closed {} table", table),
                detail: format!("{} {} rows (active + recently closed tabs)", count, table),
                source_path: source.clone(),
                forensic_value: ForensicValue::High,
                mitre_technique: Some("T1005".to_string()),
                is_suspicious: false,
                raw_data: None,
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
    fn matches_browserstate_in_safari() {
        assert!(matches(Path::new(
            "/var/mobile/Library/Safari/BrowserState.db"
        )));
        assert!(!matches(Path::new(
            "/var/mobile/Library/Other/BrowserState.db"
        )));
    }

    #[test]
    fn parses_tabs_table() {
        let dir = tempdir().unwrap();
        let safari = dir.path().join("Library").join("Safari");
        std::fs::create_dir_all(&safari).unwrap();
        let p = safari.join("BrowserState.db");
        let c = Connection::open(&p).unwrap();
        c.execute(
            "CREATE TABLE tabs (id INTEGER PRIMARY KEY, url TEXT, title TEXT)",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO tabs (url, title) VALUES ('https://a.com', 'A')",
            [],
        )
        .unwrap();
        let recs = parse(&p);
        assert!(recs.iter().any(|r| r.subcategory == "Safari tabs"));
    }

    #[test]
    fn no_known_tables_returns_empty() {
        let dir = tempdir().unwrap();
        let safari = dir.path().join("Library").join("Safari");
        std::fs::create_dir_all(&safari).unwrap();
        let p = safari.join("BrowserState.db");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(&p).is_empty());
    }
}
