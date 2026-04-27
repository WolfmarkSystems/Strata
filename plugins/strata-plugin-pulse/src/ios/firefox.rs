//! Firefox iOS — `browser.db` under `*firefox*` / `*org.mozilla*`.
//!
//! Firefox iOS uses `browser.db` with `history`, `visits`, `bookmarks`.
//! Same forensic value as Chrome/Safari history.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    let scope = util::path_contains(path, "firefox") || util::path_contains(path, "org.mozilla");
    scope && util::name_is(path, &["browser.db", "places.sqlite"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    let source = path.to_string_lossy().to_string();

    for (table, label) in [
        ("history", "browsing history"),
        ("visits", "visit timestamps"),
        ("bookmarks", "bookmarks"),
    ] {
        if util::table_exists(&conn, table) {
            let n = util::count_rows(&conn, table);
            out.push(ArtifactRecord {
                category: ArtifactCategory::WebActivity,
                subcategory: format!("Firefox {}", table),
                timestamp: None,
                title: format!("Firefox iOS {}", label),
                detail: format!("{} {} rows", n, table),
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
    fn matches_firefox() {
        assert!(matches(Path::new(
            "/var/mobile/Containers/Data/Application/UUID/Library/org.mozilla.firefox/browser.db"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses_history() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("firefox");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("browser.db");
        let c = Connection::open(&p).unwrap();
        c.execute(
            "CREATE TABLE history (id INTEGER PRIMARY KEY, url TEXT)",
            [],
        )
        .unwrap();
        c.execute(
            "CREATE TABLE visits (id INTEGER PRIMARY KEY, siteID INTEGER, date REAL)",
            [],
        )
        .unwrap();
        c.execute("INSERT INTO history (url) VALUES ('https://a.com')", [])
            .unwrap();
        c.execute(
            "INSERT INTO visits (siteID, date) VALUES (1, 1700000000.0)",
            [],
        )
        .unwrap();
        let recs = parse(&p);
        assert!(recs.iter().any(|r| r.subcategory == "Firefox history"));
        assert!(recs.iter().any(|r| r.subcategory == "Firefox visits"));
    }
    #[test]
    fn no_known_tables_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("firefox");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("browser.db");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(&p).is_empty());
    }
}
