//! Reddit iOS — `clicks.sqlite`, `autocomplete.sqlite`, cached dbs.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    util::path_contains(path, "reddit")
        && (util::name_is(path, &["clicks.sqlite", "autocomplete.sqlite"])
            || util::name_is(path, &["cache.db", "accounts.sqlite"]))
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    let source = path.to_string_lossy().to_string();
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
        category: ArtifactCategory::SocialMedia,
        subcategory: "Reddit".to_string(),
        timestamp: None,
        title: "Reddit iOS database".to_string(),
        detail: format!("{} rows across {} tables", total, tables.len()),
        source_path: source,
        forensic_value: ForensicValue::High,
        mitre_technique: Some("T1005".to_string()),
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
    use tempfile::tempdir;

    #[test]
    fn matches_reddit_paths() {
        assert!(matches(Path::new(
            "/var/mobile/Containers/Data/Application/UUID/Library/reddit.com/clicks.sqlite"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_row_count() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("reddit");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("clicks.sqlite");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE clicks (id INTEGER PRIMARY KEY, url TEXT)", [])
            .unwrap();
        c.execute(
            "INSERT INTO clicks (url) VALUES ('https://reddit.com/r/test')",
            [],
        )
        .unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].detail.contains("1 rows"));
    }

    #[test]
    fn empty_db_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("reddit");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("clicks.sqlite");
        let _c = Connection::open(&p).unwrap();
        assert!(parse(&p).is_empty());
    }
}
