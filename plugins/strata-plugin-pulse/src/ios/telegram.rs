//! iOS Telegram — `db.sqlite` under `*/Telegram*/Documents/`.
//!
//! Telegram's iOS storage is a bespoke key-value layer over SQLite.
//! Per-row decoding is not stable across releases. Pulse v1.0 reports
//! presence + total table count.

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["db.sqlite"]) && util::path_contains(path, "telegram")
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    let table_count: i64 = conn
        .prepare("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
        .and_then(|mut s| s.query_row([], |r| r.get(0)))
        .unwrap_or(0);
    if table_count == 0 {
        return out;
    }
    let source = path.to_string_lossy().to_string();
    out.push(ArtifactRecord {
        category: ArtifactCategory::Communications,
        subcategory: "Telegram".to_string(),
        timestamp: None,
        title: "Telegram iOS database".to_string(),
        detail: format!(
            "Telegram db.sqlite present at {} — {} tables, key-value layout",
            source, table_count
        ),
        source_path: source,
        forensic_value: ForensicValue::High,
        mitre_technique: Some("T1005".to_string()),
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

    fn make_telegram(tables: usize) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempdir().unwrap();
        let root = dir.path().join("telegram-data");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("db.sqlite");
        let c = Connection::open(&p).unwrap();
        for i in 0..tables {
            c.execute(&format!("CREATE TABLE t{} (k INT)", i), []).unwrap();
        }
        (dir, p)
    }

    #[test]
    fn matches_telegram_db_paths() {
        assert!(matches(Path::new(
            "/var/mobile/Containers/Data/Application/UUID/Documents/Telegram/db.sqlite"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/db.sqlite")));
    }

    #[test]
    fn parses_table_count() {
        let (_d, p) = make_telegram(4);
        let recs = parse(&p);
        let r = recs.iter().find(|r| r.subcategory == "Telegram").unwrap();
        assert!(r.detail.contains("4 tables"));
    }

    #[test]
    fn empty_db_returns_empty() {
        let (_d, p) = make_telegram(0);
        assert!(parse(&p).is_empty());
    }
}
