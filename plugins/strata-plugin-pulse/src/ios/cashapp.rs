//! Cash App iOS — `*.db` / `*.sqlite` under `*squareup*` / `*cashapp*`.
//!
//! Cash App stores payment history and contacts. High forensic value
//! for financial investigation.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    let scope = util::path_contains(path, "squareup") || util::path_contains(path, "cashapp");
    if !scope {
        return false;
    }
    let n = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    n.ends_with(".db") || n.ends_with(".sqlite")
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
        category: ArtifactCategory::AccountsCredentials,
        subcategory: "Cash App".to_string(),
        timestamp: None,
        title: "Cash App iOS database".to_string(),
        detail: format!(
            "{} rows across {} tables — payments, contacts",
            total,
            tables.len()
        ),
        source_path: source,
        forensic_value: ForensicValue::Critical,
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
    fn matches_cashapp_paths() {
        assert!(matches(Path::new(
            "/var/mobile/Containers/Data/Application/UUID/Library/com.squareup.cash/data.db"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_rows() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("squareup");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("data.db");
        let c = Connection::open(&p).unwrap();
        c.execute(
            "CREATE TABLE payments (id INTEGER PRIMARY KEY, amount REAL)",
            [],
        )
        .unwrap();
        c.execute("INSERT INTO payments (amount) VALUES (25.00)", [])
            .unwrap();
        let recs = parse(&p);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].forensic_value, ForensicValue::Critical);
    }

    #[test]
    fn empty_db_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("cashapp");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("store.db");
        let _c = Connection::open(&p).unwrap();
        assert!(parse(&p).is_empty());
    }
}
