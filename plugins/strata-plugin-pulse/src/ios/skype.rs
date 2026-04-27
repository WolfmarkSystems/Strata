//! Skype iOS — `main.db`, `live:*.db` under `*skype*`.
//!
//! iLEAPP keys off `Messages`, `Conversations`, `Contacts`.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    util::path_contains(path, "skype") && util::name_is(path, &["main.db", "s4l-live.db"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    let source = path.to_string_lossy().to_string();
    let mut emitted = false;

    for (table, label) in [
        ("Messages", "Skype messages"),
        ("Conversations", "Skype conversations"),
        ("Contacts", "Skype contacts"),
    ] {
        if util::table_exists(&conn, table) {
            let n = util::count_rows(&conn, table);
            out.push(ArtifactRecord {
                category: ArtifactCategory::Communications,
                subcategory: label.to_string(),
                timestamp: None,
                title: label.to_string(),
                detail: format!("{} {} rows", n, table),
                source_path: source.clone(),
                forensic_value: ForensicValue::High,
                mitre_technique: Some("T1005".to_string()),
                is_suspicious: false,
                raw_data: None,
                confidence: 0,
            });
            emitted = true;
        }
    }
    if !emitted {
        return Vec::new();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::tempdir;

    #[test]
    fn matches_skype_paths() {
        assert!(matches(Path::new(
            "/var/mobile/Containers/Data/Application/UUID/Library/Skype/main.db"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses_messages() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("Skype");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("main.db");
        let c = Connection::open(&p).unwrap();
        c.execute(
            "CREATE TABLE Messages (id INTEGER PRIMARY KEY, body TEXT)",
            [],
        )
        .unwrap();
        c.execute("INSERT INTO Messages (body) VALUES ('hi')", [])
            .unwrap();
        assert!(parse(&p).iter().any(|r| r.subcategory == "Skype messages"));
    }
    #[test]
    fn no_known_tables_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("Skype");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("main.db");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(&p).is_empty());
    }
}
