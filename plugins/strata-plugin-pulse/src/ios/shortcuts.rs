//! iOS Shortcuts (Siri Shortcuts) — `Shortcuts.sqlite`.
//!
//! `ZSHORTCUT` table stores every user-created and downloaded
//! shortcut with name, creation date, last run date. `ZSHORTCUTACTION`
//! holds the action chain. Can reveal automation behaviors.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["shortcuts.sqlite"])
        || (util::path_contains(path, "shortcuts") && util::name_is(path, &["workflow.db"]))
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    let source = path.to_string_lossy().to_string();
    let mut emitted = false;

    for (table, label) in [
        ("ZSHORTCUT", "shortcuts"),
        ("ZSHORTCUTACTION", "shortcut actions"),
        ("ZWORKFLOW", "workflows"),
    ] {
        if util::table_exists(&conn, table) {
            let count = util::count_rows(&conn, table);
            out.push(ArtifactRecord {
                category: ArtifactCategory::UserActivity,
                subcategory: format!("Shortcuts {}", table),
                timestamp: None,
                title: format!("iOS Shortcuts: {} {}", count, label),
                detail: format!(
                    "{} {} rows — user-created automations and downloaded shortcuts",
                    count, table
                ),
                source_path: source.clone(),
                forensic_value: ForensicValue::High,
                mitre_technique: Some("T1059".to_string()),
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
    use tempfile::NamedTempFile;

    #[test]
    fn matches_shortcuts_db() {
        assert!(matches(Path::new(
            "/var/mobile/Library/Shortcuts/Shortcuts.sqlite"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_shortcut_count() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute(
            "CREATE TABLE ZSHORTCUT (Z_PK INTEGER PRIMARY KEY, ZNAME TEXT, ZCREATIONDATE DOUBLE)",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO ZSHORTCUT (ZNAME, ZCREATIONDATE) VALUES ('Morning Routine', 700000000.0)",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO ZSHORTCUT (ZNAME, ZCREATIONDATE) VALUES ('Driving Mode', 700000100.0)",
            [],
        )
        .unwrap();
        let recs = parse(tmp.path());
        let r = recs
            .iter()
            .find(|r| r.subcategory.contains("ZSHORTCUT"))
            .unwrap();
        assert!(r.detail.contains("2 ZSHORTCUT"));
    }

    #[test]
    fn no_known_tables_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(tmp.path()).is_empty());
    }
}
