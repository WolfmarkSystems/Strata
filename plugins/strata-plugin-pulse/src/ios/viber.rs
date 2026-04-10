//! Viber iOS — `Contacts.data`, `Chats.data`.
//!
//! Viber stores messages in `ZVIBERMESSAGE` and contacts in
//! `ZABCONTACT` / `ZCONTACT`. Timestamps are Cocoa seconds.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["contacts.data", "chats.data"]) && util::path_contains(path, "viber")
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else { return out };
    let source = path.to_string_lossy().to_string();
    let mut emitted = false;

    if util::table_exists(&conn, "ZVIBERMESSAGE") {
        let count = util::count_rows(&conn, "ZVIBERMESSAGE");
        out.push(ArtifactRecord {
            category: ArtifactCategory::Communications,
            subcategory: "Viber messages".to_string(),
            timestamp: None,
            title: "Viber messages".to_string(),
            detail: format!("{} ZVIBERMESSAGE rows", count),
            source_path: source.clone(),
            forensic_value: ForensicValue::Critical,
            mitre_technique: Some("T1005".to_string()),
            is_suspicious: false,
            raw_data: None,
        });
        emitted = true;
    }
    for table in ["ZABCONTACT", "ZCONTACT"] {
        if util::table_exists(&conn, table) {
            let count = util::count_rows(&conn, table);
            out.push(ArtifactRecord {
                category: ArtifactCategory::Communications,
                subcategory: "Viber contacts".to_string(),
                timestamp: None,
                title: "Viber contacts".to_string(),
                detail: format!("{} {} rows", count, table),
                source_path: source.clone(),
                forensic_value: ForensicValue::High,
                mitre_technique: None,
                is_suspicious: false,
                raw_data: None,
            });
            emitted = true;
            break;
        }
    }
    if !emitted { return Vec::new(); }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::tempdir;

    #[test]
    fn matches_viber_paths() {
        assert!(matches(Path::new("/var/mobile/Containers/Data/Application/UUID/Documents/Viber/Contacts.data")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_messages_and_contacts() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("Viber");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("Chats.data");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE ZVIBERMESSAGE (Z_PK INTEGER PRIMARY KEY, ZTEXT TEXT)", []).unwrap();
        c.execute("CREATE TABLE ZABCONTACT (Z_PK INTEGER PRIMARY KEY, ZNAME TEXT)", []).unwrap();
        c.execute("INSERT INTO ZVIBERMESSAGE (ZTEXT) VALUES ('hello')", []).unwrap();
        c.execute("INSERT INTO ZABCONTACT (ZNAME) VALUES ('Alice')", []).unwrap();
        let recs = parse(&p);
        assert!(recs.iter().any(|r| r.subcategory == "Viber messages"));
        assert!(recs.iter().any(|r| r.subcategory == "Viber contacts"));
    }

    #[test]
    fn no_viber_tables_returns_empty() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("Viber");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join("Contacts.data");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(&p).is_empty());
    }
}
