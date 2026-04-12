//! Tinder iOS — `Tinder.sqlite`.
//!
//! Tinder stores match metadata and messages in a CoreData store.
//! iLEAPP keys off `ZMATCH` and `ZMESSAGE` tables.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["tinder.sqlite"])
        || (util::name_is(path, &["model.sqlite"]) && util::path_contains(path, "tinder"))
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else { return out };
    let source = path.to_string_lossy().to_string();
    let mut emitted = false;

    for (table, label, cat) in [
        ("ZMATCH", "Tinder matches", ArtifactCategory::SocialMedia),
        ("ZMESSAGE", "Tinder messages", ArtifactCategory::Communications),
    ] {
        if util::table_exists(&conn, table) {
            let n = util::count_rows(&conn, table);
            out.push(ArtifactRecord {
                category: cat,
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
    if !emitted { return Vec::new(); }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    #[test]
    fn matches_tinder_filenames() {
        assert!(matches(Path::new("/var/mobile/Containers/Data/Application/UUID/Library/Tinder.sqlite")));
        assert!(matches(Path::new("/var/mobile/Containers/Data/Application/UUID/Library/Tinder/model.sqlite")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_matches_and_messages() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE ZMATCH (Z_PK INTEGER PRIMARY KEY, ZPERSON TEXT)", []).unwrap();
        c.execute("CREATE TABLE ZMESSAGE (Z_PK INTEGER PRIMARY KEY, ZTEXT TEXT)", []).unwrap();
        c.execute("INSERT INTO ZMATCH (ZPERSON) VALUES ('person1')", []).unwrap();
        c.execute("INSERT INTO ZMESSAGE (ZTEXT) VALUES ('hey')", []).unwrap();
        let recs = parse(tmp.path());
        assert!(recs.iter().any(|r| r.subcategory == "Tinder matches"));
        assert!(recs.iter().any(|r| r.subcategory == "Tinder messages"));
    }

    #[test]
    fn no_tinder_tables_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(tmp.path()).is_empty());
    }
}
