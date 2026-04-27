//! iOS DuetActivityScheduler — `coreduetd.db`.
//!
//! The CoreDuet daemon's activity database records device lock/unlock
//! events, app foreground transitions, and interaction metadata.
//! Higher fidelity than KnowledgeC for lock/unlock timing.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["coreduetd.db"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    let source = path.to_string_lossy().to_string();

    let tracked = [
        (
            "ZINTERACTIONS",
            "device interactions (lock/unlock, app foreground)",
        ),
        ("ZCOREDUETACTIVITY", "activity records"),
        ("ZCOREDUETPREDICTION", "usage predictions"),
    ];
    let mut emitted = false;
    for (table, label) in tracked {
        if !util::table_exists(&conn, table) {
            continue;
        }
        let count = util::count_rows(&conn, table);
        out.push(ArtifactRecord {
            category: ArtifactCategory::UserActivity,
            subcategory: format!("CoreDuet {}", table),
            timestamp: None,
            title: format!("iOS CoreDuet {}", label),
            detail: format!("{} {} rows", count, table),
            source_path: source.clone(),
            forensic_value: ForensicValue::High,
            mitre_technique: Some("T1005".to_string()),
            is_suspicious: false,
            raw_data: None,
            confidence: 0,
        });
        emitted = true;
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
    fn matches_coreduetd() {
        assert!(matches(Path::new(
            "/var/mobile/Library/CoreDuet/coreduetd.db"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_interactions_table() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute(
            "CREATE TABLE ZINTERACTIONS (Z_PK INTEGER PRIMARY KEY, ZBUNDLEID TEXT)",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO ZINTERACTIONS (ZBUNDLEID) VALUES ('com.apple.springboard')",
            [],
        )
        .unwrap();
        let recs = parse(tmp.path());
        assert_eq!(recs.len(), 1);
        assert!(recs[0].subcategory.contains("ZINTERACTIONS"));
    }

    #[test]
    fn no_known_tables_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(tmp.path()).is_empty());
    }
}
