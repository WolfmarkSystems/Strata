//! iOS Game Center — `GKDatabase.db`, `gamecenterdb.sqlite`.
//!
//! Game Center stores achievements, friends, and matchmaking history.
//! Friends list is forensically useful for identity association.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["gkdatabase.db", "gamecenterdb.sqlite"])
        || (util::path_contains(path, "gamecenter") && {
            let n = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
            n.ends_with(".db") || n.ends_with(".sqlite")
        })
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else { return out };
    let source = path.to_string_lossy().to_string();

    for (table, label) in [
        ("ZFRIEND", "Game Center friends"),
        ("ZACHIEVEMENT", "Game Center achievements"),
        ("ZGKPLAYER", "Game Center players"),
    ] {
        if util::table_exists(&conn, table) {
            let count = util::count_rows(&conn, table);
            out.push(ArtifactRecord {
                category: ArtifactCategory::SocialMedia,
                subcategory: format!("Game Center {}", table), timestamp: None,
                title: label.to_string(),
                detail: format!("{} {} rows", count, table),
                source_path: source.clone(), forensic_value: ForensicValue::Medium,
                mitre_technique: None, is_suspicious: false, raw_data: None,
                confidence: 0,
            });
        }
    }
    // Fallback inventory
    if out.is_empty() {
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
            .and_then(|mut s| { let r = s.query_map([], |row| row.get::<_, String>(0))?; Ok(r.flatten().collect()) })
            .unwrap_or_default();
        if tables.is_empty() { return out; }
        let mut total = 0_i64;
        for t in &tables { total += util::count_rows(&conn, t); }
        out.push(ArtifactRecord {
            category: ArtifactCategory::SocialMedia,
            subcategory: "Game Center".to_string(), timestamp: None,
            title: "iOS Game Center database".to_string(),
            detail: format!("{} rows across {} tables — friends, achievements, matches", total, tables.len()),
            source_path: source, forensic_value: ForensicValue::Medium,
            mitre_technique: None, is_suspicious: false, raw_data: None,
            confidence: 0,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    #[test]
    fn matches_gamecenter() {
        assert!(matches(Path::new("/var/mobile/Library/GameCenter/GKDatabase.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }
    #[test]
    fn parses_friends_table() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE ZFRIEND (Z_PK INTEGER PRIMARY KEY, ZDISPLAYNAME TEXT)", []).unwrap();
        c.execute("INSERT INTO ZFRIEND (ZDISPLAYNAME) VALUES ('Player1')", []).unwrap();
        let recs = parse(tmp.path());
        assert!(recs.iter().any(|r| r.subcategory.contains("ZFRIEND")));
    }
    #[test]
    fn empty_db_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let _c = Connection::open(tmp.path()).unwrap();
        assert!(parse(tmp.path()).is_empty());
    }
}
