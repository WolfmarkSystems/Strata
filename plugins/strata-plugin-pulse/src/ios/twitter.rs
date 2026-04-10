//! Twitter/X iOS — `*twitter*` databases.
//!
//! Twitter stores cached DMs, tweets, and user data in
//! `gryphon.sqlite`, `t1_*.db`, or `db.sqlite` under `Twitter/`
//! paths. iLEAPP keys off `statuses`, `messages`, `users` tables.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    if util::name_is(path, &["gryphon.sqlite"]) { return true; }
    let n = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_ascii_lowercase(),
        None => return false,
    };
    (n.starts_with("t1_") && n.ends_with(".db"))
        || (util::name_is(path, &["db.sqlite"]) && util::path_contains(path, "twitter"))
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else { return out };
    let source = path.to_string_lossy().to_string();

    for (table, label, fv) in [
        ("statuses", "tweets/statuses", ForensicValue::High),
        ("messages", "direct messages", ForensicValue::Critical),
        ("users", "cached user profiles", ForensicValue::Medium),
        ("lists", "lists", ForensicValue::Low),
    ] {
        if util::table_exists(&conn, table) {
            let n = util::count_rows(&conn, table);
            out.push(ArtifactRecord {
                category: ArtifactCategory::SocialMedia,
                subcategory: format!("Twitter {}", table),
                timestamp: None,
                title: format!("Twitter/X iOS {}", label),
                detail: format!("{} {} rows", n, table),
                source_path: source.clone(),
                forensic_value: fv,
                mitre_technique: Some("T1005".to_string()),
                is_suspicious: false,
                raw_data: None,
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
    fn matches_twitter_filenames() {
        assert!(matches(Path::new("/var/mobile/Containers/Data/Application/UUID/Library/Caches/Twitter/gryphon.sqlite")));
        assert!(matches(Path::new("/var/mobile/Library/t1_abc.db")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_statuses_and_messages() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("gryphon.sqlite");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE statuses (id INTEGER PRIMARY KEY, text TEXT)", []).unwrap();
        c.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, text TEXT)", []).unwrap();
        c.execute("INSERT INTO statuses VALUES (1, 'tweet')", []).unwrap();
        c.execute("INSERT INTO messages VALUES (1, 'dm')", []).unwrap();
        let recs = parse(&p);
        assert!(recs.iter().any(|r| r.subcategory == "Twitter statuses"));
        assert!(recs.iter().any(|r| r.subcategory == "Twitter messages"));
    }

    #[test]
    fn empty_db_returns_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("gryphon.sqlite");
        let _c = Connection::open(&p).unwrap();
        assert!(parse(&p).is_empty());
    }
}
