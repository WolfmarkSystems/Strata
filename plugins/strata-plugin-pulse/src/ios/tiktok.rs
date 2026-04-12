//! TikTok iOS — `AwemeIM.db` (messages), `db.sqlite` under TikTok paths.
//!
//! iLEAPP keys off:
//!   * `AwemeIM.db` — direct messages (`msg` table with `content`,
//!     `created_time`, `sender`)
//!   * `db.sqlite` under `*/musically/*` or `*/TikTok/*` — user
//!     activity / search history
//!
//! Pulse v1.0 reports row counts + date range.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    if util::name_is(path, &["awemeim.db"]) {
        return true;
    }
    util::name_is(path, &["db.sqlite"])
        && (util::path_contains(path, "musically") || util::path_contains(path, "tiktok"))
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else { return out };
    let source = path.to_string_lossy().to_string();

    if util::table_exists(&conn, "msg") {
        let count = util::count_rows(&conn, "msg");
        let ts = conn
            .prepare("SELECT MIN(created_time), MAX(created_time) FROM msg WHERE created_time > 0")
            .and_then(|mut s| s.query_row([], |r| Ok((r.get::<_, Option<i64>>(0)?, r.get::<_, Option<i64>>(1)?))))
            .unwrap_or((None, None));
        out.push(ArtifactRecord {
            category: ArtifactCategory::Communications,
            subcategory: "TikTok messages".to_string(),
            timestamp: ts.0,
            title: "TikTok direct messages".to_string(),
            detail: format!("{} msg rows, range {:?}..{:?} Unix", count, ts.0, ts.1),
            source_path: source.clone(),
            forensic_value: ForensicValue::Critical,
            mitre_technique: Some("T1005".to_string()),
            is_suspicious: false,
            raw_data: None,
            confidence: 0,
        });
    }

    // Generic table inventory for the TikTok activity db
    if !util::table_exists(&conn, "msg") {
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
            .and_then(|mut s| {
                let r = s.query_map([], |row| row.get::<_, String>(0))?;
                Ok(r.flatten().collect())
            })
            .unwrap_or_default();
        if !tables.is_empty() {
            let mut total = 0_i64;
            for t in &tables { total += util::count_rows(&conn, t); }
            out.push(ArtifactRecord {
                category: ArtifactCategory::SocialMedia,
                subcategory: "TikTok activity".to_string(),
                timestamp: None,
                title: "TikTok iOS activity database".to_string(),
                detail: format!("{} rows across {} tables", total, tables.len()),
                source_path: source,
                forensic_value: ForensicValue::High,
                mitre_technique: Some("T1005".to_string()),
                is_suspicious: false,
                raw_data: None,
                confidence: 0,
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
    fn matches_tiktok_filenames() {
        assert!(matches(Path::new("/var/mobile/Containers/Data/Application/UUID/Library/Application Support/AwemeIM.db")));
        assert!(matches(Path::new("/var/mobile/Containers/Data/Application/UUID/Documents/musically/db.sqlite")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_message_count() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("AwemeIM.db");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE msg (id INTEGER PRIMARY KEY, content TEXT, created_time INTEGER, sender TEXT)", []).unwrap();
        c.execute("INSERT INTO msg (content, created_time, sender) VALUES ('hi', 1700000000, 'u1')", []).unwrap();
        c.execute("INSERT INTO msg (content, created_time, sender) VALUES ('yo', 1700000100, 'u2')", []).unwrap();
        let recs = parse(&p);
        let m = recs.iter().find(|r| r.subcategory == "TikTok messages").unwrap();
        assert!(m.detail.contains("2 msg rows"));
        assert_eq!(m.timestamp, Some(1_700_000_000));
    }

    #[test]
    fn empty_db_returns_empty() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("AwemeIM.db");
        let _c = Connection::open(&p).unwrap();
        assert!(parse(&p).is_empty());
    }
}
