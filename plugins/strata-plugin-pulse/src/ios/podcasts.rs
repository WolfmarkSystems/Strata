//! Apple Podcasts — `MTLibrary.sqlite`.
//!
//! iLEAPP keys off `ZMTEPISODE` (episodes with play state,
//! download date, duration) and `ZMTPODCAST` (subscriptions).

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["mtlibrary.sqlite"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else { return out };
    let source = path.to_string_lossy().to_string();
    let mut emitted = false;

    if util::table_exists(&conn, "ZMTEPISODE") {
        let count = util::count_rows(&conn, "ZMTEPISODE");
        out.push(ArtifactRecord {
            category: ArtifactCategory::UserActivity,
            subcategory: "Podcasts episodes".to_string(),
            timestamp: None,
            title: "Apple Podcasts episodes".to_string(),
            detail: format!("{} ZMTEPISODE rows (episode play/download state)", count),
            source_path: source.clone(),
            forensic_value: ForensicValue::Medium,
            mitre_technique: None,
            is_suspicious: false,
            raw_data: None,
            confidence: 0,
        });
        emitted = true;
    }
    if util::table_exists(&conn, "ZMTPODCAST") {
        let count = util::count_rows(&conn, "ZMTPODCAST");
        out.push(ArtifactRecord {
            category: ArtifactCategory::UserActivity,
            subcategory: "Podcasts subscriptions".to_string(),
            timestamp: None,
            title: "Apple Podcasts subscriptions".to_string(),
            detail: format!("{} ZMTPODCAST rows (podcast subscriptions)", count),
            source_path: source,
            forensic_value: ForensicValue::Medium,
            mitre_technique: None,
            is_suspicious: false,
            raw_data: None,
            confidence: 0,
        });
        emitted = true;
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
    fn matches_mtlibrary() {
        assert!(matches(Path::new("/var/mobile/Media/Podcasts/MTLibrary.sqlite")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_episodes_and_subscriptions() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE ZMTEPISODE (Z_PK INTEGER PRIMARY KEY, ZTITLE TEXT)", []).unwrap();
        c.execute("CREATE TABLE ZMTPODCAST (Z_PK INTEGER PRIMARY KEY, ZTITLE TEXT)", []).unwrap();
        c.execute("INSERT INTO ZMTEPISODE (ZTITLE) VALUES ('ep1')", []).unwrap();
        c.execute("INSERT INTO ZMTPODCAST (ZTITLE) VALUES ('pod1')", []).unwrap();
        let recs = parse(tmp.path());
        assert!(recs.iter().any(|r| r.subcategory == "Podcasts episodes"));
        assert!(recs.iter().any(|r| r.subcategory == "Podcasts subscriptions"));
    }

    #[test]
    fn missing_tables_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(tmp.path()).is_empty());
    }
}
