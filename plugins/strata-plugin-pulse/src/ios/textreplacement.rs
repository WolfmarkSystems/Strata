//! iOS Text Replacement — `TextReplacement.db`.
//!
//! Custom keyboard shortcuts (e.g. "omw" → "On my way!"). iLEAPP
//! keys off `ZTEXTREPLACEMENTENTRY` with `ZSHORTCUT`, `ZPHRASE`,
//! `ZTIMESTAMP`. Often contains personal addresses, emails, names.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["textreplacement.db"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    if !util::table_exists(&conn, "ZTEXTREPLACEMENTENTRY") {
        return out;
    }
    let source = path.to_string_lossy().to_string();
    let count = util::count_rows(&conn, "ZTEXTREPLACEMENTENTRY");
    out.push(ArtifactRecord {
        category: ArtifactCategory::UserActivity,
        subcategory: "Text Replacement".to_string(),
        timestamp: None,
        title: "iOS keyboard text replacements".to_string(),
        detail: format!(
            "{} ZTEXTREPLACEMENTENTRY rows (shortcut → phrase mappings, may contain personal info)",
            count
        ),
        source_path: source,
        forensic_value: ForensicValue::High,
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
    use tempfile::NamedTempFile;

    #[test]
    fn matches_textreplacement_db() {
        assert!(matches(Path::new(
            "/var/mobile/Library/Keyboard/TextReplacement.db"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_entry_count() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE ZTEXTREPLACEMENTENTRY (Z_PK INTEGER PRIMARY KEY, ZSHORTCUT TEXT, ZPHRASE TEXT)", []).unwrap();
        c.execute(
            "INSERT INTO ZTEXTREPLACEMENTENTRY (ZSHORTCUT, ZPHRASE) VALUES ('omw', 'On my way!')",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO ZTEXTREPLACEMENTENTRY (ZSHORTCUT, ZPHRASE) VALUES ('addr', '123 Main St')",
            [],
        )
        .unwrap();
        let recs = parse(tmp.path());
        assert_eq!(recs.len(), 1);
        assert!(recs[0].detail.contains("2 ZTEXTREPLACEMENTENTRY"));
    }

    #[test]
    fn missing_table_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(tmp.path()).is_empty());
    }
}
