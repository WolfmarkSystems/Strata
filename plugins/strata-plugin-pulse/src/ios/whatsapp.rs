//! iOS WhatsApp — `ChatStorage.sqlite`.
//!
//! Schema iLEAPP keys off:
//!   * `ZWAMESSAGE` — message rows (`ZTEXT`, `ZMESSAGEDATE`, `ZGROUPEVENTTYPE`)
//!   * `ZWACHATSESSION` — chat session metadata
//!   * `ZWAGROUPMEMBER` — group membership
//!   * `ZWAMEDIAITEM` — attachment metadata (image bytes NOT read)

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["chatstorage.sqlite"]) && util::path_contains(path, "whatsapp")
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    if !util::table_exists(&conn, "ZWAMESSAGE") {
        return out;
    }
    let source = path.to_string_lossy().to_string();
    let messages = util::count_rows(&conn, "ZWAMESSAGE");

    let (first, last) = conn
        .prepare("SELECT MIN(ZMESSAGEDATE), MAX(ZMESSAGEDATE) FROM ZWAMESSAGE WHERE ZMESSAGEDATE IS NOT NULL")
        .and_then(|mut s| s.query_row([], |row| Ok((row.get::<_, Option<f64>>(0)?, row.get::<_, Option<f64>>(1)?))))
        .unwrap_or((None, None));
    let first_unix = first.and_then(util::cf_absolute_to_unix);

    out.push(ArtifactRecord {
        category: ArtifactCategory::Communications,
        subcategory: "WhatsApp messages".to_string(),
        timestamp: first_unix,
        title: "WhatsApp iOS messages".to_string(),
        detail: format!(
            "{} ZWAMESSAGE rows, range {:?}..{:?} Unix",
            messages,
            first_unix,
            last.and_then(util::cf_absolute_to_unix)
        ),
        source_path: source.clone(),
        forensic_value: ForensicValue::Critical,
        mitre_technique: Some("T1005".to_string()),
        is_suspicious: false,
        raw_data: None,
        confidence: 0,
    });

    for (table, label, fv) in [
        (
            "ZWACHATSESSION",
            "WhatsApp chat sessions",
            ForensicValue::High,
        ),
        (
            "ZWAGROUPMEMBER",
            "WhatsApp group members",
            ForensicValue::High,
        ),
        (
            "ZWAMEDIAITEM",
            "WhatsApp attachments (metadata only)",
            ForensicValue::High,
        ),
    ] {
        if util::table_exists(&conn, table) {
            let n = util::count_rows(&conn, table);
            out.push(ArtifactRecord {
                category: ArtifactCategory::Communications,
                subcategory: format!("WhatsApp {}", table),
                timestamp: None,
                title: label.to_string(),
                detail: format!("{} rows in {}", n, table),
                source_path: source.clone(),
                forensic_value: fv,
                mitre_technique: None,
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

    fn make_chatstorage(rows: usize) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempdir().unwrap();
        let waroot = dir.path().join("whatsapp").join("Documents");
        std::fs::create_dir_all(&waroot).unwrap();
        let p = waroot.join("ChatStorage.sqlite");
        let c = Connection::open(&p).unwrap();
        c.execute(
            "CREATE TABLE ZWAMESSAGE (Z_PK INTEGER PRIMARY KEY, ZTEXT TEXT, ZMESSAGEDATE DOUBLE)",
            [],
        )
        .unwrap();
        c.execute(
            "CREATE TABLE ZWACHATSESSION (Z_PK INTEGER PRIMARY KEY, ZPARTNERNAME TEXT)",
            [],
        )
        .unwrap();
        c.execute(
            "CREATE TABLE ZWAGROUPMEMBER (Z_PK INTEGER PRIMARY KEY, ZMEMBERJID TEXT)",
            [],
        )
        .unwrap();
        c.execute(
            "CREATE TABLE ZWAMEDIAITEM (Z_PK INTEGER PRIMARY KEY, ZMEDIALOCALPATH TEXT)",
            [],
        )
        .unwrap();
        for i in 0..rows {
            c.execute(
                "INSERT INTO ZWAMESSAGE (ZTEXT, ZMESSAGEDATE) VALUES (?1, ?2)",
                rusqlite::params![format!("hi {}", i), 700_000_000.0_f64 + i as f64],
            )
            .unwrap();
        }
        c.execute(
            "INSERT INTO ZWACHATSESSION (ZPARTNERNAME) VALUES ('Alice')",
            [],
        )
        .unwrap();
        (dir, p)
    }

    #[test]
    fn matches_chatstorage_under_whatsapp_path() {
        assert!(matches(Path::new(
            "/var/mobile/Containers/Shared/AppGroup/UUID/whatsapp/Documents/ChatStorage.sqlite"
        )));
        assert!(!matches(Path::new(
            "/var/mobile/Library/SMS/ChatStorage.sqlite"
        )));
    }

    #[test]
    fn parses_messages_and_session_counts() {
        let (_d, p) = make_chatstorage(3);
        let recs = parse(&p);
        let m = recs
            .iter()
            .find(|r| r.subcategory == "WhatsApp messages")
            .unwrap();
        assert!(m.detail.contains("3 ZWAMESSAGE"));
        assert_eq!(m.forensic_value, ForensicValue::Critical);
        assert!(recs
            .iter()
            .any(|r| r.subcategory == "WhatsApp ZWACHATSESSION"));
    }

    #[test]
    fn empty_messages_still_emits_summary() {
        let (_d, p) = make_chatstorage(0);
        let recs = parse(&p);
        assert!(recs.iter().any(|r| r.subcategory == "WhatsApp messages"));
    }

    #[test]
    fn missing_zwamessage_returns_empty() {
        let dir = tempdir().unwrap();
        let waroot = dir.path().join("whatsapp");
        std::fs::create_dir_all(&waroot).unwrap();
        let p = waroot.join("ChatStorage.sqlite");
        let c = Connection::open(&p).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(&p).is_empty());
    }
}
