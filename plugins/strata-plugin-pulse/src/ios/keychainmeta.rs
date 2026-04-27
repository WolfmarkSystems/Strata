//! iOS Keychain metadata — `keychain-2.db`.
//!
//! The keychain stores passwords, certificates, tokens. We never
//! extract credential values — only metadata: which services have
//! saved credentials, creation/modification dates, access groups.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["keychain-2.db", "keychain-2.db-shm"])
        && !path.to_string_lossy().contains("-shm")
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    let source = path.to_string_lossy().to_string();

    for (table, label) in [
        ("genp", "generic passwords (app credentials)"),
        ("inet", "internet passwords (saved logins)"),
        ("cert", "certificates"),
        ("keys", "cryptographic keys"),
    ] {
        if util::table_exists(&conn, table) {
            let count = util::count_rows(&conn, table);
            out.push(ArtifactRecord {
                category: ArtifactCategory::AccountsCredentials,
                subcategory: format!("Keychain {}", table),
                timestamp: None,
                title: format!("iOS Keychain: {}", label),
                detail: format!(
                    "{} {} rows (metadata only — credential values NOT extracted)",
                    count, table
                ),
                source_path: source.clone(),
                forensic_value: ForensicValue::High,
                mitre_technique: Some("T1555".to_string()),
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
    use tempfile::NamedTempFile;

    #[test]
    fn matches_keychain() {
        assert!(matches(Path::new("/var/Keychains/keychain-2.db")));
        assert!(!matches(Path::new("/var/Keychains/keychain-2.db-shm")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_table_counts() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute(
            "CREATE TABLE genp (rowid INTEGER PRIMARY KEY, acct TEXT, agrp TEXT)",
            [],
        )
        .unwrap();
        c.execute(
            "CREATE TABLE inet (rowid INTEGER PRIMARY KEY, acct TEXT, srvr TEXT)",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO genp (acct, agrp) VALUES ('user', 'com.app')",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO inet (acct, srvr) VALUES ('user', 'example.com')",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO inet (acct, srvr) VALUES ('admin', 'bank.com')",
            [],
        )
        .unwrap();
        let recs = parse(tmp.path());
        let genp = recs
            .iter()
            .find(|r| r.subcategory == "Keychain genp")
            .unwrap();
        assert!(genp.detail.contains("1 genp"));
        assert!(genp.detail.contains("NOT extracted"));
        let inet = recs
            .iter()
            .find(|r| r.subcategory == "Keychain inet")
            .unwrap();
        assert!(inet.detail.contains("2 inet"));
    }

    #[test]
    fn no_known_tables_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(tmp.path()).is_empty());
    }
}
