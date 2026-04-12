//! iOS TrustStore — `TrustStore.sqlite3`.
//!
//! Stores user-installed CA certificates and certificate trust
//! overrides. Forensically critical: a rogue CA cert proves the
//! device was configured for TLS interception (MITM proxy, corporate
//! inspection, or malware).

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["truststore.sqlite3", "truststore.sqlite"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else { return out };
    let source = path.to_string_lossy().to_string();

    // tsettings = user-installed certs; overrides = per-cert trust
    for (table, label, suspicious) in [
        ("tsettings", "user-installed CA certificates", true),
        ("overrides", "per-cert trust overrides", false),
    ] {
        if util::table_exists(&conn, table) {
            let count = util::count_rows(&conn, table);
            out.push(ArtifactRecord {
                category: ArtifactCategory::EncryptionKeyMaterial,
                subcategory: format!("TrustStore {}", table),
                timestamp: None,
                title: format!("iOS TrustStore: {}", label),
                detail: format!("{} {} rows — {}", count, table, label),
                source_path: source.clone(),
                forensic_value: ForensicValue::Critical,
                mitre_technique: Some("T1553".to_string()),
                is_suspicious: suspicious && count > 0,
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
    fn matches_truststore() {
        assert!(matches(Path::new("/var/protected/trustd/TrustStore.sqlite3")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_tsettings_as_suspicious() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE tsettings (sha1 BLOB, subj BLOB, tset BLOB, data BLOB)", []).unwrap();
        c.execute("INSERT INTO tsettings VALUES (x'AA', x'BB', x'CC', x'DD')", []).unwrap();
        let recs = parse(tmp.path());
        let r = recs.iter().find(|r| r.subcategory.contains("tsettings")).unwrap();
        assert!(r.is_suspicious);
        assert_eq!(r.forensic_value, ForensicValue::Critical);
    }

    #[test]
    fn empty_table_not_suspicious() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE tsettings (sha1 BLOB)", []).unwrap();
        let recs = parse(tmp.path());
        let r = recs.iter().find(|r| r.subcategory.contains("tsettings")).unwrap();
        assert!(!r.is_suspicious);
    }

    #[test]
    fn missing_tables_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(tmp.path()).is_empty());
    }
}
