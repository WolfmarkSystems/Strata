//! iTunes / Finder backup manifest — `Manifest.db`.
//!
//! Every iTunes/Finder backup of an iPhone or iPad ships a
//! `Manifest.db` SQLite catalog. The relevant table is `Files`, with
//! columns `fileID` (SHA1), `domain`, `relativePath`, `flags`,
//! `file` (binary plist payload). iLEAPP and other forensic tools key
//! off this manifest to enumerate every file in the backup.
//!
//! Pulse v1.0 reports presence, total file count, and the per-domain
//! breakdown.

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["manifest.db"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    if !util::table_exists(&conn, "Files") {
        return out;
    }
    let source = path.to_string_lossy().to_string();
    let total = util::count_rows(&conn, "Files");

    out.push(ArtifactRecord {
        category: ArtifactCategory::SystemActivity,
        subcategory: "iTunes backup manifest".to_string(),
        timestamp: None,
        title: "iOS backup manifest".to_string(),
        detail: format!("{} files catalogued in Manifest.db Files table", total),
        source_path: source.clone(),
        forensic_value: ForensicValue::High,
        mitre_technique: None,
        is_suspicious: false,
        raw_data: None,
    });

    let by_domain = conn
        .prepare("SELECT domain, COUNT(*) FROM Files GROUP BY domain ORDER BY COUNT(*) DESC LIMIT 25")
        .and_then(|mut s| {
            let r = s.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            Ok(r.flatten().collect::<Vec<_>>())
        })
        .unwrap_or_default();

    for (domain, count) in by_domain {
        out.push(ArtifactRecord {
            category: ArtifactCategory::SystemActivity,
            subcategory: format!("Backup domain: {}", domain),
            timestamp: None,
            title: format!("Backup domain {}", domain),
            detail: format!("{} files in domain {}", count, domain),
            source_path: source.clone(),
            forensic_value: ForensicValue::Medium,
            mitre_technique: None,
            is_suspicious: false,
            raw_data: None,
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    fn make_manifest(domains: &[(&str, usize)]) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute(
            "CREATE TABLE Files (\
                fileID TEXT PRIMARY KEY, \
                domain TEXT, \
                relativePath TEXT, \
                flags INTEGER, \
                file BLOB \
             )",
            [],
        )
        .unwrap();
        let mut id = 0_i64;
        for (domain, count) in domains {
            for _ in 0..*count {
                id += 1;
                c.execute(
                    "INSERT INTO Files (fileID, domain, relativePath, flags) VALUES (?1, ?2, '/p', 1)",
                    rusqlite::params![format!("{:040x}", id), *domain],
                )
                .unwrap();
            }
        }
        tmp
    }

    #[test]
    fn matches_manifest_filename() {
        assert!(matches(Path::new(
            "/Users/me/Library/Application Support/MobileSync/Backup/UDID/Manifest.db"
        )));
        assert!(!matches(Path::new("/Users/me/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_summary_and_per_domain_breakdown() {
        let tmp = make_manifest(&[("HomeDomain", 4), ("MediaDomain", 2)]);
        let recs = parse(tmp.path());
        let summary = recs
            .iter()
            .find(|r| r.subcategory == "iTunes backup manifest")
            .unwrap();
        assert!(summary.detail.contains("6 files"));
        assert!(recs
            .iter()
            .any(|r| r.subcategory == "Backup domain: HomeDomain"));
        assert!(recs
            .iter()
            .any(|r| r.subcategory == "Backup domain: MediaDomain"));
    }

    #[test]
    fn empty_manifest_emits_summary_only() {
        let tmp = make_manifest(&[]);
        let recs = parse(tmp.path());
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].subcategory, "iTunes backup manifest");
    }

    #[test]
    fn missing_files_table_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        {
            let c = Connection::open(tmp.path()).unwrap();
            c.execute("CREATE TABLE other (x INT)", []).unwrap();
        }
        assert!(parse(tmp.path()).is_empty());
    }
}
