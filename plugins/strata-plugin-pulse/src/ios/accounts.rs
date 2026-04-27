//! iOS Accounts framework — `Accounts3.sqlite` (and `Accounts4.sqlite`).
//!
//! `Accounts3.sqlite` is the central iOS Accounts database — every
//! third-party account the user has signed in to (Mail, Twitter,
//! Facebook, Game Center, iCloud, work email) is registered here.
//! iLEAPP keys off:
//!   * `ZACCOUNT` — one row per account (display name, account type
//!     reference, parent identifier)
//!   * `ZACCOUNTTYPE` — one row per integration (e.g. iCloud, AOL,
//!     Yahoo)
//!
//! Pulse v1.0 emits per-account-type counts. Per-account credential
//! detail is queued for v1.1.

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["accounts3.sqlite", "accounts4.sqlite"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    if !util::table_exists(&conn, "ZACCOUNT") {
        return out;
    }
    let source = path.to_string_lossy().to_string();
    let total = util::count_rows(&conn, "ZACCOUNT");

    out.push(ArtifactRecord {
        category: ArtifactCategory::AccountsCredentials,
        subcategory: "Accounts".to_string(),
        timestamp: None,
        title: "iOS Accounts framework store".to_string(),
        detail: format!("{} ZACCOUNT rows (3rd-party signed-in accounts)", total),
        source_path: source.clone(),
        forensic_value: ForensicValue::High,
        mitre_technique: Some("T1078".to_string()),
        is_suspicious: false,
        raw_data: None,
        confidence: 0,
    });

    if util::table_exists(&conn, "ZACCOUNTTYPE") {
        let by_type = conn
            .prepare(
                "SELECT COALESCE(at.ZACCOUNTTYPEDESCRIPTION, '(unknown)'), COUNT(a.Z_PK) \
                 FROM ZACCOUNT a LEFT JOIN ZACCOUNTTYPE at ON at.Z_PK = a.ZACCOUNTTYPE \
                 GROUP BY at.ZACCOUNTTYPEDESCRIPTION ORDER BY COUNT(a.Z_PK) DESC",
            )
            .and_then(|mut s| {
                let r = s.query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })?;
                Ok(r.flatten().collect::<Vec<_>>())
            })
            .unwrap_or_default();

        for (type_name, count) in by_type {
            out.push(ArtifactRecord {
                category: ArtifactCategory::AccountsCredentials,
                subcategory: format!("Accounts type: {}", type_name),
                timestamp: None,
                title: format!("Account type {}", type_name),
                detail: format!("{} accounts of type {}", count, type_name),
                source_path: source.clone(),
                forensic_value: ForensicValue::High,
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
    use tempfile::NamedTempFile;

    fn make_accounts_db(types: &[(&str, usize)]) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute(
            "CREATE TABLE ZACCOUNTTYPE (\
                Z_PK INTEGER PRIMARY KEY, \
                ZACCOUNTTYPEDESCRIPTION TEXT \
             )",
            [],
        )
        .unwrap();
        c.execute(
            "CREATE TABLE ZACCOUNT (\
                Z_PK INTEGER PRIMARY KEY, \
                ZACCOUNTTYPE INTEGER, \
                ZUSERNAME TEXT \
             )",
            [],
        )
        .unwrap();
        for (i, (type_name, count)) in types.iter().enumerate() {
            let type_pk = (i + 1) as i64;
            c.execute(
                "INSERT INTO ZACCOUNTTYPE (ZACCOUNTTYPEDESCRIPTION) VALUES (?1)",
                rusqlite::params![*type_name],
            )
            .unwrap();
            for j in 0..*count {
                c.execute(
                    "INSERT INTO ZACCOUNT (ZACCOUNTTYPE, ZUSERNAME) VALUES (?1, ?2)",
                    rusqlite::params![type_pk, format!("user{}", j)],
                )
                .unwrap();
            }
        }
        tmp
    }

    #[test]
    fn matches_accounts_filenames() {
        assert!(matches(Path::new(
            "/var/mobile/Library/Accounts/Accounts3.sqlite"
        )));
        assert!(matches(Path::new("/copies/Accounts4.sqlite")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_summary_and_per_type_breakdown() {
        let tmp = make_accounts_db(&[("iCloud", 1), ("Google", 2), ("Twitter", 1)]);
        let recs = parse(tmp.path());
        let summary = recs.iter().find(|r| r.subcategory == "Accounts").unwrap();
        assert!(summary.detail.contains("4 ZACCOUNT"));
        assert!(recs
            .iter()
            .any(|r| r.subcategory == "Accounts type: iCloud"));
        assert!(recs
            .iter()
            .any(|r| r.subcategory == "Accounts type: Google"));
        assert!(recs
            .iter()
            .any(|r| r.subcategory == "Accounts type: Twitter"));
    }

    #[test]
    fn empty_accounts_table_emits_summary_only() {
        let tmp = make_accounts_db(&[]);
        let recs = parse(tmp.path());
        assert!(recs.iter().any(|r| r.subcategory == "Accounts"));
        // No type records should be present.
        assert!(!recs
            .iter()
            .any(|r| r.subcategory.starts_with("Accounts type:")));
    }

    #[test]
    fn missing_zaccount_table_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        {
            let c = Connection::open(tmp.path()).unwrap();
            c.execute("CREATE TABLE other (x INT)", []).unwrap();
        }
        assert!(parse(tmp.path()).is_empty());
    }
}
