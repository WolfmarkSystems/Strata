//! iOS Wallet — `nanopasses.sqlite3` and `passes23.sqlite`.
//!
//! Apple Wallet stores boarding passes, loyalty cards, transit passes,
//! and event tickets in `nanopasses.sqlite3`. iOS 16+ migrated some
//! types to `passes23.sqlite`. The relevant tables iLEAPP keys off:
//!   * `pass`        — pass metadata (organization, type)
//!   * `payment_pass` — Apple Pay card metadata (no PAN, but device
//!     account number)
//!
//! Pulse v1.0 emits row counts for each.

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(
        path,
        &[
            "nanopasses.sqlite3",
            "nanopasses.sqlite",
            "passes23.sqlite",
            "passes.sqlite",
        ],
    )
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    let source = path.to_string_lossy().to_string();

    let mut emitted = false;
    if util::table_exists(&conn, "pass") {
        let count = util::count_rows(&conn, "pass");
        out.push(ArtifactRecord {
            category: ArtifactCategory::AccountsCredentials,
            subcategory: "Wallet passes".to_string(),
            timestamp: None,
            title: "Apple Wallet passes".to_string(),
            detail: format!("{} pass rows (boarding, loyalty, tickets, transit)", count),
            source_path: source.clone(),
            forensic_value: ForensicValue::High,
            mitre_technique: None,
            is_suspicious: false,
            raw_data: None,
            confidence: 0,
        });
        emitted = true;
    }
    if util::table_exists(&conn, "payment_pass") {
        let count = util::count_rows(&conn, "payment_pass");
        out.push(ArtifactRecord {
            category: ArtifactCategory::AccountsCredentials,
            subcategory: "Wallet payment passes".to_string(),
            timestamp: None,
            title: "Apple Pay payment passes".to_string(),
            detail: format!("{} payment_pass rows (Apple Pay cards)", count),
            source_path: source,
            forensic_value: ForensicValue::Critical,
            mitre_technique: Some("T1005".to_string()),
            is_suspicious: false,
            raw_data: None,
            confidence: 0,
        });
        emitted = true;
    }
    if !emitted {
        return Vec::new();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    fn make_wallet_db(passes: usize, payments: usize) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute(
            "CREATE TABLE pass (id INTEGER PRIMARY KEY, organization TEXT, type INTEGER)",
            [],
        )
        .unwrap();
        c.execute(
            "CREATE TABLE payment_pass (id INTEGER PRIMARY KEY, dpan TEXT)",
            [],
        )
        .unwrap();
        for i in 0..passes {
            c.execute(
                "INSERT INTO pass (organization, type) VALUES (?1, 1)",
                rusqlite::params![format!("Org{}", i)],
            )
            .unwrap();
        }
        for i in 0..payments {
            c.execute(
                "INSERT INTO payment_pass (dpan) VALUES (?1)",
                rusqlite::params![format!("dpan{}", i)],
            )
            .unwrap();
        }
        tmp
    }

    #[test]
    fn matches_wallet_filenames() {
        assert!(matches(Path::new("/var/mobile/Library/Passes/nanopasses.sqlite3")));
        assert!(matches(Path::new("/copies/passes23.sqlite")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_pass_and_payment_pass_counts() {
        let tmp = make_wallet_db(3, 2);
        let recs = parse(tmp.path());
        let p = recs.iter().find(|r| r.subcategory == "Wallet passes").unwrap();
        assert!(p.detail.contains("3 pass rows"));
        let pp = recs
            .iter()
            .find(|r| r.subcategory == "Wallet payment passes")
            .unwrap();
        assert!(pp.detail.contains("2 payment_pass"));
        assert_eq!(pp.forensic_value, ForensicValue::Critical);
    }

    #[test]
    fn empty_wallet_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        {
            let c = Connection::open(tmp.path()).unwrap();
            c.execute("CREATE TABLE other (x INT)", []).unwrap();
        }
        assert!(parse(tmp.path()).is_empty());
    }

    #[test]
    fn passes_only_db_emits_one_record() {
        let tmp = make_wallet_db(1, 0);
        let recs = parse(tmp.path());
        // pass table emits one record; payment_pass exists but is empty,
        // so it still emits a (zero-count) record.
        assert_eq!(recs.len(), 2);
    }
}
