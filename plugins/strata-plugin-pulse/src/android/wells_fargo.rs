//! Wells Fargo — Android banking extraction.
//!
//! Source path: `/data/data/com.wf.wellsfargomobile/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Reuses banking helpers from
//! `chase_bank.rs`.

use crate::android::chase_bank::{read_accounts, read_payees, read_transactions};
use crate::android::helpers::{open_sqlite_ro, table_exists};
use std::path::Path;
use strata_plugin_sdk::ArtifactRecord;

pub const MATCHES: &[&str] = &["com.wf.wellsfargomobile/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["transactions", "transaction_history"] {
        if table_exists(&conn, table) {
            out.extend(read_transactions(&conn, path, table, "WellsFargo"));
            break;
        }
    }
    for table in &["accounts", "account_summary"] {
        if table_exists(&conn, table) {
            out.extend(read_accounts(&conn, path, table, "WellsFargo"));
            break;
        }
    }
    for table in &["payees", "zelle_payees"] {
        if table_exists(&conn, table) {
            out.extend(read_payees(&conn, path, table, "WellsFargo"));
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn make_db() -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE transactions (
                id TEXT,
                posted_date INTEGER,
                description TEXT,
                amount TEXT,
                balance TEXT,
                account_id TEXT,
                type TEXT
            );
            INSERT INTO transactions VALUES('wf-1',1609459200000,'Check #1234','-$500.00','$1500.00','acc1','DEBIT');
            CREATE TABLE zelle_payees (
                id TEXT,
                name TEXT,
                nickname TEXT,
                email TEXT,
                phone TEXT
            );
            INSERT INTO zelle_payees VALUES('z1','Bob Smith','Bobby','bob@example.com','555-0200');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_transactions_and_zelle_payees() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Bank Transaction"));
        assert!(r.iter().any(|a| a.subcategory == "Bank Payee"));
    }

    #[test]
    fn wells_fargo_label_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("WellsFargo")));
    }

    #[test]
    fn zelle_payee_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("name='Bob Smith'")));
    }

    #[test]
    fn missing_table_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE unrelated (id INTEGER);").unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}
