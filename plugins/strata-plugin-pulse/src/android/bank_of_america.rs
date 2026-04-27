//! Bank of America — Android banking extraction.
//!
//! Source path: `/data/data/com.infonow.bofa/databases/*.db` or
//! `/data/data/com.bofa.ecom.redesign/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Reuses the shared banking
//! helpers from `chase_bank.rs`.

use crate::android::chase_bank::{read_accounts, read_payees, read_transactions};
use crate::android::helpers::{open_sqlite_ro, table_exists};
use std::path::Path;
use strata_plugin_sdk::ArtifactRecord;

pub const MATCHES: &[&str] = &[
    "com.infonow.bofa/databases/",
    "com.bofa.ecom.redesign/databases/",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["transactions", "transaction_history", "tx_history"] {
        if table_exists(&conn, table) {
            out.extend(read_transactions(&conn, path, table, "BofA"));
            break;
        }
    }
    for table in &["accounts", "account_summary"] {
        if table_exists(&conn, table) {
            out.extend(read_accounts(&conn, path, table, "BofA"));
            break;
        }
    }
    for table in &["payees", "zelle_payees"] {
        if table_exists(&conn, table) {
            out.extend(read_payees(&conn, path, table, "BofA"));
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
            INSERT INTO transactions VALUES('bofa-tx1',1609459200000,'ATM Withdrawal','-$100.00','$900.00','acc1','DEBIT');
            CREATE TABLE accounts (
                account_id TEXT,
                account_type TEXT,
                account_number_masked TEXT,
                balance TEXT,
                currency TEXT
            );
            INSERT INTO accounts VALUES('acc1','savings','****5678','$900.00','USD');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_transactions_and_accounts() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Bank Transaction"));
        assert!(r.iter().any(|a| a.subcategory == "Bank Account"));
    }

    #[test]
    fn bofa_label_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("BofA")));
    }

    #[test]
    fn masked_number_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("masked_number='****5678'")));
    }

    #[test]
    fn missing_table_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE unrelated (id INTEGER);")
            .unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}
