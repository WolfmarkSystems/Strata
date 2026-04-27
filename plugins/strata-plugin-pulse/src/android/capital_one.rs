//! Capital One — Android banking extraction.
//!
//! Source path: `/data/data/com.konylabs.capitalone/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Reuses banking helpers from
//! `chase_bank.rs`.

use crate::android::chase_bank::{read_accounts, read_payees, read_transactions};
use crate::android::helpers::{open_sqlite_ro, table_exists};
use std::path::Path;
use strata_plugin_sdk::ArtifactRecord;

pub const MATCHES: &[&str] = &["com.konylabs.capitalone/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["transactions", "transaction_history"] {
        if table_exists(&conn, table) {
            out.extend(read_transactions(&conn, path, table, "CapitalOne"));
            break;
        }
    }
    for table in &["accounts", "account_summary"] {
        if table_exists(&conn, table) {
            out.extend(read_accounts(&conn, path, table, "CapitalOne"));
            break;
        }
    }
    for table in &["payees", "zelle_payees"] {
        if table_exists(&conn, table) {
            out.extend(read_payees(&conn, path, table, "CapitalOne"));
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
            INSERT INTO transactions VALUES('c1-1',1609459200000,'Amazon Purchase','-$29.99','$1970.01','acc1','DEBIT');
            CREATE TABLE accounts (
                account_id TEXT,
                account_type TEXT,
                account_number_masked TEXT,
                balance TEXT,
                currency TEXT
            );
            INSERT INTO accounts VALUES('acc1','credit card','****9012','-$500.00','USD');
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
    fn capital_one_label_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("CapitalOne")));
    }

    #[test]
    fn credit_card_account_captured() {
        let db = make_db();
        let r = parse(db.path());
        let acct = r.iter().find(|a| a.subcategory == "Bank Account").unwrap();
        assert!(acct.detail.contains("type='credit card'"));
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
