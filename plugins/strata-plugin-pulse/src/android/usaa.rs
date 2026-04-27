//! USAA — military banking and insurance.
//!
//! Source path: `/data/data/com.usaa.mobile.android.usaa/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. USAA caches accounts,
//! transactions, and insurance policies. Reuses shared banking helpers.

use crate::android::chase_bank::{read_accounts, read_payees, read_transactions};
use crate::android::helpers::{open_sqlite_ro, table_exists};
use std::path::Path;
use strata_plugin_sdk::ArtifactRecord;

pub const MATCHES: &[&str] = &["com.usaa.mobile.android.usaa/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["transactions", "transaction_history"] {
        if table_exists(&conn, table) {
            out.extend(read_transactions(&conn, path, table, "USAA"));
            break;
        }
    }
    for table in &["accounts", "account_summary"] {
        if table_exists(&conn, table) {
            out.extend(read_accounts(&conn, path, table, "USAA"));
            break;
        }
    }
    for table in &["payees", "zelle_payees"] {
        if table_exists(&conn, table) {
            out.extend(read_payees(&conn, path, table, "USAA"));
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
            CREATE TABLE transactions (id TEXT, posted_date INTEGER, description TEXT, amount TEXT, balance TEXT, account_id TEXT, type TEXT);
            INSERT INTO transactions VALUES('u1',1609459200000,'PX Fort Meade','-$42.50','$5432.10','acc1','DEBIT');
            CREATE TABLE accounts (account_id TEXT, account_type TEXT, account_number_masked TEXT, balance TEXT, currency TEXT);
            INSERT INTO accounts VALUES('acc1','checking','****3456','$5432.10','USD');
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
    fn usaa_label_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("USAA")));
    }

    #[test]
    fn px_transaction_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("description='PX Fort Meade'")));
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
