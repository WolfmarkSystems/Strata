//! Navy Federal Credit Union — military banking.
//!
//! Source path: `/data/data/com.navyfederal.android/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Reuses shared banking helpers.

use crate::android::chase_bank::{read_accounts, read_payees, read_transactions};
use crate::android::helpers::{open_sqlite_ro, table_exists};
use std::path::Path;
use strata_plugin_sdk::ArtifactRecord;

pub const MATCHES: &[&str] = &["com.navyfederal.android/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["transactions", "transaction_history"] {
        if table_exists(&conn, table) {
            out.extend(read_transactions(&conn, path, table, "NavyFed"));
            break;
        }
    }
    for table in &["accounts", "account_summary"] {
        if table_exists(&conn, table) {
            out.extend(read_accounts(&conn, path, table, "NavyFed"));
            break;
        }
    }
    for table in &["payees", "zelle_payees"] {
        if table_exists(&conn, table) {
            out.extend(read_payees(&conn, path, table, "NavyFed"));
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
            INSERT INTO transactions VALUES('nf1',1609459200000,'Military Star Card Payment','-$150.00','$3200.00','acc1','DEBIT');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_transactions() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Bank Transaction"));
    }

    #[test]
    fn navyfed_label() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("NavyFed")));
    }

    #[test]
    fn description_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("Military Star Card")));
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
