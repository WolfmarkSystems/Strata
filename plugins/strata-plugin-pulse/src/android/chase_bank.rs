//! Chase Mobile — banking transaction and account extraction.
//!
//! Source path: `/data/data/com.chase.sig.android/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Banking apps typically store
//! transaction history in `transactions` or `transaction_history`,
//! accounts in `accounts`, and payees in `payees` or `zelle_payees`.
//! Schemas vary; parser probes common column variants.

use crate::android::helpers::{build_record, column_exists, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.chase.sig.android/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["transactions", "transaction_history", "tx_history"] {
        if table_exists(&conn, table) {
            out.extend(read_transactions(&conn, path, table, "Chase"));
            break;
        }
    }
    for table in &["accounts", "account_summary"] {
        if table_exists(&conn, table) {
            out.extend(read_accounts(&conn, path, table, "Chase"));
            break;
        }
    }
    for table in &["payees", "zelle_payees"] {
        if table_exists(&conn, table) {
            out.extend(read_payees(&conn, path, table, "Chase"));
            break;
        }
    }
    out
}

/// Shared transaction extractor reused by multiple banking parsers.
pub(super) fn read_transactions(
    conn: &rusqlite::Connection,
    path: &Path,
    table: &str,
    bank: &str,
) -> Vec<ArtifactRecord> {
    let ts_col = if column_exists(conn, table, "posted_date") {
        "posted_date"
    } else if column_exists(conn, table, "timestamp") {
        "timestamp"
    } else {
        "transaction_date"
    };
    let desc_col = if column_exists(conn, table, "description") {
        "description"
    } else if column_exists(conn, table, "merchant") {
        "merchant"
    } else {
        "memo"
    };
    let sql = format!(
        "SELECT id, {ts_col}, {desc_col}, amount, balance, account_id, type \
         FROM \"{table}\" ORDER BY {ts_col} DESC LIMIT 10000",
        ts_col = ts_col,
        desc_col = desc_col,
        table = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
            row.get::<_, Option<String>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, ts_raw, description, amount, balance, account_id, tx_type) in rows.flatten() {
        let id = id.unwrap_or_else(|| "(unknown)".to_string());
        let description = description.unwrap_or_default();
        let amount = amount.unwrap_or_default();
        let balance = balance.unwrap_or_default();
        let account_id = account_id.unwrap_or_default();
        let tx_type = tx_type.unwrap_or_default();
        let ts = ts_raw.and_then(|t| {
            if t > 10_000_000_000 { unix_ms_to_i64(t) } else { Some(t) }
        });
        let title = format!("{} tx: {} {}", bank, amount, description);
        let detail = format!(
            "{} transaction id='{}' description='{}' amount='{}' balance='{}' account_id='{}' type='{}'",
            bank, id, description, amount, balance, account_id, tx_type
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Bank Transaction",
            title,
            detail,
            path,
            ts,
            ForensicValue::Critical,
            false,
        ));
    }
    out
}

pub(super) fn read_accounts(
    conn: &rusqlite::Connection,
    path: &Path,
    table: &str,
    bank: &str,
) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT account_id, account_type, account_number_masked, balance, currency \
         FROM \"{table}\" LIMIT 100",
        table = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, acct_type, masked, balance, currency) in rows.flatten() {
        let id = id.unwrap_or_else(|| "(unknown)".to_string());
        let acct_type = acct_type.unwrap_or_default();
        let masked = masked.unwrap_or_default();
        let balance = balance.unwrap_or_default();
        let currency = currency.unwrap_or_default();
        let title = format!("{} account: {} ({})", bank, masked, acct_type);
        let detail = format!(
            "{} account id='{}' type='{}' masked_number='{}' balance='{}' currency='{}'",
            bank, id, acct_type, masked, balance, currency
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "Bank Account",
            title,
            detail,
            path,
            None,
            ForensicValue::Critical,
            false,
        ));
    }
    out
}

pub(super) fn read_payees(
    conn: &rusqlite::Connection,
    path: &Path,
    table: &str,
    bank: &str,
) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, name, nickname, email, phone \
         FROM \"{table}\" LIMIT 1000",
        table = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, name, nickname, email, phone) in rows.flatten() {
        let id = id.unwrap_or_default();
        let name = name.unwrap_or_else(|| "(unknown)".to_string());
        let nickname = nickname.unwrap_or_default();
        let email = email.unwrap_or_default();
        let phone = phone.unwrap_or_default();
        let title = format!("{} payee: {}", bank, name);
        let detail = format!(
            "{} payee id='{}' name='{}' nickname='{}' email='{}' phone='{}'",
            bank, id, name, nickname, email, phone
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Bank Payee",
            title,
            detail,
            path,
            None,
            ForensicValue::High,
            false,
        ));
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
            INSERT INTO transactions VALUES('tx1',1609459200000,'Starbucks','-$5.50','$1234.50','acc1','DEBIT');
            INSERT INTO transactions VALUES('tx2',1609545600000,'Direct Deposit','$2000.00','$3234.50','acc1','CREDIT');
            CREATE TABLE accounts (
                account_id TEXT,
                account_type TEXT,
                account_number_masked TEXT,
                balance TEXT,
                currency TEXT
            );
            INSERT INTO accounts VALUES('acc1','checking','****1234','$3234.50','USD');
            CREATE TABLE payees (
                id TEXT,
                name TEXT,
                nickname TEXT,
                email TEXT,
                phone TEXT
            );
            INSERT INTO payees VALUES('p1','Alice Johnson','Alice','alice@example.com','555-0100');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_tx_accounts_payees() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Bank Transaction"));
        assert!(r.iter().any(|a| a.subcategory == "Bank Account"));
        assert!(r.iter().any(|a| a.subcategory == "Bank Payee"));
    }

    #[test]
    fn amount_and_description_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("Chase") && a.title.contains("Starbucks")));
    }

    #[test]
    fn account_masked_number_captured() {
        let db = make_db();
        let r = parse(db.path());
        let acct = r.iter().find(|a| a.subcategory == "Bank Account").unwrap();
        assert!(acct.detail.contains("masked_number='****1234'"));
    }

    #[test]
    fn payee_email_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("email='alice@example.com'")));
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
