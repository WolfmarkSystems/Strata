//! Coinbase — Android wallet/exchange account extraction.
//!
//! Source path: `/data/data/com.coinbase.android/databases/cbpay-database` or
//! `/data/data/com.coinbase.android/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. Coinbase uses Room databases
//! with tables like `account`, `transaction`, `portfolio`. Actual column
//! names vary — parser probes common variants.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.coinbase.android/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "account") {
        out.extend(read_accounts(&conn, path));
    }
    for table in &["transaction", "transactions", "tx"] {
        if table_exists(&conn, table) {
            out.extend(read_transactions(&conn, path, table));
        }
    }
    if table_exists(&conn, "portfolio") {
        out.extend(read_portfolios(&conn, path));
    }
    out
}

fn read_accounts(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, name, currency, balance, type \
               FROM account LIMIT 1000";
    let mut stmt = match conn.prepare(sql) {
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
    for (id, name, currency, balance, acct_type) in rows.flatten() {
        let id = id.unwrap_or_else(|| "(unknown)".to_string());
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let currency = currency.unwrap_or_default();
        let balance = balance.unwrap_or_else(|| "0".to_string());
        let acct_type = acct_type.unwrap_or_default();
        let title = format!("Coinbase account: {} ({} {})", name, balance, currency);
        let detail = format!(
            "Coinbase account id='{}' name='{}' currency='{}' balance='{}' type='{}'",
            id, name, currency, balance, acct_type
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "Coinbase Account",
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

fn read_transactions(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, type, status, amount, currency, created_at, native_amount \
         FROM \"{table}\" ORDER BY created_at DESC LIMIT 10000",
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
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<String>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, tx_type, status, amount, currency, created_ms, native_amount) in rows.flatten() {
        let id = id.unwrap_or_else(|| "(unknown)".to_string());
        let tx_type = tx_type.unwrap_or_default();
        let status = status.unwrap_or_default();
        let amount = amount.unwrap_or_else(|| "0".to_string());
        let currency = currency.unwrap_or_default();
        let native = native_amount.unwrap_or_default();
        let ts = created_ms.and_then(unix_ms_to_i64);
        let title = format!("Coinbase {}: {} {}", tx_type, amount, currency);
        let mut detail = format!(
            "Coinbase transaction id='{}' type='{}' status='{}' amount='{}' currency='{}'",
            id, tx_type, status, amount, currency
        );
        if !native.is_empty() {
            detail.push_str(&format!(" native_amount='{}'", native));
        }
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "Coinbase Transaction",
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

fn read_portfolios(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, name, total_balance_fiat, currency FROM portfolio LIMIT 100";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, name, balance, currency) in rows.flatten() {
        let id = id.unwrap_or_default();
        let name = name.unwrap_or_default();
        let balance = balance.unwrap_or_default();
        let currency = currency.unwrap_or_default();
        let title = format!("Coinbase portfolio: {} ({} {})", name, balance, currency);
        let detail = format!(
            "Coinbase portfolio id='{}' name='{}' balance_fiat='{}' currency='{}'",
            id, name, balance, currency
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "Coinbase Portfolio",
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

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn make_db() -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE account (
                id TEXT,
                name TEXT,
                currency TEXT,
                balance TEXT,
                type TEXT
            );
            INSERT INTO account VALUES('acct_btc','BTC Wallet','BTC','0.5','wallet');
            INSERT INTO account VALUES('acct_eth','ETH Wallet','ETH','2.0','wallet');
            CREATE TABLE "transaction" (
                id TEXT,
                type TEXT,
                status TEXT,
                amount TEXT,
                currency TEXT,
                created_at INTEGER,
                native_amount TEXT
            );
            INSERT INTO "transaction" VALUES('tx1','send','completed','0.1','BTC',1609459200000,'$4500');
            INSERT INTO "transaction" VALUES('tx2','buy','completed','1.0','ETH',1609545600000,'$2800');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_accounts_and_transactions() {
        let db = make_db();
        let r = parse(db.path());
        let accts: Vec<_> = r.iter().filter(|a| a.subcategory == "Coinbase Account").collect();
        let txs: Vec<_> = r.iter().filter(|a| a.subcategory == "Coinbase Transaction").collect();
        assert_eq!(accts.len(), 2);
        assert_eq!(txs.len(), 2);
    }

    #[test]
    fn native_amount_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("native_amount='$4500'")));
    }

    #[test]
    fn account_balance_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("0.5 BTC")));
        assert!(r.iter().any(|a| a.title.contains("2.0 ETH")));
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
