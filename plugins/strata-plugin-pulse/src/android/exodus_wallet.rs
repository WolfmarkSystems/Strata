//! Exodus Wallet — multi-asset cryptocurrency wallet extraction.
//!
//! Source path: `/data/data/exodusmovement.exodus/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Exodus uses SQLite Room databases
//! with tables like `account`, `transaction`, and `wallet`. Table and column
//! names vary across Exodus versions; parser probes common variants.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["exodusmovement.exodus/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["account", "accounts", "wallet", "wallets"] {
        if table_exists(&conn, table) {
            out.extend(read_accounts(&conn, path, table));
            break;
        }
    }
    for table in &["transaction", "transactions", "tx", "tx_history"] {
        if table_exists(&conn, table) {
            out.extend(read_transactions(&conn, path, table));
            break;
        }
    }
    out
}

fn read_accounts(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT name, coin, balance, address FROM \"{table}\" LIMIT 1000",
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
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (name, coin, balance, address) in rows.flatten() {
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let coin = coin.unwrap_or_default();
        let balance = balance.unwrap_or_else(|| "0".to_string());
        let address = address.unwrap_or_default();
        let title = format!("Exodus account: {} {} {}", name, balance, coin);
        let detail = format!(
            "Exodus wallet account name='{}' coin='{}' balance='{}' address='{}'",
            name, coin, balance, address
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "Exodus Account",
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
        "SELECT txid, amount, from_address, to_address, timestamp, coin \
         FROM \"{table}\" ORDER BY timestamp DESC LIMIT 10000",
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
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (txid, amount, from, to, ts_raw, coin) in rows.flatten() {
        let txid = txid.unwrap_or_else(|| "(unknown)".to_string());
        let amount = amount.unwrap_or_else(|| "0".to_string());
        let from = from.unwrap_or_default();
        let to = to.unwrap_or_default();
        let coin = coin.unwrap_or_default();
        let ts = ts_raw.and_then(unix_ms_to_i64);
        let title = format!("Exodus tx: {} {}", amount, coin);
        let detail = format!(
            "Exodus transaction txid='{}' amount='{}' coin='{}' from='{}' to='{}'",
            txid, amount, coin, from, to
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "Exodus Transaction",
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
                name TEXT,
                coin TEXT,
                balance TEXT,
                address TEXT
            );
            INSERT INTO account VALUES('Bitcoin Wallet','BTC','0.5','1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa');
            INSERT INTO account VALUES('Ethereum Wallet','ETH','2.0','0xabc123');
            CREATE TABLE "transaction" (
                txid TEXT,
                amount TEXT,
                from_address TEXT,
                to_address TEXT,
                timestamp INTEGER,
                coin TEXT
            );
            INSERT INTO "transaction" VALUES('abc123','0.1','1A1zP1','3J98t1',1609459200000,'BTC');
            INSERT INTO "transaction" VALUES('def456','1.5','0xabc123','0xdef456',1609545600000,'ETH');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_accounts_and_transactions() {
        let db = make_db();
        let r = parse(db.path());
        let accts: Vec<_> = r.iter().filter(|a| a.subcategory == "Exodus Account").collect();
        let txs: Vec<_> = r.iter().filter(|a| a.subcategory == "Exodus Transaction").collect();
        assert_eq!(accts.len(), 2);
        assert_eq!(txs.len(), 2);
    }

    #[test]
    fn account_balance_and_coin_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("0.5") && a.title.contains("BTC")));
    }

    #[test]
    fn transaction_addresses_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("txid='abc123'") && a.detail.contains("from='1A1zP1'")));
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
