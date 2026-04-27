//! Coinomi Wallet — multi-coin cryptocurrency wallet extraction.
//!
//! Source path: `/data/data/com.coinomi.wallet/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Coinomi uses SQLite Room databases
//! with tables like `wallets`, `coins`, and `transactions`. Table names
//! vary across Coinomi versions; parser probes common variants.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.coinomi.wallet/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["wallets", "wallet", "coins", "coin"] {
        if table_exists(&conn, table) {
            out.extend(read_wallets(&conn, path, table));
            break;
        }
    }
    for table in &["transactions", "transaction", "tx_history", "tx"] {
        if table_exists(&conn, table) {
            out.extend(read_transactions(&conn, path, table));
            break;
        }
    }
    out
}

fn read_wallets(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT coin, address, balance FROM \"{table}\" LIMIT 1000",
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
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (coin, address, balance) in rows.flatten() {
        let coin = coin.unwrap_or_else(|| "(unknown)".to_string());
        let address = address.unwrap_or_default();
        let balance = balance.unwrap_or_else(|| "0".to_string());
        let title = format!("Coinomi wallet: {} {}", balance, coin);
        let detail = format!(
            "Coinomi wallet coin='{}' address='{}' balance='{}'",
            coin, address, balance
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "Coinomi Wallet",
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
        "SELECT txid, amount, coin, from_address, to_address, timestamp \
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
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (txid, amount, coin, from, to, ts_raw) in rows.flatten() {
        let txid = txid.unwrap_or_else(|| "(unknown)".to_string());
        let amount = amount.unwrap_or_else(|| "0".to_string());
        let coin = coin.unwrap_or_default();
        let from = from.unwrap_or_default();
        let to = to.unwrap_or_default();
        let ts = ts_raw.and_then(unix_ms_to_i64);
        let title = format!("Coinomi tx: {} {}", amount, coin);
        let detail = format!(
            "Coinomi transaction txid='{}' amount='{}' coin='{}' from='{}' to='{}'",
            txid, amount, coin, from, to
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "Coinomi Transaction",
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
            CREATE TABLE wallets (
                coin TEXT,
                address TEXT,
                balance TEXT
            );
            INSERT INTO wallets VALUES('BTC','1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa','0.5');
            INSERT INTO wallets VALUES('ETH','0xabc123','2.0');
            INSERT INTO wallets VALUES('LTC','LcVTmmdaZnQDcFhGHDQ7GKcG5rBcfRQ6Xd','10.0');
            CREATE TABLE transactions (
                txid TEXT,
                amount TEXT,
                coin TEXT,
                from_address TEXT,
                to_address TEXT,
                timestamp INTEGER
            );
            INSERT INTO transactions VALUES('txabc','0.1','BTC','1A1zP1','3J98t1',1609459200000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_wallets_and_transactions() {
        let db = make_db();
        let r = parse(db.path());
        let wallets: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "Coinomi Wallet")
            .collect();
        let txs: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "Coinomi Transaction")
            .collect();
        assert_eq!(wallets.len(), 3);
        assert_eq!(txs.len(), 1);
    }

    #[test]
    fn wallet_coin_and_balance_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("coin='BTC'") && a.detail.contains("balance='0.5'")));
    }

    #[test]
    fn transaction_txid_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("txid='txabc'")));
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
