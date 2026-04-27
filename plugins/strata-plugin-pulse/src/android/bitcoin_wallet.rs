//! Bitcoin.com Wallet — cryptocurrency wallet extraction.
//!
//! Source path: `/data/data/com.bitcoin.mwallet/databases/*.db` or
//! LevelDB-backed `files/` directories.
//!
//! Schema note: not in ALEAPP upstream. This parser targets SQLite-based
//! variants of Bitcoin.com Wallet and follows common BIP-32 HD wallet
//! schema conventions (`address`, `tx`, `wallet`). Table names vary
//! across wallet versions.

use crate::android::helpers::{
    build_record, column_exists, open_sqlite_ro, table_exists, unix_ms_to_i64,
};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.bitcoin.mwallet/databases/",
    "com.bitcoin.mwallet/files/",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["address", "addresses"] {
        if table_exists(&conn, table) {
            out.extend(read_addresses(&conn, path, table));
            break;
        }
    }
    for table in &["tx", "transactions", "wallet_tx"] {
        if table_exists(&conn, table) {
            out.extend(read_transactions(&conn, path, table));
            break;
        }
    }
    for table in &["wallet", "wallets"] {
        if table_exists(&conn, table) {
            out.extend(read_wallets(&conn, path, table));
            break;
        }
    }
    out
}

fn read_addresses(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let label_col = if column_exists(conn, table, "label") {
        "label"
    } else {
        "name"
    };
    let sql = format!(
        "SELECT address, {label_col}, path, created_at FROM \"{table}\" LIMIT 5000",
        label_col = label_col,
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
            row.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (address, label, derivation_path, created_ms) in rows.flatten() {
        let address = address.unwrap_or_else(|| "(unknown)".to_string());
        let label = label.unwrap_or_default();
        let derivation_path = derivation_path.unwrap_or_default();
        let ts = created_ms.and_then(unix_ms_to_i64);
        let title = format!("BTC address: {}", address);
        let mut detail = format!("Bitcoin wallet address address='{}'", address);
        if !label.is_empty() {
            detail.push_str(&format!(" label='{}'", label));
        }
        if !derivation_path.is_empty() {
            detail.push_str(&format!(" derivation_path='{}'", derivation_path));
        }
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "Bitcoin Address",
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

fn read_transactions(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT txid, amount, fee, confirmations, address, time \
         FROM \"{table}\" ORDER BY time DESC LIMIT 10000",
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
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (txid, amount, fee, confirmations, address, time) in rows.flatten() {
        let txid = txid.unwrap_or_else(|| "(unknown)".to_string());
        let amount_sats = amount.unwrap_or(0);
        let amount_btc = amount_sats as f64 / 100_000_000.0;
        let fee_sats = fee.unwrap_or(0);
        let confirmations = confirmations.unwrap_or(0);
        let address = address.unwrap_or_default();
        let ts = time;
        let title = format!("BTC tx {:.8} BTC", amount_btc);
        let mut detail = format!(
            "Bitcoin transaction txid='{}' amount_sats={} amount_btc={:.8} fee_sats={} confirmations={}",
            txid, amount_sats, amount_btc, fee_sats, confirmations
        );
        if !address.is_empty() {
            detail.push_str(&format!(" address='{}'", address));
        }
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "Bitcoin Transaction",
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

fn read_wallets(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, name, coin, network FROM \"{table}\" LIMIT 100",
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
    for (id, name, coin, network) in rows.flatten() {
        let id = id.unwrap_or_else(|| "(unknown)".to_string());
        let name = name.unwrap_or_default();
        let coin = coin.unwrap_or_default();
        let network = network.unwrap_or_default();
        let title = format!("BTC wallet: {} ({})", name, coin);
        let detail = format!(
            "Bitcoin wallet id='{}' name='{}' coin='{}' network='{}'",
            id, name, coin, network
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "Bitcoin Wallet",
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
            CREATE TABLE wallet (
                id TEXT,
                name TEXT,
                coin TEXT,
                network TEXT
            );
            INSERT INTO wallet VALUES('w1','My Wallet','btc','livenet');
            CREATE TABLE address (
                address TEXT,
                label TEXT,
                path TEXT,
                created_at INTEGER
            );
            INSERT INTO address VALUES('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa','Satoshi','m/44''/0''/0''/0/0',1609459200000);
            INSERT INTO address VALUES('3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy','Change','m/44''/0''/0''/1/0',1609459300000);
            CREATE TABLE tx (
                txid TEXT,
                amount INTEGER,
                fee INTEGER,
                confirmations INTEGER,
                address TEXT,
                time INTEGER
            );
            INSERT INTO tx VALUES('abc123',100000000,1000,6,'1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',1609459200);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_wallets_addresses_transactions() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Bitcoin Wallet"));
        assert!(r.iter().any(|a| a.subcategory == "Bitcoin Address"));
        assert!(r.iter().any(|a| a.subcategory == "Bitcoin Transaction"));
    }

    #[test]
    fn satoshis_converted_to_btc() {
        let db = make_db();
        let r = parse(db.path());
        let tx = r
            .iter()
            .find(|a| a.subcategory == "Bitcoin Transaction")
            .unwrap();
        // 100000000 sats = 1.0 BTC
        assert!(tx.detail.contains("amount_btc=1.00000000"));
        assert!(tx.title.contains("1.00000000 BTC"));
    }

    #[test]
    fn derivation_path_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("derivation_path='m/44'/0'/0'/0/0'")));
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
