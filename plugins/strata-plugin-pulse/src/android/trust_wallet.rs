//! Trust Wallet — multi-chain cryptocurrency wallet extraction.
//!
//! Source path: `/data/data/com.wallet.crypto.trustapp/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Trust Wallet uses Room databases
//! with tables like `wallet`, `token`, `transaction`, `account`. Schema
//! varies across Trust Wallet versions.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.wallet.crypto.trustapp/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["wallet", "wallets"] {
        if table_exists(&conn, table) {
            out.extend(read_wallets(&conn, path, table));
            break;
        }
    }
    for table in &["token", "tokens", "asset"] {
        if table_exists(&conn, table) {
            out.extend(read_tokens(&conn, path, table));
            break;
        }
    }
    for table in &["transaction", "transactions", "tx"] {
        if table_exists(&conn, table) {
            out.extend(read_transactions(&conn, path, table));
            break;
        }
    }
    out
}

fn read_wallets(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, name, address, type FROM \"{table}\" LIMIT 100",
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
    for (id, name, address, wallet_type) in rows.flatten() {
        let id = id.unwrap_or_default();
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let address = address.unwrap_or_default();
        let wallet_type = wallet_type.unwrap_or_default();
        let title = format!("Trust wallet: {} ({})", name, address);
        let detail = format!(
            "Trust Wallet id='{}' name='{}' address='{}' type='{}'",
            id, name, address, wallet_type
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "Trust Wallet",
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

fn read_tokens(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT symbol, name, address, decimals, balance, chain \
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
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (symbol, name, address, decimals, balance, chain) in rows.flatten() {
        let symbol = symbol.unwrap_or_else(|| "(unknown)".to_string());
        let name = name.unwrap_or_default();
        let address = address.unwrap_or_default();
        let decimals = decimals.unwrap_or(18);
        let balance = balance.unwrap_or_else(|| "0".to_string());
        let chain = chain.unwrap_or_default();
        let title = format!("Trust token: {} ({})", symbol, name);
        let detail = format!(
            "Trust Wallet token symbol='{}' name='{}' contract='{}' decimals={} balance='{}' chain='{}'",
            symbol, name, address, decimals, balance, chain
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "Trust Token",
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
        "SELECT hash, from_address, to_address, value, timestamp, coin \
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
    for (hash, from, to, value, ts_raw, coin) in rows.flatten() {
        let hash = hash.unwrap_or_else(|| "(unknown)".to_string());
        let from = from.unwrap_or_default();
        let to = to.unwrap_or_default();
        let value = value.unwrap_or_else(|| "0".to_string());
        let coin = coin.unwrap_or_default();
        // Trust uses seconds or ms — normalize
        let ts = ts_raw.map(|t| if t > 10_000_000_000 { t / 1000 } else { t });
        let title = format!("Trust tx: {} {}", value, coin);
        let detail = format!(
            "Trust Wallet transaction hash='{}' from='{}' to='{}' value='{}' coin='{}'",
            hash, from, to, value, coin
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "Trust Transaction",
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
            CREATE TABLE wallet (
                id TEXT,
                name TEXT,
                address TEXT,
                type TEXT
            );
            INSERT INTO wallet VALUES('w1','Main Wallet','0xabc123','MnemonicWallet');
            CREATE TABLE token (
                symbol TEXT,
                name TEXT,
                address TEXT,
                decimals INTEGER,
                balance TEXT,
                chain TEXT
            );
            INSERT INTO token VALUES('ETH','Ethereum','0x0',18,'1.5','ethereum');
            INSERT INTO token VALUES('USDT','Tether','0xdac17f958d2ee523a2206206994597c13d831ec7',6,'1000','ethereum');
            CREATE TABLE "transaction" (
                hash TEXT,
                from_address TEXT,
                to_address TEXT,
                value TEXT,
                timestamp INTEGER,
                coin TEXT
            );
            INSERT INTO "transaction" VALUES('0xdeadbeef','0xabc123','0xdef456','0.5',1609459200,'ETH');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_wallets_tokens_transactions() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Trust Wallet"));
        assert!(r.iter().any(|a| a.subcategory == "Trust Token"));
        assert!(r.iter().any(|a| a.subcategory == "Trust Transaction"));
    }

    #[test]
    fn usdt_contract_captured() {
        let db = make_db();
        let r = parse(db.path());
        let usdt = r.iter().find(|a| a.detail.contains("USDT")).unwrap();
        assert!(usdt.detail.contains("contract='0xdac17f958d2ee523a2206206994597c13d831ec7'"));
        assert!(usdt.detail.contains("decimals=6"));
    }

    #[test]
    fn transaction_hash_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("hash='0xdeadbeef'")));
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
