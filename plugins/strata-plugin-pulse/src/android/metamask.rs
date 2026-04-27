//! MetaMask — Ethereum wallet and dapp browser extraction.
//!
//! Source path: `/data/data/io.metamask/databases/*.db` or
//! `/data/data/io.metamask/app_webview/Default/Local Storage/*`.
//!
//! Schema note: not in ALEAPP upstream. MetaMask uses AsyncStorage (JSON
//! key-value) on React Native, but some builds include SQLite backing
//! stores. This parser handles SQLite variants where transaction history
//! and account data are exposed via tables like `account`, `transaction`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["io.metamask/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "accounts") {
        out.extend(read_accounts(&conn, path));
    }
    for table in &["transactions", "tx_history"] {
        if table_exists(&conn, table) {
            out.extend(read_transactions(&conn, path, table));
        }
    }
    if table_exists(&conn, "connected_sites") {
        out.extend(read_dapps(&conn, path));
    }
    out
}

fn read_accounts(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT address, name, balance, chain_id \
               FROM accounts LIMIT 1000";
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
    for (address, name, balance, chain_id) in rows.flatten() {
        let address = address.unwrap_or_else(|| "(unknown)".to_string());
        let name = name.unwrap_or_default();
        let balance = balance.unwrap_or_default();
        let chain_id = chain_id.unwrap_or_default();
        let title = format!("MetaMask account: {}", address);
        let detail = format!(
            "MetaMask account address='{}' name='{}' balance='{}' chain_id='{}'",
            address, name, balance, chain_id
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "MetaMask Account",
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
        "SELECT hash, from_address, to_address, value, gas, gas_price, time \
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
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
            row.get::<_, Option<i64>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (hash, from, to, value, gas, gas_price, ts_raw) in rows.flatten() {
        let hash = hash.unwrap_or_else(|| "(unknown)".to_string());
        let from = from.unwrap_or_default();
        let to = to.unwrap_or_default();
        let value = value.unwrap_or_default();
        let gas = gas.unwrap_or_default();
        let gas_price = gas_price.unwrap_or_default();
        let ts = ts_raw.and_then(unix_ms_to_i64);
        let title = format!("MetaMask tx: {} wei", value);
        let detail = format!(
            "MetaMask transaction hash='{}' from='{}' to='{}' value_wei='{}' gas='{}' gas_price='{}'",
            hash, from, to, value, gas, gas_price
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "MetaMask Transaction",
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

fn read_dapps(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT origin, permissions, connected_at \
               FROM connected_sites LIMIT 1000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (origin, permissions, connected_ms) in rows.flatten() {
        let origin = origin.unwrap_or_else(|| "(unknown)".to_string());
        let permissions = permissions.unwrap_or_default();
        let ts = connected_ms.and_then(unix_ms_to_i64);
        let title = format!("MetaMask dapp: {}", origin);
        let detail = format!(
            "MetaMask connected site origin='{}' permissions='{}'",
            origin, permissions
        );
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "MetaMask Dapp",
            title,
            detail,
            path,
            ts,
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
            CREATE TABLE accounts (
                address TEXT,
                name TEXT,
                balance TEXT,
                chain_id TEXT
            );
            INSERT INTO accounts VALUES('0xabc123','Main Account','1.5','1');
            INSERT INTO accounts VALUES('0xdef456','Trading','0.2','137');
            CREATE TABLE transactions (
                hash TEXT,
                from_address TEXT,
                to_address TEXT,
                value TEXT,
                gas TEXT,
                gas_price TEXT,
                time INTEGER
            );
            INSERT INTO transactions VALUES('0xhash1','0xabc123','0xdef456','1000000000000000000','21000','50000000000',1609459200000);
            CREATE TABLE connected_sites (
                origin TEXT,
                permissions TEXT,
                connected_at INTEGER
            );
            INSERT INTO connected_sites VALUES('https://uniswap.org','["eth_accounts"]',1609459200000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_accounts_transactions_dapps() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "MetaMask Account"));
        assert!(r.iter().any(|a| a.subcategory == "MetaMask Transaction"));
        assert!(r.iter().any(|a| a.subcategory == "MetaMask Dapp"));
    }

    #[test]
    fn chain_id_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("chain_id='1'")));
        assert!(r.iter().any(|a| a.detail.contains("chain_id='137'")));
    }

    #[test]
    fn dapp_origin_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("origin='https://uniswap.org'")));
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
