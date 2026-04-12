//! Electrum Bitcoin Wallet — BTC wallet and Lightning channel extraction.
//!
//! Source path: `/data/data/org.electrum.electrum/databases/*.db` or
//! `/data/data/org.electrum.electrum/files/wallets/`.
//!
//! Schema note: not in ALEAPP upstream. Electrum stores wallet data in
//! SQLite (newer versions) or custom JSON/protobuf wallet files. This
//! parser targets SQLite-backed stores with tables `addresses`,
//! `transactions`, and `channels` (Lightning Network state).

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "org.electrum.electrum/databases/",
    "org.electrum.electrum/files/wallets/",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["addresses", "address"] {
        if table_exists(&conn, table) {
            out.extend(read_addresses(&conn, path, table));
            break;
        }
    }
    for table in &["transactions", "transaction", "tx"] {
        if table_exists(&conn, table) {
            out.extend(read_transactions(&conn, path, table));
            break;
        }
    }
    for table in &["channels", "channel"] {
        if table_exists(&conn, table) {
            out.extend(read_channels(&conn, path, table));
            break;
        }
    }
    out
}

fn read_addresses(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT address, label, balance FROM \"{table}\" LIMIT 5000",
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
    for (address, label, balance) in rows.flatten() {
        let address = address.unwrap_or_else(|| "(unknown)".to_string());
        let label = label.unwrap_or_default();
        let balance = balance.unwrap_or_else(|| "0".to_string());
        let title = format!("Electrum address: {}", address);
        let mut detail = format!(
            "Electrum wallet address='{}' balance='{}'",
            address, balance
        );
        if !label.is_empty() {
            detail.push_str(&format!(" label='{}'", label));
        }
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "Electrum Address",
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
        "SELECT txid, amount, timestamp, height FROM \"{table}\" ORDER BY timestamp DESC LIMIT 10000",
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
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (txid, amount_sats, ts_raw, height) in rows.flatten() {
        let txid = txid.unwrap_or_else(|| "(unknown)".to_string());
        let sats = amount_sats.unwrap_or(0);
        let btc = sats as f64 / 100_000_000.0;
        let height = height.unwrap_or(0);
        let ts = ts_raw.and_then(unix_ms_to_i64);
        let title = format!("Electrum tx: {:.8} BTC", btc);
        let detail = format!(
            "Electrum transaction txid='{}' amount_sats={} amount_btc={:.8} block_height={}",
            txid, sats, btc, height
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "Electrum Transaction",
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

fn read_channels(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT channel_id, remote_node, local_balance, remote_balance, state \
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
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (channel_id, remote_node, local_bal, remote_bal, state) in rows.flatten() {
        let channel_id = channel_id.unwrap_or_else(|| "(unknown)".to_string());
        let remote_node = remote_node.unwrap_or_default();
        let local_bal = local_bal.unwrap_or(0);
        let remote_bal = remote_bal.unwrap_or(0);
        let state = state.unwrap_or_default();
        let title = format!("Electrum LN channel: {} sats local", local_bal);
        let detail = format!(
            "Electrum Lightning channel channel_id='{}' remote_node='{}' local_balance_sats={} remote_balance_sats={} state='{}'",
            channel_id, remote_node, local_bal, remote_bal, state
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "Electrum Lightning Channel",
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
            CREATE TABLE addresses (
                address TEXT,
                label TEXT,
                balance TEXT
            );
            INSERT INTO addresses VALUES('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa','Genesis','0');
            INSERT INTO addresses VALUES('3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy','Change','0.001');
            CREATE TABLE transactions (
                txid TEXT,
                amount INTEGER,
                timestamp INTEGER,
                height INTEGER
            );
            INSERT INTO transactions VALUES('deadbeef01',100000000,1609459200000,700000);
            CREATE TABLE channels (
                channel_id TEXT,
                remote_node TEXT,
                local_balance INTEGER,
                remote_balance INTEGER,
                state TEXT
            );
            INSERT INTO channels VALUES('chan_001','03abc123',500000,200000,'OPEN');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_addresses_transactions_channels() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Electrum Address"));
        assert!(r.iter().any(|a| a.subcategory == "Electrum Transaction"));
        assert!(r.iter().any(|a| a.subcategory == "Electrum Lightning Channel"));
    }

    #[test]
    fn sats_converted_to_btc() {
        let db = make_db();
        let r = parse(db.path());
        let tx = r.iter().find(|a| a.subcategory == "Electrum Transaction").unwrap();
        assert!(tx.detail.contains("amount_btc=1.00000000"));
    }

    #[test]
    fn lightning_channel_state_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("state='OPEN'") && a.detail.contains("local_balance_sats=500000")));
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
