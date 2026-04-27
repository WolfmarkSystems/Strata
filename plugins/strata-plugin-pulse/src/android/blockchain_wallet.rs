//! Blockchain.com Wallet — Bitcoin/crypto wallet and contact extraction.
//!
//! Source path: `/data/data/piuk.blockchain.android/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Blockchain.com Wallet stores data
//! in SQLite Room databases with tables like `wallet_info`, `transaction`,
//! and `contact`. Table names vary across app versions.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["piuk.blockchain.android/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["wallet_info", "wallet", "account"] {
        if table_exists(&conn, table) {
            out.extend(read_wallet_info(&conn, path, table));
            break;
        }
    }
    for table in &["transaction", "transactions", "tx_history"] {
        if table_exists(&conn, table) {
            out.extend(read_transactions(&conn, path, table));
            break;
        }
    }
    for table in &["contact", "contacts"] {
        if table_exists(&conn, table) {
            out.extend(read_contacts(&conn, path, table));
            break;
        }
    }
    out
}

fn read_wallet_info(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT guid, currency, balance, label FROM \"{table}\" LIMIT 100",
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
    for (guid, currency, balance, label) in rows.flatten() {
        let guid = guid.unwrap_or_else(|| "(unknown)".to_string());
        let currency = currency.unwrap_or_default();
        let balance = balance.unwrap_or_else(|| "0".to_string());
        let label = label.unwrap_or_default();
        let title = format!("Blockchain.com wallet: {} {}", balance, currency);
        let detail = format!(
            "Blockchain.com wallet guid='{}' currency='{}' balance='{}' label='{}'",
            guid, currency, balance, label
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "Blockchain Wallet",
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
        "SELECT txid, amount, fee, time, direction FROM \"{table}\" ORDER BY time DESC LIMIT 10000",
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
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (txid, amount_sats, fee_sats, ts_raw, direction) in rows.flatten() {
        let txid = txid.unwrap_or_else(|| "(unknown)".to_string());
        let sats = amount_sats.unwrap_or(0);
        let fee = fee_sats.unwrap_or(0);
        let btc = sats as f64 / 100_000_000.0;
        let direction = direction.unwrap_or_default();
        let ts = ts_raw.and_then(unix_ms_to_i64);
        let title = format!("Blockchain.com tx {} {:.8} BTC", direction, btc);
        let detail = format!(
            "Blockchain.com transaction txid='{}' amount_sats={} amount_btc={:.8} fee_sats={} direction='{}'",
            txid, sats, btc, fee, direction
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "Blockchain Transaction",
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

fn read_contacts(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, name, address, mdid FROM \"{table}\" LIMIT 1000",
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
    for (id, name, address, mdid) in rows.flatten() {
        let id = id.unwrap_or_default();
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let address = address.unwrap_or_default();
        let mdid = mdid.unwrap_or_default();
        let title = format!("Blockchain.com contact: {}", name);
        let detail = format!(
            "Blockchain.com contact id='{}' name='{}' address='{}' mdid='{}'",
            id, name, address, mdid
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "Blockchain Contact",
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
            CREATE TABLE wallet_info (
                guid TEXT,
                currency TEXT,
                balance TEXT,
                label TEXT
            );
            INSERT INTO wallet_info VALUES('guid-abc-123','BTC','0.75','My Wallet');
            CREATE TABLE "transaction" (
                txid TEXT,
                amount INTEGER,
                fee INTEGER,
                time INTEGER,
                direction TEXT
            );
            INSERT INTO "transaction" VALUES('txhash001',50000000,1500,1609459200000,'sent');
            INSERT INTO "transaction" VALUES('txhash002',75000000,2000,1609545600000,'received');
            CREATE TABLE contact (
                id TEXT,
                name TEXT,
                address TEXT,
                mdid TEXT
            );
            INSERT INTO contact VALUES('c1','Alice','1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa','mdid_alice');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_wallet_transactions_contacts() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Blockchain Wallet"));
        assert!(r.iter().any(|a| a.subcategory == "Blockchain Transaction"));
        assert!(r.iter().any(|a| a.subcategory == "Blockchain Contact"));
    }

    #[test]
    fn sats_converted_to_btc() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("amount_btc=0.50000000")));
    }

    #[test]
    fn contact_address_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("name='Alice'") && a.detail.contains("mdid='mdid_alice'")));
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
