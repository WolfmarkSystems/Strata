//! Samsung Pay — payment transaction history extraction.
//!
//! Source path: `/data/data/com.samsung.android.spay/databases/SpayPaymentDB.db`
//! (or similar SpayFw variants).
//!
//! Schema note: not in ALEAPP upstream. Parser is written from documented
//! Samsung Pay forensic references. Tables commonly include `payment_history`,
//! `card_info`, `transactions`. Column names vary across Samsung Pay versions.

use crate::android::helpers::{build_record, column_exists, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.samsung.android.spay/databases/",
    "com.samsung.android.spayfw/databases/",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["payment_history", "transactions", "tx_history"] {
        if table_exists(&conn, table) {
            out.extend(read_transactions(&conn, path, table));
        }
    }
    if table_exists(&conn, "card_info") {
        out.extend(read_cards(&conn, path));
    }
    out
}

fn read_transactions(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let ts_col = if column_exists(conn, table, "timestamp") {
        "timestamp"
    } else if column_exists(conn, table, "tx_time") {
        "tx_time"
    } else {
        "create_time"
    };
    let amount_col = if column_exists(conn, table, "amount") {
        "amount"
    } else {
        "tx_amount"
    };
    let merchant_col = if column_exists(conn, table, "merchant_name") {
        "merchant_name"
    } else {
        "merchant"
    };
    let sql = format!(
        "SELECT {ts_col}, {amount_col}, {merchant_col} FROM \"{table}\" \
         ORDER BY {ts_col} DESC LIMIT 10000",
        ts_col = ts_col,
        amount_col = amount_col,
        merchant_col = merchant_col,
        table = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (ts_ms, amount, merchant) in rows.flatten() {
        let amount = amount.unwrap_or_else(|| "0".to_string());
        let merchant = merchant.unwrap_or_else(|| "(unknown)".to_string());
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Samsung Pay: {} at {}", amount, merchant);
        let detail = format!(
            "Samsung Pay transaction amount='{}' merchant='{}'",
            amount, merchant
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Samsung Pay Transaction",
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

fn read_cards(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT card_id, card_type, last_four, issuer \
               FROM card_info LIMIT 100";
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
    for (id, card_type, last_four, issuer) in rows.flatten() {
        let id = id.unwrap_or_else(|| "(unknown)".to_string());
        let card_type = card_type.unwrap_or_default();
        let last_four = last_four.unwrap_or_default();
        let issuer = issuer.unwrap_or_default();
        let title = format!("Samsung Pay card: {} ****{}", issuer, last_four);
        let detail = format!(
            "Samsung Pay card id='{}' type='{}' issuer='{}' last_four='{}'",
            id, card_type, issuer, last_four
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "Samsung Pay Card",
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
            CREATE TABLE payment_history (
                timestamp INTEGER,
                amount TEXT,
                merchant_name TEXT
            );
            INSERT INTO payment_history VALUES(1609459200000,'$45.99','Starbucks');
            INSERT INTO payment_history VALUES(1609545600000,'$120.00','Amazon');
            CREATE TABLE card_info (
                card_id TEXT,
                card_type TEXT,
                last_four TEXT,
                issuer TEXT
            );
            INSERT INTO card_info VALUES('card_1','credit','4321','Visa');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_transactions_and_cards() {
        let db = make_db();
        let r = parse(db.path());
        let tx: Vec<_> = r.iter().filter(|a| a.subcategory == "Samsung Pay Transaction").collect();
        let cards: Vec<_> = r.iter().filter(|a| a.subcategory == "Samsung Pay Card").collect();
        assert_eq!(tx.len(), 2);
        assert_eq!(cards.len(), 1);
    }

    #[test]
    fn amount_and_merchant_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("$45.99") && a.title.contains("Starbucks")));
    }

    #[test]
    fn card_last_four_captured() {
        let db = make_db();
        let r = parse(db.path());
        let card = r.iter().find(|a| a.subcategory == "Samsung Pay Card").unwrap();
        assert!(card.detail.contains("last_four='4321'"));
        assert!(card.detail.contains("issuer='Visa'"));
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
