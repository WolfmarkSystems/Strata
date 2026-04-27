//! Robinhood — Android investment app order and position extraction.
//!
//! Source path: `/data/data/com.robinhood.android/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. Robinhood uses Room databases
//! with tables like `orders` (stock/crypto orders), `positions`
//! (holdings), `instruments`. Column names vary.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.robinhood.android/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["orders", "order_history"] {
        if table_exists(&conn, table) {
            out.extend(read_orders(&conn, path, table));
            break;
        }
    }
    if table_exists(&conn, "positions") {
        out.extend(read_positions(&conn, path));
    }
    out
}

fn read_orders(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, symbol, side, quantity, price, total, \
         created_at, state, order_type \
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
            row.get::<_, Option<String>>(5).unwrap_or(None),
            row.get::<_, Option<i64>>(6).unwrap_or(None),
            row.get::<_, Option<String>>(7).unwrap_or(None),
            row.get::<_, Option<String>>(8).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, symbol, side, quantity, price, total, created_ms, state, order_type) in rows.flatten()
    {
        let id = id.unwrap_or_else(|| "(unknown)".to_string());
        let symbol = symbol.unwrap_or_else(|| "(unknown)".to_string());
        let side = side.unwrap_or_default();
        let quantity = quantity.unwrap_or_default();
        let price = price.unwrap_or_default();
        let total = total.unwrap_or_default();
        let state = state.unwrap_or_default();
        let order_type = order_type.unwrap_or_default();
        let ts = created_ms.and_then(unix_ms_to_i64);
        let title = format!("Robinhood {} {} x{}", side, symbol, quantity);
        let detail = format!(
            "Robinhood order id='{}' symbol='{}' side='{}' quantity='{}' price='{}' total='{}' state='{}' type='{}'",
            id, symbol, side, quantity, price, total, state, order_type
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Robinhood Order",
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

fn read_positions(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT instrument, symbol, quantity, average_buy_price, \
               intraday_quantity, updated_at \
               FROM positions ORDER BY updated_at DESC LIMIT 1000";
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
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (instrument, symbol, quantity, avg_price, intraday, updated_ms) in rows.flatten() {
        let instrument = instrument.unwrap_or_default();
        let symbol = symbol.unwrap_or_else(|| "(unknown)".to_string());
        let quantity = quantity.unwrap_or_default();
        let avg_price = avg_price.unwrap_or_default();
        let intraday = intraday.unwrap_or_default();
        let ts = updated_ms.and_then(unix_ms_to_i64);
        let title = format!("Robinhood position: {} x{}", symbol, quantity);
        let detail = format!(
            "Robinhood position symbol='{}' instrument='{}' quantity='{}' avg_buy_price='{}' intraday='{}'",
            symbol, instrument, quantity, avg_price, intraday
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "Robinhood Position",
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
            CREATE TABLE orders (
                id TEXT,
                symbol TEXT,
                side TEXT,
                quantity TEXT,
                price TEXT,
                total TEXT,
                created_at INTEGER,
                state TEXT,
                order_type TEXT
            );
            INSERT INTO orders VALUES('ord-1','AAPL','buy','10','150.00','1500.00',1609459200000,'filled','market');
            INSERT INTO orders VALUES('ord-2','TSLA','sell','5','720.00','3600.00',1609545600000,'filled','limit');
            CREATE TABLE positions (
                instrument TEXT,
                symbol TEXT,
                quantity TEXT,
                average_buy_price TEXT,
                intraday_quantity TEXT,
                updated_at INTEGER
            );
            INSERT INTO positions VALUES('inst-aapl','AAPL','10','150.00','0',1609459200000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_orders_and_positions() {
        let db = make_db();
        let r = parse(db.path());
        let orders: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "Robinhood Order")
            .collect();
        let positions: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "Robinhood Position")
            .collect();
        assert_eq!(orders.len(), 2);
        assert_eq!(positions.len(), 1);
    }

    #[test]
    fn order_side_and_symbol_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("Robinhood buy AAPL")));
        assert!(r.iter().any(|a| a.title.contains("Robinhood sell TSLA")));
    }

    #[test]
    fn position_average_price_captured() {
        let db = make_db();
        let r = parse(db.path());
        let p = r
            .iter()
            .find(|a| a.subcategory == "Robinhood Position")
            .unwrap();
        assert!(p.detail.contains("avg_buy_price='150.00'"));
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
