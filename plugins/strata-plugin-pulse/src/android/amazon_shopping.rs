//! Amazon Shopping — Android app data extraction.
//!
//! Source path: `/data/data/com.amazon.mShop.android.shopping/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. Amazon stores search history in
//! `search_history` and recently viewed items in `recently_viewed`. The
//! actual schema varies across Amazon app versions; parser probes common
//! column variants and degrades gracefully.

use crate::android::helpers::{
    build_record, column_exists, open_sqlite_ro, table_exists, unix_ms_to_i64,
};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.amazon.mshop.android.shopping/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["search_history", "search_queries", "queries"] {
        if table_exists(&conn, table) {
            out.extend(read_searches(&conn, path, table));
            break;
        }
    }
    for table in &["recently_viewed", "recently_viewed_items", "browse_history"] {
        if table_exists(&conn, table) {
            out.extend(read_viewed(&conn, path, table));
            break;
        }
    }
    out
}

fn read_searches(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let ts_col = if column_exists(conn, table, "timestamp") {
        "timestamp"
    } else if column_exists(conn, table, "query_time") {
        "query_time"
    } else {
        "created_at"
    };
    let query_col = if column_exists(conn, table, "query") {
        "query"
    } else {
        "search_term"
    };
    let sql = format!(
        "SELECT {query_col}, {ts_col} FROM \"{table}\" \
         ORDER BY {ts_col} DESC LIMIT 5000",
        query_col = query_col,
        ts_col = ts_col,
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
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (query, ts_raw) in rows.flatten() {
        let query = query.unwrap_or_else(|| "(empty)".to_string());
        // Normalize ms vs seconds
        let ts = ts_raw.and_then(|t| {
            if t > 10_000_000_000 {
                unix_ms_to_i64(t)
            } else {
                Some(t)
            }
        });
        let title = format!("Amazon search: {}", query);
        let detail = format!("Amazon Shopping search query='{}'", query);
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "Amazon Search",
            title,
            detail,
            path,
            ts,
            ForensicValue::Medium,
            false,
        ));
    }
    out
}

fn read_viewed(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT asin, title, timestamp, price FROM \"{table}\" \
         ORDER BY timestamp DESC LIMIT 5000",
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
            row.get::<_, Option<String>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (asin, title, ts_raw, price) in rows.flatten() {
        let asin = asin.unwrap_or_else(|| "(unknown)".to_string());
        let product_title = title.unwrap_or_else(|| "(unnamed)".to_string());
        let price = price.unwrap_or_default();
        let ts = ts_raw.and_then(|t| {
            if t > 10_000_000_000 {
                unix_ms_to_i64(t)
            } else {
                Some(t)
            }
        });
        let title_str = format!("Amazon viewed: {}", product_title);
        let detail = format!(
            "Amazon Shopping viewed asin='{}' title='{}' price='{}'",
            asin, product_title, price
        );
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "Amazon Viewed",
            title_str,
            detail,
            path,
            ts,
            ForensicValue::Medium,
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
            CREATE TABLE search_history (
                query TEXT,
                timestamp INTEGER
            );
            INSERT INTO search_history VALUES('kindle paperwhite',1609459200000);
            INSERT INTO search_history VALUES('echo dot',1609459300000);
            CREATE TABLE recently_viewed (
                asin TEXT,
                title TEXT,
                timestamp INTEGER,
                price TEXT
            );
            INSERT INTO recently_viewed VALUES('B08KWVSZK7','Fire TV Stick 4K',1609459400000,'$49.99');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_searches_and_viewed() {
        let db = make_db();
        let r = parse(db.path());
        let searches: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "Amazon Search")
            .collect();
        let viewed: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "Amazon Viewed")
            .collect();
        assert_eq!(searches.len(), 2);
        assert_eq!(viewed.len(), 1);
    }

    #[test]
    fn search_query_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("kindle paperwhite")));
    }

    #[test]
    fn asin_and_price_captured() {
        let db = make_db();
        let r = parse(db.path());
        let v = r.iter().find(|a| a.subcategory == "Amazon Viewed").unwrap();
        assert!(v.detail.contains("asin='B08KWVSZK7'"));
        assert!(v.detail.contains("price='$49.99'"));
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
