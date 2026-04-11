//! eBay — Android app search history, watchlist, recently viewed.
//!
//! Source path: `/data/data/com.ebay.mobile/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. eBay stores search history in
//! `search_history` or `recent_searches`, watchlist items in `watched_items`
//! or `watchlist`, and viewed items in `recently_viewed`. Column variants
//! probed defensively.

use crate::android::helpers::{build_record, column_exists, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.ebay.mobile/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["search_history", "recent_searches"] {
        if table_exists(&conn, table) {
            out.extend(read_searches(&conn, path, table));
            break;
        }
    }
    for table in &["watched_items", "watchlist"] {
        if table_exists(&conn, table) {
            out.extend(read_watched(&conn, path, table));
            break;
        }
    }
    out
}

fn read_searches(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let keyword_col = if column_exists(conn, table, "keyword") {
        "keyword"
    } else {
        "query"
    };
    let ts_col = if column_exists(conn, table, "last_used") {
        "last_used"
    } else {
        "timestamp"
    };
    let sql = format!(
        "SELECT {keyword_col}, {ts_col} FROM \"{table}\" \
         ORDER BY {ts_col} DESC LIMIT 5000",
        keyword_col = keyword_col,
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
    for (keyword, ts_raw) in rows.flatten() {
        let keyword = keyword.unwrap_or_default();
        let ts = ts_raw.and_then(|t| {
            if t > 10_000_000_000 { unix_ms_to_i64(t) } else { Some(t) }
        });
        let title = format!("eBay search: {}", keyword);
        let detail = format!("eBay search keyword='{}'", keyword);
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "eBay Search",
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

fn read_watched(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT item_id, title, price, currency, end_time, seller \
         FROM \"{table}\" ORDER BY end_time DESC LIMIT 5000",
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
    for (item_id, title, price, currency, end_ms, seller) in rows.flatten() {
        let item_id = item_id.unwrap_or_else(|| "(unknown)".to_string());
        let item_title = title.unwrap_or_else(|| "(unnamed)".to_string());
        let price = price.unwrap_or_default();
        let currency = currency.unwrap_or_default();
        let seller = seller.unwrap_or_default();
        let ts = end_ms.and_then(unix_ms_to_i64);
        let title_str = format!("eBay watched: {} ({} {})", item_title, price, currency);
        let detail = format!(
            "eBay watched item_id='{}' title='{}' price='{}' currency='{}' seller='{}'",
            item_id, item_title, price, currency, seller
        );
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "eBay Watched",
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
                keyword TEXT,
                last_used INTEGER
            );
            INSERT INTO search_history VALUES('vintage camera',1609459200000);
            INSERT INTO search_history VALUES('rolex submariner',1609459300000);
            CREATE TABLE watched_items (
                item_id TEXT,
                title TEXT,
                price TEXT,
                currency TEXT,
                end_time INTEGER,
                seller TEXT
            );
            INSERT INTO watched_items VALUES('12345','Nikon F3 Camera','450.00','USD',1609800000000,'camera_guy');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_searches_and_watched() {
        let db = make_db();
        let r = parse(db.path());
        let searches: Vec<_> = r.iter().filter(|a| a.subcategory == "eBay Search").collect();
        let watched: Vec<_> = r.iter().filter(|a| a.subcategory == "eBay Watched").collect();
        assert_eq!(searches.len(), 2);
        assert_eq!(watched.len(), 1);
    }

    #[test]
    fn search_keyword_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("rolex submariner")));
    }

    #[test]
    fn watched_seller_captured() {
        let db = make_db();
        let r = parse(db.path());
        let w = r.iter().find(|a| a.subcategory == "eBay Watched").unwrap();
        assert!(w.detail.contains("seller='camera_guy'"));
        assert!(w.detail.contains("price='450.00'"));
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
