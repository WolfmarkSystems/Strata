//! Zillow — Android property search, saved home, and price-alert extraction.
//!
//! Source path: `/data/data/com.zillow.android.zillowmap/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. Zillow uses Room databases with
//! tables like `property_search_history`, `saved_homes`, `price_alerts`.
//! GPS columns (`lat`/`lon`) are present on saved records and establish
//! the subject's location interest with forensic precision.

use crate::android::helpers::{build_record, fmt_ts, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.zillow.android.zillowmap/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    out.extend(parse_searches(&conn, path));
    out.extend(parse_saved_homes(&conn, path));
    out.extend(parse_price_alerts(&conn, path));
    out
}

fn parse_searches(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let table = if table_exists(conn, "property_search_history") {
        "property_search_history"
    } else if table_exists(conn, "search_history") {
        "search_history"
    } else {
        return Vec::new();
    };
    let sql = format!(
        "SELECT address, price_min, price_max, beds_min, baths_min, \
         sqft_min, lat, lon, searched_at \
         FROM \"{t}\" ORDER BY searched_at DESC LIMIT 5000",
        t = table.replace('"', "\"\"")
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
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<f64>>(6).unwrap_or(None),
            row.get::<_, Option<f64>>(7).unwrap_or(None),
            row.get::<_, Option<i64>>(8).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (address, price_min, price_max, beds, baths, sqft, lat, lon, searched_ms) in
        rows.flatten()
    {
        let address = address.unwrap_or_else(|| "(unknown)".to_string());
        let ts = searched_ms.and_then(unix_ms_to_i64);
        let title = format!("Zillow search: {}", address);
        let mut detail = format!(
            "Zillow property_search address='{}' price_min={} price_max={} \
             beds_min={} baths_min={} sqft_min={} searched_at='{}'",
            address,
            price_min.unwrap_or(0),
            price_max.unwrap_or(0),
            beds.unwrap_or(0),
            baths.unwrap_or(0),
            sqft.unwrap_or(0),
            fmt_ts(ts)
        );
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" lat={:.6} lon={:.6}", la, lo));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Zillow Property Search",
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

fn parse_saved_homes(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let table = if table_exists(conn, "saved_homes") {
        "saved_homes"
    } else if table_exists(conn, "favorites") {
        "favorites"
    } else {
        return Vec::new();
    };
    let sql = format!(
        "SELECT zpid, address, price, beds, baths, sqft, lat, lon, saved_at \
         FROM \"{t}\" ORDER BY saved_at DESC LIMIT 2000",
        t = table.replace('"', "\"\"")
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
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<f64>>(6).unwrap_or(None),
            row.get::<_, Option<f64>>(7).unwrap_or(None),
            row.get::<_, Option<i64>>(8).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (zpid, address, price, beds, baths, sqft, lat, lon, saved_ms) in rows.flatten() {
        let zpid = zpid.unwrap_or_default();
        let address = address.unwrap_or_else(|| "(unknown)".to_string());
        let ts = saved_ms.and_then(unix_ms_to_i64);
        let title = format!("Zillow saved home: {}", address);
        let mut detail = format!(
            "Zillow saved_home zpid='{}' address='{}' price={} beds={} baths={} \
             sqft={} saved_at='{}'",
            zpid,
            address,
            price.unwrap_or(0),
            beds.unwrap_or(0),
            baths.unwrap_or(0),
            sqft.unwrap_or(0),
            fmt_ts(ts)
        );
        if let (Some(la), Some(lo)) = (lat, lon) {
            detail.push_str(&format!(" lat={:.6} lon={:.6}", la, lo));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Zillow Saved Home",
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

fn parse_price_alerts(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let table = if table_exists(conn, "price_alerts") {
        "price_alerts"
    } else if table_exists(conn, "price_change_alerts") {
        "price_change_alerts"
    } else {
        return Vec::new();
    };
    let sql = format!(
        "SELECT zpid, address, old_price, new_price, alerted_at \
         FROM \"{t}\" ORDER BY alerted_at DESC LIMIT 2000",
        t = table.replace('"', "\"\"")
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
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (zpid, address, old_price, new_price, alerted_ms) in rows.flatten() {
        let zpid = zpid.unwrap_or_default();
        let address = address.unwrap_or_else(|| "(unknown)".to_string());
        let ts = alerted_ms.and_then(unix_ms_to_i64);
        let title = format!("Zillow price alert: {}", address);
        let detail = format!(
            "Zillow price_alert zpid='{}' address='{}' old_price={} new_price={} alerted_at='{}'",
            zpid,
            address,
            old_price.unwrap_or(0),
            new_price.unwrap_or(0),
            fmt_ts(ts)
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Zillow Price Alert",
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

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn make_db() -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE property_search_history (
                address TEXT,
                price_min INTEGER,
                price_max INTEGER,
                beds_min INTEGER,
                baths_min INTEGER,
                sqft_min INTEGER,
                lat REAL,
                lon REAL,
                searched_at INTEGER
            );
            INSERT INTO property_search_history VALUES(
                'Austin, TX',300000,600000,3,2,1500,30.2672,-97.7431,1700000000000
            );
            CREATE TABLE saved_homes (
                zpid TEXT,
                address TEXT,
                price INTEGER,
                beds INTEGER,
                baths INTEGER,
                sqft INTEGER,
                lat REAL,
                lon REAL,
                saved_at INTEGER
            );
            INSERT INTO saved_homes VALUES(
                'z-12345','456 Elm St, Austin, TX',450000,3,2,1800,30.2700,-97.7500,1700100000000
            );
            CREATE TABLE price_alerts (
                zpid TEXT,
                address TEXT,
                old_price INTEGER,
                new_price INTEGER,
                alerted_at INTEGER
            );
            INSERT INTO price_alerts VALUES('z-12345','456 Elm St, Austin, TX',470000,450000,1700200000000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_search_saved_and_alert() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Zillow Property Search"));
        assert!(r.iter().any(|a| a.subcategory == "Zillow Saved Home"));
        assert!(r.iter().any(|a| a.subcategory == "Zillow Price Alert"));
    }

    #[test]
    fn search_contains_gps_and_filters() {
        let db = make_db();
        let r = parse(db.path());
        let searches: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "Zillow Property Search")
            .collect();
        assert_eq!(searches.len(), 1);
        assert!(searches[0].detail.contains("lat=30.267200"));
        assert!(searches[0].detail.contains("beds_min=3"));
    }

    #[test]
    fn saved_home_is_critical_with_gps() {
        let db = make_db();
        let r = parse(db.path());
        let saved: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "Zillow Saved Home")
            .collect();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].forensic_value, ForensicValue::Critical);
        assert!(saved[0].detail.contains("zpid='z-12345'"));
        assert!(saved[0].detail.contains("lat=30.270000"));
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
