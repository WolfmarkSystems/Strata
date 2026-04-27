//! OsmAnd — Android offline map search history.
//!
//! Source path: `/data/data/net.osmand/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. OsmAnd stores search history in
//! a `search_history` table with `query`, `latitude`, `longitude`, and
//! `date` columns. The `date` column stores Unix millisecond timestamps.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["net.osmand/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "search_history") {
        out.extend(read_search(&conn, path));
    }
    out
}

fn read_search(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT query, latitude, longitude, date \
               FROM search_history \
               ORDER BY date DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<f64>>(1).unwrap_or(None),
            row.get::<_, Option<f64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (query, lat, lon, date_ms) in rows.flatten() {
        let q = query.unwrap_or_default();
        if q.is_empty() {
            continue;
        }
        let la = lat.unwrap_or(0.0);
        let lo = lon.unwrap_or(0.0);
        let ts = date_ms.and_then(unix_ms_to_i64);
        let title = format!("OsmAnd Search: {}", q);
        let detail = format!("OsmAnd search query='{}' lat={:.6} lon={:.6}", q, la, lo);
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "OsmAnd Search",
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
            CREATE TABLE search_history (
                id INTEGER PRIMARY KEY,
                query TEXT,
                latitude REAL,
                longitude REAL,
                date INTEGER
            );
            INSERT INTO search_history VALUES(1,'grocery store',51.507351,-0.127758,1609459200000);
            INSERT INTO search_history VALUES(2,'parking lot',51.515617,-0.091998,1609459300000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_search_entries() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|a| a.subcategory == "OsmAnd Search"));
    }

    #[test]
    fn query_in_title_and_coords_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let grocery = r
            .iter()
            .find(|a| a.title.contains("grocery store"))
            .unwrap();
        assert!(grocery.detail.contains("lat=51.507351"));
        assert!(grocery.detail.contains("lon=-0.127758"));
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
