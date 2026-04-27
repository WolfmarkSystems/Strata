//! Maps.me — Android bookmarks and saved places.
//!
//! Source path: `/data/data/com.mapswithme.maps.pro/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. Maps.me stores user bookmarks
//! in a `bookmarks` table with `name`, `lat`, `lon`, and `type` columns.
//! Some versions use `description` and `created_at` as well.

use crate::android::helpers::{
    build_record, column_exists, open_sqlite_ro, table_exists, unix_ms_to_i64,
};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.mapswithme.maps.pro/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "bookmarks") {
        out.extend(read_bookmarks(&conn, path));
    }
    out
}

fn read_bookmarks(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let has_ts = column_exists(conn, "bookmarks", "created_at");
    let sql = format!(
        "SELECT name, lat, lon, type{} FROM bookmarks LIMIT 5000",
        if has_ts { ", created_at" } else { ", 0" }
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<f64>>(1).unwrap_or(None),
            row.get::<_, Option<f64>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (name, lat, lon, bm_type, ts_ms) in rows.flatten() {
        let n = name.unwrap_or_else(|| "(unnamed)".to_string());
        let la = lat.unwrap_or(0.0);
        let lo = lon.unwrap_or(0.0);
        let bm_type = bm_type.unwrap_or_else(|| "unknown".to_string());
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Maps.me Bookmark: {}", n);
        let detail = format!(
            "Maps.me bookmark name='{}' type='{}' lat={:.6} lon={:.6}",
            n, bm_type, la, lo
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Maps.me Bookmark",
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
            CREATE TABLE bookmarks (
                id INTEGER PRIMARY KEY,
                name TEXT,
                lat REAL,
                lon REAL,
                type TEXT,
                created_at INTEGER
            );
            INSERT INTO bookmarks VALUES(1,'Hotel Berlin',52.520008,13.404954,'hotel',1609459200000);
            INSERT INTO bookmarks VALUES(2,'Airport CDG',49.009691,2.547925,'transport',1609459300000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_bookmarks() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|a| a.subcategory == "Maps.me Bookmark"));
    }

    #[test]
    fn type_appears_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let hotel = r.iter().find(|a| a.title.contains("Hotel Berlin")).unwrap();
        assert!(hotel.detail.contains("type='hotel'"));
        assert!(hotel.detail.contains("lat=52.520008"));
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
