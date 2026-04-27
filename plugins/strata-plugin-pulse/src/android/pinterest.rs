//! Pinterest — boards, pins, and search history extraction.
//!
//! Source path: `/data/data/com.pinterest/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Pinterest uses Room databases
//! with tables like `board`, `pin`, `search_history`. Column names
//! vary across versions.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.pinterest/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "board") {
        out.extend(read_boards(&conn, path));
    }
    if table_exists(&conn, "pin") {
        out.extend(read_pins(&conn, path));
    }
    for table in &["search_history", "recent_searches"] {
        if table_exists(&conn, table) {
            out.extend(read_searches(&conn, path, table));
            break;
        }
    }
    out
}

fn read_boards(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, name, description, pin_count, is_secret, created_at \
               FROM board LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, name, description, pin_count, is_secret, created_ms) in rows.flatten() {
        let id = id.unwrap_or_else(|| "(unknown)".to_string());
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let description = description.unwrap_or_default();
        let pin_count = pin_count.unwrap_or(0);
        let is_secret = is_secret.unwrap_or(0) != 0;
        let ts = created_ms.and_then(unix_ms_to_i64);
        let title = format!("Pinterest board: {} ({} pins)", name, pin_count);
        let detail = format!(
            "Pinterest board id='{}' name='{}' description='{}' pin_count={} secret={}",
            id, name, description, pin_count, is_secret
        );
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "Pinterest Board",
            title,
            detail,
            path,
            ts,
            if is_secret {
                ForensicValue::High
            } else {
                ForensicValue::Medium
            },
            is_secret,
        ));
    }
    out
}

fn read_pins(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, board_id, description, image_url, link, \
               saved_at FROM pin ORDER BY saved_at DESC LIMIT 5000";
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
    for (id, board_id, description, image_url, link, saved_ms) in rows.flatten() {
        let id = id.unwrap_or_else(|| "(unknown)".to_string());
        let board_id = board_id.unwrap_or_default();
        let description = description.unwrap_or_default();
        let image_url = image_url.unwrap_or_default();
        let link = link.unwrap_or_default();
        let ts = saved_ms.and_then(unix_ms_to_i64);
        let preview: String = description.chars().take(80).collect();
        let title = format!("Pinterest pin: {}", preview);
        let detail = format!(
            "Pinterest pin id='{}' board_id='{}' description='{}' image_url='{}' link='{}'",
            id, board_id, description, image_url, link
        );
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "Pinterest Pin",
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

fn read_searches(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT query, timestamp FROM \"{table}\" \
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
            row.get::<_, Option<i64>>(1).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (query, ts_ms) in rows.flatten() {
        let query = query.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Pinterest search: {}", query);
        let detail = format!("Pinterest search query='{}'", query);
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "Pinterest Search",
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
            CREATE TABLE board (
                id TEXT,
                name TEXT,
                description TEXT,
                pin_count INTEGER,
                is_secret INTEGER,
                created_at INTEGER
            );
            INSERT INTO board VALUES('b1','Travel','Places to visit',42,0,1609459200000);
            INSERT INTO board VALUES('b2','Secret','Private',10,1,1609459300000);
            CREATE TABLE pin (
                id TEXT,
                board_id TEXT,
                description TEXT,
                image_url TEXT,
                link TEXT,
                saved_at INTEGER
            );
            INSERT INTO pin VALUES('p1','b1','Tokyo at sunset','http://img1.jpg','http://blog.com',1609459400000);
            CREATE TABLE search_history (
                query TEXT,
                timestamp INTEGER
            );
            INSERT INTO search_history VALUES('japanese garden design',1609459500000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_boards_pins_searches() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Pinterest Board"));
        assert!(r.iter().any(|a| a.subcategory == "Pinterest Pin"));
        assert!(r.iter().any(|a| a.subcategory == "Pinterest Search"));
    }

    #[test]
    fn secret_board_flagged_suspicious() {
        let db = make_db();
        let r = parse(db.path());
        let secret = r.iter().find(|a| a.detail.contains("secret=true")).unwrap();
        assert!(secret.is_suspicious);
    }

    #[test]
    fn pin_image_url_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("image_url='http://img1.jpg'")));
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
