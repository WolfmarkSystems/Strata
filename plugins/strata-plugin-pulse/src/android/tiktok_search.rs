//! TikTok Search — search query history extraction.
//!
//! Source path: `/data/data/com.zhiliaoapp.musically/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. Complements `tiktok.rs` which
//! handles DMs/users. TikTok stores search queries in `search_history`
//! or `sug_word` tables with timestamps and type flags (user/hashtag/
//! video).

use crate::android::helpers::{
    build_record, column_exists, open_sqlite_ro, table_exists, unix_ms_to_i64,
};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.zhiliaoapp.musically/databases/",
    "com.ss.android.ugc.trill/databases/",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &[
        "search_history",
        "search_queries",
        "sug_word",
        "user_search_history",
    ] {
        if table_exists(&conn, table) {
            out.extend(read_searches(&conn, path, table));
        }
    }
    out
}

fn read_searches(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let query_col = if column_exists(conn, table, "keyword") {
        "keyword"
    } else if column_exists(conn, table, "query") {
        "query"
    } else {
        "word"
    };
    let ts_col = if column_exists(conn, table, "search_time") {
        "search_time"
    } else if column_exists(conn, table, "timestamp") {
        "timestamp"
    } else {
        "create_time"
    };
    let type_col = if column_exists(conn, table, "type") {
        "type"
    } else {
        "search_type"
    };
    let sql = format!(
        "SELECT {query_col}, {ts_col}, {type_col} FROM \"{table}\" \
         ORDER BY {ts_col} DESC LIMIT 5000",
        query_col = query_col,
        ts_col = ts_col,
        type_col = type_col,
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
            row.get::<_, Option<String>>(2).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (query, ts_raw, search_type) in rows.flatten() {
        let query = query.unwrap_or_default();
        let search_type = search_type.unwrap_or_else(|| "general".to_string());
        let ts = ts_raw.and_then(|t| {
            if t > 10_000_000_000 {
                unix_ms_to_i64(t)
            } else {
                Some(t)
            }
        });
        let title = format!("TikTok search ({}): {}", search_type, query);
        let detail = format!(
            "TikTok search query='{}' type='{}' source_table='{}'",
            query, search_type, table
        );
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "TikTok Search",
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
                search_time INTEGER,
                type TEXT
            );
            INSERT INTO search_history VALUES('dance tutorial',1609459200000,'general');
            INSERT INTO search_history VALUES('#viral',1609459300000,'hashtag');
            INSERT INTO search_history VALUES('@celebrity',1609459400000,'user');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_three_searches() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|a| a.subcategory == "TikTok Search"));
    }

    #[test]
    fn search_type_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.title.contains("(hashtag)") && a.title.contains("#viral")));
        assert!(r
            .iter()
            .any(|a| a.title.contains("(user)") && a.title.contains("@celebrity")));
    }

    #[test]
    fn source_table_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .all(|a| a.detail.contains("source_table='search_history'")));
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
