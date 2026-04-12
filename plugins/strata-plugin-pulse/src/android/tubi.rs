//! Tubi — free streaming watch history and favorites.
//!
//! Source path: `/data/data/com.tubitv/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Tubi uses Room databases with
//! tables like `watch_history`, `favorite`, `content`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.tubitv/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["watch_history", "viewing_history", "resume_history"] {
        if table_exists(&conn, table) {
            out.extend(read_watch_history(&conn, path, table));
            break;
        }
    }
    for table in &["favorite", "favorites", "watchlist"] {
        if table_exists(&conn, table) {
            out.extend(read_favorites(&conn, path, table));
            break;
        }
    }
    out
}

fn read_watch_history(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT content_id, title, content_type, watched_at, duration \
         FROM \"{table}\" ORDER BY watched_at DESC LIMIT 5000",
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
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (content_id, title, content_type, watched_ms, duration_s) in rows.flatten() {
        let content_id = content_id.unwrap_or_default();
        let title = title.unwrap_or_else(|| "(untitled)".to_string());
        let content_type = content_type.unwrap_or_else(|| "video".to_string());
        let dur = duration_s.unwrap_or(0);
        let ts = watched_ms.and_then(unix_ms_to_i64);
        let title_str = format!("Tubi watched: {}", title);
        let detail = format!(
            "Tubi watch history content_id='{}' title='{}' type='{}' duration={}s",
            content_id, title, content_type, dur
        );
        out.push(build_record(
            ArtifactCategory::Media,
            "Tubi Watch",
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

fn read_favorites(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT content_id, title, content_type, added_at \
         FROM \"{table}\" ORDER BY added_at DESC LIMIT 5000",
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
            row.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (content_id, title, content_type, added_ms) in rows.flatten() {
        let content_id = content_id.unwrap_or_default();
        let title = title.unwrap_or_else(|| "(untitled)".to_string());
        let content_type = content_type.unwrap_or_else(|| "video".to_string());
        let ts = added_ms.and_then(unix_ms_to_i64);
        let title_str = format!("Tubi favorite: {}", title);
        let detail = format!(
            "Tubi favorite content_id='{}' title='{}' type='{}'",
            content_id, title, content_type
        );
        out.push(build_record(
            ArtifactCategory::Media,
            "Tubi Favorite",
            title_str,
            detail,
            path,
            ts,
            ForensicValue::Low,
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
            CREATE TABLE watch_history (
                content_id TEXT,
                title TEXT,
                content_type TEXT,
                watched_at INTEGER,
                duration INTEGER
            );
            INSERT INTO watch_history VALUES('m123','The Avengers','movie',1609459200000,7320);
            INSERT INTO watch_history VALUES('s456','Breaking Bad','series',1609459300000,2700);
            CREATE TABLE favorite (
                content_id TEXT,
                title TEXT,
                content_type TEXT,
                added_at INTEGER
            );
            INSERT INTO favorite VALUES('m999','Inception','movie',1609459000000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_watch_history_and_favorites() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Tubi Watch"));
        assert!(r.iter().any(|a| a.subcategory == "Tubi Favorite"));
    }

    #[test]
    fn content_type_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("type='movie'") && a.detail.contains("The Avengers")));
        assert!(r.iter().any(|a| a.detail.contains("type='series'") && a.detail.contains("Breaking Bad")));
    }

    #[test]
    fn favorite_title_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("title='Inception'") && a.subcategory == "Tubi Favorite"));
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
