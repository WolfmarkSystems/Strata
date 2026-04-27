//! Dailymotion — video watch history and search history.
//!
//! Source path: `/data/data/com.dailymotion.dailymotion/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Dailymotion uses Room databases with
//! tables like `watch_history`, `search_history`, `video`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.dailymotion.dailymotion/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["watch_history", "video_history", "viewed_video"] {
        if table_exists(&conn, table) {
            out.extend(read_watch_history(&conn, path, table));
            break;
        }
    }
    for table in &["search_history", "search_query", "recent_search"] {
        if table_exists(&conn, table) {
            out.extend(read_search_history(&conn, path, table));
            break;
        }
    }
    out
}

fn read_watch_history(
    conn: &rusqlite::Connection,
    path: &Path,
    table: &str,
) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT video_id, title, owner_name, watched_at, duration \
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
    for (video_id, title, owner, watched_ms, duration_s) in rows.flatten() {
        let video_id = video_id.unwrap_or_default();
        let title = title.unwrap_or_else(|| "(untitled)".to_string());
        let owner = owner.unwrap_or_else(|| "(unknown)".to_string());
        let dur = duration_s.unwrap_or(0);
        let ts = watched_ms.and_then(unix_ms_to_i64);
        let title_str = format!("Dailymotion watched: {} by {}", title, owner);
        let detail = format!(
            "Dailymotion watch history video_id='{}' title='{}' owner='{}' duration={}s",
            video_id, title, owner, dur
        );
        out.push(build_record(
            ArtifactCategory::Media,
            "Dailymotion Watch",
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

fn read_search_history(
    conn: &rusqlite::Connection,
    path: &Path,
    table: &str,
) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT query, searched_at \
         FROM \"{table}\" ORDER BY searched_at DESC LIMIT 5000",
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
    for (query, searched_ms) in rows.flatten() {
        let query = query.unwrap_or_default();
        let ts = searched_ms.and_then(unix_ms_to_i64);
        let title = format!("Dailymotion search: {}", query);
        let detail = format!("Dailymotion search query='{}'", query);
        out.push(build_record(
            ArtifactCategory::Media,
            "Dailymotion Search",
            title,
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
                video_id TEXT,
                title TEXT,
                owner_name TEXT,
                watched_at INTEGER,
                duration INTEGER
            );
            INSERT INTO watch_history VALUES('x7abc','Funny Cats','CatLovers',1609459200000,180);
            INSERT INTO watch_history VALUES('x7xyz','Travel Vlog','WanderlustTV',1609459300000,900);
            CREATE TABLE search_history (
                query TEXT,
                searched_at INTEGER
            );
            INSERT INTO search_history VALUES('funny animals',1609459100000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_watch_and_search() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Dailymotion Watch"));
        assert!(r.iter().any(|a| a.subcategory == "Dailymotion Search"));
    }

    #[test]
    fn watch_duration_and_owner_captured() {
        let db = make_db();
        let r = parse(db.path());
        let w = r
            .iter()
            .find(|a| a.subcategory == "Dailymotion Watch" && a.detail.contains("x7abc"))
            .unwrap();
        assert!(w.detail.contains("duration=180s"));
        assert!(w.detail.contains("owner='CatLovers'"));
    }

    #[test]
    fn search_query_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("query='funny animals'")));
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
