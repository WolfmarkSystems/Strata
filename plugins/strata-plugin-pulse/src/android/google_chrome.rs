//! Google Chrome — Android Chrome browser-specific artifacts beyond
//! the generic URL history (which is handled by `browser_history`).
//!
//! ALEAPP reference: `scripts/artifacts/chromeBookmarks.py`,
//! `scripts/artifacts/chromeOfflinePages.py`, plus the top-of-URLs
//! and autofill tables from `/data/data/com.android.chrome/app_chrome/Default/`:
//!
//! - `Bookmarks` (JSON file — not our target; handled elsewhere)
//! - `History` → `keyword_search_terms` for search engine queries
//! - `Web Data` → `autofill`, `autofill_profiles`
//!
//! This module focuses on `keyword_search_terms` (search queries the
//! user typed into Chrome's omnibox) because it's the single most
//! revealing Chrome-specific table beyond plain URL visits.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists};
use rusqlite::Connection;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["/history", "\\history", "web data", "webdata"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "keyword_search_terms") && table_exists(&conn, "urls") {
        read_searches(&conn, path, &mut out);
    }
    if table_exists(&conn, "autofill") {
        read_autofill(&conn, path, &mut out);
    }
    out
}

fn read_searches(conn: &Connection, path: &Path, out: &mut Vec<ArtifactRecord>) {
    let sql = r#"
        SELECT k.term, u.url, u.visit_count
        FROM keyword_search_terms k
        LEFT JOIN urls u ON u.id = k.url_id
        LIMIT 20000
    "#;
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return,
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return;
    };
    for (term, url, count) in rows.flatten() {
        let term = term.unwrap_or_default();
        if term.is_empty() {
            continue;
        }
        let detail = format!(
            "Chrome omnibox search term='{}' url='{}' visit_count={}",
            term,
            url.unwrap_or_default(),
            count.unwrap_or(0)
        );
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "Android Chrome Search",
            format!("Chrome search: {}", term),
            detail,
            path,
            None,
            ForensicValue::Medium,
            false,
        ));
    }
}

fn read_autofill(conn: &Connection, path: &Path, out: &mut Vec<ArtifactRecord>) {
    let sql = "SELECT name, value, count FROM autofill LIMIT 20000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return,
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return;
    };
    for (name, value, count) in rows.flatten() {
        let name = name.unwrap_or_default();
        let value = value.unwrap_or_default();
        if name.is_empty() && value.is_empty() {
            continue;
        }
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "Android Chrome Autofill",
            format!("Autofill: {}", name),
            format!(
                "Chrome autofill field='{}' value='{}' submission_count={}",
                name,
                value,
                count.unwrap_or(0)
            ),
            path,
            None,
            ForensicValue::Medium,
            false,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn make_history_db() -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER);
            INSERT INTO urls VALUES (1,'https://www.google.com/search?q=bitcoin+mixer','Google',5,1,0,0);
            CREATE TABLE keyword_search_terms (keyword_id INTEGER, url_id INTEGER, lower_term TEXT, term TEXT);
            INSERT INTO keyword_search_terms VALUES (1,1,'bitcoin mixer','bitcoin mixer');
            "#,
        )
        .unwrap();
        tmp
    }

    fn make_webdata_db() -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE autofill (name TEXT, value TEXT, value_lower TEXT, date_created INTEGER, date_last_used INTEGER, count INTEGER);
            INSERT INTO autofill VALUES ('email','user@example.com','user@example.com',0,0,3);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn reads_keyword_search_terms() {
        let db = make_history_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 1);
        assert!(r[0].title.contains("bitcoin mixer"));
    }

    #[test]
    fn reads_autofill() {
        let db = make_webdata_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].subcategory, "Android Chrome Autofill");
        assert!(r[0].detail.contains("user@example.com"));
    }

    #[test]
    fn empty_db_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE unrelated(x INTEGER);")
            .unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }

    #[test]
    fn autofill_categorized_as_credentials() {
        let db = make_webdata_db();
        let r = parse(db.path());
        assert_eq!(r[0].category, ArtifactCategory::AccountsCredentials);
    }
}
