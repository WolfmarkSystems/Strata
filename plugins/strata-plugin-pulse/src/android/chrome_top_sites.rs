//! Chrome Top Sites — most-visited URLs cache.
//!
//! ALEAPP reference: `scripts/artifacts/chromeTopSites.py`. Source path:
//! `/data/data/com.android.chrome/app_chrome/Default/Top Sites` with
//! the `top_sites` table:
//!
//! - `url`
//! - `url_rank`
//! - `title`
//! - `redirects` — comma list
//!
//! This is what populates the new-tab page on a fresh open. It is
//! valuable for showing where the user habitually goes.

use crate::android::helpers::{build_record, column_exists, open_sqlite_ro, table_exists};
use rusqlite::Connection;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["top sites", "top_sites", "topsites"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "top_sites") {
        return Vec::new();
    }
    read(&conn, path)
}

fn read(conn: &Connection, path: &Path) -> Vec<ArtifactRecord> {
    let has_rank = column_exists(conn, "top_sites", "url_rank");
    let has_title = column_exists(conn, "top_sites", "title");

    let sql = format!(
        "SELECT url, {}, {} FROM top_sites ORDER BY {} ASC LIMIT 1000",
        if has_rank { "url_rank" } else { "0" },
        if has_title { "title" } else { "''" },
        if has_rank { "url_rank" } else { "url" }
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
    for (url, rank, title) in rows.flatten() {
        let url = url.unwrap_or_default();
        if url.is_empty() {
            continue;
        }
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "Android Chrome Top Site",
            format!("Top Site #{}: {}", rank.unwrap_or(0), url),
            format!(
                "Chrome top site rank={} url='{}' title='{}'",
                rank.unwrap_or(0),
                url,
                title.unwrap_or_default()
            ),
            path,
            None,
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
            CREATE TABLE top_sites (
                url TEXT,
                url_rank INTEGER,
                title TEXT,
                redirects TEXT
            );
            INSERT INTO top_sites VALUES ('https://google.com',0,'Google','');
            INSERT INTO top_sites VALUES ('https://news.ycombinator.com',1,'Hacker News','');
            INSERT INTO top_sites VALUES ('https://reddit.com',2,'Reddit','');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_three_sites_in_rank_order() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 3);
        assert!(r[0].title.contains("#0"));
        assert!(r[1].title.contains("#1"));
        assert!(r[2].title.contains("#2"));
    }

    #[test]
    fn url_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|x| x.title.contains("google.com")));
        assert!(r.iter().any(|x| x.title.contains("news.ycombinator.com")));
    }

    #[test]
    fn category_is_web_activity() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().all(|x| x.category == ArtifactCategory::WebActivity));
    }

    #[test]
    fn missing_table_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE foo(x INTEGER);").unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}
