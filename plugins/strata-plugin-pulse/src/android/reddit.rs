//! Reddit — subscribed subreddits, saved posts, search history.
//!
//! Source path: `/data/data/com.reddit.frontpage/databases/*.db` or
//! `/data/data/com.reddit.android/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Reddit stores data in Room
//! databases with tables like `subscribed_subreddit`, `saved_post`,
//! `search_history`, `link_info`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.reddit.frontpage/databases/",
    "com.reddit.android/databases/",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["subscribed_subreddit", "subreddit", "subscriptions"] {
        if table_exists(&conn, table) {
            out.extend(read_subscriptions(&conn, path, table));
            break;
        }
    }
    for table in &["saved_post", "saved", "saved_items"] {
        if table_exists(&conn, table) {
            out.extend(read_saved(&conn, path, table));
            break;
        }
    }
    for table in &["search_history", "recent_searches"] {
        if table_exists(&conn, table) {
            out.extend(read_searches(&conn, path, table));
            break;
        }
    }
    out
}

fn read_subscriptions(
    conn: &rusqlite::Connection,
    path: &Path,
    table: &str,
) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT display_name, title, subscribers, is_nsfw \
         FROM \"{table}\" LIMIT 5000",
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
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (display_name, title, subscribers, is_nsfw) in rows.flatten() {
        let display_name = display_name.unwrap_or_else(|| "(unknown)".to_string());
        let sub_title = title.unwrap_or_default();
        let subscribers = subscribers.unwrap_or(0);
        let is_nsfw = is_nsfw.unwrap_or(0) != 0;
        let title_str = format!("Reddit sub: r/{} ({})", display_name, subscribers);
        let detail = format!(
            "Reddit subscribed subreddit display_name='r/{}' title='{}' subscribers={} nsfw={}",
            display_name, sub_title, subscribers, is_nsfw
        );
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "Reddit Subscription",
            title_str,
            detail,
            path,
            None,
            if is_nsfw {
                ForensicValue::High
            } else {
                ForensicValue::Medium
            },
            is_nsfw,
        ));
    }
    out
}

fn read_saved(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT post_id, title, subreddit, author, url, saved_at \
         FROM \"{table}\" ORDER BY saved_at DESC LIMIT 5000",
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
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (post_id, post_title, subreddit, author, url, saved_ms) in rows.flatten() {
        let post_id = post_id.unwrap_or_else(|| "(unknown)".to_string());
        let post_title = post_title.unwrap_or_default();
        let subreddit = subreddit.unwrap_or_default();
        let author = author.unwrap_or_default();
        let url = url.unwrap_or_default();
        let ts = saved_ms.and_then(unix_ms_to_i64);
        let title_str = format!("Reddit saved: {}", post_title);
        let detail = format!(
            "Reddit saved post id='{}' title='{}' subreddit='r/{}' author='u/{}' url='{}'",
            post_id, post_title, subreddit, author, url
        );
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "Reddit Saved Post",
            title_str,
            detail,
            path,
            ts,
            ForensicValue::High,
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
        let title = format!("Reddit search: {}", query);
        let detail = format!("Reddit search query='{}'", query);
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "Reddit Search",
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
            CREATE TABLE subscribed_subreddit (
                display_name TEXT,
                title TEXT,
                subscribers INTEGER,
                is_nsfw INTEGER
            );
            INSERT INTO subscribed_subreddit VALUES('programming','Programming',3500000,0);
            INSERT INTO subscribed_subreddit VALUES('weird_topic','Weird Topic',50000,1);
            CREATE TABLE saved_post (
                post_id TEXT,
                title TEXT,
                subreddit TEXT,
                author TEXT,
                url TEXT,
                saved_at INTEGER
            );
            INSERT INTO saved_post VALUES('p1','Cool Article','programming','user123','https://example.com',1609459200000);
            CREATE TABLE search_history (
                query TEXT,
                timestamp INTEGER
            );
            INSERT INTO search_history VALUES('rust programming',1609459300000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_subs_saved_searches() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Reddit Subscription"));
        assert!(r.iter().any(|a| a.subcategory == "Reddit Saved Post"));
        assert!(r.iter().any(|a| a.subcategory == "Reddit Search"));
    }

    #[test]
    fn nsfw_sub_flagged_suspicious() {
        let db = make_db();
        let r = parse(db.path());
        let nsfw = r.iter().find(|a| a.detail.contains("nsfw=true")).unwrap();
        assert!(nsfw.is_suspicious);
    }

    #[test]
    fn saved_post_url_captured() {
        let db = make_db();
        let r = parse(db.path());
        let saved = r
            .iter()
            .find(|a| a.subcategory == "Reddit Saved Post")
            .unwrap();
        assert!(saved.detail.contains("url='https://example.com'"));
        assert!(saved.detail.contains("subreddit='r/programming'"));
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
