//! Nextdoor — neighborhood social network posts, comments, and neighbor profiles.
//!
//! Source path: `/data/data/com.nextdoor/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Nextdoor uses Room databases with
//! tables like `post`, `comment`, `neighbor`, `profile`. Neighborhood
//! identification from posts is forensically significant for establishing
//! geographic area of residence and community ties.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.nextdoor/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["post", "posts", "feed_item"] {
        if table_exists(&conn, table) {
            out.extend(read_posts(&conn, path, table));
            break;
        }
    }
    for table in &["comment", "comments", "reply"] {
        if table_exists(&conn, table) {
            out.extend(read_comments(&conn, path, table));
            break;
        }
    }
    for table in &["neighbor", "neighbors", "profile", "contact"] {
        if table_exists(&conn, table) {
            out.extend(read_neighbors(&conn, path, table));
            break;
        }
    }
    out
}

fn read_posts(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, title, body, neighborhood, posted_at, author \
         FROM \"{table}\" ORDER BY posted_at DESC LIMIT 5000",
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
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, title, body, neighborhood, posted_ms, author) in rows.flatten() {
        let id = id.unwrap_or_default();
        let title = title.unwrap_or_else(|| "(untitled)".to_string());
        let body = body.unwrap_or_default();
        let neighborhood = neighborhood.unwrap_or_else(|| "(unknown)".to_string());
        let author = author.unwrap_or_else(|| "(unknown)".to_string());
        let ts = posted_ms.and_then(unix_ms_to_i64);
        let title_str = format!("Nextdoor post [{}]: {}", neighborhood, title);
        let detail = format!(
            "Nextdoor post id='{}' title='{}' neighborhood='{}' author='{}' body='{}'",
            id, title, neighborhood, author, body
        );
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "Nextdoor Post",
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

fn read_comments(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, post_id, author, body, commented_at \
         FROM \"{table}\" ORDER BY commented_at DESC LIMIT 5000",
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
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, post_id, author, body, commented_ms) in rows.flatten() {
        let id = id.unwrap_or_default();
        let post_id = post_id.unwrap_or_default();
        let author = author.unwrap_or_else(|| "(unknown)".to_string());
        let body = body.unwrap_or_default();
        let ts = commented_ms.and_then(unix_ms_to_i64);
        let preview: String = body.chars().take(80).collect();
        let title = format!("Nextdoor comment by {}: {}", author, preview);
        let detail = format!(
            "Nextdoor comment id='{}' post_id='{}' author='{}' body='{}'",
            id, post_id, author, body
        );
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "Nextdoor Comment",
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

fn read_neighbors(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, display_name, neighborhood, street \
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
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, display_name, neighborhood, street) in rows.flatten() {
        let id = id.unwrap_or_default();
        let display_name = display_name.unwrap_or_else(|| "(no name)".to_string());
        let neighborhood = neighborhood.unwrap_or_else(|| "(unknown)".to_string());
        let street = street.unwrap_or_default();
        let title = format!("Nextdoor neighbor: {} ({})", display_name, neighborhood);
        let mut detail = format!(
            "Nextdoor neighbor id='{}' display_name='{}' neighborhood='{}'",
            id, display_name, neighborhood
        );
        if !street.is_empty() {
            detail.push_str(&format!(" street='{}'", street));
        }
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "Nextdoor Neighbor",
            title,
            detail,
            path,
            None,
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
            CREATE TABLE post (
                id TEXT,
                title TEXT,
                body TEXT,
                neighborhood TEXT,
                posted_at INTEGER,
                author TEXT
            );
            INSERT INTO post VALUES('p1','Lost Dog','Black lab named Max missing since Tuesday','Maple Ridge',1609459200000,'Jane Smith');
            INSERT INTO post VALUES('p2','Suspicious Vehicle','White van parked overnight','Maple Ridge',1609459300000,'Bob Jones');
            CREATE TABLE comment (
                id TEXT,
                post_id TEXT,
                author TEXT,
                body TEXT,
                commented_at INTEGER
            );
            INSERT INTO comment VALUES('c1','p1','Alice Brown','I saw him near Oak St!',1609459400000);
            CREATE TABLE neighbor (
                id TEXT,
                display_name TEXT,
                neighborhood TEXT,
                street TEXT
            );
            INSERT INTO neighbor VALUES('n1','John Doe','Maple Ridge','123 Oak St');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_posts_comments_neighbors() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Nextdoor Post"));
        assert!(r.iter().any(|a| a.subcategory == "Nextdoor Comment"));
        assert!(r.iter().any(|a| a.subcategory == "Nextdoor Neighbor"));
    }

    #[test]
    fn neighborhood_identified_in_post() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Nextdoor Post" && a.detail.contains("neighborhood='Maple Ridge'")));
    }

    #[test]
    fn neighbor_street_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Nextdoor Neighbor" && a.detail.contains("street='123 Oak St'")));
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
