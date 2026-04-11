//! Hinge — dating app match and likes extraction.
//!
//! Source path: `/data/data/co.hinge.app/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Hinge uses Room databases with
//! tables like `match`, `like`, `message`. Hinge differs from Tinder
//! in that likes can target specific content (photo, prompt answer).

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["co.hinge.app/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["match", "matches"] {
        if table_exists(&conn, table) {
            out.extend(read_matches(&conn, path, table));
            break;
        }
    }
    for table in &["like", "likes"] {
        if table_exists(&conn, table) {
            out.extend(read_likes(&conn, path, table));
            break;
        }
    }
    for table in &["message", "messages"] {
        if table_exists(&conn, table) {
            out.extend(read_messages(&conn, path, table));
            break;
        }
    }
    out
}

fn read_matches(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, subject_id, subject_name, created_at, has_rose \
         FROM \"{table}\" ORDER BY created_at DESC LIMIT 5000",
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
    for (id, subject_id, subject_name, created_ms, has_rose) in rows.flatten() {
        let id = id.unwrap_or_else(|| "(unknown)".to_string());
        let subject_id = subject_id.unwrap_or_default();
        let subject_name = subject_name.unwrap_or_else(|| "(no name)".to_string());
        let has_rose = has_rose.unwrap_or(0) != 0;
        let ts = created_ms.and_then(unix_ms_to_i64);
        let title = format!("Hinge match: {}", subject_name);
        let detail = format!(
            "Hinge match id='{}' subject_id='{}' subject_name='{}' has_rose={}",
            id, subject_id, subject_name, has_rose
        );
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "Hinge Match",
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

fn read_likes(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, subject_id, content_type, content_id, comment, \
         created_at FROM \"{table}\" ORDER BY created_at DESC LIMIT 5000",
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
    for (id, subject_id, content_type, content_id, comment, created_ms) in rows.flatten() {
        let id = id.unwrap_or_default();
        let subject_id = subject_id.unwrap_or_default();
        let content_type = content_type.unwrap_or_default();
        let content_id = content_id.unwrap_or_default();
        let comment = comment.unwrap_or_default();
        let ts = created_ms.and_then(unix_ms_to_i64);
        let title = format!("Hinge like on {}", content_type);
        let mut detail = format!(
            "Hinge like id='{}' subject_id='{}' content_type='{}' content_id='{}'",
            id, subject_id, content_type, content_id
        );
        if !comment.is_empty() {
            detail.push_str(&format!(" comment='{}'", comment));
        }
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "Hinge Like",
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

fn read_messages(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, match_id, sender_id, body, sent_at \
         FROM \"{table}\" ORDER BY sent_at DESC LIMIT 10000",
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
    for (id, match_id, sender_id, body, sent_ms) in rows.flatten() {
        let id = id.unwrap_or_default();
        let match_id = match_id.unwrap_or_default();
        let sender_id = sender_id.unwrap_or_default();
        let body = body.unwrap_or_default();
        let ts = sent_ms.and_then(unix_ms_to_i64);
        let preview: String = body.chars().take(120).collect();
        let title = format!("Hinge msg {}: {}", sender_id, preview);
        let detail = format!(
            "Hinge message id='{}' match_id='{}' sender_id='{}' body='{}'",
            id, match_id, sender_id, body
        );
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "Hinge Message",
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
            CREATE TABLE "match" (
                id TEXT,
                subject_id TEXT,
                subject_name TEXT,
                created_at INTEGER,
                has_rose INTEGER
            );
            INSERT INTO "match" VALUES('m1','s1','Alice',1609459200000,1);
            CREATE TABLE "like" (
                id TEXT,
                subject_id TEXT,
                content_type TEXT,
                content_id TEXT,
                comment TEXT,
                created_at INTEGER
            );
            INSERT INTO "like" VALUES('l1','s1','photo','ph1','Great pic!',1609459100000);
            CREATE TABLE message (
                id TEXT,
                match_id TEXT,
                sender_id TEXT,
                body TEXT,
                sent_at INTEGER
            );
            INSERT INTO message VALUES('msg1','m1','s1','Hello!',1609459300000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_match_like_message() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Hinge Match"));
        assert!(r.iter().any(|a| a.subcategory == "Hinge Like"));
        assert!(r.iter().any(|a| a.subcategory == "Hinge Message"));
    }

    #[test]
    fn rose_flag_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("has_rose=true")));
    }

    #[test]
    fn like_with_comment_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("comment='Great pic!'")));
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
