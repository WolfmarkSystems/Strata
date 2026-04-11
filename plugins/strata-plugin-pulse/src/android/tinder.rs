//! Tinder — dating app matches and messages extraction.
//!
//! Source path: `/data/data/com.tinder/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Tinder uses Room databases with
//! tables like `match`, `message`, `swipe`. Schema varies by version.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.tinder/databases/"];

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
        "SELECT id, person_id, person_name, person_bio, matched_at, \
         last_activity_at, is_super_like \
         FROM \"{table}\" ORDER BY matched_at DESC LIMIT 5000",
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
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<i64>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, person_id, person_name, bio, matched_ms, _last_ms, is_super) in rows.flatten() {
        let id = id.unwrap_or_else(|| "(unknown)".to_string());
        let person_id = person_id.unwrap_or_default();
        let person_name = person_name.unwrap_or_else(|| "(no name)".to_string());
        let bio = bio.unwrap_or_default();
        let is_super = is_super.unwrap_or(0) != 0;
        let ts = matched_ms.and_then(unix_ms_to_i64);
        let title = format!("Tinder match: {}", person_name);
        let mut detail = format!(
            "Tinder match id='{}' person_id='{}' person_name='{}' super_like={}",
            id, person_id, person_name, is_super
        );
        if !bio.is_empty() {
            detail.push_str(&format!(" bio='{}'", bio));
        }
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "Tinder Match",
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

fn read_messages(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, match_id, sender_id, text, sent_at, is_liked \
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
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, match_id, sender_id, text, sent_ms, is_liked) in rows.flatten() {
        let id = id.unwrap_or_default();
        let match_id = match_id.unwrap_or_default();
        let sender_id = sender_id.unwrap_or_default();
        let text = text.unwrap_or_default();
        let is_liked = is_liked.unwrap_or(0) != 0;
        let ts = sent_ms.and_then(unix_ms_to_i64);
        let preview: String = text.chars().take(120).collect();
        let title = format!("Tinder msg {}: {}", sender_id, preview);
        let detail = format!(
            "Tinder message id='{}' match_id='{}' sender_id='{}' body='{}' liked={}",
            id, match_id, sender_id, text, is_liked
        );
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "Tinder Message",
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
                person_id TEXT,
                person_name TEXT,
                person_bio TEXT,
                matched_at INTEGER,
                last_activity_at INTEGER,
                is_super_like INTEGER
            );
            INSERT INTO "match" VALUES('m1','p1','Alice','Love hiking',1609459200000,1609459300000,0);
            INSERT INTO "match" VALUES('m2','p2','Bob','Coffee enthusiast',1609545600000,1609545700000,1);
            CREATE TABLE message (
                id TEXT,
                match_id TEXT,
                sender_id TEXT,
                text TEXT,
                sent_at INTEGER,
                is_liked INTEGER
            );
            INSERT INTO message VALUES('ms1','m1','p1','Hey there!',1609459400000,1);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_matches_and_messages() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Tinder Match"));
        assert!(r.iter().any(|a| a.subcategory == "Tinder Message"));
    }

    #[test]
    fn super_like_flag_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("super_like=true") && a.detail.contains("Bob")));
    }

    #[test]
    fn match_bio_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("bio='Love hiking'")));
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
