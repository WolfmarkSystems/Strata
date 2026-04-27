//! Grindr — dating/social app profiles viewed, messages, taps, blocks, and favorites.
//!
//! Source path: `/data/data/com.grindr.android/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Grindr uses Room databases with
//! tables like `profile`, `message`, `tap`, `block`, `favorite`.
//! Distance field is included when present (forensically significant for
//! establishing proximity between parties).

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.grindr.android/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["message", "messages", "chat_message"] {
        if table_exists(&conn, table) {
            out.extend(read_messages(&conn, path, table));
            break;
        }
    }
    for table in &["profile", "profile_view", "viewed_profile"] {
        if table_exists(&conn, table) {
            out.extend(read_profiles(&conn, path, table));
            break;
        }
    }
    for table in &["tap", "taps"] {
        if table_exists(&conn, table) {
            out.extend(read_taps(&conn, path, table));
            break;
        }
    }
    for table in &["block", "blocks", "blocked_profile"] {
        if table_exists(&conn, table) {
            out.extend(read_blocks(&conn, path, table));
            break;
        }
    }
    out
}

fn read_messages(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, sender_id, recipient_id, body, sent_at, is_incoming \
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
    for (id, sender, recipient, body, sent_ms, is_incoming) in rows.flatten() {
        let id = id.unwrap_or_default();
        let sender = sender.unwrap_or_else(|| "(unknown)".to_string());
        let recipient = recipient.unwrap_or_else(|| "(unknown)".to_string());
        let body = body.unwrap_or_default();
        let direction = if is_incoming.unwrap_or(0) == 1 {
            "incoming"
        } else {
            "outgoing"
        };
        let ts = sent_ms.and_then(unix_ms_to_i64);
        let preview: String = body.chars().take(120).collect();
        let title = format!("Grindr {} msg {}: {}", direction, sender, preview);
        let detail = format!(
            "Grindr message id='{}' sender='{}' recipient='{}' direction='{}' body='{}'",
            id, sender, recipient, direction, body
        );
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "Grindr Message",
            title,
            detail,
            path,
            ts,
            ForensicValue::Critical,
            true,
        ));
    }
    out
}

fn read_profiles(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT profile_id, display_name, age, distance, viewed_at \
         FROM \"{table}\" ORDER BY viewed_at DESC LIMIT 5000",
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
            row.get::<_, Option<f64>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (profile_id, display_name, age, distance, viewed_ms) in rows.flatten() {
        let profile_id = profile_id.unwrap_or_default();
        let display_name = display_name.unwrap_or_else(|| "(no name)".to_string());
        let ts = viewed_ms.and_then(unix_ms_to_i64);
        let title = format!("Grindr profile viewed: {}", display_name);
        let mut detail = format!(
            "Grindr profile profile_id='{}' display_name='{}'",
            profile_id, display_name
        );
        if let Some(a) = age {
            detail.push_str(&format!(" age={}", a));
        }
        if let Some(d) = distance {
            detail.push_str(&format!(" distance={:.1}m", d));
        }
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "Grindr Profile View",
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

fn read_taps(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT sender_id, recipient_id, tap_type, tapped_at \
         FROM \"{table}\" ORDER BY tapped_at DESC LIMIT 5000",
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
    for (sender, recipient, tap_type, tapped_ms) in rows.flatten() {
        let sender = sender.unwrap_or_default();
        let recipient = recipient.unwrap_or_default();
        let tap_type = tap_type.unwrap_or_else(|| "tap".to_string());
        let ts = tapped_ms.and_then(unix_ms_to_i64);
        let title = format!("Grindr tap: {} -> {}", sender, recipient);
        let detail = format!(
            "Grindr tap sender='{}' recipient='{}' type='{}'",
            sender, recipient, tap_type
        );
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "Grindr Tap",
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

fn read_blocks(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT profile_id, display_name, blocked_at \
         FROM \"{table}\" ORDER BY blocked_at DESC LIMIT 5000",
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
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (profile_id, display_name, blocked_ms) in rows.flatten() {
        let profile_id = profile_id.unwrap_or_default();
        let display_name = display_name.unwrap_or_else(|| "(no name)".to_string());
        let ts = blocked_ms.and_then(unix_ms_to_i64);
        let title = format!("Grindr blocked: {}", display_name);
        let detail = format!(
            "Grindr block profile_id='{}' display_name='{}'",
            profile_id, display_name
        );
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "Grindr Block",
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
            CREATE TABLE message (
                id TEXT,
                sender_id TEXT,
                recipient_id TEXT,
                body TEXT,
                sent_at INTEGER,
                is_incoming INTEGER
            );
            INSERT INTO message VALUES('msg1','u1','u2','Hey there',1609459200000,0);
            INSERT INTO message VALUES('msg2','u2','u1','Hi!',1609459300000,1);
            CREATE TABLE profile (
                profile_id TEXT,
                display_name TEXT,
                age INTEGER,
                distance REAL,
                viewed_at INTEGER
            );
            INSERT INTO profile VALUES('p1','Alex',28,150.5,1609459100000);
            CREATE TABLE tap (
                sender_id TEXT,
                recipient_id TEXT,
                tap_type TEXT,
                tapped_at INTEGER
            );
            INSERT INTO tap VALUES('u1','p1','friendly',1609459050000);
            CREATE TABLE block (
                profile_id TEXT,
                display_name TEXT,
                blocked_at INTEGER
            );
            INSERT INTO block VALUES('p2','BadUser',1609459400000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_messages_profiles_taps_blocks() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Grindr Message"));
        assert!(r.iter().any(|a| a.subcategory == "Grindr Profile View"));
        assert!(r.iter().any(|a| a.subcategory == "Grindr Tap"));
        assert!(r.iter().any(|a| a.subcategory == "Grindr Block"));
    }

    #[test]
    fn messages_are_critical_forensic_value() {
        let db = make_db();
        let r = parse(db.path());
        let msg = r
            .iter()
            .find(|a| a.subcategory == "Grindr Message")
            .unwrap();
        assert_eq!(
            msg.forensic_value,
            strata_plugin_sdk::ForensicValue::Critical
        );
    }

    #[test]
    fn distance_captured_in_profile() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(
            |a| a.subcategory == "Grindr Profile View" && a.detail.contains("distance=150.5m")
        ));
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
