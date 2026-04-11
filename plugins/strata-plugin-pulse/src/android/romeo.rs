//! Planet Romeo — dating app message and contact extraction.
//!
//! ALEAPP reference: `scripts/artifacts/RomeoDatingApp.py`. Source path:
//! `/data/data/com.planetromeo.android.app/databases/planetromeo-room.db`.
//!
//! Key tables: `MessageEntity`, `ContactEntity`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.planetromeo.android.app/databases/planetromeo-room.db"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "MessageEntity") {
        out.extend(read_messages(&conn, path));
    }
    if table_exists(&conn, "ContactEntity") {
        out.extend(read_contacts(&conn, path));
    }
    out
}

fn read_messages(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT timestamp, contact_id, contact_name, message_text, \
               status, saved, unread, message_id \
               FROM MessageEntity \
               ORDER BY timestamp DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<i64>>(6).unwrap_or(None),
            row.get::<_, Option<String>>(7).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (ts_ms, contact_id, contact_name, text, status, saved, unread, msg_id) in rows.flatten() {
        let contact_id = contact_id.unwrap_or_else(|| "(unknown)".to_string());
        let contact_name = contact_name.unwrap_or_else(|| "(no name)".to_string());
        let body = text.unwrap_or_default();
        let status = status.unwrap_or_else(|| "unknown".to_string());
        let is_saved = saved.unwrap_or(0) != 0;
        let is_unread = unread.unwrap_or(0) != 0;
        let msg_id = msg_id.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let preview: String = body.chars().take(120).collect();
        let title = format!("Romeo {}: {}", contact_name, preview);
        let mut detail = format!(
            "PlanetRomeo message contact_id='{}' contact_name='{}' status='{}' saved={} unread={} body='{}'",
            contact_id, contact_name, status, is_saved, is_unread, body
        );
        if !msg_id.is_empty() {
            detail.push_str(&format!(" message_id='{}'", msg_id));
        }
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "PlanetRomeo Message",
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

fn read_contacts(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT user_id, name, age, city, country, \
               deactivated, blocked \
               FROM ContactEntity LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<i64>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (uid, name, age, city, country, deactivated, blocked) in rows.flatten() {
        let uid = uid.unwrap_or_else(|| "(unknown)".to_string());
        let name = name.unwrap_or_else(|| "(no name)".to_string());
        let is_deactivated = deactivated.unwrap_or(0) != 0;
        let is_blocked = blocked.unwrap_or(0) != 0;
        let title = format!("Romeo contact: {} ({})", name, uid);
        let mut detail = format!(
            "PlanetRomeo contact user_id='{}' name='{}' deactivated={} blocked={}",
            uid, name, is_deactivated, is_blocked
        );
        if let Some(a) = age {
            detail.push_str(&format!(" age={}", a));
        }
        if let Some(c) = city.filter(|c| !c.is_empty()) {
            detail.push_str(&format!(" city='{}'", c));
        }
        if let Some(c) = country.filter(|c| !c.is_empty()) {
            detail.push_str(&format!(" country='{}'", c));
        }
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "PlanetRomeo Contact",
            title,
            detail,
            path,
            None,
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
            CREATE TABLE MessageEntity (
                timestamp INTEGER,
                contact_id TEXT,
                contact_name TEXT,
                message_text TEXT,
                status TEXT,
                saved INTEGER,
                unread INTEGER,
                message_id TEXT
            );
            INSERT INTO MessageEntity VALUES(1609459200000,'c1','Alice','Hi Romeo','sent',0,0,'msg_1');
            INSERT INTO MessageEntity VALUES(1609459300000,'c1','Alice','Reply','received',0,1,'msg_2');
            CREATE TABLE ContactEntity (
                user_id TEXT,
                name TEXT,
                age INTEGER,
                city TEXT,
                country TEXT,
                deactivated INTEGER,
                blocked INTEGER
            );
            INSERT INTO ContactEntity VALUES('c1','Alice',28,'Berlin','Germany',0,0);
            INSERT INTO ContactEntity VALUES('c2','Bob',35,'Paris','France',0,1);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_messages_and_contacts() {
        let db = make_db();
        let r = parse(db.path());
        let msgs: Vec<_> = r.iter().filter(|a| a.subcategory == "PlanetRomeo Message").collect();
        let contacts: Vec<_> = r.iter().filter(|a| a.subcategory == "PlanetRomeo Contact").collect();
        assert_eq!(msgs.len(), 2);
        assert_eq!(contacts.len(), 2);
    }

    #[test]
    fn blocked_contact_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let bob = r.iter().find(|a| a.detail.contains("Bob")).unwrap();
        assert!(bob.detail.contains("blocked=true"));
    }

    #[test]
    fn city_and_country_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("city='Berlin'") && a.detail.contains("country='Germany'")));
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
