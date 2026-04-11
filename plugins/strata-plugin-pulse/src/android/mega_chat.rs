//! MEGA (karere) — chat message extraction.
//!
//! ALEAPP reference: `scripts/artifacts/mega.py`. Source path:
//! `/data/data/mega.privacy.android.app/karere-*.db*`.
//!
//! Key tables: `history`, `contacts`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["mega.privacy.android.app/karere-"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "history") {
        return Vec::new();
    }
    read_history(&conn, path)
}

fn msg_type_name(code: i64) -> &'static str {
    match code {
        0 => "normal",
        1 => "management",
        2 => "alter_participants",
        3 => "truncate",
        4 => "priv_change",
        5 => "chat_title",
        10 => "attachment",
        11 => "revoke_attachment",
        12 => "contact",
        13 => "contains_meta",
        14 => "voice_clip",
        _ => "unknown",
    }
}

fn read_history(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let has_contacts = table_exists(conn, "contacts");
    let sql = if has_contacts {
        "SELECT h.ts, c.email, h.type, h.data, h.userid \
         FROM history h \
         LEFT JOIN contacts c ON h.userid = c.userid \
         ORDER BY h.ts DESC LIMIT 10000"
    } else {
        "SELECT ts, NULL, type, data, userid \
         FROM history ORDER BY ts DESC LIMIT 10000"
    };
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (ts, email, msg_type, data, userid) in rows.flatten() {
        let email = email.unwrap_or_else(|| "(unknown)".to_string());
        let kind = msg_type_name(msg_type.unwrap_or(-1));
        let body = data.unwrap_or_default();
        let userid = userid.unwrap_or_default();
        let preview: String = body.chars().take(120).collect();
        let title = format!("MEGA chat {} ({}): {}", email, kind, preview);
        let mut detail = format!(
            "MEGA chat history type='{}' email='{}' userid='{}' data='{}'",
            kind, email, userid, body
        );
        if let Some(t) = msg_type {
            detail.push_str(&format!(" type_code={}", t));
        }
        out.push(build_record(
            ArtifactCategory::Communications,
            "MEGA Chat",
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
            CREATE TABLE contacts (
                userid TEXT,
                email TEXT
            );
            INSERT INTO contacts VALUES('uid_1','alice@mega.nz');
            INSERT INTO contacts VALUES('uid_2','bob@mega.nz');
            CREATE TABLE history (
                ts INTEGER,
                type INTEGER,
                data TEXT,
                userid TEXT
            );
            INSERT INTO history VALUES(1609459200,0,'Hello MEGA','uid_1');
            INSERT INTO history VALUES(1609459300,10,'file.zip','uid_2');
            INSERT INTO history VALUES(1609459400,5,'New Chat Title','uid_1');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_three_entries() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|a| a.subcategory == "MEGA Chat"));
    }

    #[test]
    fn message_type_mapped() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("type='normal'")));
        assert!(r.iter().any(|a| a.detail.contains("type='attachment'")));
        assert!(r.iter().any(|a| a.detail.contains("type='chat_title'")));
    }

    #[test]
    fn email_from_contacts_join() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("email='alice@mega.nz'")));
        assert!(r.iter().any(|a| a.detail.contains("email='bob@mega.nz'")));
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
