//! SMS — Android native text messages (the `sms` table, not WhatsApp).
//!
//! ALEAPP reference: `scripts/artifacts/sms.py`. Source path:
//! `/data/data/com.android.providers.telephony/databases/mmssms.db`.
//!
//! Schema:
//! ```sql
//! CREATE TABLE sms (
//!   _id INTEGER PRIMARY KEY,
//!   thread_id INTEGER,
//!   address TEXT,
//!   person INTEGER,
//!   date INTEGER,       -- ms since epoch
//!   date_sent INTEGER,
//!   protocol INTEGER,
//!   read INTEGER,
//!   status INTEGER,
//!   type INTEGER,       -- 1=inbox, 2=sent, 3=draft, 4=outbox, 5=failed
//!   reply_path_present INTEGER,
//!   subject TEXT,
//!   body TEXT,
//!   service_center TEXT,
//!   locked INTEGER,
//!   sub_id INTEGER,
//!   error_code INTEGER,
//!   seen INTEGER
//! );
//! ```
//!
//! The `type` column values are documented in
//! `android.provider.Telephony.TextBasedSmsColumns`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use rusqlite::Connection;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["mmssms.db", "telephony.db"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "sms") {
        return Vec::new();
    }
    read_sms(&conn, path)
}

fn sms_type_name(code: i64) -> &'static str {
    match code {
        1 => "inbox",
        2 => "sent",
        3 => "draft",
        4 => "outbox",
        5 => "failed",
        6 => "queued",
        _ => "unknown",
    }
}

fn read_sms(conn: &Connection, path: &Path) -> Vec<ArtifactRecord> {
    let mut stmt = match conn
        .prepare("SELECT address, body, date, type, read FROM sms ORDER BY date DESC LIMIT 10000")
    {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (address, body, date_ms, type_code, read) in rows.flatten() {
        let address = address.unwrap_or_else(|| "(unknown)".to_string());
        let body = body.unwrap_or_default();
        let kind = sms_type_name(type_code.unwrap_or(0));
        let ts = date_ms.and_then(unix_ms_to_i64);
        let read_flag = read.unwrap_or(0) != 0;

        let preview: String = body.chars().take(120).collect();
        let title = format!("SMS {} {}: {}", kind, address, preview);
        let detail = format!(
            "Android SMS direction={} address='{}' read={} body='{}'",
            kind, address, read_flag, body
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Android SMS",
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
            CREATE TABLE sms (
                _id INTEGER PRIMARY KEY,
                address TEXT,
                body TEXT,
                date INTEGER,
                type INTEGER,
                read INTEGER
            );
            INSERT INTO sms VALUES (1,'+15551234567','Hi there',1609459200000,1,1);
            INSERT INTO sms VALUES (2,'+15551234567','See you soon',1609459300000,2,1);
            INSERT INTO sms VALUES (3,'+15557654321','Meeting at 3',1609459400000,1,0);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_three_messages() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|x| x.subcategory == "Android SMS"));
    }

    #[test]
    fn directions_are_mapped() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|x| x.title.starts_with("SMS inbox")));
        assert!(r.iter().any(|x| x.title.starts_with("SMS sent")));
    }

    #[test]
    fn body_appears_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|x| x.detail.contains("'Meeting at 3'")));
    }

    #[test]
    fn missing_table_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE irrelevant(x INTEGER);")
            .unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}
