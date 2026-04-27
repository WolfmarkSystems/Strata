//! Contacts — Android contacts database.
//!
//! ALEAPP reference: `scripts/artifacts/contacts.py`. Source path:
//! `/data/data/com.android.providers.contacts/databases/contacts2.db`.
//!
//! The high-value query is against the `view_contacts` view (or the
//! `raw_contacts` + `data` join) to pull a single row per contact
//! with their display name, primary phone number, and primary email.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use rusqlite::Connection;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["contacts2.db"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "raw_contacts") && table_exists(&conn, "data") {
        read_join(&conn, path, &mut out);
    }
    out
}

fn read_join(conn: &Connection, path: &Path, out: &mut Vec<ArtifactRecord>) {
    // Use mimetype id→name via `mimetypes` table if available.
    // ALEAPP relies on the well-known literal mimetype strings,
    // which are stable across Android versions.
    let sql = r#"
        SELECT rc._id, rc.display_name, rc.contact_last_updated_timestamp,
               m.mimetype, d.data1, d.data2
        FROM raw_contacts rc
        LEFT JOIN data d ON d.raw_contact_id = rc._id
        LEFT JOIN mimetypes m ON m._id = d.mimetype_id
        ORDER BY rc._id
        LIMIT 20000
    "#;

    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return,
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return;
    };

    // Coalesce rows by contact id so we emit one record per contact
    // containing all of their phone numbers, emails, and addresses.
    use std::collections::BTreeMap;
    #[derive(Default)]
    struct Aggregate {
        name: Option<String>,
        updated: Option<i64>,
        phones: Vec<String>,
        emails: Vec<String>,
        addresses: Vec<String>,
    }
    let mut agg: BTreeMap<i64, Aggregate> = BTreeMap::new();

    for (id, name, updated, mimetype, data1, _data2) in rows.flatten() {
        let id = match id {
            Some(i) => i,
            None => continue,
        };
        let entry = agg.entry(id).or_default();
        if entry.name.is_none() {
            entry.name = name;
        }
        if entry.updated.is_none() {
            entry.updated = updated;
        }
        let mt = mimetype.unwrap_or_default();
        if let Some(v) = data1.filter(|v| !v.is_empty()) {
            match mt.as_str() {
                "vnd.android.cursor.item/phone_v2" => entry.phones.push(v),
                "vnd.android.cursor.item/email_v2" => entry.emails.push(v),
                "vnd.android.cursor.item/postal-address_v2" => entry.addresses.push(v),
                _ => {}
            }
        }
    }

    for (id, a) in agg {
        let name = a.name.clone().unwrap_or_else(|| format!("contact #{id}"));
        let mut detail_parts = Vec::new();
        if !a.phones.is_empty() {
            detail_parts.push(format!("phones=[{}]", a.phones.join(", ")));
        }
        if !a.emails.is_empty() {
            detail_parts.push(format!("emails=[{}]", a.emails.join(", ")));
        }
        if !a.addresses.is_empty() {
            detail_parts.push(format!("addresses=[{}]", a.addresses.join("; ")));
        }
        let detail = format!(
            "Android contact '{}' {}",
            name,
            if detail_parts.is_empty() {
                "(no contact methods)".to_string()
            } else {
                detail_parts.join(" ")
            }
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Android Contact",
            format!("Contact: {}", name),
            detail,
            path,
            a.updated.and_then(unix_ms_to_i64),
            ForensicValue::Medium,
            false,
        ));
    }
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
            CREATE TABLE raw_contacts (
                _id INTEGER PRIMARY KEY,
                display_name TEXT,
                contact_last_updated_timestamp INTEGER
            );
            CREATE TABLE mimetypes (
                _id INTEGER PRIMARY KEY,
                mimetype TEXT
            );
            CREATE TABLE data (
                _id INTEGER PRIMARY KEY,
                raw_contact_id INTEGER,
                mimetype_id INTEGER,
                data1 TEXT,
                data2 TEXT
            );
            INSERT INTO raw_contacts VALUES (1,'Alice Example',1609459200000);
            INSERT INTO raw_contacts VALUES (2,'Bob Tester',1609459300000);
            INSERT INTO mimetypes VALUES (1,'vnd.android.cursor.item/phone_v2');
            INSERT INTO mimetypes VALUES (2,'vnd.android.cursor.item/email_v2');
            INSERT INTO mimetypes VALUES (3,'vnd.android.cursor.item/postal-address_v2');
            INSERT INTO data VALUES (1,1,1,'+15551234567','mobile');
            INSERT INTO data VALUES (2,1,2,'alice@example.com','home');
            INSERT INTO data VALUES (3,1,3,'1 Evidence Way','home');
            INSERT INTO data VALUES (4,2,1,'+15557654321','work');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn coalesces_by_contact_id() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn alice_has_phone_email_and_address() {
        let db = make_db();
        let r = parse(db.path());
        let alice = r.iter().find(|c| c.title.contains("Alice")).unwrap();
        assert!(alice.detail.contains("+15551234567"));
        assert!(alice.detail.contains("alice@example.com"));
        assert!(alice.detail.contains("1 Evidence Way"));
    }

    #[test]
    fn bob_has_phone_only() {
        let db = make_db();
        let r = parse(db.path());
        let bob = r.iter().find(|c| c.title.contains("Bob")).unwrap();
        assert!(bob.detail.contains("+15557654321"));
        assert!(!bob.detail.contains("emails="));
    }

    #[test]
    fn missing_tables_yield_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE raw_contacts(_id INTEGER PRIMARY KEY);")
            .unwrap();
        // no `data` table
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}
