//! iOS `AddressBook.sqlitedb` — contacts.
//!
//! The classic AddressBook schema iLEAPP keys off:
//!   * `ABPerson`     — one row per contact (`First`, `Last`,
//!     `Organization`, `Note`, etc.)
//!   * `ABMultiValue` — one row per phone number / email / address,
//!     joined to `ABPerson` via `record_id` and labelled by
//!     `ABMultiValueLabel`
//!   * `ABMultiValueLabel` — label dictionary
//!
//! Pulse v1.0 emits a summary plus three breakdown records:
//! contact count, phone-number count, and email count. The full
//! per-contact extraction is queued for v1.1.

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["addressbook.sqlitedb"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    if !util::table_exists(&conn, "ABPerson") {
        return out;
    }

    let source = path.to_string_lossy().to_string();
    let person_count = util::count_rows(&conn, "ABPerson");

    out.push(ArtifactRecord {
        category: ArtifactCategory::AccountsCredentials,
        subcategory: "Contacts".to_string(),
        timestamp: None,
        title: "iOS Contacts (AddressBook)".to_string(),
        detail: format!("{} ABPerson rows (contact records)", person_count),
        source_path: source.clone(),
        forensic_value: ForensicValue::High,
        mitre_technique: None,
        is_suspicious: false,
        raw_data: None,
        confidence: 0,
    });

    if util::table_exists(&conn, "ABMultiValue") {
        // Property 3 == phone, property 4 == email in the canonical
        // ABMultiValue layout (constants from the iOS AddressBook
        // framework). Other property values exist (URL, address) but
        // we report only the high-signal ones in v1.0.
        let phone_count: i64 = conn
            .prepare("SELECT COUNT(*) FROM ABMultiValue WHERE property = 3")
            .and_then(|mut s| s.query_row([], |row| row.get(0)))
            .unwrap_or(0);
        let email_count: i64 = conn
            .prepare("SELECT COUNT(*) FROM ABMultiValue WHERE property = 4")
            .and_then(|mut s| s.query_row([], |row| row.get(0)))
            .unwrap_or(0);

        if phone_count > 0 {
            out.push(ArtifactRecord {
                category: ArtifactCategory::AccountsCredentials,
                subcategory: "Contacts phone numbers".to_string(),
                timestamp: None,
                title: "Stored phone numbers".to_string(),
                detail: format!("{} phone-number rows in ABMultiValue", phone_count),
                source_path: source.clone(),
                forensic_value: ForensicValue::High,
                mitre_technique: None,
                is_suspicious: false,
                raw_data: None,
                confidence: 0,
            });
        }
        if email_count > 0 {
            out.push(ArtifactRecord {
                category: ArtifactCategory::AccountsCredentials,
                subcategory: "Contacts email addresses".to_string(),
                timestamp: None,
                title: "Stored email addresses".to_string(),
                detail: format!("{} email-address rows in ABMultiValue", email_count),
                source_path: source.clone(),
                forensic_value: ForensicValue::High,
                mitre_technique: None,
                is_suspicious: false,
                raw_data: None,
                confidence: 0,
            });
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    fn make_addressbook(persons: usize, phones: usize, emails: usize) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute(
            "CREATE TABLE ABPerson (\
                ROWID INTEGER PRIMARY KEY, \
                First TEXT, Last TEXT, Organization TEXT \
             )",
            [],
        )
        .unwrap();
        c.execute(
            "CREATE TABLE ABMultiValue (\
                UID INTEGER PRIMARY KEY, \
                record_id INTEGER, \
                property INTEGER, \
                value TEXT \
             )",
            [],
        )
        .unwrap();

        for i in 0..persons {
            c.execute(
                "INSERT INTO ABPerson (First, Last, Organization) VALUES (?1, 'Doe', 'Acme')",
                rusqlite::params![format!("Jane{}", i)],
            )
            .unwrap();
        }
        for i in 0..phones {
            c.execute(
                "INSERT INTO ABMultiValue (record_id, property, value) VALUES (1, 3, ?1)",
                rusqlite::params![format!("+1555000{:04}", i)],
            )
            .unwrap();
        }
        for i in 0..emails {
            c.execute(
                "INSERT INTO ABMultiValue (record_id, property, value) VALUES (1, 4, ?1)",
                rusqlite::params![format!("user{}@example.com", i)],
            )
            .unwrap();
        }
        tmp
    }

    #[test]
    fn matches_addressbook_filename_only() {
        assert!(matches(Path::new("/var/mobile/AddressBook.sqlitedb")));
        assert!(!matches(Path::new("/var/mobile/sms.db")));
    }

    #[test]
    fn parses_summary_phone_and_email_counts() {
        let tmp = make_addressbook(5, 7, 3);
        let records = parse(tmp.path());

        let summary = records
            .iter()
            .find(|r| r.subcategory == "Contacts")
            .unwrap();
        assert!(summary.detail.contains("5 ABPerson"));

        let phones = records
            .iter()
            .find(|r| r.subcategory == "Contacts phone numbers")
            .expect("phones bucket");
        assert!(phones.detail.contains("7 phone-number rows"));

        let emails = records
            .iter()
            .find(|r| r.subcategory == "Contacts email addresses")
            .expect("emails bucket");
        assert!(emails.detail.contains("3 email-address rows"));
    }

    #[test]
    fn empty_address_book_emits_only_summary() {
        let tmp = make_addressbook(0, 0, 0);
        let records = parse(tmp.path());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].subcategory, "Contacts");
    }

    #[test]
    fn missing_abperson_returns_nothing() {
        let tmp = NamedTempFile::new().unwrap();
        {
            let c = Connection::open(tmp.path()).unwrap();
            c.execute("CREATE TABLE other (x INT)", []).unwrap();
        }
        let records = parse(tmp.path());
        assert!(records.is_empty());
    }
}
