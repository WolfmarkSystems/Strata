//! AccountsGoogle — Google accounts registered on an Android device.
//!
//! ALEAPP reference: `scripts/artifacts/accountsDb.py`, which opens
//! `/data/system_ce/0/accounts_ce.db` (and the older
//! `/data/system/users/0/accounts.db`) and pulls rows from the
//! `accounts` table.
//!
//! Schema of interest (Android 9+):
//! ```sql
//! CREATE TABLE accounts (
//!   _id INTEGER PRIMARY KEY,
//!   name TEXT NOT NULL,        -- email for com.google accounts
//!   type TEXT NOT NULL,        -- e.g. "com.google"
//!   password TEXT,
//!   previous_name TEXT,
//!   last_password_entry_time_millis_epoch INTEGER
//! );
//! ```
//!
//! Pulse extracts the Google accounts in particular because they tie
//! the device to a real identity (Gmail address), which is
//! investigator gold. Any non-Google accounts still surface but at a
//! lower forensic value.

use crate::android::helpers::{build_record, column_exists, open_sqlite_ro, table_exists, unix_ms_to_i64};
use rusqlite::Connection;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

/// Candidate path fragments (lowercased) used by the dispatcher.
pub const MATCHES: &[&str] = &["accounts_ce.db", "accounts.db"];

/// Parse an Android accounts database.
pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "accounts") {
        return Vec::new();
    }
    read_accounts(&conn, path)
}

fn read_accounts(conn: &Connection, path: &Path) -> Vec<ArtifactRecord> {
    let has_ts = column_exists(conn, "accounts", "last_password_entry_time_millis_epoch");
    let has_prev = column_exists(conn, "accounts", "previous_name");

    let mut select = String::from("SELECT name, type");
    if has_prev {
        select.push_str(", previous_name");
    } else {
        select.push_str(", NULL");
    }
    if has_ts {
        select.push_str(", last_password_entry_time_millis_epoch");
    } else {
        select.push_str(", NULL");
    }
    select.push_str(" FROM accounts");

    let mut stmt = match conn.prepare(&select) {
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
    for (name, type_, prev, ts_ms) in rows.flatten() {
        let name = name.unwrap_or_else(|| "(no name)".to_string());
        let type_ = type_.unwrap_or_else(|| "unknown".to_string());
        let ts = ts_ms.and_then(unix_ms_to_i64);

        let is_google = type_.eq_ignore_ascii_case("com.google");
        let title = if is_google {
            format!("Google Account: {}", name)
        } else {
            format!("Android Account: {} ({})", name, type_)
        };
        let mut detail = format!(
            "Account name='{}' type='{}' registered on device",
            name, type_
        );
        if let Some(p) = prev {
            if !p.is_empty() && p != name {
                detail.push_str(&format!("; previous_name='{}'", p));
            }
        }

        let forensic_value = if is_google {
            ForensicValue::High
        } else {
            ForensicValue::Medium
        };

        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "Android Account",
            title,
            detail,
            path,
            ts,
            forensic_value,
            false,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn make_db_with_schema() -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = Connection::open(tmp.path()).unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE accounts (
                _id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                password TEXT,
                previous_name TEXT,
                last_password_entry_time_millis_epoch INTEGER
            );
            INSERT INTO accounts VALUES (1, 'user@gmail.com', 'com.google', NULL, NULL, 1609459200000);
            INSERT INTO accounts VALUES (2, 'john', 'com.whatsapp', NULL, 'johnny', 0);
            INSERT INTO accounts VALUES (3, 'work@company.com', 'com.google', NULL, 'personal@gmail.com', 1612137600000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_google_and_non_google_accounts() {
        let db = make_db_with_schema();
        let records = parse(db.path());
        assert_eq!(records.len(), 3);
        // 2 Google accounts flagged High
        let google: Vec<_> = records.iter().filter(|r| r.title.starts_with("Google")).collect();
        assert_eq!(google.len(), 2);
        assert!(google.iter().all(|r| r.forensic_value == ForensicValue::High));
    }

    #[test]
    fn google_record_has_email_in_title() {
        let db = make_db_with_schema();
        let records = parse(db.path());
        let g = records
            .iter()
            .find(|r| r.title.contains("user@gmail.com"))
            .expect("gmail account present");
        assert_eq!(g.subcategory, "Android Account");
        assert_eq!(g.category, ArtifactCategory::AccountsCredentials);
        assert_eq!(g.timestamp, Some(1_609_459_200));
    }

    #[test]
    fn previous_name_is_captured_in_detail() {
        let db = make_db_with_schema();
        let records = parse(db.path());
        let work = records
            .iter()
            .find(|r| r.title.contains("work@company.com"))
            .expect("work account present");
        assert!(work.detail.contains("previous_name='personal@gmail.com'"));
    }

    #[test]
    fn missing_table_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = Connection::open(tmp.path()).unwrap();
        conn.execute_batch("CREATE TABLE unrelated (id INTEGER);").unwrap();
        drop(conn);
        assert!(parse(tmp.path()).is_empty());
    }

    #[test]
    fn nonexistent_file_yields_empty() {
        assert!(parse(Path::new("/no/such/accounts_ce.db")).is_empty());
    }
}
