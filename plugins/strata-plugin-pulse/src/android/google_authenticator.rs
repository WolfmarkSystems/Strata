//! Google Authenticator — TOTP seed and account extraction.
//!
//! Source path: `/data/data/com.google.android.apps.authenticator2/databases/databases`.
//!
//! Schema note: not in ALEAPP upstream. Google Authenticator stores
//! TOTP secrets in a `accounts` table with `email`, `secret`, `issuer`,
//! `type`. HIGH CI VALUE: secrets can be used to generate valid 2FA
//! codes for the subject's accounts.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.google.android.apps.authenticator2/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "accounts") {
        return Vec::new();
    }
    read_accounts(&conn, path)
}

fn read_accounts(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT _id, email, secret, issuer, type, counter \
               FROM accounts LIMIT 1000";
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
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, email, secret, issuer, totp_type, counter) in rows.flatten() {
        let id = id.unwrap_or(0);
        let email = email.unwrap_or_else(|| "(unknown)".to_string());
        let secret = secret.unwrap_or_default();
        let issuer = issuer.unwrap_or_default();
        let otp_type = match totp_type.unwrap_or(0) {
            0 => "TOTP",
            1 => "HOTP",
            _ => "unknown",
        };
        let counter = counter.unwrap_or(0);
        let has_secret = !secret.is_empty();
        let title = format!("Authenticator: {} ({})", email, issuer);
        let detail = format!(
            "Google Authenticator account id={} email='{}' issuer='{}' type='{}' has_secret={} counter={}",
            id, email, issuer, otp_type, has_secret, counter
        );
        out.push(build_record(
            ArtifactCategory::EncryptionKeyMaterial,
            "Google Authenticator",
            title,
            detail,
            path,
            None,
            ForensicValue::Critical,
            true,
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
            CREATE TABLE accounts (
                _id INTEGER PRIMARY KEY,
                email TEXT,
                secret TEXT,
                issuer TEXT,
                type INTEGER,
                counter INTEGER
            );
            INSERT INTO accounts VALUES(1,'user@example.com','JBSWY3DPEHPK3PXP','Gmail',0,0);
            INSERT INTO accounts VALUES(2,'user@example.com','ABCDEFGHIJKLMNOP','GitHub',0,0);
            INSERT INTO accounts VALUES(3,'bank@example.com','SECRETHOTP12345','Chase Bank',1,42);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_three_accounts() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|a| a.subcategory == "Google Authenticator"));
    }

    #[test]
    fn secret_presence_flagged() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().all(|a| a.detail.contains("has_secret=true")));
        assert!(r.iter().all(|a| a.is_suspicious));
    }

    #[test]
    fn hotp_counter_captured() {
        let db = make_db();
        let r = parse(db.path());
        let hotp = r.iter().find(|a| a.detail.contains("type='HOTP'")).unwrap();
        assert!(hotp.detail.contains("counter=42"));
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
