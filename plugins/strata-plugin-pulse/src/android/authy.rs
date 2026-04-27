//! Authy — 2FA token metadata extraction.
//!
//! Source: /data/data/com.authy.authy/databases/authy.db

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.authy.authy/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "tokens") {
        return Vec::new();
    }
    read_tokens(&conn, path)
}

fn read_tokens(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT name, issuer, digits, period \
               FROM tokens LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (name, issuer, digits, period) in rows.flatten() {
        let name_str = name.unwrap_or_else(|| "(unnamed)".to_string());
        let issuer_str = issuer.unwrap_or_default();
        let digits = digits.unwrap_or(6);
        let period = period.unwrap_or(30);
        let display = format!("Authy 2FA Token: {} ({})", name_str, issuer_str);
        let detail = format!(
            "Authy 2FA token name='{}' issuer='{}' digits={} period={}s",
            name_str, issuer_str, digits, period
        );
        out.push(build_record(
            ArtifactCategory::EncryptionKeyMaterial,
            "Authy 2FA Token",
            display,
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
            CREATE TABLE tokens (
                _id INTEGER PRIMARY KEY,
                name TEXT,
                issuer TEXT,
                digits INTEGER,
                period INTEGER
            );
            INSERT INTO tokens VALUES(1,'work@company.com','Okta',6,30);
            INSERT INTO tokens VALUES(2,'user@gmail.com','Google',6,30);
            INSERT INTO tokens VALUES(3,'admin','AWS',6,60);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_three_tokens() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|a| a.subcategory == "Authy 2FA Token"));
    }

    #[test]
    fn issuer_and_period_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("issuer='AWS'") && a.detail.contains("period=60s")));
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
