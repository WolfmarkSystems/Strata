//! Bitwarden — password manager metadata extraction.
//!
//! Source: /data/data/com.x8bit.bitwarden/databases/bitwarden.db
//!
//! SECURITY: metadata only — never extract passwords, secrets, or credential data

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.x8bit.bitwarden/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "ciphers") {
        return Vec::new();
    }
    read_ciphers(&conn, path)
}

fn read_ciphers(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    // SECURITY: only select name, type, uri, revisionDate — never passwords or encrypted fields
    let sql = "SELECT name, type, uri, revisionDate \
               FROM ciphers \
               ORDER BY revisionDate DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
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
    for (name, cipher_type, uri, revision_date) in rows.flatten() {
        let name_str = name.unwrap_or_else(|| "(unnamed)".to_string());
        let type_str = cipher_type.unwrap_or_else(|| "Login".to_string());
        let uri_str = uri.unwrap_or_default();
        let ts = revision_date.and_then(unix_ms_to_i64);
        let display = format!("Bitwarden Entry: {}", name_str);
        let detail = format!(
            "Bitwarden entry name='{}' type='{}' uri='{}' (metadata only)",
            name_str, type_str, uri_str
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "Bitwarden Entry",
            display,
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
            CREATE TABLE ciphers (
                _id INTEGER PRIMARY KEY,
                name TEXT,
                type TEXT,
                uri TEXT,
                revisionDate INTEGER
            );
            INSERT INTO ciphers VALUES(1,'Company VPN','Login','https://vpn.company.com',1609459200000);
            INSERT INTO ciphers VALUES(2,'Personal Email','Login','https://mail.google.com',1609459300000);
            INSERT INTO ciphers VALUES(3,'SSH Key','SecureNote','',1609459400000);
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
        assert!(r.iter().all(|a| a.subcategory == "Bitwarden Entry"));
    }

    #[test]
    fn name_and_uri_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("name='Company VPN'")
            && a.detail.contains("uri='https://vpn.company.com'")));
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
