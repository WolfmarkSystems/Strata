//! LastPass — password manager metadata extraction.
//!
//! Source: /data/data/com.lastpass.lpandroid/databases/lastpass.db
//!
//! SECURITY: metadata only — never extract passwords, secrets, or credential data

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.lastpass.lpandroid/databases/",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "Logins") {
        return Vec::new();
    }
    read_logins(&conn, path)
}

fn read_logins(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    // SECURITY: only select name, url, and last_used — never password or encrypted fields
    let sql = "SELECT name, url, last_used \
               FROM Logins \
               ORDER BY last_used DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
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
    for (name, url, last_used) in rows.flatten() {
        let name_str = name.unwrap_or_else(|| "(unnamed)".to_string());
        let url_str = url.unwrap_or_default();
        let ts = last_used.and_then(unix_ms_to_i64);
        let display = format!("LastPass Entry: {}", name_str);
        let detail = format!(
            "LastPass entry name='{}' url='{}' (metadata only)",
            name_str, url_str
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "LastPass Entry",
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
            CREATE TABLE Logins (
                _id INTEGER PRIMARY KEY,
                name TEXT,
                url TEXT,
                last_used INTEGER
            );
            INSERT INTO Logins VALUES(1,'Gmail','https://mail.google.com',1609459200000);
            INSERT INTO Logins VALUES(2,'GitHub','https://github.com',1609459300000);
            INSERT INTO Logins VALUES(3,'Bank Portal','https://bank.example.com',1609459400000);
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
        assert!(r.iter().all(|a| a.subcategory == "LastPass Entry"));
    }

    #[test]
    fn name_and_url_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("name='GitHub'") && a.detail.contains("url='https://github.com'")));
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
