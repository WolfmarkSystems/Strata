//! 1Password — password manager metadata extraction.
//!
//! Source: /data/data/com.agilebits.onepassword/databases/1password.db
//!
//! SECURITY: metadata only — never extract passwords, secrets, or credential data

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.agilebits.onepassword/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "items") {
        return Vec::new();
    }
    read_items(&conn, path)
}

fn read_items(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    // SECURITY: only select title, category, created_at, vault_name — never secrets or keys
    let sql = "SELECT title, category, created_at, vault_name \
               FROM items \
               ORDER BY created_at DESC LIMIT 5000";
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
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (title, category, created_at, vault_name) in rows.flatten() {
        let title_str = title.unwrap_or_else(|| "(unnamed)".to_string());
        let category_str = category.unwrap_or_else(|| "Login".to_string());
        let vault = vault_name.unwrap_or_else(|| "Personal".to_string());
        let ts = created_at.and_then(unix_ms_to_i64);
        let display = format!("1Password Entry: {}", title_str);
        let detail = format!(
            "1Password entry title='{}' category='{}' vault='{}' (metadata only)",
            title_str, category_str, vault
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "1Password Entry",
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
            CREATE TABLE items (
                _id INTEGER PRIMARY KEY,
                title TEXT,
                category TEXT,
                created_at INTEGER,
                vault_name TEXT
            );
            INSERT INTO items VALUES(1,'Gmail Account','Login',1609459200000,'Personal');
            INSERT INTO items VALUES(2,'AWS Root','Login',1609459300000,'Work');
            INSERT INTO items VALUES(3,'Home WiFi','Password',1609459400000,'Personal');
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
        assert!(r.iter().all(|a| a.subcategory == "1Password Entry"));
    }

    #[test]
    fn vault_and_category_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("vault='Work'") && a.detail.contains("title='AWS Root'")));
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
