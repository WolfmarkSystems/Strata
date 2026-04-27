//! Chrome Login Data — saved password database.
//!
//! ALEAPP reference: `scripts/artifacts/chromeLoginData.py`. Source path:
//! `/data/data/com.android.chrome/app_chrome/Default/Login Data` with
//! the `logins` table:
//!
//! - `origin_url`
//! - `username_value`
//! - `password_value` — encrypted with the OS-level Chrome key, never
//!   stored as plaintext on Android. Pulse records the host/username
//!   pair only and never attempts to decrypt.
//! - `date_created` / `date_last_used` — Chrome microseconds.
//!
//! Each saved login is forensically high-value because it confirms an
//! account exists, even though the secret is opaque.

use crate::android::helpers::{
    build_record, chrome_to_unix, column_exists, open_sqlite_ro, table_exists,
};
use rusqlite::Connection;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["login data", "logindata", "passwords.db"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "logins") {
        return Vec::new();
    }
    read(&conn, path)
}

fn read(conn: &Connection, path: &Path) -> Vec<ArtifactRecord> {
    let has_origin = column_exists(conn, "logins", "origin_url");
    let has_user = column_exists(conn, "logins", "username_value");
    if !(has_origin && has_user) {
        return Vec::new();
    }
    let has_created = column_exists(conn, "logins", "date_created");
    let has_used = column_exists(conn, "logins", "date_last_used");

    let sql = format!(
        "SELECT origin_url, username_value, {}, {} FROM logins LIMIT 5000",
        if has_created { "date_created" } else { "0" },
        if has_used { "date_last_used" } else { "0" }
    );
    let mut stmt = match conn.prepare(&sql) {
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
    for (origin, user, created_us, used_us) in rows.flatten() {
        let origin = origin.unwrap_or_default();
        let user = user.unwrap_or_default();
        if origin.is_empty() && user.is_empty() {
            continue;
        }
        let ts = used_us
            .and_then(chrome_to_unix)
            .or_else(|| created_us.and_then(chrome_to_unix));
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "Android Chrome Saved Login",
            format!("Login: {} @ {}", user, origin),
            format!(
                "Chrome saved login origin='{}' username='{}' (password is encrypted on disk)",
                origin, user
            ),
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

    fn webkit_us(unix_sec: i64) -> i64 {
        (unix_sec + 11_644_473_600) * 1_000_000
    }

    fn make_db() -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE logins (
                origin_url TEXT,
                username_value TEXT,
                password_value BLOB,
                date_created INTEGER,
                date_last_used INTEGER
            );
            "#,
        )
        .unwrap();
        let t = webkit_us(1_609_459_200);
        c.execute(
            "INSERT INTO logins VALUES ('https://github.com','octocat',X'',?1,?1)",
            [t],
        )
        .unwrap();
        c.execute(
            "INSERT INTO logins VALUES ('https://example.com','admin',X'',?1,?1)",
            [t],
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_two_logins() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn user_and_origin_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|x| x.title.contains("octocat") && x.title.contains("github.com")));
    }

    #[test]
    fn category_is_credentials() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .all(|x| x.category == ArtifactCategory::AccountsCredentials));
        assert!(r.iter().all(|x| x.forensic_value == ForensicValue::High));
    }

    #[test]
    fn missing_table_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE foo(x INTEGER);").unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}
