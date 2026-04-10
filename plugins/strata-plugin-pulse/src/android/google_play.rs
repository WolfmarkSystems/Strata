//! Google Play — install / uninstall history from the Play Store
//! database.
//!
//! ALEAPP reference: `scripts/artifacts/googlePlay.py`. Source path:
//! `/data/data/com.android.vending/databases/library.db` with the
//! `ownership` table:
//!
//! - `account` — Google account that purchased / installed
//! - `library_id` — usually `u-wl` (wishlist) or `u-pl` (apps)
//! - `doc_id` — package name (e.g. `com.example.app`)
//! - `doc_type` — 1 = app
//! - `valid_from_timestamp_msec` — install timestamp
//!
//! Tracks "this account installed this package on this device" — the
//! single most useful data point when correlating apps to identity.

use crate::android::helpers::{build_record, column_exists, open_sqlite_ro, table_exists, unix_ms_to_i64};
use rusqlite::Connection;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["library.db", "localappstate.db", "vending"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if table_exists(&conn, "ownership") {
        return read_ownership(&conn, path);
    }
    if table_exists(&conn, "appstate") {
        return read_appstate(&conn, path);
    }
    Vec::new()
}

fn read_ownership(conn: &Connection, path: &Path) -> Vec<ArtifactRecord> {
    let has_account = column_exists(conn, "ownership", "account");
    let has_doc = column_exists(conn, "ownership", "doc_id");
    let has_ts = column_exists(conn, "ownership", "valid_from_timestamp_msec");
    if !has_doc {
        return Vec::new();
    }
    let sql = format!(
        "SELECT {}, doc_id, {} FROM ownership LIMIT 10000",
        if has_account { "account" } else { "''" },
        if has_ts {
            "valid_from_timestamp_msec"
        } else {
            "0"
        }
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
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (account, doc_id, ts_ms) in rows.flatten() {
        let doc_id = doc_id.unwrap_or_default();
        if doc_id.is_empty() {
            continue;
        }
        let account = account.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        out.push(build_record(
            ArtifactCategory::SystemActivity,
            "Android Google Play Install",
            format!("Play Install: {} ({})", doc_id, account),
            format!(
                "Google Play installed package='{}' account='{}'",
                doc_id, account
            ),
            path,
            ts,
            ForensicValue::Medium,
            false,
        ));
    }
    out
}

fn read_appstate(conn: &Connection, path: &Path) -> Vec<ArtifactRecord> {
    let has_pkg = column_exists(conn, "appstate", "package_name");
    if !has_pkg {
        return Vec::new();
    }
    let sql = "SELECT package_name FROM appstate LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| row.get::<_, Option<String>>(0));
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for pkg in rows.flatten().flatten() {
        if pkg.is_empty() {
            continue;
        }
        out.push(build_record(
            ArtifactCategory::SystemActivity,
            "Android Google Play Install",
            format!("Play AppState: {}", pkg),
            format!("Google Play app state package='{}'", pkg),
            path,
            None,
            ForensicValue::Low,
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
            CREATE TABLE ownership (
                account TEXT,
                doc_id TEXT,
                doc_type INTEGER,
                valid_from_timestamp_msec INTEGER
            );
            INSERT INTO ownership VALUES ('user@gmail.com','com.whatsapp',1,1609459200000);
            INSERT INTO ownership VALUES ('user@gmail.com','com.signal.android',1,1609459300000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_two_installs() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn package_and_account_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|x| x.title.contains("com.whatsapp") && x.title.contains("user@gmail.com")));
    }

    #[test]
    fn appstate_fallback_works() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE appstate (package_name TEXT);
            INSERT INTO appstate VALUES ('com.foo.bar');
            "#,
        )
        .unwrap();
        drop(c);
        let r = parse(tmp.path());
        assert_eq!(r.len(), 1);
        assert!(r[0].title.contains("com.foo.bar"));
    }

    #[test]
    fn missing_tables_yield_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE foo(x INTEGER);").unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}
