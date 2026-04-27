//! Notifications — pushed notification log.
//!
//! ALEAPP reference: `scripts/artifacts/notifications.py`. Source path:
//! `/data/data/com.android.systemui/databases/notification_log.db`
//! with the `notifications` table:
//!
//! - `_id`
//! - `pkg` — source package
//! - `title` — notification title
//! - `text` — body
//! - `posted_time_ms`
//!
//! Notifications often contain message previews from end-to-end
//! encrypted apps, 2FA codes, and authentication prompts — they are
//! one of the highest-yield artifacts on a modern Android device.

use crate::android::helpers::{
    build_record, column_exists, open_sqlite_ro, table_exists, unix_ms_to_i64,
};
use rusqlite::Connection;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["notification_log.db", "notifications.db"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "notifications") {
        return Vec::new();
    }
    read(&conn, path)
}

fn read(conn: &Connection, path: &Path) -> Vec<ArtifactRecord> {
    let has_pkg = column_exists(conn, "notifications", "pkg");
    let has_title = column_exists(conn, "notifications", "title");
    let has_text = column_exists(conn, "notifications", "text");
    let has_ts = column_exists(conn, "notifications", "posted_time_ms");
    if !(has_pkg || has_title || has_text) {
        return Vec::new();
    }
    let sql = format!(
        "SELECT {}, {}, {}, {} FROM notifications ORDER BY {} DESC LIMIT 10000",
        if has_pkg { "pkg" } else { "''" },
        if has_title { "title" } else { "''" },
        if has_text { "text" } else { "''" },
        if has_ts { "posted_time_ms" } else { "0" },
        if has_ts { "posted_time_ms" } else { "_id" }
    );
    let mut stmt = match conn.prepare(&sql) {
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
    for (pkg, title, text, ts_ms) in rows.flatten() {
        let pkg = pkg.unwrap_or_default();
        let title = title.unwrap_or_default();
        let text = text.unwrap_or_default();
        if pkg.is_empty() && title.is_empty() && text.is_empty() {
            continue;
        }
        let ts = ts_ms.and_then(unix_ms_to_i64);
        out.push(build_record(
            ArtifactCategory::Communications,
            "Android Notification",
            format!("Notification: {} — {}", pkg, title),
            format!(
                "Notification pkg='{}' title='{}' text='{}'",
                pkg, title, text
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

    fn make_db() -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE notifications (
                _id INTEGER PRIMARY KEY,
                pkg TEXT,
                title TEXT,
                text TEXT,
                posted_time_ms INTEGER
            );
            INSERT INTO notifications VALUES (1,'com.whatsapp','Mom','Are you home?',1609459200000);
            INSERT INTO notifications VALUES (2,'com.google.android.gm','Bank','Your code is 928374',1609459300000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_notifications() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn pkg_appears_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|x| x.title.contains("com.whatsapp")));
        assert!(r.iter().any(|x| x.title.contains("com.google.android.gm")));
    }

    #[test]
    fn body_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|x| x.detail.contains("Are you home?")));
        assert!(r.iter().any(|x| x.detail.contains("928374")));
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
