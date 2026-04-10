//! Chrome Downloads — `downloads` and `downloads_url_chains` tables
//! from Chrome's `History` SQLite database.
//!
//! ALEAPP reference: `scripts/artifacts/chromeDownloads.py`. The
//! `downloads` table on every Chromium-derived browser carries:
//!
//! - `id`
//! - `target_path` — final on-disk filename
//! - `received_bytes` / `total_bytes`
//! - `start_time` / `end_time` — Chrome microseconds since 1601
//! - `state` / `danger_type`
//! - `referrer` / `tab_url`
//!
//! State codes: 0=in_progress, 1=complete, 2=cancelled, 3=interrupted.
//! Danger codes 2..7 mean Chrome flagged the file as malicious.

use crate::android::helpers::{build_record, chrome_to_unix, column_exists, open_sqlite_ro, table_exists};
use rusqlite::Connection;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["/history", "\\history", "downloads.db"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "downloads") {
        return Vec::new();
    }
    read_downloads(&conn, path)
}

fn state_name(state: i64) -> &'static str {
    match state {
        0 => "in_progress",
        1 => "complete",
        2 => "cancelled",
        3 => "interrupted",
        _ => "unknown",
    }
}

fn read_downloads(conn: &Connection, path: &Path) -> Vec<ArtifactRecord> {
    let has_target = column_exists(conn, "downloads", "target_path");
    let has_received = column_exists(conn, "downloads", "received_bytes");
    let has_total = column_exists(conn, "downloads", "total_bytes");
    let has_state = column_exists(conn, "downloads", "state");
    let has_start = column_exists(conn, "downloads", "start_time");
    let has_danger = column_exists(conn, "downloads", "danger_type");
    let has_referrer = column_exists(conn, "downloads", "referrer");

    if !has_target {
        return Vec::new();
    }

    let sql = format!(
        "SELECT target_path, {}, {}, {}, {}, {}, {} FROM downloads ORDER BY {} DESC LIMIT 5000",
        if has_received { "received_bytes" } else { "0" },
        if has_total { "total_bytes" } else { "0" },
        if has_state { "state" } else { "0" },
        if has_start { "start_time" } else { "0" },
        if has_danger { "danger_type" } else { "0" },
        if has_referrer { "referrer" } else { "''" },
        if has_start { "start_time" } else { "id" }
    );

    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<String>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (target, received, total, state, start_us, danger, referrer) in rows.flatten() {
        let target = target.unwrap_or_default();
        if target.is_empty() {
            continue;
        }
        let state = state.unwrap_or(0);
        let danger = danger.unwrap_or(0);
        let suspicious = (2..=7).contains(&danger);
        let ts = start_us.and_then(chrome_to_unix);
        let detail = format!(
            "Chrome download target='{}' received={} total={} state={} danger={} referrer='{}'",
            target,
            received.unwrap_or(0),
            total.unwrap_or(0),
            state_name(state),
            danger,
            referrer.unwrap_or_default()
        );
        let value = if suspicious {
            ForensicValue::High
        } else {
            ForensicValue::Medium
        };
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "Android Chrome Download",
            format!("Download: {}", target),
            detail,
            path,
            ts,
            value,
            suspicious,
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
            CREATE TABLE downloads (
                id INTEGER PRIMARY KEY,
                target_path TEXT,
                received_bytes INTEGER,
                total_bytes INTEGER,
                state INTEGER,
                start_time INTEGER,
                danger_type INTEGER,
                referrer TEXT
            );
            "#,
        )
        .unwrap();
        let t = webkit_us(1_609_459_200);
        c.execute(
            "INSERT INTO downloads VALUES (1,'/sdcard/Download/safe.zip',1024,1024,1,?1,0,'https://example.com')",
            [t],
        )
        .unwrap();
        c.execute(
            "INSERT INTO downloads VALUES (2,'/sdcard/Download/malware.apk',2048,2048,1,?1,3,'https://shady.example')",
            [t],
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_two_downloads() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn dangerous_download_is_flagged() {
        let db = make_db();
        let r = parse(db.path());
        let bad = r.iter().find(|x| x.title.contains("malware.apk")).unwrap();
        assert!(bad.is_suspicious);
        assert_eq!(bad.forensic_value, ForensicValue::High);
    }

    #[test]
    fn safe_download_is_medium() {
        let db = make_db();
        let r = parse(db.path());
        let good = r.iter().find(|x| x.title.contains("safe.zip")).unwrap();
        assert!(!good.is_suspicious);
        assert_eq!(good.forensic_value, ForensicValue::Medium);
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
