//! Usage Stats — Android app usage statistics.
//!
//! ALEAPP reference: `scripts/artifacts/usagestats.py`. Source paths:
//! - `/data/system/usagestats/0/` (Android ≤10)
//! - `/data/system_ce/0/usagestats/` (Android 11+)
//!
//! This parser handles the SQLite database variant that ALEAPP creates
//! during processing. The database contains `usage_stats` table with
//! package, last_time, total_time, and app_launch_count.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "usagestats/usage",
    "usagestats/0/",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if table_exists(&conn, "usage_stats") {
        read_usage_stats(&conn, path)
    } else if table_exists(&conn, "events") {
        read_events(&conn, path)
    } else {
        Vec::new()
    }
}

fn read_usage_stats(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT package, last_time_active, total_time_active, \
               app_launch_count \
               FROM usage_stats \
               ORDER BY last_time_active DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (package, last_active, total_active, launch_count) in rows.flatten() {
        let package = package.unwrap_or_else(|| "(unknown)".to_string());
        let ts = last_active.and_then(unix_ms_to_i64);
        let total_s = total_active.unwrap_or(0) / 1000;
        let launches = launch_count.unwrap_or(0);
        let title = format!("Usage: {} ({}s active, {} launches)", package, total_s, launches);
        let detail = format!(
            "Usage stats package='{}' total_active={}s launch_count={}",
            package, total_s, launches
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Usage Stats",
            title,
            detail,
            path,
            ts,
            ForensicValue::Medium,
            false,
        ));
    }
    out
}

fn read_events(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT package, lastime, timeactive, types \
               FROM events \
               ORDER BY lastime DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (package, last_time, time_active, event_type) in rows.flatten() {
        let package = package.unwrap_or_else(|| "(unknown)".to_string());
        let ts = last_time.and_then(unix_ms_to_i64);
        let active_s = time_active.unwrap_or(0) / 1000;
        let etype = event_type.unwrap_or_default();
        let title = format!("Usage: {} — {} ({}s)", package, etype, active_s);
        let detail = format!(
            "Usage stats package='{}' event='{}' active={}s",
            package, etype, active_s
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Usage Stats",
            title,
            detail,
            path,
            ts,
            ForensicValue::Medium,
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
            CREATE TABLE usage_stats (
                package TEXT,
                last_time_active INTEGER,
                total_time_active INTEGER,
                app_launch_count INTEGER
            );
            INSERT INTO usage_stats VALUES('com.whatsapp',1609459200000,3600000,50);
            INSERT INTO usage_stats VALUES('com.android.chrome',1609459300000,7200000,100);
            INSERT INTO usage_stats VALUES('com.instagram.android',1609459400000,1800000,25);
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
        assert!(r.iter().all(|a| a.subcategory == "Usage Stats"));
    }

    #[test]
    fn time_and_launches_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let wa = r.iter().find(|a| a.detail.contains("com.whatsapp")).unwrap();
        assert!(wa.detail.contains("total_active=3600s"));
        assert!(wa.detail.contains("launch_count=50"));
    }

    #[test]
    fn package_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("com.android.chrome")));
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
