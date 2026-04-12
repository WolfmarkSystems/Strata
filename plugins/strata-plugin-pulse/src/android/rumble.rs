//! Rumble — video watch history and channel subscriptions.
//!
//! Source path: `/data/data/com.rumble.battles/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Rumble uses Room databases with
//! tables like `watch_history`, `video`, `subscription`, `channel`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.rumble.battles/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["watch_history", "video_history", "watched_video"] {
        if table_exists(&conn, table) {
            out.extend(read_watch_history(&conn, path, table));
            break;
        }
    }
    for table in &["subscription", "subscriptions", "channel_subscription"] {
        if table_exists(&conn, table) {
            out.extend(read_subscriptions(&conn, path, table));
            break;
        }
    }
    out
}

fn read_watch_history(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT video_id, title, creator, watched_at, duration \
         FROM \"{table}\" ORDER BY watched_at DESC LIMIT 5000",
        table = table.replace('"', "\"\"")
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
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (video_id, title, creator, watched_ms, duration_s) in rows.flatten() {
        let video_id = video_id.unwrap_or_default();
        let title = title.unwrap_or_else(|| "(untitled)".to_string());
        let creator = creator.unwrap_or_else(|| "(unknown)".to_string());
        let dur = duration_s.unwrap_or(0);
        let ts = watched_ms.and_then(unix_ms_to_i64);
        let title_str = format!("Rumble watched: {} by {}", title, creator);
        let detail = format!(
            "Rumble watch history video_id='{}' title='{}' creator='{}' duration={}s",
            video_id, title, creator, dur
        );
        out.push(build_record(
            ArtifactCategory::Media,
            "Rumble Watch",
            title_str,
            detail,
            path,
            ts,
            ForensicValue::Medium,
            false,
        ));
    }
    out
}

fn read_subscriptions(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT channel_id, channel_name, subscribed_at \
         FROM \"{table}\" ORDER BY subscribed_at DESC LIMIT 5000",
        table = table.replace('"', "\"\"")
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
    for (channel_id, channel_name, sub_ms) in rows.flatten() {
        let channel_id = channel_id.unwrap_or_default();
        let channel_name = channel_name.unwrap_or_else(|| "(unknown)".to_string());
        let ts = sub_ms.and_then(unix_ms_to_i64);
        let title = format!("Rumble subscription: {}", channel_name);
        let detail = format!(
            "Rumble subscription channel_id='{}' channel_name='{}'",
            channel_id, channel_name
        );
        out.push(build_record(
            ArtifactCategory::Media,
            "Rumble Subscription",
            title,
            detail,
            path,
            ts,
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
            CREATE TABLE watch_history (
                video_id TEXT,
                title TEXT,
                creator TEXT,
                watched_at INTEGER,
                duration INTEGER
            );
            INSERT INTO watch_history VALUES('v1','Truth Report','NewsChannel',1609459200000,1200);
            INSERT INTO watch_history VALUES('v2','Political Debate','TalkShow',1609459300000,3600);
            CREATE TABLE subscription (
                channel_id TEXT,
                channel_name TEXT,
                subscribed_at INTEGER
            );
            INSERT INTO subscription VALUES('ch1','FreedomMedia',1609459100000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_watch_history_and_subscriptions() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Rumble Watch"));
        assert!(r.iter().any(|a| a.subcategory == "Rumble Subscription"));
    }

    #[test]
    fn watch_duration_captured() {
        let db = make_db();
        let r = parse(db.path());
        let w = r.iter().find(|a| a.subcategory == "Rumble Watch" && a.detail.contains("v1")).unwrap();
        assert!(w.detail.contains("duration=1200s"));
        assert!(w.detail.contains("creator='NewsChannel'"));
    }

    #[test]
    fn subscription_channel_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("channel_name='FreedomMedia'")));
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
