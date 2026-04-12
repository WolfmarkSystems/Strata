//! Pluto TV — streaming watch history.
//!
//! Source path: `/data/data/tv.pluto.android/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Pluto TV uses Room databases with
//! tables like `watch_history`, `channel`, `episode`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["tv.pluto.android/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["watch_history", "viewing_history", "watched_content"] {
        if table_exists(&conn, table) {
            out.extend(read_watch_history(&conn, path, table));
            break;
        }
    }
    out
}

fn read_watch_history(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT channel_name, show_title, episode_title, watched_at, duration \
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
    for (channel_name, show_title, episode_title, watched_ms, duration_s) in rows.flatten() {
        let channel = channel_name.unwrap_or_else(|| "(unknown)".to_string());
        let show = show_title.unwrap_or_else(|| "(untitled)".to_string());
        let episode = episode_title.unwrap_or_default();
        let dur = duration_s.unwrap_or(0);
        let ts = watched_ms.and_then(unix_ms_to_i64);
        let title = format!("Pluto TV: {} — {}", channel, show);
        let mut detail = format!(
            "Pluto TV watch history channel='{}' show='{}' duration={}s",
            channel, show, dur
        );
        if !episode.is_empty() {
            detail.push_str(&format!(" episode='{}'", episode));
        }
        out.push(build_record(
            ArtifactCategory::Media,
            "Pluto TV Watch",
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
            CREATE TABLE watch_history (
                channel_name TEXT,
                show_title TEXT,
                episode_title TEXT,
                watched_at INTEGER,
                duration INTEGER
            );
            INSERT INTO watch_history VALUES('Action Movies','Die Hard','',1609459200000,7200);
            INSERT INTO watch_history VALUES('Comedy Central','Parks & Rec','S01E01 Pilot',1609459300000,1800);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_watch_history() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.iter().filter(|a| a.subcategory == "Pluto TV Watch").count(), 2);
    }

    #[test]
    fn channel_and_show_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("channel='Action Movies'") && a.detail.contains("show='Die Hard'")));
    }

    #[test]
    fn episode_title_included_when_present() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("episode='S01E01 Pilot'")));
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
