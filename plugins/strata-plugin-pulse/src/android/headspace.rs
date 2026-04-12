//! Headspace — meditation app session history.
//!
//! Source path: `/data/data/com.getsomeheadspace.android/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Headspace caches completed
//! meditations, courses, and mindful moment reminders.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.getsomeheadspace.android/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["session_completion", "completed_session", "session_history"] {
        if table_exists(&conn, table) {
            out.extend(read_sessions(&conn, path, table));
            break;
        }
    }
    if table_exists(&conn, "pack_progress") {
        out.extend(read_packs(&conn, path));
    }
    out
}

fn read_sessions(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, session_name, pack_name, completed_at, duration_seconds \
         FROM \"{table}\" ORDER BY completed_at DESC LIMIT 5000",
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
    for (id, session_name, pack_name, ts_ms, duration) in rows.flatten() {
        let id = id.unwrap_or_default();
        let session_name = session_name.unwrap_or_else(|| "(unknown)".to_string());
        let pack_name = pack_name.unwrap_or_default();
        let duration = duration.unwrap_or(0);
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Headspace: {} ({}s)", session_name, duration);
        let detail = format!(
            "Headspace session id='{}' session_name='{}' pack_name='{}' duration_seconds={}",
            id, session_name, pack_name, duration
        );
        out.push(build_record(
            ArtifactCategory::Media,
            "Headspace Session",
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

fn read_packs(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT pack_id, pack_name, sessions_completed, total_sessions, \
               last_session_at \
               FROM pack_progress LIMIT 1000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, name, completed, total, ts_ms) in rows.flatten() {
        let id = id.unwrap_or_default();
        let name = name.unwrap_or_else(|| "(unknown)".to_string());
        let completed = completed.unwrap_or(0);
        let total = total.unwrap_or(0);
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Headspace pack: {} ({}/{})", name, completed, total);
        let detail = format!(
            "Headspace pack progress id='{}' name='{}' sessions_completed={} total_sessions={}",
            id, name, completed, total
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Headspace Pack",
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
            CREATE TABLE session_completion (
                id TEXT,
                session_name TEXT,
                pack_name TEXT,
                completed_at INTEGER,
                duration_seconds INTEGER
            );
            INSERT INTO session_completion VALUES('s1','Basics Day 1','Basics',1609459200000,600);
            INSERT INTO session_completion VALUES('s2','Anxiety Day 3','Managing Anxiety',1609459300000,900);
            CREATE TABLE pack_progress (
                pack_id TEXT,
                pack_name TEXT,
                sessions_completed INTEGER,
                total_sessions INTEGER,
                last_session_at INTEGER
            );
            INSERT INTO pack_progress VALUES('p1','Basics',3,10,1609459200000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_sessions_and_packs() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Headspace Session"));
        assert!(r.iter().any(|a| a.subcategory == "Headspace Pack"));
    }

    #[test]
    fn pack_progress_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("Basics") && a.title.contains("(3/10)")));
    }

    #[test]
    fn session_pack_name_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("pack_name='Managing Anxiety'")));
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
