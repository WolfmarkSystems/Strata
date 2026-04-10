//! Recent Activity — Android task switcher / recents extraction.
//!
//! ALEAPP reference: `scripts/artifacts/recentactivity.py`. Source path:
//! `/data/system_ce/*/recent_tasks/*.xml` or the derived SQLite databases.
//!
//! Key table: `recent` — task ID, package, timestamps, snapshot paths.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["recent_tasks/", "recentact"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if table_exists(&conn, "recent") {
        read_recent(&conn, path)
    } else if table_exists(&conn, "task_history") {
        read_task_history(&conn, path)
    } else {
        Vec::new()
    }
}

fn read_recent(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT Task_ID, Real_Activity, First_Active_Time, \
               Last_Active_Time, Calling_Package \
               FROM recent \
               ORDER BY Last_Active_Time DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (task_id, activity, first_active, last_active, calling) in rows.flatten() {
        let activity = activity.unwrap_or_else(|| "(unknown)".to_string());
        let task = task_id.unwrap_or(0);
        let ts = last_active.and_then(unix_ms_to_i64);
        let calling = calling.unwrap_or_default();
        let title = format!("Recent task #{}: {}", task, activity);
        let mut detail = format!(
            "Recent activity task={} activity='{}'",
            task, activity
        );
        if let Some(first) = first_active.and_then(unix_ms_to_i64) {
            detail.push_str(&format!(" first_active={}", first));
        }
        if !calling.is_empty() {
            detail.push_str(&format!(" calling_package='{}'", calling));
        }
        out.push(build_record(
            ArtifactCategory::ExecutionHistory,
            "Recent Activity",
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

fn read_task_history(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT task_id, package_name, last_active_time \
               FROM task_history \
               ORDER BY last_active_time DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (task_id, package, last_active) in rows.flatten() {
        let package = package.unwrap_or_else(|| "(unknown)".to_string());
        let task = task_id.unwrap_or(0);
        let ts = last_active.and_then(unix_ms_to_i64);
        let title = format!("Recent task #{}: {}", task, package);
        let detail = format!("Recent activity task={} package='{}'", task, package);
        out.push(build_record(
            ArtifactCategory::ExecutionHistory,
            "Recent Activity",
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
            CREATE TABLE recent (
                Task_ID INTEGER,
                Real_Activity TEXT,
                First_Active_Time INTEGER,
                Last_Active_Time INTEGER,
                Calling_Package TEXT
            );
            INSERT INTO recent VALUES(1,'com.whatsapp/.Main',1609459200000,1609459300000,'com.android.launcher3');
            INSERT INTO recent VALUES(2,'com.android.chrome/.Main',1609459400000,1609459500000,NULL);
            INSERT INTO recent VALUES(3,'com.snapchat.android/.Main',1609459600000,1609459700000,'com.android.launcher3');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_three_tasks() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|a| a.subcategory == "Recent Activity"));
    }

    #[test]
    fn activity_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("com.whatsapp")));
    }

    #[test]
    fn calling_package_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("calling_package='com.android.launcher3'")));
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
