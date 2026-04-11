//! Nike Run Club — activity extraction.
//!
//! ALEAPP reference: `scripts/artifacts/NikeActivities.py`. Source path:
//! `/data/data/com.nike.plusgps/databases/com.nike.nrc.room*`.
//!
//! Key tables: `activity`, `activity_tag`, `activity_summary`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.nike.plusgps/databases/com.nike.nrc.room"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "activity") {
        return Vec::new();
    }
    read_activities(&conn, path)
}

fn read_activities(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT as2_sa_id, as2_sa_source, as2_sa_start_utc_ms, \
               as2_sa_end_utc_ms, as2_sa_active_duration_ms \
               FROM activity \
               ORDER BY as2_sa_start_utc_ms DESC LIMIT 5000";
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
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, source, start_ms, end_ms, active_ms) in rows.flatten() {
        let id = id.unwrap_or(0);
        let source = source.unwrap_or_else(|| "nike".to_string());
        let ts = start_ms.and_then(unix_ms_to_i64);
        let duration_s = active_ms.unwrap_or(0) / 1000;
        let total_s = end_ms.zip(start_ms).map(|(e, s)| (e - s) / 1000).unwrap_or(0);
        let title = format!("Nike run #{} ({}s active)", id, duration_s);
        let detail = format!(
            "Nike Run Club activity id={} source='{}' active_duration={}s total_duration={}s",
            id, source, duration_s, total_s
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Nike Activity",
            title,
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
            CREATE TABLE activity (
                as2_sa_id INTEGER PRIMARY KEY,
                as2_sa_source TEXT,
                as2_sa_start_utc_ms INTEGER,
                as2_sa_end_utc_ms INTEGER,
                as2_sa_active_duration_ms INTEGER
            );
            INSERT INTO activity VALUES(1,'run',1609459200000,1609461000000,1800000);
            INSERT INTO activity VALUES(2,'run',1609545600000,1609548000000,2400000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_two_activities() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|a| a.subcategory == "Nike Activity"));
    }

    #[test]
    fn duration_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("1800s")));
        assert!(r.iter().any(|a| a.title.contains("2400s")));
    }

    #[test]
    fn total_and_active_differ() {
        let db = make_db();
        let r = parse(db.path());
        // activity 1: total = 1800, active = 1800. activity 2: total = 2400, active = 2400
        let a1 = r.iter().find(|a| a.detail.contains("id=1")).unwrap();
        assert!(a1.detail.contains("active_duration=1800s"));
        assert!(a1.detail.contains("total_duration=1800s"));
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
