//! Nike Run Club — activity moments (timestamped metrics).
//!
//! ALEAPP reference: `scripts/artifacts/NikeAMoments.py`. Source path:
//! `/data/data/com.nike.plusgps/databases/com.nike.nrc.room*`.
//!
//! Key table: `activity_moment` joined with `activity`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.nike.plusgps/databases/com.nike.nrc.room"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "activity_moment") {
        return Vec::new();
    }
    read_moments(&conn, path)
}

fn read_moments(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT as2_m_activity_id, as2_m_type, as2_m_value, \
               as2_m_timestamp_utc_ms \
               FROM activity_moment \
               ORDER BY as2_m_timestamp_utc_ms DESC LIMIT 20000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (activity_id, kind, value, ts_ms) in rows.flatten() {
        let id = activity_id.unwrap_or(0);
        let kind = kind.unwrap_or_else(|| "unknown".to_string());
        let value = value.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Nike moment {}: {}={}", id, kind, value);
        let detail = format!(
            "Nike activity moment activity_id={} type='{}' value='{}'",
            id, kind, value
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Nike Moment",
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
            CREATE TABLE activity_moment (
                as2_m_activity_id INTEGER,
                as2_m_type TEXT,
                as2_m_value TEXT,
                as2_m_timestamp_utc_ms INTEGER
            );
            INSERT INTO activity_moment VALUES(1,'pause','true',1609459500000);
            INSERT INTO activity_moment VALUES(1,'resume','true',1609459560000);
            INSERT INTO activity_moment VALUES(1,'halt','end',1609460000000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_three_moments() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|a| a.subcategory == "Nike Moment"));
    }

    #[test]
    fn moment_type_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("type='pause'")));
        assert!(r.iter().any(|a| a.detail.contains("type='resume'")));
    }

    #[test]
    fn activity_id_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().all(|a| a.title.contains("moment 1:")));
    }

    #[test]
    fn missing_table_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE unrelated (id INTEGER);")
            .unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}
