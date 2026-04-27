//! Zepp Life (Xiaomi Mi Fit) — heart rate tracking.
//!
//! ALEAPP reference: `scripts/artifacts/zepplife.py`. Source path:
//! `/data/data/com.xiaomi.hm.health/databases/origin_db*`.
//!
//! Key table: `HEART_RATE`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.xiaomi.hm.health/databases/origin_db"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "HEART_RATE") {
        return Vec::new();
    }
    read_heart_rate(&conn, path)
}

fn read_heart_rate(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT TIME, HR FROM HEART_RATE \
               ORDER BY TIME DESC LIMIT 20000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (time_s, hr) in rows.flatten() {
        let hr = hr.unwrap_or(0);
        let ts = time_s;
        let title = format!("Zepp Life HR: {} bpm", hr);
        let detail = format!("Zepp Life heart rate reading bpm={}", hr);
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Zepp Life Heart Rate",
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
            CREATE TABLE HEART_RATE (
                TIME INTEGER,
                HR INTEGER
            );
            INSERT INTO HEART_RATE VALUES(1609459200,65);
            INSERT INTO HEART_RATE VALUES(1609459260,68);
            INSERT INTO HEART_RATE VALUES(1609459320,72);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_three_readings() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|a| a.subcategory == "Zepp Life Heart Rate"));
    }

    #[test]
    fn bpm_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("65 bpm")));
        assert!(r.iter().any(|a| a.title.contains("72 bpm")));
    }

    #[test]
    fn timestamps_preserved() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.timestamp == Some(1609459200)));
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
