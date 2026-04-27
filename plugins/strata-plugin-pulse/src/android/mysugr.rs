//! mySugr — diabetes management app with log entries.
//!
//! Source path: `/data/data/com.mysugr.android.companion/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. mySugr caches log entries with
//! blood sugar, carbs, insulin, activity, and tags.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.mysugr.android.companion/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    for table in &["log_entry", "logbook_entry", "entry"] {
        if table_exists(&conn, table) {
            return read_entries(&conn, path, table);
        }
    }
    Vec::new()
}

fn read_entries(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, timestamp, blood_sugar_mgdl, carbs_g, \
         insulin_bolus, insulin_basal, activity_duration, note, tags \
         FROM \"{table}\" ORDER BY timestamp DESC LIMIT 10000",
        table = table.replace('"', "\"\"")
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
            row.get::<_, Option<f64>>(3).unwrap_or(None),
            row.get::<_, Option<f64>>(4).unwrap_or(None),
            row.get::<_, Option<f64>>(5).unwrap_or(None),
            row.get::<_, Option<i64>>(6).unwrap_or(None),
            row.get::<_, Option<String>>(7).unwrap_or(None),
            row.get::<_, Option<String>>(8).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, ts_ms, blood_sugar, carbs, bolus, basal, activity_duration, note, tags) in
        rows.flatten()
    {
        let id = id.unwrap_or_default();
        let blood_sugar = blood_sugar.unwrap_or(0);
        let carbs = carbs.unwrap_or(0.0);
        let bolus = bolus.unwrap_or(0.0);
        let basal = basal.unwrap_or(0.0);
        let activity_duration = activity_duration.unwrap_or(0);
        let note = note.unwrap_or_default();
        let tags = tags.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("mySugr log: bs={} mg/dL", blood_sugar);
        let mut detail = format!(
            "mySugr log entry id='{}' blood_sugar_mgdl={} carbs_g={:.1} insulin_bolus={:.2} insulin_basal={:.2} activity_duration={}",
            id, blood_sugar, carbs, bolus, basal, activity_duration
        );
        if !note.is_empty() {
            detail.push_str(&format!(" note='{}'", note));
        }
        if !tags.is_empty() {
            detail.push_str(&format!(" tags='{}'", tags));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "mySugr Log",
            title,
            detail,
            path,
            ts,
            ForensicValue::Critical,
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
            CREATE TABLE log_entry (
                id TEXT,
                timestamp INTEGER,
                blood_sugar_mgdl INTEGER,
                carbs_g REAL,
                insulin_bolus REAL,
                insulin_basal REAL,
                activity_duration INTEGER,
                note TEXT,
                tags TEXT
            );
            INSERT INTO log_entry VALUES('e1',1609459200000,110,45.0,6.0,0.0,0,'Before lunch','meal');
            INSERT INTO log_entry VALUES('e2',1609459500000,220,0.0,0.0,0.0,30,'Post run','exercise');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_entries() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|a| a.subcategory == "mySugr Log"));
    }

    #[test]
    fn note_and_tags_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("note='Before lunch'") && a.detail.contains("tags='meal'")));
    }

    #[test]
    fn insulin_bolus_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("insulin_bolus=6.00")));
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
