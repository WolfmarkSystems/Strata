//! Peloton — workout history and class activity.
//!
//! Source path: `/data/data/com.onepeloton.callisto/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Peloton caches workout history,
//! class info, and instructor data.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.onepeloton.callisto/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["workout", "workout_history"] {
        if table_exists(&conn, table) {
            out.extend(read_workouts(&conn, path, table));
            break;
        }
    }
    out
}

fn read_workouts(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, class_id, class_title, instructor_name, discipline, \
         started_at, ended_at, duration_seconds, total_output, \
         distance_mi, calories, avg_hr \
         FROM \"{table}\" ORDER BY started_at DESC LIMIT 5000",
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
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<i64>>(6).unwrap_or(None),
            row.get::<_, Option<i64>>(7).unwrap_or(None),
            row.get::<_, Option<f64>>(8).unwrap_or(None),
            row.get::<_, Option<f64>>(9).unwrap_or(None),
            row.get::<_, Option<f64>>(10).unwrap_or(None),
            row.get::<_, Option<f64>>(11).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (
        id,
        class_id,
        class_title,
        instructor,
        discipline,
        started_ms,
        _ended_ms,
        duration,
        output,
        distance,
        calories,
        avg_hr,
    ) in rows.flatten()
    {
        let id = id.unwrap_or_default();
        let class_id = class_id.unwrap_or_default();
        let class_title = class_title.unwrap_or_else(|| "(unnamed)".to_string());
        let instructor = instructor.unwrap_or_default();
        let discipline = discipline.unwrap_or_default();
        let duration = duration.unwrap_or(0);
        let output = output.unwrap_or(0.0);
        let distance = distance.unwrap_or(0.0);
        let calories = calories.unwrap_or(0.0);
        let avg_hr = avg_hr.unwrap_or(0.0);
        let ts = started_ms.and_then(unix_ms_to_i64);
        let title = format!("Peloton {}: {}", discipline, class_title);
        let detail = format!(
            "Peloton workout id='{}' class_id='{}' class_title='{}' instructor='{}' discipline='{}' duration_seconds={} total_output={:.0} distance_mi={:.2} calories={:.0} avg_hr={:.0}",
            id, class_id, class_title, instructor, discipline, duration, output, distance, calories, avg_hr
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Peloton Workout",
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
            CREATE TABLE workout (
                id TEXT,
                class_id TEXT,
                class_title TEXT,
                instructor_name TEXT,
                discipline TEXT,
                started_at INTEGER,
                ended_at INTEGER,
                duration_seconds INTEGER,
                total_output REAL,
                distance_mi REAL,
                calories REAL,
                avg_hr REAL
            );
            INSERT INTO workout VALUES('w1','c1','30 min HIIT Ride','Cody Rigsby','cycling',1609459200000,1609461000000,1800,350.0,15.0,420.0,155.0);
            INSERT INTO workout VALUES('w2','c2','20 min Strength','Adrian Williams','strength',1609545600000,1609546800000,1200,0.0,0.0,180.0,125.0);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_two_workouts() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|a| a.subcategory == "Peloton Workout"));
    }

    #[test]
    fn instructor_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("instructor='Cody Rigsby'")));
        assert!(r
            .iter()
            .any(|a| a.detail.contains("instructor='Adrian Williams'")));
    }

    #[test]
    fn output_and_distance_captured() {
        let db = make_db();
        let r = parse(db.path());
        let cycling = r.iter().find(|a| a.detail.contains("HIIT Ride")).unwrap();
        assert!(cycling.detail.contains("total_output=350"));
        assert!(cycling.detail.contains("distance_mi=15.00"));
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
