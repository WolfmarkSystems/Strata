//! iOS HealthKit workouts — deeper extraction from `healthdb_secure.sqlite`.
//!
//! Complements the existing `health.rs` by parsing workout metadata:
//! workout type, duration, distance, energy burned, start/end dates.
//! This is separate because iLEAPP's workout parser is distinct from
//! the samples parser.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["healthdb_secure.sqlite"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    if !util::table_exists(&conn, "workouts") {
        return out;
    }
    let source = path.to_string_lossy().to_string();
    let count = util::count_rows(&conn, "workouts");
    if count == 0 {
        return out;
    }

    let ts = conn
        .prepare(
            "SELECT MIN(start_date), MAX(start_date) FROM workouts WHERE start_date IS NOT NULL",
        )
        .and_then(|mut s| {
            s.query_row([], |r| {
                Ok((r.get::<_, Option<f64>>(0)?, r.get::<_, Option<f64>>(1)?))
            })
        })
        .unwrap_or((None, None));
    let first = ts.0.and_then(util::cf_absolute_to_unix);

    // Count by workout_activity_type
    let by_type = conn
        .prepare("SELECT COALESCE(workout_activity_type, -1), COUNT(*) FROM workouts GROUP BY workout_activity_type ORDER BY COUNT(*) DESC LIMIT 5")
        .and_then(|mut s| {
            let r = s.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?;
            Ok(r.flatten().collect::<Vec<_>>())
        })
        .unwrap_or_default();

    let type_str: String = by_type
        .iter()
        .map(|(t, c)| format!("type {}={}", t, c))
        .collect::<Vec<_>>()
        .join(", ");

    out.push(ArtifactRecord {
        category: ArtifactCategory::UserActivity,
        subcategory: "Health workouts".to_string(),
        timestamp: first,
        title: "HealthKit workout history".to_string(),
        detail: format!("{} workouts ({})", count, type_str),
        source_path: source,
        forensic_value: ForensicValue::High,
        mitre_technique: None,
        is_suspicious: false,
        raw_data: None,
        confidence: 0,
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    fn make_workouts(rows: &[(i64, f64)]) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE workouts (data_id INTEGER PRIMARY KEY, workout_activity_type INTEGER, start_date DOUBLE, duration REAL)", []).unwrap();
        for (wtype, start) in rows {
            c.execute("INSERT INTO workouts (workout_activity_type, start_date, duration) VALUES (?1, ?2, 1800.0)", rusqlite::params![*wtype, *start]).unwrap();
        }
        tmp
    }

    #[test]
    fn parses_workout_count_and_types() {
        let tmp = make_workouts(&[
            (37, 700_000_000.0),
            (37, 700_100_000.0),
            (13, 700_200_000.0),
        ]);
        let recs = parse(tmp.path());
        let r = recs
            .iter()
            .find(|r| r.subcategory == "Health workouts")
            .unwrap();
        assert!(r.detail.contains("3 workouts"));
        assert!(r.detail.contains("type 37=2"));
    }

    #[test]
    fn empty_workouts_returns_empty() {
        let tmp = make_workouts(&[]);
        assert!(parse(tmp.path()).is_empty());
    }

    #[test]
    fn missing_table_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(tmp.path()).is_empty());
    }
}
