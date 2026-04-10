//! iOS HealthKit — `healthdb_secure.sqlite`.
//!
//! HealthKit's encrypted store contains every Apple Health sample (heart
//! rate, steps, blood oxygen, sleep) plus workouts. iLEAPP keys off:
//!   * `samples` — every numeric/categorical sample
//!   * `quantity_samples` / `category_samples` — type-specific tables
//!     in some iOS versions
//!   * `workouts` — workout records
//!   * `data_provenances` — source app for each sample
//!
//! Pulse v1.0 emits one summary plus per-table counts. Sample-level
//! decoding (heart rate values, GPS routes) is queued for v1.1; this
//! v1.0 record is enough for an examiner to know "Health data exists,
//! and how much".

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["healthdb_secure.sqlite", "healthdb.sqlite"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    let source = path.to_string_lossy().to_string();

    let interesting = [
        "samples",
        "quantity_samples",
        "category_samples",
        "workouts",
        "data_provenances",
        "metadata_values",
    ];

    let mut found_any = false;
    for table in interesting {
        if !util::table_exists(&conn, table) {
            continue;
        }
        found_any = true;
        let count = util::count_rows(&conn, table);
        out.push(ArtifactRecord {
            category: ArtifactCategory::UserActivity,
            subcategory: format!("Health {}", table),
            timestamp: None,
            title: format!("HealthKit {} table", table),
            detail: format!("{} rows in HealthKit `{}` table", count, table),
            source_path: source.clone(),
            forensic_value: ForensicValue::High,
            mitre_technique: None,
            is_suspicious: false,
            raw_data: None,
        });
    }

    if found_any {
        // Probe `samples.start_date` for the date range, since it
        // exists in every HealthKit version.
        let (first, last) = conn
            .prepare(
                "SELECT MIN(start_date), MAX(start_date) FROM samples \
                 WHERE start_date IS NOT NULL",
            )
            .and_then(|mut s| {
                s.query_row([], |row| {
                    Ok((row.get::<_, Option<f64>>(0)?, row.get::<_, Option<f64>>(1)?))
                })
            })
            .unwrap_or((None, None));
        let first_unix = first.and_then(util::cf_absolute_to_unix);
        let last_unix = last.and_then(util::cf_absolute_to_unix);
        out.push(ArtifactRecord {
            category: ArtifactCategory::UserActivity,
            subcategory: "Health summary".to_string(),
            timestamp: first_unix,
            title: "HealthKit secure store".to_string(),
            detail: format!(
                "HealthKit database present, sample range {:?}..{:?} Unix",
                first_unix, last_unix
            ),
            source_path: source,
            forensic_value: ForensicValue::High,
            mitre_technique: None,
            is_suspicious: false,
            raw_data: None,
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    fn make_health_db(samples: usize, workouts: usize) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute(
            "CREATE TABLE samples (\
                data_id INTEGER PRIMARY KEY, \
                start_date DOUBLE, \
                end_date DOUBLE, \
                data_type INTEGER \
             )",
            [],
        )
        .unwrap();
        c.execute(
            "CREATE TABLE workouts (data_id INTEGER PRIMARY KEY, total_distance REAL)",
            [],
        )
        .unwrap();
        c.execute(
            "CREATE TABLE data_provenances (rowid INTEGER PRIMARY KEY, source_id TEXT)",
            [],
        )
        .unwrap();
        for i in 0..samples {
            c.execute(
                "INSERT INTO samples (start_date, end_date, data_type) VALUES (?1, ?2, 5)",
                rusqlite::params![700_000_000.0_f64 + i as f64, 700_000_010.0_f64 + i as f64],
            )
            .unwrap();
        }
        for _ in 0..workouts {
            c.execute("INSERT INTO workouts (total_distance) VALUES (1234.5)", [])
                .unwrap();
        }
        tmp
    }

    #[test]
    fn matches_health_filenames() {
        assert!(matches(Path::new(
            "/var/mobile/Library/Health/healthdb_secure.sqlite"
        )));
        assert!(matches(Path::new(
            "/var/mobile/Library/Health/healthdb.sqlite"
        )));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_samples_workouts_and_summary() {
        let tmp = make_health_db(5, 2);
        let records = parse(tmp.path());

        let samples = records
            .iter()
            .find(|r| r.subcategory == "Health samples")
            .expect("samples record");
        assert!(samples.detail.contains("5 rows"));

        let workouts = records
            .iter()
            .find(|r| r.subcategory == "Health workouts")
            .expect("workouts record");
        assert!(workouts.detail.contains("2 rows"));

        let summary = records
            .iter()
            .find(|r| r.subcategory == "Health summary")
            .expect("summary record");
        assert_eq!(
            summary.timestamp,
            Some(700_000_000_i64 + util::APPLE_EPOCH_OFFSET)
        );
    }

    #[test]
    fn empty_health_db_returns_summary_with_zero_samples() {
        let tmp = make_health_db(0, 0);
        let records = parse(tmp.path());
        // We get table records (with 0 rows) AND a summary because at
        // least one of the tracked tables exists.
        assert!(records.iter().any(|r| r.subcategory == "Health samples"));
        let summary = records
            .iter()
            .find(|r| r.subcategory == "Health summary")
            .unwrap();
        assert!(summary.detail.contains("HealthKit database present"));
    }

    #[test]
    fn missing_health_tables_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        {
            let c = Connection::open(tmp.path()).unwrap();
            c.execute("CREATE TABLE other (x INT)", []).unwrap();
        }
        assert!(parse(tmp.path()).is_empty());
    }
}
