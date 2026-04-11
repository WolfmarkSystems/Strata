//! iOS HealthKit per-type sample breakdown — `healthdb_secure.sqlite`.
//!
//! Extends the existing `health.rs` (total row count) with a per-
//! `data_type` breakdown. HealthKit `data_type` IDs map to categories:
//!   * 5  = HKQuantityTypeIdentifierStepCount
//!   * 7  = HKQuantityTypeIdentifierHeartRate
//!   * 12 = HKQuantityTypeIdentifierBloodPressureSystolic
//!   * 63 = HKCategoryTypeIdentifierSleepAnalysis
//!   * 70 = HKQuantityTypeIdentifierBodyMass
//!   * 75 = HKQuantityTypeIdentifierHeight
//!   * 79 = HKQuantityTypeIdentifierActiveEnergyBurned
//!
//! This parser emits one record per data_type with row count and date
//! range. Proves the user was wearing the device / tracking health at
//! specific times.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

const TYPE_NAMES: &[(i64, &str)] = &[
    (5, "StepCount"),
    (7, "HeartRate"),
    (8, "BodyTemperature"),
    (12, "BloodPressureSystolic"),
    (13, "BloodPressureDiastolic"),
    (63, "SleepAnalysis"),
    (70, "BodyMass"),
    (75, "Height"),
    (79, "ActiveEnergyBurned"),
    (80, "BasalEnergyBurned"),
    (9, "BloodGlucose"),
    (10, "OxygenSaturation"),
    (76, "DistanceWalkingRunning"),
    (83, "FlightsClimbed"),
];

fn type_label(id: i64) -> &'static str {
    TYPE_NAMES.iter().find(|(k, _)| *k == id).map(|(_, v)| *v).unwrap_or("Other")
}

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["healthdb_secure.sqlite"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else { return out };
    if !util::table_exists(&conn, "samples") { return out; }
    let source = path.to_string_lossy().to_string();

    let by_type = conn
        .prepare(
            "SELECT data_type, COUNT(*), MIN(start_date), MAX(start_date) \
             FROM samples WHERE data_type IS NOT NULL \
             GROUP BY data_type ORDER BY COUNT(*) DESC LIMIT 20"
        )
        .and_then(|mut s| {
            let r = s.query_map([], |row| Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<f64>>(2)?,
                row.get::<_, Option<f64>>(3)?,
            )))?;
            Ok(r.flatten().collect::<Vec<_>>())
        })
        .unwrap_or_default();

    if by_type.is_empty() { return out; }

    for (dt, count, first, last) in by_type {
        let label = type_label(dt);
        let first_unix = first.and_then(util::cf_absolute_to_unix);
        let last_unix = last.and_then(util::cf_absolute_to_unix);
        out.push(ArtifactRecord {
            category: ArtifactCategory::UserActivity,
            subcategory: format!("HealthKit {}", label),
            timestamp: first_unix,
            title: format!("HealthKit {} samples", label),
            detail: format!(
                "{} samples (type {}={}) range {:?}..{:?} Unix",
                count, dt, label, first_unix, last_unix
            ),
            source_path: source.clone(),
            forensic_value: if label == "HeartRate" || label == "StepCount" || label == "SleepAnalysis" {
                ForensicValue::High
            } else {
                ForensicValue::Medium
            },
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

    fn make_health_samples(types: &[(i64, usize)]) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE samples (data_id INTEGER PRIMARY KEY, data_type INTEGER, start_date DOUBLE, end_date DOUBLE)", []).unwrap();
        for (dt, count) in types {
            for i in 0..*count {
                c.execute(
                    "INSERT INTO samples (data_type, start_date, end_date) VALUES (?1, ?2, ?3)",
                    rusqlite::params![*dt, 700_000_000.0 + i as f64, 700_000_010.0 + i as f64],
                ).unwrap();
            }
        }
        tmp
    }

    #[test]
    fn parses_per_type_breakdown() {
        let tmp = make_health_samples(&[(5, 10), (7, 20), (63, 5)]);
        let recs = parse(tmp.path());
        assert!(recs.iter().any(|r| r.subcategory == "HealthKit StepCount" && r.detail.contains("10 samples")));
        assert!(recs.iter().any(|r| r.subcategory == "HealthKit HeartRate" && r.detail.contains("20 samples")));
        assert!(recs.iter().any(|r| r.subcategory == "HealthKit SleepAnalysis"));
    }

    #[test]
    fn heart_rate_is_high_forensic_value() {
        let tmp = make_health_samples(&[(7, 1)]);
        let recs = parse(tmp.path());
        let hr = recs.iter().find(|r| r.subcategory == "HealthKit HeartRate").unwrap();
        assert_eq!(hr.forensic_value, ForensicValue::High);
    }

    #[test]
    fn empty_samples_returns_empty() {
        let tmp = make_health_samples(&[]);
        assert!(parse(tmp.path()).is_empty());
    }

    #[test]
    fn missing_table_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(tmp.path()).is_empty());
    }

    #[test]
    fn type_label_falls_back_to_other() {
        assert_eq!(type_label(9999), "Other");
        assert_eq!(type_label(7), "HeartRate");
    }
}
