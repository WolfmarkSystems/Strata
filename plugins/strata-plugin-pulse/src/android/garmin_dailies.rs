//! Garmin Connect — daily summary extraction (steps, calories, HR, stress).
//!
//! ALEAPP reference: `scripts/artifacts/GarminDailies.py`. Source path:
//! `/data/data/com.garmin.android.apps.connectmobile/databases/cache-database`.
//!
//! Key table: `user_daily_summary`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.garmin.android.apps.connectmobile/databases/cache-database"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    if !table_exists(&conn, "user_daily_summary") {
        return Vec::new();
    }
    read_dailies(&conn, path)
}

fn read_dailies(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT calendarDate, totalSteps, totalKilocalories, \
               activeKilocalories, totalDistanceMeters, \
               restingHeartRate, minHeartRate, maxHeartRate, \
               averageStressLevel, averageSpo2 \
               FROM user_daily_summary \
               ORDER BY calendarDate DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<f64>>(2).unwrap_or(None),
            row.get::<_, Option<f64>>(3).unwrap_or(None),
            row.get::<_, Option<f64>>(4).unwrap_or(None),
            row.get::<_, Option<f64>>(5).unwrap_or(None),
            row.get::<_, Option<f64>>(6).unwrap_or(None),
            row.get::<_, Option<f64>>(7).unwrap_or(None),
            row.get::<_, Option<f64>>(8).unwrap_or(None),
            row.get::<_, Option<f64>>(9).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (date, steps, total_cal, active_cal, distance, rest_hr, min_hr, max_hr, stress, spo2) in
        rows.flatten()
    {
        let date = date.unwrap_or_else(|| "(unknown)".to_string());
        let steps = steps.unwrap_or(0);
        let title = format!("Garmin daily {}: {} steps", date, steps);
        let mut detail = format!("Garmin daily summary date='{}' steps={}", date, steps);
        if let Some(c) = total_cal {
            detail.push_str(&format!(" total_cal={:.0}", c));
        }
        if let Some(c) = active_cal {
            detail.push_str(&format!(" active_cal={:.0}", c));
        }
        if let Some(d) = distance {
            detail.push_str(&format!(" distance={:.0}m", d));
        }
        if let Some(hr) = rest_hr {
            detail.push_str(&format!(" rest_hr={:.0}", hr));
        }
        if let (Some(mn), Some(mx)) = (min_hr, max_hr) {
            detail.push_str(&format!(" hr_range={:.0}-{:.0}", mn, mx));
        }
        if let Some(s) = stress {
            detail.push_str(&format!(" stress={:.0}", s));
        }
        if let Some(o) = spo2 {
            detail.push_str(&format!(" spo2={:.0}", o));
        }
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Garmin Daily Summary",
            title,
            detail,
            path,
            None,
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
            CREATE TABLE user_daily_summary (
                calendarDate TEXT,
                totalKilocalories REAL,
                activeKilocalories REAL,
                totalSteps INTEGER,
                totalDistanceMeters REAL,
                restingHeartRate REAL,
                minHeartRate REAL,
                maxHeartRate REAL,
                averageStressLevel REAL,
                averageSpo2 REAL
            );
            INSERT INTO user_daily_summary VALUES('2021-01-01',2500.0,800.0,12000,8500.0,58.0,48.0,145.0,25.0,97.0);
            INSERT INTO user_daily_summary VALUES('2021-01-02',2200.0,500.0,7000,5000.0,60.0,50.0,120.0,35.0,96.0);
            INSERT INTO user_daily_summary VALUES('2021-01-03',2800.0,1000.0,15000,10500.0,56.0,45.0,155.0,20.0,98.0);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_three_days() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|a| a.subcategory == "Garmin Daily Summary"));
    }

    #[test]
    fn steps_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.title.contains("2021-01-01") && a.title.contains("12000 steps")));
    }

    #[test]
    fn hr_range_and_spo2_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let day = r.iter().find(|a| a.detail.contains("2021-01-01")).unwrap();
        assert!(day.detail.contains("hr_range=48-145"));
        assert!(day.detail.contains("spo2=97"));
        assert!(day.detail.contains("rest_hr=58"));
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
