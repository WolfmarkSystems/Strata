//! iOS PowerLog — `CurrentPowerlog.PLSQL`.
//!
//! `CurrentPowerlog.PLSQL` is a SQLite database that records every
//! foreground application invocation, battery percentage, push
//! notification, and screen-on event for the last few weeks. iLEAPP
//! keys off:
//!   * `PLApplicationAgent_EventForward_ApplicationRunTime` —
//!     foreground/background runs with `BundleID` and `timestamp`
//!   * `PLBatteryAgent_EventBackward_Battery` — battery levels
//!   * `PLProcessMonitorAgent_EventBackward_Process` — process activity
//!
//! Pulse v1.0 reports row counts for each table that exists. This
//! complements the MacTrace plugin's filename-only detection.

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

pub fn matches(path: &Path) -> bool {
    let n = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_ascii_lowercase(),
        None => return false,
    };
    n == "currentpowerlog.plsql" || n.starts_with("powerlog_")
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    let source = path.to_string_lossy().to_string();

    // Apple's PL* table names are absurdly long; we list only the
    // ones iLEAPP and APOLLO actively use.
    let tracked = [
        "PLApplicationAgent_EventForward_ApplicationRunTime",
        "PLBatteryAgent_EventBackward_Battery",
        "PLProcessMonitorAgent_EventBackward_Process",
        "PLLocationAgent_EventForward_TimerEvent",
    ];

    let mut hits = 0_usize;
    for table in tracked {
        if !util::table_exists(&conn, table) {
            continue;
        }
        hits += 1;
        let count = util::count_rows(&conn, table);
        out.push(ArtifactRecord {
            category: ArtifactCategory::SystemActivity,
            subcategory: format!("PowerLog {}", table),
            timestamp: None,
            title: format!("PowerLog `{}`", table),
            detail: format!("{} rows in `{}`", count, table),
            source_path: source.clone(),
            forensic_value: ForensicValue::High,
            mitre_technique: Some("T1005".to_string()),
            is_suspicious: false,
            raw_data: None,
            confidence: 0,
        });
    }

    if hits > 0 {
        out.push(ArtifactRecord {
            category: ArtifactCategory::SystemActivity,
            subcategory: "PowerLog summary".to_string(),
            timestamp: None,
            title: "iOS PowerLog".to_string(),
            detail: format!(
                "PowerLog database present, {} tracked PL* tables found",
                hits
            ),
            source_path: source,
            forensic_value: ForensicValue::High,
            mitre_technique: Some("T1005".to_string()),
            is_suspicious: false,
            raw_data: None,
            confidence: 0,
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    fn make_powerlog(rows: usize) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute(
            "CREATE TABLE PLApplicationAgent_EventForward_ApplicationRunTime (\
                ID INTEGER PRIMARY KEY, BundleID TEXT, timestamp DOUBLE \
             )",
            [],
        )
        .unwrap();
        c.execute(
            "CREATE TABLE PLBatteryAgent_EventBackward_Battery (\
                ID INTEGER PRIMARY KEY, Level INTEGER, timestamp DOUBLE \
             )",
            [],
        )
        .unwrap();
        for i in 0..rows {
            c.execute(
                "INSERT INTO PLApplicationAgent_EventForward_ApplicationRunTime \
                 (BundleID, timestamp) VALUES ('com.example', ?1)",
                rusqlite::params![700_000_000.0_f64 + i as f64],
            )
            .unwrap();
            c.execute(
                "INSERT INTO PLBatteryAgent_EventBackward_Battery \
                 (Level, timestamp) VALUES (?1, ?2)",
                rusqlite::params![80 - i as i64, 700_000_000.0_f64 + i as f64],
            )
            .unwrap();
        }
        tmp
    }

    #[test]
    fn matches_canonical_filename_and_rotated_logs() {
        assert!(matches(Path::new(
            "/var/containers/Shared/SystemGroup/UUID/Library/BatteryLife/CurrentPowerlog.PLSQL"
        )));
        assert!(matches(Path::new("/copies/powerlog_2026-04-09.PLSQL")));
        assert!(!matches(Path::new("/var/mobile/Library/SMS/sms.db")));
    }

    #[test]
    fn parses_known_tables_with_counts() {
        let tmp = make_powerlog(3);
        let recs = parse(tmp.path());
        let app = recs
            .iter()
            .find(|r| r.subcategory.contains("ApplicationRunTime"))
            .unwrap();
        assert!(app.detail.contains("3 rows"));
        let battery = recs
            .iter()
            .find(|r| r.subcategory.contains("Battery"))
            .unwrap();
        assert!(battery.detail.contains("3 rows"));
        let summary = recs
            .iter()
            .find(|r| r.subcategory == "PowerLog summary")
            .unwrap();
        assert!(summary.detail.contains("2 tracked"));
    }

    #[test]
    fn unknown_schema_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        {
            let c = Connection::open(tmp.path()).unwrap();
            c.execute("CREATE TABLE other (x INT)", []).unwrap();
        }
        assert!(parse(tmp.path()).is_empty());
    }

    #[test]
    fn empty_known_tables_still_summarises() {
        let tmp = make_powerlog(0);
        let recs = parse(tmp.path());
        assert!(recs.iter().any(|r| r.subcategory == "PowerLog summary"));
    }
}
