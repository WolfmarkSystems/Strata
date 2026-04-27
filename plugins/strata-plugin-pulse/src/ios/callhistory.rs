//! iOS `CallHistory.storedata` — voice + FaceTime call history.
//!
//! `CallHistory.storedata` is a CoreData SQLite database. The relevant
//! table is `ZCALLRECORD` with columns `ZADDRESS` (callee/caller),
//! `ZDATE` (Cocoa seconds double), `ZDURATION` (seconds double),
//! `ZORIGINATED` (1 if outgoing, 0 if incoming), `ZANSWERED`,
//! `ZSERVICE_PROVIDER` (e.g. `com.apple.Telephony`,
//! `com.apple.FaceTime`), and `ZCALLTYPE` (1 = phone, 8 = FaceTime
//! audio, 16 = FaceTime video).
//!
//! Pulse v1.0 emits one summary record plus one record per
//! `(direction, service)` bucket so the examiner can spot heavy
//! FaceTime audio without paging through every row. Per-row extraction
//! is queued for v1.1+.

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["callhistory.storedata"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    if !util::table_exists(&conn, "ZCALLRECORD") {
        return out;
    }

    let source = path.to_string_lossy().to_string();
    let total = util::count_rows(&conn, "ZCALLRECORD");

    // Earliest / latest call date.
    let (first, last) = conn
        .prepare("SELECT MIN(ZDATE), MAX(ZDATE) FROM ZCALLRECORD WHERE ZDATE IS NOT NULL")
        .and_then(|mut s| {
            s.query_row([], |row| {
                Ok((row.get::<_, Option<f64>>(0)?, row.get::<_, Option<f64>>(1)?))
            })
        })
        .unwrap_or((None, None));
    let first_unix = first.and_then(util::cf_absolute_to_unix);
    let last_unix = last.and_then(util::cf_absolute_to_unix);

    let range = match (first_unix, last_unix) {
        (Some(a), Some(b)) => format!("range {}..{} Unix", a, b),
        _ => "no usable timestamps".to_string(),
    };

    out.push(ArtifactRecord {
        category: ArtifactCategory::Communications,
        subcategory: "CallHistory".to_string(),
        timestamp: first_unix,
        title: "iOS call history".to_string(),
        detail: format!("{} total ZCALLRECORD rows, {}", total, range),
        source_path: source.clone(),
        forensic_value: ForensicValue::Critical,
        mitre_technique: Some("T1005".to_string()),
        is_suspicious: false,
        raw_data: None,
        confidence: 0,
    });

    // Direction breakdown.
    let by_direction = conn
        .prepare(
            "SELECT COALESCE(ZORIGINATED, -1), COUNT(*) FROM ZCALLRECORD \
             GROUP BY COALESCE(ZORIGINATED, -1)",
        )
        .and_then(|mut s| {
            let r = s.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?;
            Ok(r.flatten().collect::<Vec<_>>())
        })
        .unwrap_or_default();

    for (originated, count) in by_direction {
        let label = match originated {
            1 => "Outgoing",
            0 => "Incoming",
            _ => "Unknown direction",
        };
        out.push(ArtifactRecord {
            category: ArtifactCategory::Communications,
            subcategory: format!("CallHistory {}", label),
            timestamp: None,
            title: format!("{} calls", label),
            detail: format!("{} {} call rows", count, label.to_lowercase()),
            source_path: source.clone(),
            forensic_value: ForensicValue::High,
            mitre_technique: Some("T1005".to_string()),
            is_suspicious: false,
            raw_data: None,
            confidence: 0,
        });
    }

    // Service provider breakdown — only meaningful when present.
    let by_service = conn
        .prepare(
            "SELECT COALESCE(ZSERVICE_PROVIDER, '(unknown)'), COUNT(*) \
             FROM ZCALLRECORD GROUP BY ZSERVICE_PROVIDER",
        )
        .and_then(|mut s| {
            let r = s.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            Ok(r.flatten().collect::<Vec<_>>())
        })
        .unwrap_or_default();

    for (service, count) in by_service {
        out.push(ArtifactRecord {
            category: ArtifactCategory::Communications,
            subcategory: format!("CallHistory service: {}", service),
            timestamp: None,
            title: format!("{} call provider", service),
            detail: format!("{} calls routed via {}", count, service),
            source_path: source.clone(),
            forensic_value: ForensicValue::High,
            mitre_technique: None,
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

    fn make_callhistory(rows: &[(i64, f64, &str)]) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute(
            "CREATE TABLE ZCALLRECORD (\
                Z_PK INTEGER PRIMARY KEY, \
                ZADDRESS TEXT, \
                ZDATE DOUBLE, \
                ZDURATION DOUBLE, \
                ZORIGINATED INTEGER, \
                ZANSWERED INTEGER, \
                ZSERVICE_PROVIDER TEXT, \
                ZCALLTYPE INTEGER \
             )",
            [],
        )
        .unwrap();
        for (originated, date, service) in rows {
            c.execute(
                "INSERT INTO ZCALLRECORD \
                 (ZADDRESS, ZDATE, ZDURATION, ZORIGINATED, ZANSWERED, ZSERVICE_PROVIDER, ZCALLTYPE) \
                 VALUES ('+15551234567', ?1, 60.0, ?2, 1, ?3, 1)",
                rusqlite::params![*date, *originated, *service],
            )
            .unwrap();
        }
        tmp
    }

    #[test]
    fn matches_canonical_filename() {
        assert!(matches(Path::new(
            "/private/var/mobile/Library/CallHistoryDB/CallHistory.storedata"
        )));
        assert!(!matches(Path::new("/something/sms.db")));
    }

    #[test]
    fn parses_summary_with_correct_count_and_range() {
        let tmp = make_callhistory(&[
            (1, 700_000_000.0, "com.apple.Telephony"),
            (0, 700_000_500.0, "com.apple.Telephony"),
            (1, 700_000_900.0, "com.apple.FaceTime"),
        ]);
        let records = parse(tmp.path());

        let summary = records
            .iter()
            .find(|r| r.subcategory == "CallHistory")
            .expect("summary record");
        assert!(summary.detail.contains("3 total"));
        assert_eq!(
            summary.timestamp,
            Some(700_000_000 + util::APPLE_EPOCH_OFFSET)
        );
    }

    #[test]
    fn breaks_down_by_direction_and_service() {
        let tmp = make_callhistory(&[
            (1, 700_000_000.0, "com.apple.Telephony"),
            (0, 700_000_500.0, "com.apple.Telephony"),
            (1, 700_000_900.0, "com.apple.FaceTime"),
        ]);
        let records = parse(tmp.path());

        let outgoing = records
            .iter()
            .find(|r| r.subcategory == "CallHistory Outgoing")
            .expect("outgoing bucket");
        assert!(outgoing.detail.contains("2 outgoing"));

        let incoming = records
            .iter()
            .find(|r| r.subcategory == "CallHistory Incoming")
            .expect("incoming bucket");
        assert!(incoming.detail.contains("1 incoming"));

        assert!(records
            .iter()
            .any(|r| r.subcategory == "CallHistory service: com.apple.Telephony"));
        assert!(records
            .iter()
            .any(|r| r.subcategory == "CallHistory service: com.apple.FaceTime"));
    }

    #[test]
    fn empty_db_returns_summary_only() {
        let tmp = make_callhistory(&[]);
        let records = parse(tmp.path());
        let summary = records.iter().find(|r| r.subcategory == "CallHistory");
        assert!(summary.is_some());
        assert!(summary.unwrap().detail.contains("0 total"));
    }
}
