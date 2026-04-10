//! iOS `KnowledgeC.db` — app usage, screen time, device activity.
//!
//! KnowledgeC is a CoreData SQLite database that ties every interactive
//! event on the device to an owning bundle ID and a start/end instant.
//! iLEAPP's `knowledgeC.py` and APOLLO's KnowledgeC module both key off
//! `ZOBJECT` and `ZSTRUCTUREDMETADATA`. We produce one
//! [`ArtifactRecord`] per distinct stream bucket (`/app/usage`,
//! `/app/inFocus`, `/notification/usage`, `/device/batteryPercentage`,
//! `/display/isBacklit`, etc.) so the Artifacts panel can display a
//! breakdown without having to render millions of raw rows.
//!
//! Full row-level extraction is deliberately deferred to v1.1+ — the
//! goal of v1.0 is to prove "we found KnowledgeC and know what's inside".

use std::path::Path;

use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

use super::util;

/// Returns true if this path is a KnowledgeC database. The canonical
/// location is `Library/CoreDuet/Knowledge/knowledgeC.db` on both iOS
/// and macOS, but examiners frequently copy the file to an ad-hoc
/// location, so we also match by basename.
pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["knowledgec.db"])
}

/// Parse a KnowledgeC database and emit one [`ArtifactRecord`] per
/// stream bucket discovered inside `ZOBJECT`. An empty vector is
/// returned if the database is locked, unreadable, or missing
/// `ZOBJECT`.
pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    if !util::table_exists(&conn, "ZOBJECT") {
        return out;
    }

    // Aggregate by stream name — this is orders of magnitude cheaper
    // than pulling every row and the v1.0 panel only needs counts.
    let mut stmt = match conn.prepare(
        "SELECT ZSTREAMNAME, COUNT(*), MIN(ZSTARTDATE), MAX(ZENDDATE) \
         FROM ZOBJECT GROUP BY ZSTREAMNAME ORDER BY COUNT(*) DESC",
    ) {
        Ok(s) => s,
        Err(_) => return out,
    };

    let rows = stmt.query_map([], |row| {
        let stream: Option<String> = row.get(0).ok();
        let count: i64 = row.get(1).unwrap_or(0);
        let start: Option<f64> = row.get(2).ok();
        let end: Option<f64> = row.get(3).ok();
        Ok((stream, count, start, end))
    });
    let Ok(rows) = rows else {
        return out;
    };

    let source = path.to_string_lossy().to_string();

    for row in rows.flatten() {
        let (stream, count, start, end) = row;
        let stream = stream.unwrap_or_else(|| "(unknown)".to_string());

        let (label, forensic_value, mitre) = classify_stream(&stream);
        let start_unix = start.and_then(util::cf_absolute_to_unix);
        let end_unix = end.and_then(util::cf_absolute_to_unix);

        let detail = match (start_unix, end_unix) {
            (Some(s), Some(e)) => format!(
                "{} events in KnowledgeC stream {} (first {}s, last {}s Unix)",
                count, stream, s, e
            ),
            _ => format!(
                "{} events in KnowledgeC stream {} (no timestamps)",
                count, stream
            ),
        };

        out.push(ArtifactRecord {
            category: ArtifactCategory::UserActivity,
            subcategory: format!("KnowledgeC {}", label),
            timestamp: start_unix,
            title: format!("KnowledgeC: {}", stream),
            detail,
            source_path: source.clone(),
            forensic_value,
            mitre_technique: mitre.map(String::from),
            is_suspicious: false,
            raw_data: None,
        });
    }

    out
}

/// Map a `ZSTREAMNAME` to a human-readable bucket label, forensic
/// value, and optional MITRE ATT&CK technique. The classification list
/// is intentionally conservative — everything unknown falls back to
/// Medium so we never over-state confidence.
fn classify_stream(stream: &str) -> (&'static str, ForensicValue, Option<&'static str>) {
    match stream {
        "/app/inFocus" | "/app/usage" | "/app/activity" => {
            ("App Usage", ForensicValue::High, Some("T1005"))
        }
        "/app/webUsage" | "/browser/url" | "/safari/history" => {
            ("Web Usage", ForensicValue::High, Some("T1005"))
        }
        "/notification/usage" => ("Notifications", ForensicValue::High, Some("T1005")),
        "/device/batteryPercentage" | "/device/isCharging" | "/device/isPluggedIn" => {
            ("Device State", ForensicValue::Medium, None)
        }
        "/display/isBacklit" => ("Screen State", ForensicValue::Medium, None),
        "/inferred/motion" | "/inferred/mode" | "/portrait/pose" => {
            ("Inferred Activity", ForensicValue::Medium, None)
        }
        "/search/queries" => ("Search Queries", ForensicValue::High, Some("T1005")),
        "/app/intents" | "/app/mediaUsage" => {
            ("App Intents", ForensicValue::High, Some("T1005"))
        }
        _ => ("Other", ForensicValue::Medium, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    fn build_fake_knowledgec(with_rows: bool) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute(
            "CREATE TABLE ZOBJECT (\
                ZSTREAMNAME TEXT, \
                ZVALUESTRING TEXT, \
                ZSTARTDATE DOUBLE, \
                ZENDDATE DOUBLE \
             )",
            [],
        )
        .unwrap();
        if with_rows {
            // 3 /app/inFocus rows and 1 /notification/usage row.
            let base = 700_000_000.0_f64; // arbitrary Cocoa seconds
            for i in 0..3 {
                c.execute(
                    "INSERT INTO ZOBJECT VALUES ('/app/inFocus', 'com.apple.mobilesafari', ?1, ?2)",
                    rusqlite::params![base + i as f64, base + i as f64 + 10.0],
                )
                .unwrap();
            }
            c.execute(
                "INSERT INTO ZOBJECT VALUES ('/notification/usage', 'com.apple.Maps', ?1, ?2)",
                rusqlite::params![base + 50.0, base + 51.0],
            )
            .unwrap();
        }
        tmp
    }

    #[test]
    fn matches_knowledgec_by_name() {
        assert!(matches(Path::new("/Library/CoreDuet/Knowledge/knowledgeC.db")));
        assert!(matches(Path::new("C:/copied/KnowledgeC.db")));
        assert!(!matches(Path::new("/Library/Safari/History.db")));
    }

    #[test]
    fn parses_two_buckets_from_fake_db() {
        let tmp = build_fake_knowledgec(true);
        let records = parse(tmp.path());
        assert_eq!(records.len(), 2, "expected two stream buckets");

        let in_focus = records
            .iter()
            .find(|r| r.subcategory == "KnowledgeC App Usage")
            .expect("app usage record");
        assert!(in_focus.detail.contains("3 events"));
        assert_eq!(in_focus.forensic_value, ForensicValue::High);
        assert_eq!(in_focus.mitre_technique.as_deref(), Some("T1005"));

        let notif = records
            .iter()
            .find(|r| r.subcategory == "KnowledgeC Notifications")
            .expect("notifications record");
        assert!(notif.detail.contains("1 events"));
    }

    #[test]
    fn empty_database_returns_no_records() {
        let tmp = build_fake_knowledgec(false);
        let records = parse(tmp.path());
        assert!(records.is_empty());
    }

    #[test]
    fn classify_unknown_stream_falls_back_to_medium() {
        let (label, fv, mitre) = classify_stream("/weird/future/stream");
        assert_eq!(label, "Other");
        assert_eq!(fv, ForensicValue::Medium);
        assert!(mitre.is_none());
    }

    #[test]
    fn classify_maps_known_streams_correctly() {
        let (l, _, _) = classify_stream("/app/inFocus");
        assert_eq!(l, "App Usage");
        let (l, _, _) = classify_stream("/notification/usage");
        assert_eq!(l, "Notifications");
        let (l, _, _) = classify_stream("/search/queries");
        assert_eq!(l, "Search Queries");
    }

    #[test]
    fn timestamps_are_converted_to_unix_epoch() {
        let tmp = build_fake_knowledgec(true);
        let records = parse(tmp.path());
        // The first /app/inFocus row uses base == 700_000_000.0 Cocoa
        // seconds, which in Unix is 700_000_000 + APPLE_EPOCH_OFFSET.
        let in_focus = records
            .iter()
            .find(|r| r.subcategory == "KnowledgeC App Usage")
            .unwrap();
        let expected = 700_000_000_i64 + util::APPLE_EPOCH_OFFSET;
        assert_eq!(in_focus.timestamp, Some(expected));
    }
}
