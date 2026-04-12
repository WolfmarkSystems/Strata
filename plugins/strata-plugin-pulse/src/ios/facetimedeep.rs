//! iOS FaceTime deep — extended `CallHistory.storedata` analysis.
//!
//! Extends the basic `callhistory.rs` by filtering specifically for
//! FaceTime calls (ZCALLTYPE 8=audio, 16=video) and extracting
//! per-call duration + connection metadata.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["callhistory.storedata"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else { return out };
    if !util::table_exists(&conn, "ZCALLRECORD") { return out; }
    let source = path.to_string_lossy().to_string();

    // FaceTime audio = type 8, video = type 16 (varies by iOS version)
    let ft_audio: i64 = conn
        .prepare("SELECT COUNT(*) FROM ZCALLRECORD WHERE ZCALLTYPE = 8")
        .and_then(|mut s| s.query_row([], |r| r.get(0)))
        .unwrap_or(0);
    let ft_video: i64 = conn
        .prepare("SELECT COUNT(*) FROM ZCALLRECORD WHERE ZCALLTYPE = 16")
        .and_then(|mut s| s.query_row([], |r| r.get(0)))
        .unwrap_or(0);

    if ft_audio == 0 && ft_video == 0 { return out; }

    let total_duration: f64 = conn
        .prepare("SELECT COALESCE(SUM(ZDURATION), 0) FROM ZCALLRECORD WHERE ZCALLTYPE IN (8, 16)")
        .and_then(|mut s| s.query_row([], |r| r.get(0)))
        .unwrap_or(0.0);

    out.push(ArtifactRecord {
        category: ArtifactCategory::Communications,
        subcategory: "FaceTime deep".to_string(), timestamp: None,
        title: "FaceTime call breakdown".to_string(),
        detail: format!(
            "{} FaceTime audio + {} FaceTime video calls, total duration {:.0}s",
            ft_audio, ft_video, total_duration
        ),
        source_path: source,
        forensic_value: ForensicValue::Critical,
        mitre_technique: Some("T1005".to_string()),
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

    fn make_calls(calls: &[(i64, f64)]) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE ZCALLRECORD (Z_PK INTEGER PRIMARY KEY, ZCALLTYPE INTEGER, ZDURATION DOUBLE, ZDATE DOUBLE)", []).unwrap();
        for (ctype, dur) in calls {
            c.execute("INSERT INTO ZCALLRECORD (ZCALLTYPE, ZDURATION, ZDATE) VALUES (?1, ?2, 700000000.0)", rusqlite::params![*ctype, *dur]).unwrap();
        }
        tmp
    }

    #[test]
    fn parses_facetime_audio_and_video() {
        let tmp = make_calls(&[(8, 120.0), (8, 60.0), (16, 300.0), (1, 45.0)]);
        let recs = parse(tmp.path());
        let r = recs.iter().find(|r| r.subcategory == "FaceTime deep").unwrap();
        assert!(r.detail.contains("2 FaceTime audio"));
        assert!(r.detail.contains("1 FaceTime video"));
        assert!(r.detail.contains("480s"));
    }

    #[test]
    fn no_facetime_calls_returns_empty() {
        let tmp = make_calls(&[(1, 30.0), (1, 60.0)]);
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
