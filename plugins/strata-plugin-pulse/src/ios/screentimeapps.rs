//! iOS Screen Time per-app detail — deeper `RMAdminStore-Local.sqlite`.
//!
//! Extends `screentime.rs` by querying `ZUSAGETIMEDITEM` to produce
//! a per-bundle-ID breakdown showing exactly which apps were used and
//! for how long each day.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["rmadminstore-local.sqlite", "rmadminstore-cloud.sqlite"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else { return out };
    if !util::table_exists(&conn, "ZUSAGETIMEDITEM") { return out; }
    let source = path.to_string_lossy().to_string();

    let by_app = conn
        .prepare(
            "SELECT COALESCE(ZBUNDLEIDENTIFIER, '(unknown)'), COUNT(*), \
             COALESCE(SUM(ZTOTALTIMEINSECONDS), 0) \
             FROM ZUSAGETIMEDITEM \
             GROUP BY ZBUNDLEIDENTIFIER ORDER BY SUM(ZTOTALTIMEINSECONDS) DESC LIMIT 20"
        )
        .and_then(|mut s| {
            let r = s.query_map([], |row| Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, f64>(2)?,
            )))?;
            Ok(r.flatten().collect::<Vec<_>>())
        })
        .unwrap_or_default();

    if by_app.is_empty() { return out; }

    for (bundle, rows, seconds) in by_app {
        out.push(ArtifactRecord {
            category: ArtifactCategory::UserActivity,
            subcategory: format!("Screen Time app: {}", bundle),
            timestamp: None,
            title: format!("Screen Time: {}", bundle),
            detail: format!("{} entries, {:.0}s total foreground time", rows, seconds),
            source_path: source.clone(), forensic_value: ForensicValue::High,
            mitre_technique: Some("T1005".to_string()), is_suspicious: false, raw_data: None,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    fn make_st(apps: &[(&str, f64)]) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE ZUSAGETIMEDITEM (Z_PK INTEGER PRIMARY KEY, ZBUNDLEIDENTIFIER TEXT, ZTOTALTIMEINSECONDS DOUBLE)", []).unwrap();
        for (bundle, secs) in apps {
            c.execute("INSERT INTO ZUSAGETIMEDITEM (ZBUNDLEIDENTIFIER, ZTOTALTIMEINSECONDS) VALUES (?1, ?2)",
                rusqlite::params![*bundle, *secs]).unwrap();
        }
        tmp
    }

    #[test]
    fn parses_per_app_breakdown() {
        let tmp = make_st(&[("com.apple.mobilesafari", 3600.0), ("com.apple.mobilesafari", 1800.0), ("com.example", 600.0)]);
        let recs = parse(tmp.path());
        let safari = recs.iter().find(|r| r.subcategory.contains("mobilesafari")).unwrap();
        assert!(safari.detail.contains("5400s"));
        assert!(recs.iter().any(|r| r.subcategory.contains("com.example")));
    }

    #[test]
    fn empty_table_returns_empty() {
        let tmp = make_st(&[]);
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
