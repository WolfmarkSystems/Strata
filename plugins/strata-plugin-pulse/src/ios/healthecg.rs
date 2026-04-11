//! iOS HealthKit ECG — `electrocardiograms` table in
//! `healthdb_secure.sqlite`.
//!
//! Apple Watch ECG recordings include classification (normal sinus,
//! AFib, inconclusive) + timestamp. Proves device worn at that time.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["healthdb_secure.sqlite"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else { return out };
    if !util::table_exists(&conn, "electrocardiograms") { return out; }
    let source = path.to_string_lossy().to_string();
    let count = util::count_rows(&conn, "electrocardiograms");
    if count == 0 { return out; }

    let ts = conn
        .prepare("SELECT MIN(date), MAX(date) FROM electrocardiograms WHERE date IS NOT NULL")
        .and_then(|mut s| s.query_row([], |r| Ok((r.get::<_, Option<f64>>(0)?, r.get::<_, Option<f64>>(1)?))))
        .unwrap_or((None, None));
    let first = ts.0.and_then(util::cf_absolute_to_unix);

    out.push(ArtifactRecord {
        category: ArtifactCategory::UserActivity,
        subcategory: "HealthKit ECG".to_string(), timestamp: first,
        title: "Apple Watch ECG recordings".to_string(),
        detail: format!("{} ECG recordings (classification + voltage data, proves device worn)", count),
        source_path: source, forensic_value: ForensicValue::High,
        mitre_technique: None, is_suspicious: false, raw_data: None,
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    #[test]
    fn parses_ecg_count() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE electrocardiograms (data_id INTEGER PRIMARY KEY, date DOUBLE, classification INTEGER)", []).unwrap();
        c.execute("INSERT INTO electrocardiograms (date, classification) VALUES (700000000.0, 1)", []).unwrap();
        let recs = parse(tmp.path());
        assert_eq!(recs.len(), 1);
        assert!(recs[0].detail.contains("1 ECG"));
    }

    #[test]
    fn no_ecgs_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE electrocardiograms (data_id INTEGER PRIMARY KEY)", []).unwrap();
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
