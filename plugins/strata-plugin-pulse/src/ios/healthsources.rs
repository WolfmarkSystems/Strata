//! iOS HealthKit data sources — `data_provenances` in `healthdb_secure.sqlite`.
//!
//! Maps each HealthKit sample to the app/device that recorded it.
//! Shows which third-party apps had health data access and which
//! Apple Watch contributed readings.

use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};
use super::util;

pub fn matches(path: &Path) -> bool {
    util::name_is(path, &["healthdb_secure.sqlite"])
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else { return out };
    if !util::table_exists(&conn, "data_provenances") { return out; }
    let source = path.to_string_lossy().to_string();

    let by_source = conn
        .prepare(
            "SELECT COALESCE(origin_product_type, '(unknown)'), COUNT(*) \
             FROM data_provenances GROUP BY origin_product_type \
             ORDER BY COUNT(*) DESC LIMIT 15"
        )
        .and_then(|mut s| {
            let r = s.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))?;
            Ok(r.flatten().collect::<Vec<_>>())
        })
        .unwrap_or_default();

    if by_source.is_empty() { return out; }

    for (product, count) in by_source {
        out.push(ArtifactRecord {
            category: ArtifactCategory::UserActivity,
            subcategory: format!("HealthKit source: {}", product),
            timestamp: None,
            title: format!("HealthKit data source: {}", product),
            detail: format!("{} provenance rows from {}", count, product),
            source_path: source.clone(),
            forensic_value: ForensicValue::Medium,
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

    fn make_prov(products: &[(&str, usize)]) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE data_provenances (rowid INTEGER PRIMARY KEY, origin_product_type TEXT, source_id TEXT)", []).unwrap();
        for (prod, count) in products {
            for _ in 0..*count {
                c.execute("INSERT INTO data_provenances (origin_product_type, source_id) VALUES (?1, 'src')", rusqlite::params![*prod]).unwrap();
            }
        }
        tmp
    }

    #[test]
    fn parses_source_breakdown() {
        let tmp = make_prov(&[("Watch6,2", 10), ("iPhone14,5", 5)]);
        let recs = parse(tmp.path());
        assert!(recs.iter().any(|r| r.subcategory.contains("Watch6,2")));
        assert!(recs.iter().any(|r| r.subcategory.contains("iPhone14,5")));
    }

    #[test]
    fn empty_table_returns_empty() {
        let tmp = make_prov(&[]);
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
