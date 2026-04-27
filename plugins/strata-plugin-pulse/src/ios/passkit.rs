//! iOS PassKit — boarding passes, event tickets, loyalty cards.
//!
//! `pass_data` / `pass_type` tables in `nanopasses.sqlite3` hold the
//! actual pass metadata (airline, date, seat, barcode). Extends
//! `wallet.rs` which counts rows; this parser classifies pass types.

use super::util;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub fn matches(path: &Path) -> bool {
    util::name_is(
        path,
        &["nanopasses.sqlite3", "nanopasses.sqlite", "passes23.sqlite"],
    )
}

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let mut out = Vec::new();
    let Some(conn) = util::open_sqlite_ro(path) else {
        return out;
    };
    let source = path.to_string_lossy().to_string();

    // Classify passes by type if pass_type table exists
    if util::table_exists(&conn, "pass") && util::table_exists(&conn, "pass_type") {
        let by_type = conn
            .prepare(
                "SELECT COALESCE(pt.description, '(unknown)'), COUNT(p.unique_id) \
                 FROM pass p LEFT JOIN pass_type pt ON p.pass_type_id = pt.unique_id \
                 GROUP BY pt.description ORDER BY COUNT(*) DESC LIMIT 10",
            )
            .and_then(|mut s| {
                let r = s.query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })?;
                Ok(r.flatten().collect::<Vec<_>>())
            })
            .unwrap_or_default();

        if !by_type.is_empty() {
            for (desc, count) in by_type {
                out.push(ArtifactRecord {
                    category: ArtifactCategory::UserActivity,
                    subcategory: format!("PassKit: {}", desc),
                    timestamp: None,
                    title: format!("Wallet pass type: {}", desc),
                    detail: format!(
                        "{} passes of type {} — boarding passes, tickets, loyalty cards",
                        count, desc
                    ),
                    source_path: source.clone(),
                    forensic_value: ForensicValue::High,
                    mitre_technique: None,
                    is_suspicious: false,
                    raw_data: None,
                    confidence: 0,
                });
            }
            return out;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    fn make_passes(types: &[(&str, usize)]) -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute(
            "CREATE TABLE pass_type (unique_id INTEGER PRIMARY KEY, description TEXT)",
            [],
        )
        .unwrap();
        c.execute(
            "CREATE TABLE pass (unique_id INTEGER PRIMARY KEY, pass_type_id INTEGER)",
            [],
        )
        .unwrap();
        for (i, (desc, count)) in types.iter().enumerate() {
            let tid = (i + 1) as i64;
            c.execute(
                "INSERT INTO pass_type VALUES (?1, ?2)",
                rusqlite::params![tid, *desc],
            )
            .unwrap();
            for _ in 0..*count {
                c.execute(
                    "INSERT INTO pass (pass_type_id) VALUES (?1)",
                    rusqlite::params![tid],
                )
                .unwrap();
            }
        }
        tmp
    }

    #[test]
    fn parses_pass_type_breakdown() {
        let tmp = make_passes(&[("Boarding Pass", 3), ("Loyalty Card", 2)]);
        let recs = parse(tmp.path());
        assert!(recs.iter().any(|r| r.subcategory.contains("Boarding Pass")));
        assert!(recs.iter().any(|r| r.subcategory.contains("Loyalty Card")));
    }

    #[test]
    fn no_pass_tables_returns_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute("CREATE TABLE other (x INT)", []).unwrap();
        assert!(parse(tmp.path()).is_empty());
    }

    #[test]
    fn empty_passes_returns_empty() {
        let tmp = make_passes(&[]);
        assert!(parse(tmp.path()).is_empty());
    }
}
