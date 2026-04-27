//! IRS2Go — IRS mobile app refund status and payment extraction.
//!
//! Source path: `/data/data/gov.irs.mobile.irs2go/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. IRS2Go stores refund lookups
//! and tax year info in local tables. Schemas vary; parser uses
//! plausible column names.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["gov.irs.mobile.irs2go/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["refund_status", "refund_lookup", "refund_history"] {
        if table_exists(&conn, table) {
            out.extend(read_refunds(&conn, path, table));
            break;
        }
    }
    out
}

fn read_refunds(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT tax_year, filing_status, refund_amount, status, \
         ssn_last_four, checked_at \
         FROM \"{table}\" ORDER BY checked_at DESC LIMIT 100",
        table = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (tax_year, filing_status, refund_amount, status, ssn_last_four, checked_ms) in
        rows.flatten()
    {
        let tax_year = tax_year.unwrap_or(0);
        let filing_status = filing_status.unwrap_or_default();
        let refund_amount = refund_amount.unwrap_or_default();
        let status = status.unwrap_or_default();
        let ssn_last_four = ssn_last_four.unwrap_or_default();
        let ts = checked_ms.and_then(unix_ms_to_i64);
        let title = format!("IRS2Go refund lookup: tax year {} ({})", tax_year, status);
        let detail = format!(
            "IRS2Go refund lookup tax_year={} filing_status='{}' refund_amount='{}' status='{}' ssn_last_four='{}'",
            tax_year, filing_status, refund_amount, status, ssn_last_four
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "IRS2Go Refund",
            title,
            detail,
            path,
            ts,
            ForensicValue::Critical,
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
            CREATE TABLE refund_status (
                tax_year INTEGER,
                filing_status TEXT,
                refund_amount TEXT,
                status TEXT,
                ssn_last_four TEXT,
                checked_at INTEGER
            );
            INSERT INTO refund_status VALUES(2024,'single','$1,234','approved','1234',1609459200000);
            INSERT INTO refund_status VALUES(2023,'married filing jointly','$3,456','issued','1234',1577923200000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_two_lookups() {
        let db = make_db();
        let r = parse(db.path());
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|a| a.subcategory == "IRS2Go Refund"));
    }

    #[test]
    fn tax_year_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.title.contains("2024") && a.title.contains("approved")));
    }

    #[test]
    fn filing_status_and_ssn_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("filing_status='single'")
            && a.detail.contains("ssn_last_four='1234'")));
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
