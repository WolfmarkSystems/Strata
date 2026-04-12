//! PACER / CM/ECF — federal court filing viewer.
//!
//! Source paths: various PACER mobile apps and court-specific filing apps.
//! `/data/data/uscourts.*/databases/*`, `/data/data/gov.uscourts.*/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. Court filing apps cache case
//! lookups, docket entries, and document views.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "uscourts/databases/",
    "gov.uscourts/databases/",
    "pacer/databases/",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["case_lookup", "case_search", "case_history"] {
        if table_exists(&conn, table) {
            out.extend(read_cases(&conn, path, table));
            break;
        }
    }
    for table in &["docket_entry", "docket_history"] {
        if table_exists(&conn, table) {
            out.extend(read_docket(&conn, path, table));
            break;
        }
    }
    out
}

fn read_cases(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT case_number, case_title, court, case_type, \
         date_filed, date_closed, viewed_at \
         FROM \"{table}\" ORDER BY viewed_at DESC LIMIT 5000",
        table = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
            row.get::<_, Option<i64>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (case_number, case_title, court, case_type, date_filed, date_closed, ts_ms) in rows.flatten() {
        let case_number = case_number.unwrap_or_else(|| "(unknown)".to_string());
        let case_title = case_title.unwrap_or_default();
        let court = court.unwrap_or_default();
        let case_type = case_type.unwrap_or_default();
        let date_filed = date_filed.unwrap_or_default();
        let date_closed = date_closed.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("PACER case: {} — {}", case_number, case_title);
        let detail = format!(
            "PACER case case_number='{}' case_title='{}' court='{}' case_type='{}' date_filed='{}' date_closed='{}'",
            case_number, case_title, court, case_type, date_filed, date_closed
        );
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "PACER Case",
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

fn read_docket(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT case_number, entry_number, description, filed_date, \
         document_url, viewed_at \
         FROM \"{table}\" ORDER BY viewed_at DESC LIMIT 10000",
        table = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
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
    for (case_number, entry_number, description, filed_date, document_url, ts_ms) in rows.flatten() {
        let case_number = case_number.unwrap_or_default();
        let entry_number = entry_number.unwrap_or(0);
        let description = description.unwrap_or_default();
        let filed_date = filed_date.unwrap_or_default();
        let document_url = document_url.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let preview: String = description.chars().take(100).collect();
        let title = format!("PACER docket #{}: {}", entry_number, preview);
        let detail = format!(
            "PACER docket entry case_number='{}' entry_number={} description='{}' filed_date='{}' document_url='{}'",
            case_number, entry_number, description, filed_date, document_url
        );
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "PACER Docket",
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
            CREATE TABLE case_lookup (case_number TEXT, case_title TEXT, court TEXT, case_type TEXT, date_filed TEXT, date_closed TEXT, viewed_at INTEGER);
            INSERT INTO case_lookup VALUES('1:24-cr-00001','United States v. Smith','NDCA','criminal','2024-01-15','',1609459200000);
            CREATE TABLE docket_entry (case_number TEXT, entry_number INTEGER, description TEXT, filed_date TEXT, document_url TEXT, viewed_at INTEGER);
            INSERT INTO docket_entry VALUES('1:24-cr-00001',1,'Indictment filed','2024-01-15','https://ecf.cand.uscourts.gov/doc/1',1609459300000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_cases_and_docket() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "PACER Case"));
        assert!(r.iter().any(|a| a.subcategory == "PACER Docket"));
    }

    #[test]
    fn case_number_and_court_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("court='NDCA'") && a.detail.contains("case_type='criminal'")));
    }

    #[test]
    fn docket_url_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("document_url='https://ecf.cand.uscourts.gov/doc/1'")));
    }

    #[test]
    fn missing_table_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE unrelated (id INTEGER);").unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}
