//! LexisNexis — legal research search history and saved documents.
//!
//! Source path: `/data/data/com.lexisnexis.*/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. LexisNexis caches recent
//! searches, document views, and folder contents. Forensic interest:
//! legal research patterns can establish intent or knowledge.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.lexisnexis.advance/databases/",
    "com.lexisnexis.research/databases/",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["search_history", "recent_searches", "query_history"] {
        if table_exists(&conn, table) {
            out.extend(read_searches(&conn, path, table));
            break;
        }
    }
    for table in &["document_history", "recent_documents", "viewed_document"] {
        if table_exists(&conn, table) {
            out.extend(read_documents(&conn, path, table));
            break;
        }
    }
    out
}

fn read_searches(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, query, source, jurisdiction, searched_at, result_count \
         FROM \"{table}\" ORDER BY searched_at DESC LIMIT 5000",
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
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, query, source, jurisdiction, ts_ms, result_count) in rows.flatten() {
        let id = id.unwrap_or_default();
        let query = query.unwrap_or_default();
        let source = source.unwrap_or_default();
        let jurisdiction = jurisdiction.unwrap_or_default();
        let result_count = result_count.unwrap_or(0);
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("LexisNexis search: {}", query);
        let detail = format!(
            "LexisNexis search id='{}' query='{}' source='{}' jurisdiction='{}' result_count={}",
            id, query, source, jurisdiction, result_count
        );
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "LexisNexis Search",
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

fn read_documents(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, title, citation, document_type, viewed_at \
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
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, doc_title, citation, doc_type, ts_ms) in rows.flatten() {
        let id = id.unwrap_or_default();
        let doc_title = doc_title.unwrap_or_else(|| "(untitled)".to_string());
        let citation = citation.unwrap_or_default();
        let doc_type = doc_type.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("LexisNexis doc: {}", doc_title);
        let detail = format!(
            "LexisNexis document id='{}' title='{}' citation='{}' document_type='{}'",
            id, doc_title, citation, doc_type
        );
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "LexisNexis Document",
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
            CREATE TABLE search_history (id TEXT, query TEXT, source TEXT, jurisdiction TEXT, searched_at INTEGER, result_count INTEGER);
            INSERT INTO search_history VALUES('s1','18 USC 2258A','Case Law','Federal',1609459200000,45);
            CREATE TABLE document_history (id TEXT, title TEXT, citation TEXT, document_type TEXT, viewed_at INTEGER);
            INSERT INTO document_history VALUES('d1','United States v. Doe','123 F.3d 456','case',1609459300000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_searches_and_documents() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "LexisNexis Search"));
        assert!(r.iter().any(|a| a.subcategory == "LexisNexis Document"));
    }

    #[test]
    fn citation_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("citation='123 F.3d 456'")));
    }

    #[test]
    fn jurisdiction_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("jurisdiction='Federal'")));
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
