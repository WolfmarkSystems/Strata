//! Westlaw — legal research search and document history.
//!
//! Source path: `/data/data/com.westlaw.*/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Westlaw caches searches,
//! viewed cases, statutes, and KeyCite history.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "com.westlaw.edge/databases/",
    "com.westlaw.android/databases/",
    "com.thomsonreuters.westlaw/databases/",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["search_history", "query_history"] {
        if table_exists(&conn, table) {
            out.extend(read_searches(&conn, path, table));
            break;
        }
    }
    for table in &["document_history", "case_history", "recent_documents"] {
        if table_exists(&conn, table) {
            out.extend(read_docs(&conn, path, table));
            break;
        }
    }
    out
}

fn read_searches(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, query, database_name, jurisdiction, searched_at \
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
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, query, database_name, jurisdiction, ts_ms) in rows.flatten() {
        let id = id.unwrap_or_default();
        let query = query.unwrap_or_default();
        let database_name = database_name.unwrap_or_default();
        let jurisdiction = jurisdiction.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Westlaw search: {}", query);
        let detail = format!(
            "Westlaw search id='{}' query='{}' database='{}' jurisdiction='{}'",
            id, query, database_name, jurisdiction
        );
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "Westlaw Search",
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

fn read_docs(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, title, citation, doc_type, keycite_status, viewed_at \
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
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, doc_title, citation, doc_type, keycite, ts_ms) in rows.flatten() {
        let id = id.unwrap_or_default();
        let doc_title = doc_title.unwrap_or_else(|| "(untitled)".to_string());
        let citation = citation.unwrap_or_default();
        let doc_type = doc_type.unwrap_or_default();
        let keycite = keycite.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Westlaw doc: {}", doc_title);
        let mut detail = format!(
            "Westlaw document id='{}' title='{}' citation='{}' doc_type='{}'",
            id, doc_title, citation, doc_type
        );
        if !keycite.is_empty() {
            detail.push_str(&format!(" keycite_status='{}'", keycite));
        }
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "Westlaw Document",
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
            CREATE TABLE search_history (id TEXT, query TEXT, database_name TEXT, jurisdiction TEXT, searched_at INTEGER);
            INSERT INTO search_history VALUES('s1','self defense AND deadly force','ALLCASES','All Federal',1609459200000);
            CREATE TABLE document_history (id TEXT, title TEXT, citation TEXT, doc_type TEXT, keycite_status TEXT, viewed_at INTEGER);
            INSERT INTO document_history VALUES('d1','Miranda v. Arizona','384 U.S. 436','case','green_flag',1609459300000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_searches_and_docs() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Westlaw Search"));
        assert!(r.iter().any(|a| a.subcategory == "Westlaw Document"));
    }

    #[test]
    fn keycite_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("keycite_status='green_flag'")));
    }

    #[test]
    fn search_query_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("self defense AND deadly force")));
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
