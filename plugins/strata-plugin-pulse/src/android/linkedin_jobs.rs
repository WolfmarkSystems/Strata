//! LinkedIn Jobs — job searches, applications, and saved postings.
//!
//! Source path: `/data/data/com.linkedin.android/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. Complements `linkedin.rs`
//! (messaging) by targeting job-related tables like `job`,
//! `job_application`, `saved_job`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.linkedin.android/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "job_application") {
        out.extend(read_applications(&conn, path));
    }
    for table in &["saved_job", "saved_jobs"] {
        if table_exists(&conn, table) {
            out.extend(read_saved(&conn, path, table));
            break;
        }
    }
    for table in &["job_search_history", "job_searches"] {
        if table_exists(&conn, table) {
            out.extend(read_searches(&conn, path, table));
            break;
        }
    }
    out
}

fn read_applications(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT job_id, title, company, location, \
               applied_at, application_status \
               FROM job_application ORDER BY applied_at DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
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
            row.get::<_, Option<String>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (job_id, title, company, location, applied_ms, status) in rows.flatten() {
        let job_id = job_id.unwrap_or_else(|| "(unknown)".to_string());
        let title = title.unwrap_or_default();
        let company = company.unwrap_or_default();
        let location = location.unwrap_or_default();
        let status = status.unwrap_or_default();
        let ts = applied_ms.and_then(unix_ms_to_i64);
        let title_str = format!("LinkedIn application: {} at {}", title, company);
        let detail = format!(
            "LinkedIn job application job_id='{}' title='{}' company='{}' location='{}' status='{}'",
            job_id, title, company, location, status
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "LinkedIn Job Application",
            title_str,
            detail,
            path,
            ts,
            ForensicValue::High,
            false,
        ));
    }
    out
}

fn read_saved(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT job_id, title, company, location, saved_at \
         FROM \"{table}\" ORDER BY saved_at DESC LIMIT 5000",
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
    for (job_id, title, company, location, saved_ms) in rows.flatten() {
        let job_id = job_id.unwrap_or_default();
        let title = title.unwrap_or_default();
        let company = company.unwrap_or_default();
        let location = location.unwrap_or_default();
        let ts = saved_ms.and_then(unix_ms_to_i64);
        let title_str = format!("LinkedIn saved job: {} at {}", title, company);
        let detail = format!(
            "LinkedIn saved job job_id='{}' title='{}' company='{}' location='{}'",
            job_id, title, company, location
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "LinkedIn Saved Job",
            title_str,
            detail,
            path,
            ts,
            ForensicValue::Medium,
            false,
        ));
    }
    out
}

fn read_searches(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT keywords, location, searched_at \
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
            row.get::<_, Option<i64>>(2).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (keywords, location, searched_ms) in rows.flatten() {
        let keywords = keywords.unwrap_or_default();
        let location = location.unwrap_or_default();
        let ts = searched_ms.and_then(unix_ms_to_i64);
        let title = format!("LinkedIn job search: {} in {}", keywords, location);
        let detail = format!(
            "LinkedIn job search keywords='{}' location='{}'",
            keywords, location
        );
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "LinkedIn Job Search",
            title,
            detail,
            path,
            ts,
            ForensicValue::Medium,
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
            CREATE TABLE job_application (
                job_id TEXT,
                title TEXT,
                company TEXT,
                location TEXT,
                applied_at INTEGER,
                application_status TEXT
            );
            INSERT INTO job_application VALUES('j1','Senior Engineer','Acme','Remote',1609459200000,'submitted');
            CREATE TABLE saved_job (
                job_id TEXT,
                title TEXT,
                company TEXT,
                location TEXT,
                saved_at INTEGER
            );
            INSERT INTO saved_job VALUES('j2','Staff Engineer','Globex','NYC',1609459300000);
            CREATE TABLE job_search_history (
                keywords TEXT,
                location TEXT,
                searched_at INTEGER
            );
            INSERT INTO job_search_history VALUES('rust developer','Remote',1609459400000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_apps_saved_searches() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.subcategory == "LinkedIn Job Application"));
        assert!(r.iter().any(|a| a.subcategory == "LinkedIn Saved Job"));
        assert!(r.iter().any(|a| a.subcategory == "LinkedIn Job Search"));
    }

    #[test]
    fn application_status_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("status='submitted'")));
    }

    #[test]
    fn search_keywords_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.title.contains("rust developer")));
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
