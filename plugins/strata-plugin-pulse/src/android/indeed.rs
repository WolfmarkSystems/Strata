//! Indeed — Android job search, applied job, and saved job extraction.
//!
//! Source path: `/data/data/com.indeed.android.jobsearch/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. Indeed uses Room databases with
//! tables like `job_searches`, `job_applications`, `saved_jobs`. Application
//! records include company, title, applied_at, and status, establishing the
//! subject's employment-seeking activity with a timestamped record.

use crate::android::helpers::{build_record, fmt_ts, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.indeed.android.jobsearch/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    out.extend(parse_searches(&conn, path));
    out.extend(parse_applications(&conn, path));
    out.extend(parse_saved_jobs(&conn, path));
    out
}

fn parse_searches(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let table = if table_exists(conn, "job_searches") {
        "job_searches"
    } else if table_exists(conn, "search_history") {
        "search_history"
    } else {
        return Vec::new();
    };
    let sql = format!(
        "SELECT keywords, location, searched_at \
         FROM \"{t}\" ORDER BY searched_at DESC LIMIT 5000",
        t = table.replace('"', "\"\"")
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
        let keywords = keywords.unwrap_or_else(|| "(unknown)".to_string());
        let location = location.unwrap_or_default();
        let ts = searched_ms.and_then(unix_ms_to_i64);
        let title = format!("Indeed search: {} in {}", keywords, location);
        let detail = format!(
            "Indeed job_search keywords='{}' location='{}' searched_at='{}'",
            keywords,
            location,
            fmt_ts(ts)
        );
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "Indeed Job Search",
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

fn parse_applications(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let table = if table_exists(conn, "job_applications") {
        "job_applications"
    } else if table_exists(conn, "applications") {
        "applications"
    } else {
        return Vec::new();
    };
    let sql = format!(
        "SELECT job_id, company, title, location, applied_at, status \
         FROM \"{t}\" ORDER BY applied_at DESC LIMIT 5000",
        t = table.replace('"', "\"\"")
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
            row.get::<_, Option<String>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (job_id, company, title, location, applied_ms, status) in rows.flatten() {
        let job_id = job_id.unwrap_or_default();
        let company = company.unwrap_or_else(|| "(unknown)".to_string());
        let title_str = title.unwrap_or_default();
        let location = location.unwrap_or_default();
        let status = status.unwrap_or_default();
        let ts = applied_ms.and_then(unix_ms_to_i64);
        let record_title = format!("Indeed application: {} at {}", title_str, company);
        let detail = format!(
            "Indeed job_application id='{}' company='{}' title='{}' location='{}' \
             applied_at='{}' status='{}'",
            job_id,
            company,
            title_str,
            location,
            fmt_ts(ts),
            status
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Indeed Job Application",
            record_title,
            detail,
            path,
            ts,
            ForensicValue::High,
            false,
        ));
    }
    out
}

fn parse_saved_jobs(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let table = if table_exists(conn, "saved_jobs") {
        "saved_jobs"
    } else if table_exists(conn, "bookmarked_jobs") {
        "bookmarked_jobs"
    } else {
        return Vec::new();
    };
    let sql = format!(
        "SELECT job_id, company, title, location, saved_at \
         FROM \"{t}\" ORDER BY saved_at DESC LIMIT 5000",
        t = table.replace('"', "\"\"")
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
    for (job_id, company, title, location, saved_ms) in rows.flatten() {
        let job_id = job_id.unwrap_or_default();
        let company = company.unwrap_or_else(|| "(unknown)".to_string());
        let title_str = title.unwrap_or_default();
        let location = location.unwrap_or_default();
        let ts = saved_ms.and_then(unix_ms_to_i64);
        let record_title = format!("Indeed saved job: {} at {}", title_str, company);
        let detail = format!(
            "Indeed saved_job id='{}' company='{}' title='{}' location='{}' saved_at='{}'",
            job_id,
            company,
            title_str,
            location,
            fmt_ts(ts)
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Indeed Saved Job",
            record_title,
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
            CREATE TABLE job_searches (
                keywords TEXT,
                location TEXT,
                searched_at INTEGER
            );
            INSERT INTO job_searches VALUES('software engineer','Chicago, IL',1700000000000);
            CREATE TABLE job_applications (
                job_id TEXT,
                company TEXT,
                title TEXT,
                location TEXT,
                applied_at INTEGER,
                status TEXT
            );
            INSERT INTO job_applications VALUES('ind-501','Acme Corp','Backend Engineer','Chicago, IL',1700100000000,'submitted');
            CREATE TABLE saved_jobs (
                job_id TEXT,
                company TEXT,
                title TEXT,
                location TEXT,
                saved_at INTEGER
            );
            INSERT INTO saved_jobs VALUES('ind-502','Globex Inc','Staff Engineer','Remote',1700150000000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_search_application_and_saved() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Indeed Job Search"));
        assert!(r.iter().any(|a| a.subcategory == "Indeed Job Application"));
        assert!(r.iter().any(|a| a.subcategory == "Indeed Saved Job"));
    }

    #[test]
    fn application_captures_status_and_company() {
        let db = make_db();
        let r = parse(db.path());
        let apps: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "Indeed Job Application")
            .collect();
        assert_eq!(apps.len(), 1);
        assert!(apps[0].detail.contains("company='Acme Corp'"));
        assert!(apps[0].detail.contains("status='submitted'"));
    }

    #[test]
    fn search_keywords_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.subcategory == "Indeed Job Search"
                && a.title.contains("software engineer")));
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
