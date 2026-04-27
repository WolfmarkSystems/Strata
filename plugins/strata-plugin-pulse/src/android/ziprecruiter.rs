//! ZipRecruiter — Android job search, application, and profile view extraction.
//!
//! Source path: `/data/data/com.ziprecruiter.android.release/databases/*`.
//!
//! Schema note: not in ALEAPP upstream. ZipRecruiter uses Room databases with
//! tables like `job_searches`, `job_applications`, `profile_views`. Profile
//! views reveal which employers or candidates the subject investigated and
//! are classified High forensic value.

use crate::android::helpers::{build_record, fmt_ts, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.ziprecruiter.android.release/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    out.extend(parse_searches(&conn, path));
    out.extend(parse_applications(&conn, path));
    out.extend(parse_profile_views(&conn, path));
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
        let title = format!("ZipRecruiter search: {} in {}", keywords, location);
        let detail = format!(
            "ZipRecruiter job_search keywords='{}' location='{}' searched_at='{}'",
            keywords,
            location,
            fmt_ts(ts)
        );
        out.push(build_record(
            ArtifactCategory::WebActivity,
            "ZipRecruiter Job Search",
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
        let record_title = format!("ZipRecruiter application: {} at {}", title_str, company);
        let detail = format!(
            "ZipRecruiter job_application id='{}' company='{}' title='{}' location='{}' \
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
            "ZipRecruiter Job Application",
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

fn parse_profile_views(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let table = if table_exists(conn, "profile_views") {
        "profile_views"
    } else if table_exists(conn, "employer_profile_views") {
        "employer_profile_views"
    } else {
        return Vec::new();
    };
    let sql = format!(
        "SELECT profile_id, profile_name, profile_type, viewed_at \
         FROM \"{t}\" ORDER BY viewed_at DESC LIMIT 5000",
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
            row.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (profile_id, profile_name, profile_type, viewed_ms) in rows.flatten() {
        let profile_id = profile_id.unwrap_or_default();
        let profile_name = profile_name.unwrap_or_else(|| "(unknown)".to_string());
        let profile_type = profile_type.unwrap_or_default();
        let ts = viewed_ms.and_then(unix_ms_to_i64);
        let title = format!("ZipRecruiter profile view: {}", profile_name);
        let detail = format!(
            "ZipRecruiter profile_view id='{}' name='{}' type='{}' viewed_at='{}'",
            profile_id,
            profile_name,
            profile_type,
            fmt_ts(ts)
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "ZipRecruiter Profile View",
            title,
            detail,
            path,
            ts,
            ForensicValue::High,
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
            INSERT INTO job_searches VALUES('warehouse supervisor','Phoenix, AZ',1700000000000);
            CREATE TABLE job_applications (
                job_id TEXT,
                company TEXT,
                title TEXT,
                location TEXT,
                applied_at INTEGER,
                status TEXT
            );
            INSERT INTO job_applications VALUES('zr-8001','Pinnacle Logistics','Warehouse Supervisor','Phoenix, AZ',1700100000000,'viewed');
            CREATE TABLE profile_views (
                profile_id TEXT,
                profile_name TEXT,
                profile_type TEXT,
                viewed_at INTEGER
            );
            INSERT INTO profile_views VALUES('emp-301','Pinnacle Logistics','employer',1700050000000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_search_application_and_profile_view() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "ZipRecruiter Job Search"));
        assert!(r
            .iter()
            .any(|a| a.subcategory == "ZipRecruiter Job Application"));
        assert!(r
            .iter()
            .any(|a| a.subcategory == "ZipRecruiter Profile View"));
    }

    #[test]
    fn application_captures_company_and_status() {
        let db = make_db();
        let r = parse(db.path());
        let apps: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "ZipRecruiter Job Application")
            .collect();
        assert_eq!(apps.len(), 1);
        assert!(apps[0].detail.contains("company='Pinnacle Logistics'"));
        assert!(apps[0].detail.contains("status='viewed'"));
    }

    #[test]
    fn profile_view_captures_type_and_name() {
        let db = make_db();
        let r = parse(db.path());
        let views: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "ZipRecruiter Profile View")
            .collect();
        assert_eq!(views.len(), 1);
        assert!(views[0].detail.contains("name='Pinnacle Logistics'"));
        assert!(views[0].detail.contains("type='employer'"));
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
