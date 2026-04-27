//! Blackboard — Blackboard Learn mobile LMS.
//!
//! Source path: `/data/data/com.blackboard.android.bbstudent/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Blackboard caches courses,
//! announcements, grades, and discussion posts.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.blackboard.android.bbstudent/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "course") {
        out.extend(read_courses(&conn, path));
    }
    if table_exists(&conn, "announcement") {
        out.extend(read_announcements(&conn, path));
    }
    if table_exists(&conn, "discussion_post") {
        out.extend(read_posts(&conn, path));
    }
    out
}

fn read_courses(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, name, course_code, instructor, semester \
               FROM course LIMIT 1000";
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
            row.get::<_, Option<String>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, name, course_code, instructor, semester) in rows.flatten() {
        let id = id.unwrap_or_default();
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let course_code = course_code.unwrap_or_default();
        let instructor = instructor.unwrap_or_default();
        let semester = semester.unwrap_or_default();
        let title = format!("Blackboard course: {} ({})", name, course_code);
        let detail = format!(
            "Blackboard course id='{}' name='{}' course_code='{}' instructor='{}' semester='{}'",
            id, name, course_code, instructor, semester
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Blackboard Course",
            title,
            detail,
            path,
            None,
            ForensicValue::Medium,
            false,
        ));
    }
    out
}

fn read_announcements(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, course_id, title, body, posted_at, author \
               FROM announcement ORDER BY posted_at DESC LIMIT 5000";
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
    for (id, course_id, announcement_title, body, ts_ms, author) in rows.flatten() {
        let id = id.unwrap_or_default();
        let course_id = course_id.unwrap_or_default();
        let announcement_title = announcement_title.unwrap_or_else(|| "(unnamed)".to_string());
        let body = body.unwrap_or_default();
        let author = author.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title_str = format!("Blackboard announcement: {}", announcement_title);
        let detail = format!(
            "Blackboard announcement id='{}' course_id='{}' title='{}' body='{}' author='{}'",
            id, course_id, announcement_title, body, author
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Blackboard Announcement",
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

fn read_posts(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, course_id, thread_id, author, body, posted_at \
               FROM discussion_post ORDER BY posted_at DESC LIMIT 5000";
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
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, course_id, thread_id, author, body, ts_ms) in rows.flatten() {
        let id = id.unwrap_or_default();
        let course_id = course_id.unwrap_or_default();
        let thread_id = thread_id.unwrap_or_default();
        let author = author.unwrap_or_default();
        let body = body.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let preview: String = body.chars().take(120).collect();
        let title = format!("Blackboard post: {} — {}", author, preview);
        let detail = format!(
            "Blackboard discussion post id='{}' course_id='{}' thread_id='{}' author='{}' body='{}'",
            id, course_id, thread_id, author, body
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Blackboard Post",
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
            CREATE TABLE course (
                id TEXT,
                name TEXT,
                course_code TEXT,
                instructor TEXT,
                semester TEXT
            );
            INSERT INTO course VALUES('c1','Organic Chemistry','CHEM201','Dr. Johnson','Spring 2025');
            CREATE TABLE announcement (
                id TEXT,
                course_id TEXT,
                title TEXT,
                body TEXT,
                posted_at INTEGER,
                author TEXT
            );
            INSERT INTO announcement VALUES('a1','c1','Exam reminder','Midterm next Tuesday',1609459200000,'Dr. Johnson');
            CREATE TABLE discussion_post (
                id TEXT,
                course_id TEXT,
                thread_id TEXT,
                author TEXT,
                body TEXT,
                posted_at INTEGER
            );
            INSERT INTO discussion_post VALUES('p1','c1','t1','student1','What about problem 3?',1609459300000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_course_announcement_post() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Blackboard Course"));
        assert!(r.iter().any(|a| a.subcategory == "Blackboard Announcement"));
        assert!(r.iter().any(|a| a.subcategory == "Blackboard Post"));
    }

    #[test]
    fn instructor_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("instructor='Dr. Johnson'")));
    }

    #[test]
    fn discussion_body_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("body='What about problem 3?'")));
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
