//! Canvas — Instructure Canvas student LMS.
//!
//! Source path: `/data/data/com.instructure.candroid/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Canvas caches courses,
//! assignments, announcements, and grades.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.instructure.candroid/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "course") {
        out.extend(read_courses(&conn, path));
    }
    if table_exists(&conn, "assignment") {
        out.extend(read_assignments(&conn, path));
    }
    if table_exists(&conn, "grade") {
        out.extend(read_grades(&conn, path));
    }
    out
}

fn read_courses(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, name, course_code, enrollment_state, \
               term, start_at, end_at \
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
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<i64>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, name, course_code, enrollment_state, term, start_ms, _end_ms) in rows.flatten() {
        let id = id.unwrap_or_default();
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let course_code = course_code.unwrap_or_default();
        let enrollment_state = enrollment_state.unwrap_or_default();
        let term = term.unwrap_or_default();
        let ts = start_ms.and_then(unix_ms_to_i64);
        let title = format!("Canvas course: {} ({})", name, course_code);
        let detail = format!(
            "Canvas course id='{}' name='{}' course_code='{}' enrollment_state='{}' term='{}'",
            id, name, course_code, enrollment_state, term
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Canvas Course",
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

fn read_assignments(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, course_id, name, due_at, points_possible, \
               submission_types, has_submitted \
               FROM assignment ORDER BY due_at DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<f64>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
            row.get::<_, Option<i64>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, course_id, name, due_ms, points_possible, submission_types, has_submitted) in rows.flatten() {
        let id = id.unwrap_or_default();
        let course_id = course_id.unwrap_or_default();
        let name = name.unwrap_or_else(|| "(unnamed)".to_string());
        let points_possible = points_possible.unwrap_or(0.0);
        let submission_types = submission_types.unwrap_or_default();
        let has_submitted = has_submitted.unwrap_or(0) != 0;
        let ts = due_ms.and_then(unix_ms_to_i64);
        let title = format!("Canvas assignment: {}", name);
        let detail = format!(
            "Canvas assignment id='{}' course_id='{}' name='{}' points_possible={:.0} submission_types='{}' has_submitted={}",
            id, course_id, name, points_possible, submission_types, has_submitted
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Canvas Assignment",
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

fn read_grades(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT assignment_id, course_id, score, grade, \
               submitted_at, graded_at \
               FROM grade ORDER BY graded_at DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<f64>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (assignment_id, course_id, score, grade, submitted_ms, graded_ms) in rows.flatten() {
        let assignment_id = assignment_id.unwrap_or_default();
        let course_id = course_id.unwrap_or_default();
        let score = score.unwrap_or(0.0);
        let grade = grade.unwrap_or_default();
        let ts = graded_ms.or(submitted_ms).and_then(unix_ms_to_i64);
        let title = format!("Canvas grade: {} ({:.1})", grade, score);
        let detail = format!(
            "Canvas grade assignment_id='{}' course_id='{}' score={:.2} grade='{}'",
            assignment_id, course_id, score, grade
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Canvas Grade",
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
                enrollment_state TEXT,
                term TEXT,
                start_at INTEGER,
                end_at INTEGER
            );
            INSERT INTO course VALUES('c1','Intro to CS','CS101','active','Fall 2024',1609459200000,1609459300000);
            CREATE TABLE assignment (
                id TEXT,
                course_id TEXT,
                name TEXT,
                due_at INTEGER,
                points_possible REAL,
                submission_types TEXT,
                has_submitted INTEGER
            );
            INSERT INTO assignment VALUES('a1','c1','Homework 1',1609459300000,100.0,'online_upload',1);
            CREATE TABLE grade (
                assignment_id TEXT,
                course_id TEXT,
                score REAL,
                grade TEXT,
                submitted_at INTEGER,
                graded_at INTEGER
            );
            INSERT INTO grade VALUES('a1','c1',85.0,'B',1609459400000,1609459500000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_course_assignment_grade() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Canvas Course"));
        assert!(r.iter().any(|a| a.subcategory == "Canvas Assignment"));
        assert!(r.iter().any(|a| a.subcategory == "Canvas Grade"));
    }

    #[test]
    fn assignment_has_submitted_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.detail.contains("has_submitted=true")));
    }

    #[test]
    fn grade_score_and_letter() {
        let db = make_db();
        let r = parse(db.path());
        let g = r.iter().find(|a| a.subcategory == "Canvas Grade").unwrap();
        assert!(g.detail.contains("score=85.00"));
        assert!(g.detail.contains("grade='B'"));
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
