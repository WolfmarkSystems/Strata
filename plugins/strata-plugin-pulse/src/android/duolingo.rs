//! Duolingo — language learning progress and lesson history.
//!
//! Source path: `/data/data/com.duolingo/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. Duolingo caches user progress,
//! lesson completions, and daily streak data.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.duolingo/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "user_profile") {
        out.extend(read_profile(&conn, path));
    }
    for table in &["lesson_completion", "session_history"] {
        if table_exists(&conn, table) {
            out.extend(read_lessons(&conn, path, table));
            break;
        }
    }
    out
}

fn read_profile(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT username, email, learning_language, from_language, \
               current_streak, total_xp, lingots, created_at \
               FROM user_profile LIMIT 10";
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
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<i64>>(6).unwrap_or(None),
            row.get::<_, Option<i64>>(7).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (username, email, learning_lang, from_lang, streak, xp, lingots, created_ms) in
        rows.flatten()
    {
        let username = username.unwrap_or_default();
        let email = email.unwrap_or_default();
        let learning_lang = learning_lang.unwrap_or_default();
        let from_lang = from_lang.unwrap_or_default();
        let streak = streak.unwrap_or(0);
        let xp = xp.unwrap_or(0);
        let lingots = lingots.unwrap_or(0);
        let ts = created_ms.and_then(unix_ms_to_i64);
        let title = format!("Duolingo: {} ({})", username, learning_lang);
        let detail = format!(
            "Duolingo profile username='{}' email='{}' learning_language='{}' from_language='{}' current_streak={} total_xp={} lingots={}",
            username, email, learning_lang, from_lang, streak, xp, lingots
        );
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "Duolingo Profile",
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

fn read_lessons(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, skill_name, lesson_number, completed_at, xp_earned \
         FROM \"{table}\" ORDER BY completed_at DESC LIMIT 5000",
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
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, skill_name, lesson_number, ts_ms, xp_earned) in rows.flatten() {
        let id = id.unwrap_or_default();
        let skill_name = skill_name.unwrap_or_else(|| "(unknown)".to_string());
        let lesson_number = lesson_number.unwrap_or(0);
        let xp_earned = xp_earned.unwrap_or(0);
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Duolingo lesson: {} #{}", skill_name, lesson_number);
        let detail = format!(
            "Duolingo lesson id='{}' skill_name='{}' lesson_number={} xp_earned={}",
            id, skill_name, lesson_number, xp_earned
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Duolingo Lesson",
            title,
            detail,
            path,
            ts,
            ForensicValue::Low,
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
            CREATE TABLE user_profile (
                username TEXT,
                email TEXT,
                learning_language TEXT,
                from_language TEXT,
                current_streak INTEGER,
                total_xp INTEGER,
                lingots INTEGER,
                created_at INTEGER
            );
            INSERT INTO user_profile VALUES('jane_learner','jane@example.com','es','en',45,12500,320,1609459200000);
            CREATE TABLE lesson_completion (
                id TEXT,
                skill_name TEXT,
                lesson_number INTEGER,
                completed_at INTEGER,
                xp_earned INTEGER
            );
            INSERT INTO lesson_completion VALUES('l1','Basics 1',1,1609459200000,10);
            INSERT INTO lesson_completion VALUES('l2','Basics 1',2,1609459500000,15);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_profile_and_lessons() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Duolingo Profile"));
        assert!(r.iter().any(|a| a.subcategory == "Duolingo Lesson"));
    }

    #[test]
    fn streak_and_xp_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(
            r.iter()
                .any(|a| a.detail.contains("current_streak=45")
                    && a.detail.contains("total_xp=12500"))
        );
    }

    #[test]
    fn email_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.detail.contains("email='jane@example.com'")));
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
