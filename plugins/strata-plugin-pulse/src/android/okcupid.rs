//! OkCupid — dating app matches/likes, messages, and profile questions answered.
//!
//! Source path: `/data/data/com.okcupid.okcupid/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. OkCupid uses Room databases with
//! tables like `match`, `like`, `message`, `question_answer`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.okcupid.okcupid/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["match", "matches", "liked_profile"] {
        if table_exists(&conn, table) {
            out.extend(read_matches(&conn, path, table));
            break;
        }
    }
    for table in &["message", "messages", "conversation_message"] {
        if table_exists(&conn, table) {
            out.extend(read_messages(&conn, path, table));
            break;
        }
    }
    for table in &["question_answer", "profile_answer", "answer"] {
        if table_exists(&conn, table) {
            out.extend(read_answers(&conn, path, table));
            break;
        }
    }
    out
}

fn read_matches(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, user_id, username, age, match_percentage, liked_at \
         FROM \"{table}\" ORDER BY liked_at DESC LIMIT 5000",
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
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, user_id, username, age, match_pct, liked_ms) in rows.flatten() {
        let id = id.unwrap_or_default();
        let user_id = user_id.unwrap_or_default();
        let username = username.unwrap_or_else(|| "(no name)".to_string());
        let ts = liked_ms.and_then(unix_ms_to_i64);
        let title = format!("OkCupid like: {}", username);
        let mut detail = format!(
            "OkCupid like id='{}' user_id='{}' username='{}'",
            id, user_id, username
        );
        if let Some(a) = age {
            detail.push_str(&format!(" age={}", a));
        }
        if let Some(pct) = match_pct {
            detail.push_str(&format!(" match_pct={}%", pct));
        }
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "OkCupid Like",
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

fn read_messages(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT id, sender_id, recipient_id, body, sent_at, is_incoming \
         FROM \"{table}\" ORDER BY sent_at DESC LIMIT 10000",
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
    for (id, sender, recipient, body, sent_ms, is_incoming) in rows.flatten() {
        let id = id.unwrap_or_default();
        let sender = sender.unwrap_or_else(|| "(unknown)".to_string());
        let recipient = recipient.unwrap_or_else(|| "(unknown)".to_string());
        let body = body.unwrap_or_default();
        let direction = if is_incoming.unwrap_or(0) == 1 {
            "incoming"
        } else {
            "outgoing"
        };
        let ts = sent_ms.and_then(unix_ms_to_i64);
        let preview: String = body.chars().take(120).collect();
        let title = format!("OkCupid {} msg {}: {}", direction, sender, preview);
        let detail = format!(
            "OkCupid message id='{}' sender='{}' recipient='{}' direction='{}' body='{}'",
            id, sender, recipient, direction, body
        );
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "OkCupid Message",
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

fn read_answers(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT question_id, question_text, answer_text, answered_at \
         FROM \"{table}\" ORDER BY answered_at DESC LIMIT 2000",
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
            row.get::<_, Option<i64>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (question_id, question_text, answer_text, answered_ms) in rows.flatten() {
        let question_id = question_id.unwrap_or_default();
        let question = question_text.unwrap_or_else(|| "(no question)".to_string());
        let answer = answer_text.unwrap_or_default();
        let ts = answered_ms.and_then(unix_ms_to_i64);
        let title = format!("OkCupid answer: {}", question);
        let detail = format!(
            "OkCupid question answer question_id='{}' question='{}' answer='{}'",
            question_id, question, answer
        );
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "OkCupid Answer",
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
            CREATE TABLE "match" (
                id TEXT,
                user_id TEXT,
                username TEXT,
                age INTEGER,
                match_percentage INTEGER,
                liked_at INTEGER
            );
            INSERT INTO "match" VALUES('l1','u1','Ashley',27,85,1609459200000);
            CREATE TABLE message (
                id TEXT,
                sender_id TEXT,
                recipient_id TEXT,
                body TEXT,
                sent_at INTEGER,
                is_incoming INTEGER
            );
            INSERT INTO message VALUES('m1','u1','me','Hey!',1609459300000,1);
            CREATE TABLE question_answer (
                question_id TEXT,
                question_text TEXT,
                answer_text TEXT,
                answered_at INTEGER
            );
            INSERT INTO question_answer VALUES('q1','Cats or dogs?','Dogs',1609459000000);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_likes_messages_answers() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "OkCupid Like"));
        assert!(r.iter().any(|a| a.subcategory == "OkCupid Message"));
        assert!(r.iter().any(|a| a.subcategory == "OkCupid Answer"));
    }

    #[test]
    fn match_percentage_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.subcategory == "OkCupid Like" && a.detail.contains("match_pct=85%")));
    }

    #[test]
    fn answer_text_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.subcategory == "OkCupid Answer" && a.detail.contains("answer='Dogs'")));
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
