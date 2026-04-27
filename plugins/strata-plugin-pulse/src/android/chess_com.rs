//! Chess.com — game and message extraction.
//!
//! ALEAPP references: `ChessComGames.py` and `ChessComMessages.py`. Source:
//! `/data/data/com.chess/databases/chess-database*`.
//!
//! Key tables: `daily_games`, `messages`.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.chess/databases/chess-database"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "daily_games") {
        out.extend(read_games(&conn, path));
    }
    if table_exists(&conn, "messages") {
        out.extend(read_messages(&conn, path));
    }
    out
}

fn read_games(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT game_id, game_start_time, timestamp, \
               white_username, black_username, is_opponent_friend, result_message \
               FROM daily_games \
               ORDER BY game_start_time DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<String>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, start, _updated, white, black, friend, result) in rows.flatten() {
        let id = id.unwrap_or(0);
        let white = white.unwrap_or_else(|| "(unknown)".to_string());
        let black = black.unwrap_or_else(|| "(unknown)".to_string());
        let ts = start; // Unix seconds
        let is_friend = friend.unwrap_or(0) != 0;
        let result = result.unwrap_or_default();
        let title = format!("Chess.com game #{}: {} vs {}", id, white, black);
        let detail = format!(
            "Chess.com game id={} white='{}' black='{}' friend_game={} result='{}'",
            id, white, black, is_friend, result
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "Chess.com Game",
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

fn read_messages(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT created_at, conversation_id, sender_username, content \
               FROM messages \
               ORDER BY created_at DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (created_ms, conv, sender, content) in rows.flatten() {
        let sender = sender.unwrap_or_else(|| "(unknown)".to_string());
        let body = content.unwrap_or_default();
        let conv = conv.unwrap_or_default();
        let ts = created_ms.and_then(unix_ms_to_i64);
        let preview: String = body.chars().take(120).collect();
        let title = format!("Chess.com {}: {}", sender, preview);
        let detail = format!(
            "Chess.com message sender='{}' conversation='{}' body='{}'",
            sender, conv, body
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Chess.com Message",
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
            CREATE TABLE daily_games (
                game_id INTEGER,
                game_start_time INTEGER,
                timestamp INTEGER,
                white_username TEXT,
                black_username TEXT,
                is_opponent_friend INTEGER,
                result_message TEXT
            );
            INSERT INTO daily_games VALUES(1001,1609459200,1609459400,'magnus','hikaru',1,'White won by resignation');
            INSERT INTO daily_games VALUES(1002,1609545600,1609545900,'fabi','levy',0,'Draw');
            CREATE TABLE messages (
                created_at INTEGER,
                conversation_id TEXT,
                sender_username TEXT,
                content TEXT
            );
            INSERT INTO messages VALUES(1609459500000,'conv_1','magnus','Good game!');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_games_and_messages() {
        let db = make_db();
        let r = parse(db.path());
        let games: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "Chess.com Game")
            .collect();
        let msgs: Vec<_> = r
            .iter()
            .filter(|a| a.subcategory == "Chess.com Message")
            .collect();
        assert_eq!(games.len(), 2);
        assert_eq!(msgs.len(), 1);
    }

    #[test]
    fn friend_flag_in_detail() {
        let db = make_db();
        let r = parse(db.path());
        let g1 = r.iter().find(|a| a.detail.contains("id=1001")).unwrap();
        assert!(g1.detail.contains("friend_game=true"));
        assert!(g1.detail.contains("result='White won by resignation'"));
    }

    #[test]
    fn message_sender_captured() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.title.contains("magnus") && a.title.contains("Good game")));
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
