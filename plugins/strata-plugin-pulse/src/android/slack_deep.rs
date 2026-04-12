//! Slack — deep thread, file-share, and reaction parsing.
//!
//! Source path: `/data/data/com.Slack/databases/`.
//!
//! Schema note: not in ALEAPP upstream. Supplements any basic Slack parser
//! with thread metadata, file shares, and emoji reactions which are forensically
//! significant for establishing communication context and document exchange.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.slack/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for table in &["threads", "thread_messages", "slack_threads"] {
        if table_exists(&conn, table) {
            out.extend(read_threads(&conn, path, table));
            break;
        }
    }
    for table in &["file_shares", "shared_files", "files"] {
        if table_exists(&conn, table) {
            out.extend(read_file_shares(&conn, path, table));
            break;
        }
    }
    for table in &["reactions", "message_reactions", "emoji_reactions"] {
        if table_exists(&conn, table) {
            out.extend(read_reactions(&conn, path, table));
            break;
        }
    }
    out
}

fn read_threads(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT thread_ts, reply_count, latest_reply, channel_id \
         FROM \"{t}\" ORDER BY thread_ts DESC LIMIT 10000",
        t = table.replace('"', "\"\"")
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (thread_ts, reply_count, latest_reply, channel_id) in rows.flatten() {
        let thread_ts = thread_ts.unwrap_or_default();
        let reply_count = reply_count.unwrap_or(0);
        let latest_reply = latest_reply.unwrap_or_default();
        let channel_id = channel_id.unwrap_or_default();
        let ts_secs: Option<i64> = thread_ts
            .split('.')
            .next()
            .and_then(|s| s.parse::<i64>().ok());
        let title = format!("Slack thread {} ({} replies)", thread_ts, reply_count);
        let detail = format!(
            "Slack thread thread_ts='{}' reply_count={} latest_reply='{}' channel_id='{}'",
            thread_ts, reply_count, latest_reply, channel_id
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Slack Thread",
            title,
            detail,
            path,
            ts_secs,
            ForensicValue::High,
            false,
        ));
    }
    out
}

fn read_file_shares(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT file_name, file_type, file_size, uploader, channel_id, shared_at \
         FROM \"{t}\" ORDER BY shared_at DESC LIMIT 5000",
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
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (file_name, file_type, file_size, uploader, channel_id, ts_ms) in rows.flatten() {
        let file_name = file_name.unwrap_or_else(|| "(unknown)".to_string());
        let file_type = file_type.unwrap_or_default();
        let file_size = file_size.unwrap_or(0);
        let uploader = uploader.unwrap_or_default();
        let channel_id = channel_id.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("Slack file share: {} by {}", file_name, uploader);
        let detail = format!(
            "Slack file_share file_name='{}' file_type='{}' file_size={} uploader='{}' channel_id='{}'",
            file_name, file_type, file_size, uploader, channel_id
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Slack File Share",
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

fn read_reactions(conn: &rusqlite::Connection, path: &Path, table: &str) -> Vec<ArtifactRecord> {
    let sql = format!(
        "SELECT emoji, user_id, message_ts, channel_id \
         FROM \"{t}\" ORDER BY message_ts DESC LIMIT 10000",
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
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (emoji, user_id, message_ts, channel_id) in rows.flatten() {
        let emoji = emoji.unwrap_or_default();
        let user_id = user_id.unwrap_or_default();
        let message_ts = message_ts.unwrap_or_default();
        let channel_id = channel_id.unwrap_or_default();
        let ts_secs: Option<i64> = message_ts
            .split('.')
            .next()
            .and_then(|s| s.parse::<i64>().ok());
        let title = format!("Slack reaction :{}: by {} on {}", emoji, user_id, message_ts);
        let detail = format!(
            "Slack reaction emoji='{}' user_id='{}' message_ts='{}' channel_id='{}'",
            emoji, user_id, message_ts, channel_id
        );
        out.push(build_record(
            ArtifactCategory::Communications,
            "Slack Reaction",
            title,
            detail,
            path,
            ts_secs,
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
            CREATE TABLE threads (
                thread_ts TEXT,
                reply_count INTEGER,
                latest_reply TEXT,
                channel_id TEXT
            );
            INSERT INTO threads VALUES('1609459200.000100',5,'1609459500.000200','C001');
            CREATE TABLE file_shares (
                file_name TEXT,
                file_type TEXT,
                file_size INTEGER,
                uploader TEXT,
                channel_id TEXT,
                shared_at INTEGER
            );
            INSERT INTO file_shares VALUES('report.pdf','pdf',204800,'alice','C001',1609459200000);
            CREATE TABLE reactions (
                emoji TEXT,
                user_id TEXT,
                message_ts TEXT,
                channel_id TEXT
            );
            INSERT INTO reactions VALUES('thumbsup','U001','1609459200.000100','C001');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_threads_files_reactions() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "Slack Thread"));
        assert!(r.iter().any(|a| a.subcategory == "Slack File Share"));
        assert!(r.iter().any(|a| a.subcategory == "Slack Reaction"));
    }

    #[test]
    fn thread_reply_count_in_title() {
        let db = make_db();
        let r = parse(db.path());
        let t = r.iter().find(|a| a.subcategory == "Slack Thread").unwrap();
        assert!(t.title.contains("5 replies"));
    }

    #[test]
    fn file_share_detail_has_size() {
        let db = make_db();
        let r = parse(db.path());
        let f = r.iter().find(|a| a.subcategory == "Slack File Share").unwrap();
        assert!(f.detail.contains("file_size=204800"));
        assert!(f.detail.contains("uploader='alice'"));
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
