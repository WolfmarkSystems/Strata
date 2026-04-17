//! Windows Recall artifact parser (W-14).
//!
//! Recall lives under `%AppData%\Local\CoreAIPlatform.00\UKP{GUID}\`.
//! The database (`ukg.db`) is SQLite; on many configurations it is
//! encrypted via DPAPI or Windows Hello and sqlite will refuse to
//! open. We handle both paths.
//!
//! MITRE: T1113 (screen capture), T1005.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OpenFlags};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecallCapture {
    pub capture_id: i64,
    pub window_title: Option<String>,
    pub app_name: Option<String>,
    pub app_path: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub ocr_text: Option<String>,
    pub screenshot_path: Option<String>,
}

pub fn is_recall_db_path(path: &Path) -> bool {
    let normalised = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    normalised.ends_with("/ukg.db") && normalised.contains("coreaiplatform.00/ukp")
}

/// Outcome of attempting to open a Recall database.
#[derive(Debug, Clone)]
pub enum RecallOutcome {
    Captures(Vec<RecallCapture>),
    Locked,
    Missing,
}

pub fn parse(path: &Path) -> RecallOutcome {
    if !is_recall_db_path(path) {
        return RecallOutcome::Missing;
    }
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let Ok(conn) = Connection::open_with_flags(path, flags) else {
        return RecallOutcome::Locked;
    };
    match query_captures(&conn) {
        Ok(c) => RecallOutcome::Captures(c),
        Err(_) => RecallOutcome::Locked,
    }
}

fn query_captures(conn: &Connection) -> rusqlite::Result<Vec<RecallCapture>> {
    let sql = "SELECT wc.Id, wc.WindowTitle, wc.AppName, wc.AppPath, \
                      wc.TimeStamp, wc.ImageToken, tc.Text \
               FROM WindowCapture wc \
               LEFT JOIN TextContent tc ON tc.CaptureId = wc.Id \
               ORDER BY wc.TimeStamp ASC";
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map([], |row| {
        let id: i64 = row.get(0)?;
        let title: Option<String> = row.get(1)?;
        let app_name: Option<String> = row.get(2)?;
        let app_path: Option<String> = row.get(3)?;
        let ts_ms: i64 = row.get::<_, Option<i64>>(4)?.unwrap_or(0);
        let image_token: Option<String> = row.get(5)?;
        let text: Option<String> = row.get(6)?;
        Ok((id, title, app_name, app_path, ts_ms, image_token, text))
    })?;
    let mut out = Vec::new();
    for row in rows.flatten() {
        let (id, title, app_name, app_path, ts_ms, image_token, text) = row;
        let secs = ts_ms / 1000;
        let nanos = ((ts_ms % 1000) as u32) * 1_000_000;
        let Some(ts) = DateTime::<Utc>::from_timestamp(secs, nanos) else {
            continue;
        };
        let ocr_text = text.map(|s| s.chars().take(2048).collect::<String>());
        out.push(RecallCapture {
            capture_id: id,
            window_title: title,
            app_name,
            app_path,
            timestamp: ts,
            ocr_text,
            screenshot_path: image_token,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_recall_db_path_recognises_canonical_layout() {
        assert!(is_recall_db_path(Path::new(
            "C:\\Users\\a\\AppData\\Local\\CoreAIPlatform.00\\UKP0123\\ukg.db"
        )));
        assert!(is_recall_db_path(Path::new(
            "/users/a/AppData/Local/CoreAIPlatform.00/UKP0123/ukg.db"
        )));
        assert!(!is_recall_db_path(Path::new("/tmp/ukg.db")));
    }

    #[test]
    fn parse_returns_missing_for_wrong_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("elsewhere.db");
        std::fs::write(&path, b"").expect("write");
        assert!(matches!(parse(&path), RecallOutcome::Missing));
    }

    #[test]
    fn parse_locked_when_not_a_sqlite() {
        let dir = tempfile::tempdir().expect("tempdir");
        let recall = dir
            .path()
            .join("AppData")
            .join("Local")
            .join("CoreAIPlatform.00")
            .join("UKP0001");
        std::fs::create_dir_all(&recall).expect("mkdirs");
        let path = recall.join("ukg.db");
        std::fs::write(&path, b"not-a-sqlite-db").expect("write");
        // On non-Windows the path normalization lowercased fragments match,
        // but sqlite will refuse to open → Locked.
        assert!(matches!(parse(&path), RecallOutcome::Locked));
    }

    #[test]
    fn parse_returns_captures_when_db_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let recall = dir
            .path()
            .join("AppData")
            .join("Local")
            .join("CoreAIPlatform.00")
            .join("UKP0001");
        std::fs::create_dir_all(&recall).expect("mkdirs");
        let path = recall.join("ukg.db");
        let conn = rusqlite::Connection::open(&path).expect("open");
        conn.execute_batch(
            "CREATE TABLE WindowCapture (Id INTEGER PRIMARY KEY, WindowTitle TEXT, AppName TEXT, AppPath TEXT, TimeStamp INTEGER, ImageToken TEXT); \
             CREATE TABLE TextContent (CaptureId INTEGER, Text TEXT, TimeStamp INTEGER);",
        )
        .expect("schema");
        conn.execute(
            "INSERT INTO WindowCapture VALUES (1, 'Notepad', 'notepad.exe', 'C:\\Windows\\System32\\notepad.exe', 1717243200000, 'img-1')",
            [],
        )
        .expect("wc");
        conn.execute(
            "INSERT INTO TextContent VALUES (1, 'malicious note', 1717243200000)",
            [],
        )
        .expect("tc");
        drop(conn);
        let outcome = parse(&path);
        match outcome {
            RecallOutcome::Captures(caps) => {
                assert_eq!(caps.len(), 1);
                assert_eq!(caps[0].window_title.as_deref(), Some("Notepad"));
                assert_eq!(caps[0].ocr_text.as_deref(), Some("malicious note"));
                assert_eq!(caps[0].timestamp.timestamp(), 1_717_243_200);
            }
            _ => panic!("expected Captures"),
        }
    }
}
