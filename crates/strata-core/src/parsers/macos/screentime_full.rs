//! Screen Time (knowledgeC.db) full parser.
//!
//! macOS exposes Screen Time data in two places:
//!
//!   1. `~/Library/Application Support/Knowledge/knowledgeC.db` — the
//!      Knowledge graph database (rich, per-event records).
//!   2. `RMAdminStore.sqlite` — Screen Time enforcement state (covered by
//!      the existing `MacosScreentimeParser`).
//!
//! This parser pulls structured Screen Time-relevant streams out of
//! knowledgeC.db's `ZOBJECT` table:
//!
//!   * `/app/usage` — per-app foreground duration
//!   * `/app/inFocus` — focus events
//!   * `/safari/history` — Safari URL events
//!   * `/notification/usage` — notification interactions
//!
//! Forensic value:
//! knowledgeC.db is the most reliable record of *what app the user was using
//! at what time*, including how long the session lasted. Combined with
//! Screen Time enforcement (RMAdminStore), it gives you both the user's
//! actual activity and the limits/restrictions placed on them.

use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::sqlite_utils::{table_exists, with_sqlite_connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

const COREDATA_EPOCH_OFFSET: i64 = 978_307_200;
const KC_LIMIT: usize = 5000;

pub struct MacosScreentimeFullParser;

impl MacosScreentimeFullParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MacosScreentimeFullParser {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KnowledgeUsageEvent {
    pub stream_name: String,
    pub bundle_id: Option<String>,
    pub start_time: Option<i64>,
    pub end_time: Option<i64>,
    pub duration_seconds: Option<i64>,
    pub source: String,
}

impl ArtifactParser for MacosScreentimeFullParser {
    fn name(&self) -> &str {
        "macOS Screen Time (knowledgeC)"
    }

    fn artifact_type(&self) -> &str {
        "user_activity"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["knowledgec.db", "/knowledge/knowledgec.db"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let path_str = path.to_string_lossy().to_lowercase();
        // Differentiate the macOS Screen Time copy from the iOS biome copy by
        // requiring the macOS-specific Knowledge directory in the path.
        if !path_str.contains("/knowledge/knowledgec.db") {
            return Ok(Vec::new());
        }

        let mut artifacts = Vec::new();
        let result = with_sqlite_connection(path, data, |conn| {
            let mut entries: Vec<ParsedArtifact> = Vec::new();
            if !table_exists(conn, "ZOBJECT") {
                return Ok(entries);
            }

            // Pull only the streams that map to Screen Time-style events.
            let sql = format!(
                "SELECT ZSTREAMNAME, ZVALUESTRING, ZSTARTDATE, ZENDDATE \
                 FROM ZOBJECT \
                 WHERE ZSTREAMNAME IN ('/app/usage','/app/inFocus','/safari/history',\
                 '/notification/usage','/display/isBacklit') \
                 LIMIT {}",
                KC_LIMIT
            );
            let mut stmt = conn
                .prepare(&sql)
                .map_err(|e| ParserError::Database(e.to_string()))?;
            let rows = stmt
                .query_map([], |row| {
                    let stream_name: String =
                        row.get::<_, String>(0).unwrap_or_else(|_| "unknown".into());
                    let value: Option<String> = row.get(1).ok();
                    let start = row.get::<_, f64>(2).ok();
                    let end = row.get::<_, f64>(3).ok();
                    let start_unix = start.map(|s| s as i64 + COREDATA_EPOCH_OFFSET);
                    let end_unix = end.map(|s| s as i64 + COREDATA_EPOCH_OFFSET);
                    let duration = match (start, end) {
                        (Some(s), Some(e)) if e >= s => Some((e - s) as i64),
                        _ => None,
                    };
                    Ok(KnowledgeUsageEvent {
                        stream_name,
                        bundle_id: value,
                        start_time: start_unix,
                        end_time: end_unix,
                        duration_seconds: duration,
                        source: "knowledgeC.db".to_string(),
                    })
                })
                .map_err(|e| ParserError::Database(e.to_string()))?;

            for entry in rows.flatten() {
                entries.push(ParsedArtifact {
                    timestamp: entry.start_time,
                    artifact_type: "user_activity".to_string(),
                    description: format!(
                        "Screen Time event ({}): {} ({}s)",
                        entry.stream_name,
                        entry.bundle_id.as_deref().unwrap_or(""),
                        entry.duration_seconds.unwrap_or(0)
                    ),
                    source_path: path.to_string_lossy().to_string(),
                    json_data: serde_json::to_value(entry).unwrap_or_default(),
                });
            }
            Ok(entries)
        });
        if let Ok(mut entries) = result {
            artifacts.append(&mut entries);
        }
        Ok(artifacts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn knowledge_path() -> PathBuf {
        PathBuf::from("/Users/test/Library/Application Support/Knowledge/knowledgeC.db")
    }

    fn build_test_kc(dir: &TempDir) -> PathBuf {
        let db_path = dir.path().join("knowledgeC.db");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE ZOBJECT (
                Z_PK INTEGER PRIMARY KEY,
                ZSTREAMNAME TEXT,
                ZVALUESTRING TEXT,
                ZSTARTDATE REAL,
                ZENDDATE REAL
            );
            INSERT INTO ZOBJECT VALUES
                (1, '/app/usage', 'com.apple.Safari', 700000000.0, 700000600.0),
                (2, '/app/inFocus', 'com.apple.mail', 700000700.0, 700000800.0),
                (3, '/safari/history', 'https://example.com', 700000900.0, 700000910.0),
                (4, '/random/stream', 'should-be-skipped', 700001000.0, 700001010.0);",
        )
        .unwrap();
        db_path
    }

    #[test]
    fn parses_screen_time_events_only() {
        let dir = TempDir::new().unwrap();
        let db = build_test_kc(&dir);
        let data = std::fs::read(&db).unwrap();
        let parser = MacosScreentimeFullParser::new();
        let out = parser.parse_file(&knowledge_path(), &data).unwrap();
        // The parser whitelists app/usage, app/inFocus, safari/history,
        // notification/usage, display/isBacklit. /random/stream is skipped.
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn computes_duration_seconds() {
        let dir = TempDir::new().unwrap();
        let db = build_test_kc(&dir);
        let data = std::fs::read(&db).unwrap();
        let parser = MacosScreentimeFullParser::new();
        let out = parser.parse_file(&knowledge_path(), &data).unwrap();
        let safari = out
            .iter()
            .find(|a| {
                a.json_data
                    .get("bundle_id")
                    .and_then(|v| v.as_str())
                    == Some("com.apple.Safari")
            })
            .unwrap();
        assert_eq!(
            safari
                .json_data
                .get("duration_seconds")
                .and_then(|v| v.as_i64()),
            Some(600)
        );
    }

    #[test]
    fn ignores_non_knowledge_paths() {
        let parser = MacosScreentimeFullParser::new();
        let path = PathBuf::from("/Users/test/Library/Other/knowledgeC.db");
        let out = parser.parse_file(&path, b"x").unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn timestamp_uses_unix_epoch() {
        let dir = TempDir::new().unwrap();
        let db = build_test_kc(&dir);
        let data = std::fs::read(&db).unwrap();
        let parser = MacosScreentimeFullParser::new();
        let out = parser.parse_file(&knowledge_path(), &data).unwrap();
        // 700_000_000 + 978_307_200 = 1_678_307_200
        assert!(out.iter().any(|a| a.timestamp == Some(1_678_307_200)));
    }
}
