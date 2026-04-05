use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::sqlite_utils::{table_exists, with_sqlite_connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct IosCallHistoryParser;

impl IosCallHistoryParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IosCallLogEntry {
    pub id: Option<String>,
    pub address: Option<String>,
    pub date: Option<i64>,
    pub duration_secs: Option<i64>,
    pub flags: Option<i32>,
    pub is_outgoing: bool,
    pub is_video: bool,
    pub service: Option<String>,
}

impl Default for IosCallHistoryParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for IosCallHistoryParser {
    fn name(&self) -> &str {
        "iOS Call History"
    }

    fn artifact_type(&self) -> &str {
        "mobile_call_log"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "callhistory.storedata",
            "call_history.db",
            "callhistorydatabase",
            "calls.db",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        let sqlite_result = with_sqlite_connection(path, data, |conn| {
            let mut parsed = Vec::new();
            parse_zcallrecord(conn, path, &mut parsed);
            parse_call_table(conn, path, &mut parsed);
            Ok(parsed)
        });

        if let Ok(mut parsed) = sqlite_result {
            artifacts.append(&mut parsed);
        }

        if artifacts.is_empty() {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "mobile_call_log".to_string(),
                description: "iOS call history database".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::json!({
                    "note": "Call history database detected, but no readable rows were parsed."
                }),
            });
        }

        Ok(artifacts)
    }
}

fn parse_zcallrecord(conn: &rusqlite::Connection, path: &Path, out: &mut Vec<ParsedArtifact>) {
    if !table_exists(conn, "ZCALLRECORD") {
        return;
    }

    let mut stmt = match conn.prepare(
        "SELECT Z_PK, ZADDRESS, ZDATE, ZDURATION, ZORIGINATED, ZCALLTYPE, ZSERVICE_PROVIDER FROM ZCALLRECORD ORDER BY ZDATE DESC LIMIT 10000",
    ) {
        Ok(stmt) => stmt,
        Err(_) => return,
    };

    let rows = stmt.query_map([], |row| {
        let cocoa_ts: Option<f64> = row.get(2).ok();
        let unix_ts = cocoa_ts.map(|v| (v as i64) + 978_307_200);
        let call_type = row.get::<_, i32>(5).ok();
        Ok(IosCallLogEntry {
            id: row.get::<_, i64>(0).ok().map(|v| v.to_string()),
            address: row.get(1).ok(),
            date: unix_ts,
            duration_secs: row.get(3).ok(),
            flags: call_type,
            is_outgoing: row.get::<_, i32>(4).unwrap_or(0) != 0,
            is_video: call_type.map(|v| v == 8).unwrap_or(false),
            service: row.get(6).ok(),
        })
    });

    let Ok(rows) = rows else {
        return;
    };

    for entry in rows.flatten() {
        out.push(ParsedArtifact {
            timestamp: entry.date,
            artifact_type: "mobile_call_log".to_string(),
            description: format!("iOS call {}", entry.address.as_deref().unwrap_or("unknown")),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
    }
}

fn parse_call_table(conn: &rusqlite::Connection, path: &Path, out: &mut Vec<ParsedArtifact>) {
    if !table_exists(conn, "call") {
        return;
    }

    let mut stmt = match conn.prepare(
        "SELECT ROWID, address, date, duration, flags FROM call ORDER BY date DESC LIMIT 10000",
    ) {
        Ok(stmt) => stmt,
        Err(_) => return,
    };

    let rows = stmt.query_map([], |row| {
        let unix_ts = row.get::<_, i64>(2).ok().map(normalize_apple_epoch);
        let flags = row.get::<_, i32>(4).ok();
        Ok(IosCallLogEntry {
            id: row.get::<_, i64>(0).ok().map(|v| v.to_string()),
            address: row.get(1).ok(),
            date: unix_ts,
            duration_secs: row.get(3).ok(),
            flags,
            is_outgoing: flags.map(|v| v & 1 == 1).unwrap_or(false),
            is_video: flags.map(|v| v & 16 == 16).unwrap_or(false),
            service: None,
        })
    });

    let Ok(rows) = rows else {
        return;
    };

    for entry in rows.flatten() {
        out.push(ParsedArtifact {
            timestamp: entry.date,
            artifact_type: "mobile_call_log".to_string(),
            description: format!("iOS call {}", entry.address.as_deref().unwrap_or("unknown")),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
    }
}

fn normalize_apple_epoch(value: i64) -> i64 {
    if value > 1_000_000_000_000 {
        value / 1_000_000_000 + 978_307_200
    } else if value > 10_000_000 {
        value + 978_307_200
    } else {
        value
    }
}
