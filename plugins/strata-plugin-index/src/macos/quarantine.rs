use crate::sqlite_utils::{table_exists, with_sqlite_connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct MacosQuarantineParser;

impl MacosQuarantineParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub timestamp: Option<i64>,
    pub agent_name: Option<String>,
    pub data_url: Option<String>,
    pub origin_url: Option<String>,
    pub sender_name: Option<String>,
    pub sender_address: Option<String>,
    pub quarantine_type: Option<String>,
}

impl Default for MacosQuarantineParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosQuarantineParser {
    fn name(&self) -> &str {
        "macOS Quarantine"
    }

    fn artifact_type(&self) -> &str {
        "macos_quarantine"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["quarantineeventsv2", "com.apple.quarantine", "quarantine"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        let sqlite_result = with_sqlite_connection(path, data, |conn: &rusqlite::Connection| {
            let mut parsed = Vec::new();
            if table_exists(conn, "LSQuarantineEvent") {
                let mut stmt = conn
                    .prepare(
                        "SELECT
                            LSQuarantineTimeStamp,
                            LSQuarantineAgentName,
                            LSQuarantineDataURLString,
                            LSQuarantineOriginURLString,
                            LSQuarantineSenderName,
                            LSQuarantineSenderAddress
                         FROM LSQuarantineEvent LIMIT 10000",
                    )
                    .map_err(|e: rusqlite::Error| ParserError::Database(e.to_string()))?;
                let rows = stmt
                    .query_map([], |row: &rusqlite::Row| {
                        Ok(QuarantineEntry {
                            timestamp: row.get::<_, f64>(0).ok().map(|v| v as i64 + 978_307_200),
                            agent_name: row.get(1).ok(),
                            data_url: row.get(2).ok(),
                            origin_url: row.get(3).ok(),
                            sender_name: row.get(4).ok(),
                            sender_address: row.get(5).ok(),
                            quarantine_type: Some("sqlite".to_string()),
                        })
                    })
                    .map_err(|e: rusqlite::Error| ParserError::Database(e.to_string()))?;
                for row in rows.flatten() {
                    parsed.push(ParsedArtifact {
                        timestamp: row.timestamp,
                        artifact_type: "macos_quarantine".to_string(),
                        description: format!(
                            "Quarantine {}",
                            row.agent_name
                                .clone()
                                .unwrap_or_else(|| "event".to_string())
                        ),
                        source_path: path.to_string_lossy().to_string(),
                        json_data: serde_json::to_value(row).unwrap_or_default(),
                    });
                }
            }
            Ok(parsed)
        });
        if let Ok(mut parsed) = sqlite_result {
            artifacts.append(&mut parsed);
        }

        parse_xattr_quarantine(path, data, &mut artifacts);
        Ok(artifacts)
    }
}

fn parse_xattr_quarantine(path: &Path, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    let text = String::from_utf8_lossy(data);
    for line in text.lines().take(2000) {
        let trimmed = line.trim();
        if !trimmed.contains(';') {
            continue;
        }
        let parts: Vec<&str> = trimmed.split(';').collect();
        if parts.len() < 3 {
            continue;
        }
        let timestamp = i64::from_str_radix(parts[1], 16).ok();
        let entry = QuarantineEntry {
            timestamp,
            agent_name: parts.get(2).map(|v| v.to_string()),
            data_url: parts.get(3).map(|v| v.to_string()),
            origin_url: parts.get(4).map(|v| v.to_string()),
            sender_name: None,
            sender_address: None,
            quarantine_type: Some("xattr".to_string()),
        };
        out.push(ParsedArtifact {
            timestamp: entry.timestamp,
            artifact_type: "macos_quarantine".to_string(),
            description: format!(
                "File Downloaded from: {}",
                entry.origin_url.as_deref().unwrap_or("unknown source")
            ),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
    }
}
