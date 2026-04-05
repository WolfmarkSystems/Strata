use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct JournalParser;

impl JournalParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JournalEntry {
    pub timestamp: Option<i64>,
    pub hostname: Option<String>,
    pub identifier: Option<String>,
    pub pid: Option<i32>,
    pub message: Option<String>,
    pub priority: Option<i32>,
    pub unit: Option<String>,
    pub syslog_identifier: Option<String>,
}

impl Default for JournalParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for JournalParser {
    fn name(&self) -> &str {
        "systemd Journal"
    }

    fn artifact_type(&self) -> &str {
        "system_log"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["journal", "system.journal"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        parse_json_journal_lines(path, data, &mut artifacts);
        if artifacts.is_empty() {
            parse_text_journal_lines(path, data, &mut artifacts);
        }

        if artifacts.is_empty() && !data.is_empty() {
            let entry = JournalEntry {
                timestamp: None,
                hostname: None,
                identifier: None,
                pid: None,
                message: Some(format!("Journal entry from: {}", path.display())),
                priority: None,
                unit: None,
                syslog_identifier: None,
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "system_log".to_string(),
                description: "systemd journal entry".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

fn parse_json_journal_lines(path: &Path, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    for line in text.lines().take(50000) {
        let line = line.trim();
        if line.is_empty() || !line.starts_with('{') {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };

        let timestamp = value
            .get("__REALTIME_TIMESTAMP")
            .and_then(|v| v.as_str())
            .and_then(|v| v.parse::<i64>().ok())
            .map(|micros| micros / 1_000_000)
            .or_else(|| {
                value
                    .get("_SOURCE_REALTIME_TIMESTAMP")
                    .and_then(parse_json_i64)
            });

        let pid = value
            .get("_PID")
            .or_else(|| value.get("PID"))
            .and_then(parse_json_i64)
            .map(|v| v as i32);

        let entry = JournalEntry {
            timestamp,
            hostname: value
                .get("_HOSTNAME")
                .and_then(|v| v.as_str())
                .map(|v| v.to_string()),
            identifier: value
                .get("SYSLOG_IDENTIFIER")
                .or_else(|| value.get("_COMM"))
                .and_then(|v| v.as_str())
                .map(|v| v.to_string()),
            pid,
            message: value
                .get("MESSAGE")
                .and_then(|v| v.as_str())
                .map(|v| v.to_string()),
            priority: value
                .get("PRIORITY")
                .and_then(parse_json_i64)
                .map(|v| v as i32),
            unit: value
                .get("_SYSTEMD_UNIT")
                .or_else(|| value.get("UNIT"))
                .and_then(|v| v.as_str())
                .map(|v| v.to_string()),
            syslog_identifier: value
                .get("SYSLOG_IDENTIFIER")
                .and_then(|v| v.as_str())
                .map(|v| v.to_string()),
        };

        if entry.message.is_none() {
            continue;
        }

        out.push(ParsedArtifact {
            timestamp: entry.timestamp,
            artifact_type: "system_log".to_string(),
            description: format!(
                "systemd journal {}",
                entry
                    .identifier
                    .clone()
                    .unwrap_or_else(|| "entry".to_string())
            ),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
    }
}

fn parse_text_journal_lines(path: &Path, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    for line in text.lines().take(50000) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry = JournalEntry {
            timestamp: None,
            hostname: None,
            identifier: extract_identifier(trimmed),
            pid: None,
            message: Some(trimmed.to_string()),
            priority: None,
            unit: None,
            syslog_identifier: None,
        };

        out.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "system_log".to_string(),
            description: "systemd journal text entry".to_string(),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
    }
}

fn parse_json_i64(value: &serde_json::Value) -> Option<i64> {
    if let Some(v) = value.as_i64() {
        return Some(v);
    }
    if let Some(v) = value.as_u64() {
        return i64::try_from(v).ok();
    }
    value.as_str().and_then(|v| v.parse::<i64>().ok())
}

fn extract_identifier(line: &str) -> Option<String> {
    let marker = line.find('[').or_else(|| line.find(':'))?;
    let tail = &line[..marker];
    tail.split_whitespace().last().map(|v| v.to_string())
}
