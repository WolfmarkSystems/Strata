use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct UnifiedLogsParser;

impl UnifiedLogsParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnifiedLogEntry {
    pub timestamp: Option<i64>,
    pub subsystem: Option<String>,
    pub category: Option<String>,
    pub message: Option<String>,
    pub process: Option<String>,
    pub pid: Option<i32>,
    pub tid: Option<i32>,
    pub activity_id: Option<i64>,
    pub thread: Option<String>,
}

impl Default for UnifiedLogsParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for UnifiedLogsParser {
    fn name(&self) -> &str {
        "macOS Unified Logs"
    }

    fn artifact_type(&self) -> &str {
        "system_log"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["logd", "unified", ".logarchive"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        parse_unified_json(path, data, &mut artifacts);
        if artifacts.is_empty() {
            let _ = crate::parsers::macos::unified_logs_binary::parse_tracev3(
                path,
                data,
                &mut artifacts,
            );
        }
        if artifacts.is_empty() {
            parse_unified_text(path, data, &mut artifacts);
        }

        if artifacts.is_empty() && !data.is_empty() {
            let entry = UnifiedLogEntry {
                timestamp: None,
                subsystem: Some("logd".to_string()),
                category: None,
                message: Some(format!("Log data from: {}", path.display())),
                process: None,
                pid: None,
                tid: None,
                activity_id: None,
                thread: None,
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "system_log".to_string(),
                description: "macOS Unified Log entry".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

fn parse_unified_json(path: &Path, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        parse_unified_ndjson(path, data, out);
        return;
    };

    if let Some(entries) = value.get("traceEvents").and_then(|v| v.as_array()) {
        for item in entries.iter().take(50000) {
            if let Some(artifact) = entry_from_json(path, item) {
                out.push(artifact);
            }
        }
        return;
    }

    if let Some(entries) = value.as_array() {
        for item in entries.iter().take(50000) {
            if let Some(artifact) = entry_from_json(path, item) {
                out.push(artifact);
            }
        }
        return;
    }

    if let Some(artifact) = entry_from_json(path, &value) {
        out.push(artifact);
    }
}

fn parse_unified_ndjson(path: &Path, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    for line in text.lines().take(50000) {
        let trimmed = line.trim();
        if trimmed.is_empty() || !trimmed.starts_with('{') {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) else {
            continue;
        };
        if let Some(artifact) = entry_from_json(path, &value) {
            out.push(artifact);
        }
    }
}

fn entry_from_json(path: &Path, value: &serde_json::Value) -> Option<ParsedArtifact> {
    let timestamp = value
        .get("timestamp")
        .and_then(parse_iso_or_numeric_ts)
        .or_else(|| value.get("time").and_then(parse_iso_or_numeric_ts));
    let message = value
        .get("eventMessage")
        .or_else(|| value.get("message"))
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())?;

    let entry = UnifiedLogEntry {
        timestamp,
        subsystem: value
            .get("subsystem")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
        category: value
            .get("category")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
        message: Some(message.clone()),
        process: value
            .get("process")
            .or_else(|| value.get("processImagePath"))
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
        pid: value.get("pid").and_then(parse_json_i64).map(|v| v as i32),
        tid: value
            .get("threadID")
            .or_else(|| value.get("tid"))
            .and_then(parse_json_i64)
            .map(|v| v as i32),
        activity_id: value
            .get("activityIdentifier")
            .or_else(|| value.get("activity_id"))
            .and_then(parse_json_i64),
        thread: value
            .get("thread")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
    };

    Some(ParsedArtifact {
        timestamp: entry.timestamp,
        artifact_type: "system_log".to_string(),
        description: format!(
            "macOS unified log {}",
            entry
                .subsystem
                .clone()
                .unwrap_or_else(|| "entry".to_string())
        ),
        source_path: path.to_string_lossy().to_string(),
        json_data: serde_json::to_value(entry).unwrap_or_default(),
    })
}

fn parse_unified_text(path: &Path, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    for line in text.lines().take(50000) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry = UnifiedLogEntry {
            timestamp: None,
            subsystem: None,
            category: None,
            message: Some(trimmed.to_string()),
            process: extract_process(trimmed),
            pid: None,
            tid: None,
            activity_id: None,
            thread: None,
        };

        out.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "system_log".to_string(),
            description: "macOS unified log text entry".to_string(),
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

fn parse_iso_or_numeric_ts(value: &serde_json::Value) -> Option<i64> {
    if let Some(v) = parse_json_i64(value) {
        return Some(v);
    }
    let text = value.as_str()?;
    chrono::DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|dt| dt.timestamp())
}

fn extract_process(line: &str) -> Option<String> {
    let marker = line.find(':')?;
    let head = &line[..marker];
    head.split_whitespace().last().map(|v| v.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_json_array_with_subsystem() {
        let json = r#"[{"timestamp":1700000000,"subsystem":"com.apple.security","category":"auth","eventMessage":"Auth succeeded","process":"securityd","pid":42}]"#;
        let parser = UnifiedLogsParser::new();
        let arts = parser
            .parse_file(Path::new("unified.json"), json.as_bytes())
            .unwrap();
        assert!(!arts.is_empty());
        let a = &arts[0];
        assert!(a.description.contains("com.apple.security"));
        assert_eq!(a.timestamp, Some(1700000000));
    }

    #[test]
    fn parses_ndjson_entries() {
        let ndjson = "{\"eventMessage\":\"login\",\"subsystem\":\"com.apple.loginwindow\"}\n{\"eventMessage\":\"logout\",\"subsystem\":\"com.apple.loginwindow\"}\n";
        let parser = UnifiedLogsParser::new();
        let arts = parser
            .parse_file(Path::new("log.ndjson"), ndjson.as_bytes())
            .unwrap();
        assert_eq!(arts.len(), 2);
    }

    #[test]
    fn parses_plaintext_lines() {
        let text = "2026-04-12 logd[1]: System started\n2026-04-12 kernel[0]: Something happened\n";
        let parser = UnifiedLogsParser::new();
        let arts = parser
            .parse_file(Path::new("log.txt"), text.as_bytes())
            .unwrap();
        assert_eq!(arts.len(), 2);
    }

    #[test]
    fn empty_data_returns_empty() {
        let parser = UnifiedLogsParser::new();
        let arts = parser.parse_file(Path::new("empty"), b"").unwrap();
        assert!(arts.is_empty());
    }

    #[test]
    fn extract_process_from_line() {
        assert_eq!(
            extract_process("2026-04-12 securityd: auth"),
            Some("securityd".to_string())
        );
        assert_eq!(extract_process("no colon here"), None);
    }

    #[test]
    fn parses_rfc3339_timestamp() {
        let json = r#"[{"timestamp":"2026-04-12T10:00:00Z","eventMessage":"hello"}]"#;
        let parser = UnifiedLogsParser::new();
        let arts = parser
            .parse_file(Path::new("t.json"), json.as_bytes())
            .unwrap();
        assert_eq!(arts.len(), 1);
        assert!(arts[0].timestamp.is_some());
    }
}
