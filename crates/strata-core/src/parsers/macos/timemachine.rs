use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct TimeMachineParser;

impl TimeMachineParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TimeMachineEntry {
    pub snapshot_id: Option<String>,
    pub backup_date: Option<i64>,
    pub volume_name: Option<String>,
    pub source_path: Option<String>,
    pub size: i64,
    pub is_incremental: bool,
}

impl Default for TimeMachineParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for TimeMachineParser {
    fn name(&self) -> &str {
        "Time Machine"
    }

    fn artifact_type(&self) -> &str {
        "backup"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "timemachine",
            "backups.backupdb",
            ".snapshot",
            "com.apple.TimeMachine.localsnapshots",
            "listlocalsnapshots",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        use crate::parsers::plist_utils::parse_plist_data;

        let mut artifacts = Vec::new();
        let path_str = path.to_string_lossy().to_lowercase();

        if path_str.ends_with("backupinfo.plist") {
            if let Ok(plist_val) = parse_plist_data(data) {
                let entry = TimeMachineEntry {
                    snapshot_id: path
                        .parent()
                        .and_then(|p| p.file_name())
                        .map(|n| n.to_string_lossy().to_string()),
                    backup_date: None,
                    volume_name: plist_val
                        .as_dictionary()
                        .and_then(|d| d.get("VolumeName"))
                        .and_then(|v| v.as_string())
                        .map(|s| s.to_string()),
                    source_path: Some(path.to_string_lossy().to_string()),
                    size: data.len() as i64,
                    is_incremental: true,
                };

                artifacts.push(ParsedArtifact {
                    timestamp: None,
                    artifact_type: "backup".to_string(),
                    description: format!(
                        "Time Machine Backup Set ({})",
                        entry.volume_name.as_deref().unwrap_or("unknown")
                    ),
                    source_path: path.to_string_lossy().to_string(),
                    json_data: serde_json::to_value(&entry).unwrap_or_default(),
                });
            }
        }

        parse_snapshot_names(path, &mut artifacts);
        parse_snapshot_listing(path, data, &mut artifacts);

        if artifacts.is_empty() && !data.is_empty() {
            // ... same as before ...
        }
        Ok(artifacts)
    }
}

fn parse_snapshot_names(path: &Path, out: &mut Vec<ParsedArtifact>) {
    let path_str = path.to_string_lossy();
    for token in path_str.split(['/', '\\']) {
        if let Some(snapshot) = extract_snapshot_from_token(token) {
            out.push(ParsedArtifact {
                timestamp: snapshot.backup_date,
                artifact_type: "backup".to_string(),
                description: format!(
                    "APFS snapshot {}",
                    snapshot.snapshot_id.clone().unwrap_or_default()
                ),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(snapshot).unwrap_or_default(),
            });
            break;
        }
    }
}

fn parse_snapshot_listing(path: &Path, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    for line in text.lines().take(5000) {
        if let Some(snapshot) = extract_snapshot_from_token(line.trim()) {
            out.push(ParsedArtifact {
                timestamp: snapshot.backup_date,
                artifact_type: "backup".to_string(),
                description: format!(
                    "APFS snapshot {}",
                    snapshot.snapshot_id.clone().unwrap_or_default()
                ),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(snapshot).unwrap_or_default(),
            });
        }
    }
}

fn extract_snapshot_from_token(token: &str) -> Option<TimeMachineEntry> {
    let lower = token.to_ascii_lowercase();
    if !lower.contains("snapshot") && !lower.contains("timemachine") {
        return None;
    }

    let snapshot_id = token
        .split_whitespace()
        .next()
        .map(|v| v.trim_matches('"').to_string())
        .filter(|v| !v.is_empty());

    let backup_date = parse_snapshot_time(token);
    Some(TimeMachineEntry {
        snapshot_id,
        backup_date,
        volume_name: None,
        source_path: None,
        size: 0,
        is_incremental: true,
    })
}

fn parse_snapshot_time(token: &str) -> Option<i64> {
    let mut normalized = token.replace(['.', '_', ':'], "-");
    normalized.retain(|c| c.is_ascii_alphanumeric() || c == '-');
    for part in normalized.split('-') {
        if part.len() == 8 && part.chars().all(|c| c.is_ascii_digit()) {
            let yyyy = &part[0..4];
            let mm = &part[4..6];
            let dd = &part[6..8];
            let composed = format!("{yyyy}-{mm}-{dd}T00:00:00Z");
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&composed) {
                return Some(dt.timestamp());
            }
        }
    }

    let formats = [
        "%Y-%m-%d-%H%M%S",
        "%Y-%m-%d-%H-%M-%S",
        "%Y-%m-%d-%H%M",
        "%Y-%m-%d",
    ];
    for fmt in formats {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(&normalized, fmt) {
            return Some(dt.and_utc().timestamp());
        }
        if let Ok(date) = chrono::NaiveDate::parse_from_str(&normalized, fmt) {
            return date.and_hms_opt(0, 0, 0).map(|v| v.and_utc().timestamp());
        }
    }
    None
}

pub fn reconstruct_file_history(
    target_path: &Path,
    available_artifacts: &[ParsedArtifact],
) -> Vec<ParsedArtifact> {
    let mut history = Vec::new();
    let target_name = target_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    // Sort artifacts by backup date if available
    for art in available_artifacts {
        if art.artifact_type == "backup" {
            if let Some(desc) = art
                .description
                .to_lowercase()
                .contains(target_name)
                .then(|| art.description.clone())
            {
                history.push(ParsedArtifact {
                    timestamp: art.timestamp,
                    artifact_type: "backup_version".to_string(),
                    description: format!("Historical Version Identified: {}", desc),
                    source_path: art.source_path.clone(),
                    json_data: art.json_data.clone(),
                });
            }
        }
    }

    history.sort_by_key(|a| a.timestamp.unwrap_or(0));
    history
}
