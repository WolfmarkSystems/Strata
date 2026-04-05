use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct ApfsSnapshotDiffParser;

impl ApfsSnapshotDiffParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApfsSnapshotDiffEntry {
    pub action: Option<String>,
    pub path: Option<String>,
    pub snapshot_a: Option<String>,
    pub snapshot_b: Option<String>,
    pub timestamp: Option<i64>,
}

impl Default for ApfsSnapshotDiffParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for ApfsSnapshotDiffParser {
    fn name(&self) -> &str {
        "APFS Snapshot Diff"
    }

    fn artifact_type(&self) -> &str {
        "macos_snapshot_diff"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "snapshot_diff",
            "tmutil compare",
            "apfs diff",
            "localsnapshots",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let text = String::from_utf8_lossy(data);

        let mut snapshot_a = None;
        let mut snapshot_b = None;
        for line in text.lines().take(10000) {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let lower = trimmed.to_ascii_lowercase();
            if lower.starts_with("snapshot_a=") {
                snapshot_a = Some(trimmed["snapshot_a=".len()..].trim().to_string());
                continue;
            }
            if lower.starts_with("snapshot_b=") {
                snapshot_b = Some(trimmed["snapshot_b=".len()..].trim().to_string());
                continue;
            }

            let action = if trimmed.starts_with('+') {
                Some("added".to_string())
            } else if trimmed.starts_with('-') {
                Some("removed".to_string())
            } else if trimmed.starts_with('~') {
                Some("modified".to_string())
            } else {
                None
            };
            let changed_path = action
                .as_ref()
                .map(|_| trimmed[1..].trim().to_string())
                .filter(|v| !v.is_empty());
            if action.is_none() && changed_path.is_none() {
                continue;
            }
            let entry = ApfsSnapshotDiffEntry {
                action: action.clone(),
                path: changed_path.clone(),
                snapshot_a: snapshot_a.clone(),
                snapshot_b: snapshot_b.clone(),
                timestamp: None,
            };
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "macos_snapshot_diff".to_string(),
                description: format!(
                    "APFS diff {}",
                    action.unwrap_or_else(|| "change".to_string())
                ),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}
