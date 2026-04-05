use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct GoogleDriveParser;

impl GoogleDriveParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GoogleDriveFileEntry {
    pub file_id: Option<String>,
    pub file_name: Option<String>,
    pub mime_type: Option<String>,
    pub size: i64,
    pub created_time: Option<i64>,
    pub modified_time: Option<i64>,
    pub parents: Vec<String>,
    pub shared: bool,
    pub trashed: bool,
    pub revision_ids: Vec<String>,
    pub last_revision_id: Option<String>,
}

impl Default for GoogleDriveParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for GoogleDriveParser {
    fn name(&self) -> &str {
        "Google Drive"
    }

    fn artifact_type(&self) -> &str {
        "cloud_sync"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "google drive",
            "gdrive",
            "my drive",
            "takeout/drive",
            "metadata.json",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        parse_drive_json(path, data, &mut artifacts);

        if artifacts.is_empty() && !data.is_empty() {
            let entry = GoogleDriveFileEntry {
                file_id: None,
                file_name: path.file_name().map(|n| n.to_string_lossy().to_string()),
                mime_type: None,
                size: data.len() as i64,
                created_time: None,
                modified_time: None,
                parents: vec![],
                shared: false,
                trashed: false,
                revision_ids: vec![],
                last_revision_id: None,
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "cloud_sync".to_string(),
                description: "Google Drive file".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

fn parse_drive_json(path: &Path, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };

    if let Some(revisions) = value.get("revisions").and_then(|v| v.as_array()) {
        for revision in revisions.iter().take(20000) {
            let revision_id = revision
                .get("id")
                .and_then(value_to_string)
                .unwrap_or_else(|| "unknown".to_string());
            let ts = revision
                .get("modifiedTime")
                .or_else(|| revision.get("lastModifyingUser"))
                .and_then(parse_iso_or_numeric_ts);
            let entry = GoogleDriveFileEntry {
                file_id: value.get("fileId").and_then(value_to_string),
                file_name: value
                    .get("name")
                    .and_then(value_to_string)
                    .or_else(|| path.file_name().map(|n| n.to_string_lossy().to_string())),
                mime_type: None,
                size: revision.get("size").and_then(value_to_i64).unwrap_or(0),
                created_time: None,
                modified_time: ts,
                parents: vec![],
                shared: false,
                trashed: false,
                revision_ids: vec![revision_id.clone()],
                last_revision_id: Some(revision_id.clone()),
            };
            out.push(ParsedArtifact {
                timestamp: entry.modified_time,
                artifact_type: "cloud_sync".to_string(),
                description: format!("Google Drive revision {}", revision_id),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(entry).unwrap_or_default(),
            });
        }
        if !out.is_empty() {
            return;
        }
    }

    if let Some(files) = value.get("files").and_then(|v| v.as_array()) {
        for file in files.iter().take(20000) {
            if let Some(artifact) = file_from_json(path, file) {
                out.push(artifact);
            }
        }
        return;
    }

    if let Some(files) = value.as_array() {
        for file in files.iter().take(20000) {
            if let Some(artifact) = file_from_json(path, file) {
                out.push(artifact);
            }
        }
        return;
    }

    if let Some(artifact) = file_from_json(path, &value) {
        out.push(artifact);
    }
}

fn file_from_json(path: &Path, value: &serde_json::Value) -> Option<ParsedArtifact> {
    let file_name = value
        .get("title")
        .or_else(|| value.get("name"))
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())?;

    let entry = GoogleDriveFileEntry {
        file_id: value.get("id").and_then(value_to_string),
        file_name: Some(file_name.clone()),
        mime_type: value
            .get("mimeType")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
        size: value.get("size").and_then(value_to_i64).unwrap_or(0),
        created_time: value
            .get("createdTime")
            .and_then(parse_iso_or_numeric_ts)
            .or_else(|| value.get("createdDate").and_then(parse_iso_or_numeric_ts)),
        modified_time: value
            .get("modifiedTime")
            .and_then(parse_iso_or_numeric_ts)
            .or_else(|| value.get("modifiedDate").and_then(parse_iso_or_numeric_ts)),
        parents: value
            .get("parents")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(value_to_string).collect())
            .unwrap_or_default(),
        shared: value
            .get("shared")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        trashed: value
            .get("trashed")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        revision_ids: value
            .get("revisions")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|r| r.get("id").and_then(value_to_string))
                    .collect()
            })
            .unwrap_or_default(),
        last_revision_id: value
            .get("headRevisionId")
            .or_else(|| value.get("lastRevisionId"))
            .and_then(value_to_string),
    };

    Some(ParsedArtifact {
        timestamp: entry.modified_time.or(entry.created_time),
        artifact_type: "cloud_sync".to_string(),
        description: format!("Google Drive file {}", file_name),
        source_path: path.to_string_lossy().to_string(),
        json_data: serde_json::to_value(entry).unwrap_or_default(),
    })
}

fn value_to_i64(value: &serde_json::Value) -> Option<i64> {
    if let Some(v) = value.as_i64() {
        return Some(v);
    }
    if let Some(v) = value.as_u64() {
        return i64::try_from(v).ok();
    }
    if let Some(v) = value.as_str() {
        return v.parse::<i64>().ok();
    }
    None
}

fn value_to_string(value: &serde_json::Value) -> Option<String> {
    if let Some(v) = value.as_str() {
        return Some(v.to_string());
    }
    value_to_i64(value).map(|v| v.to_string())
}

fn parse_iso_or_numeric_ts(value: &serde_json::Value) -> Option<i64> {
    if let Some(num) = value_to_i64(value) {
        return Some(num);
    }
    let text = value.as_str()?;
    chrono::DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|dt| dt.timestamp())
}
