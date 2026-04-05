use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct DropboxParser;

impl DropboxParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DropboxFileEntry {
    pub path: Option<String>,
    pub name: Option<String>,
    pub size: i64,
    pub is_folder: bool,
    pub modified: Option<i64>,
    pub client_modified: Option<i64>,
    pub rev: Option<String>,
    pub content_hash: Option<String>,
}

impl Default for DropboxParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for DropboxParser {
    fn name(&self) -> &str {
        "Dropbox"
    }

    fn artifact_type(&self) -> &str {
        "cloud_sync"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["dropbox", "drop box", "files/list_folder", "dropbox export"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        parse_dropbox_json(path, data, &mut artifacts);

        if artifacts.is_empty() && !data.is_empty() {
            let entry = DropboxFileEntry {
                path: Some(path.to_string_lossy().to_string()),
                name: path.file_name().map(|n| n.to_string_lossy().to_string()),
                size: data.len() as i64,
                is_folder: false,
                modified: None,
                client_modified: None,
                rev: None,
                content_hash: None,
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "cloud_sync".to_string(),
                description: "Dropbox file".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

fn parse_dropbox_json(path: &Path, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };

    if let Some(entries) = value.get("entries").and_then(|v| v.as_array()) {
        for entry in entries.iter().take(20000) {
            if let Some(artifact) = entry_from_json(path, entry) {
                out.push(artifact);
            }
        }
        return;
    }

    if let Some(entries) = value.as_array() {
        for entry in entries.iter().take(20000) {
            if let Some(artifact) = entry_from_json(path, entry) {
                out.push(artifact);
            }
        }
        return;
    }

    if let Some(artifact) = entry_from_json(path, &value) {
        out.push(artifact);
    }
}

fn entry_from_json(path: &Path, value: &serde_json::Value) -> Option<ParsedArtifact> {
    let name = value
        .get("name")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())?;

    let entry = DropboxFileEntry {
        path: value
            .get("path_display")
            .or_else(|| value.get("path_lower"))
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
        name: Some(name.clone()),
        size: value.get("size").and_then(value_to_i64).unwrap_or(0),
        is_folder: value
            .get(".tag")
            .and_then(|v| v.as_str())
            .map(|v| v == "folder")
            .unwrap_or(false),
        modified: value
            .get("server_modified")
            .and_then(parse_iso_or_numeric_ts),
        client_modified: value
            .get("client_modified")
            .and_then(parse_iso_or_numeric_ts),
        rev: value
            .get("rev")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
        content_hash: value
            .get("content_hash")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
    };

    Some(ParsedArtifact {
        timestamp: entry.modified.or(entry.client_modified),
        artifact_type: "cloud_sync".to_string(),
        description: format!("Dropbox file {}", name),
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

fn parse_iso_or_numeric_ts(value: &serde_json::Value) -> Option<i64> {
    if let Some(num) = value_to_i64(value) {
        return Some(num);
    }
    let text = value.as_str()?;
    chrono::DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|dt| dt.timestamp())
}
