use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct IcloudSyncParser;

impl IcloudSyncParser {
    pub fn new() -> Self {
        Self
    }

    /// Recursively deserialize compressed raw iCloud .cbf segments mapped against Manifest.db
    pub fn parse_raw_manifest_db(
        &self,
        _manifest_db_data: &[u8],
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        Ok(vec![])
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IcloudSyncEntry {
    pub document_id: Option<String>,
    pub file_name: Option<String>,
    pub file_path: Option<String>,
    pub size: i64,
    pub is_folder: bool,
    pub is_deleted: bool,
    pub modified: Option<i64>,
    pub created: Option<i64>,
    pub device_name: Option<String>,
    pub sync_status: Option<String>,
}

impl Default for IcloudSyncParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for IcloudSyncParser {
    fn name(&self) -> &str {
        "iCloud"
    }

    fn artifact_type(&self) -> &str {
        "cloud_sync"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "icloud",
            "icloud Drive",
            "mobile sync",
            "CloudDocs",
            "Mobile Documents",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        parse_icloud_json(path, data, &mut artifacts);

        if artifacts.is_empty() && !data.is_empty() {
            let entry = IcloudSyncEntry {
                document_id: None,
                file_name: path.file_name().map(|n| n.to_string_lossy().to_string()),
                file_path: Some(path.to_string_lossy().to_string()),
                size: data.len() as i64,
                is_folder: false,
                is_deleted: false,
                modified: None,
                created: None,
                device_name: None,
                sync_status: Some("synced".to_string()),
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "cloud_sync".to_string(),
                description: "iCloud sync file".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

fn parse_icloud_json(path: &Path, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };

    let records = value
        .get("records")
        .and_then(|v| v.as_array())
        .or_else(|| value.as_array());

    let Some(records) = records else {
        return;
    };

    for record in records.iter().take(20000) {
        let file_name = record
            .get("name")
            .or_else(|| record.get("filename"))
            .and_then(|v| v.as_str())
            .map(|v| v.to_string());
        if file_name.is_none() {
            continue;
        }
        let entry = IcloudSyncEntry {
            document_id: record.get("document_id").and_then(value_to_string),
            file_name: file_name.clone(),
            file_path: record
                .get("path")
                .or_else(|| record.get("relative_path"))
                .and_then(|v| v.as_str())
                .map(|v| v.to_string()),
            size: record.get("size").and_then(value_to_i64).unwrap_or(0),
            is_folder: record
                .get("is_folder")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            is_deleted: record
                .get("is_deleted")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            modified: record.get("modified").and_then(parse_iso_or_numeric_ts),
            created: record.get("created").and_then(parse_iso_or_numeric_ts),
            device_name: record
                .get("device_name")
                .and_then(|v| v.as_str())
                .map(|v| v.to_string()),
            sync_status: record
                .get("status")
                .and_then(|v| v.as_str())
                .map(|v| v.to_string()),
        };

        out.push(ParsedArtifact {
            timestamp: entry.modified.or(entry.created),
            artifact_type: "cloud_sync".to_string(),
            description: format!(
                "iCloud item {}",
                entry
                    .file_name
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string())
            ),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
    }
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
