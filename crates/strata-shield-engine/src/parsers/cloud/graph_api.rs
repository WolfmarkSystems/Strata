use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct GraphApiParser;

impl GraphApiParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GraphApiEntry {
    pub resource: Option<String>,
    pub operation: Option<String>,
    pub user: Option<String>,
    pub timestamp: Option<i64>,
    pub details: Option<serde_json::Value>,
}

impl Default for GraphApiParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for GraphApiParser {
    fn name(&self) -> &str {
        "Microsoft Graph API"
    }

    fn artifact_type(&self) -> &str {
        "cloud_export"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "graph.microsoft.com",
            "graph_api",
            "inboxrules",
            "teamschats",
            "mailbox",
            "oauth",
            "forwarding",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
            return Ok(artifacts);
        };

        let rows = value
            .get("value")
            .and_then(|v| v.as_array())
            .or_else(|| value.as_array());
        let Some(rows) = rows else {
            if let Some(artifact) = build_graph_artifact(path, &value) {
                artifacts.push(artifact);
            }
            return Ok(artifacts);
        };

        for row in rows.iter().take(50000) {
            if let Some(artifact) = build_graph_artifact(path, row) {
                artifacts.push(artifact);
            }
        }
        Ok(artifacts)
    }
}

fn build_graph_artifact(path: &Path, value: &serde_json::Value) -> Option<ParsedArtifact> {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    let resource = if lower.contains("inboxrules") {
        Some("mailbox_rules".to_string())
    } else if lower.contains("teams") || lower.contains("chats") {
        Some("teams_chat".to_string())
    } else if lower.contains("forward") {
        Some("mail_forwarding".to_string())
    } else if lower.contains("oauth") || lower.contains("grants") {
        Some("oauth_grant".to_string())
    } else {
        value.get("@odata.type").and_then(value_to_string)
    };

    let operation = value
        .get("displayName")
        .or_else(|| value.get("name"))
        .or_else(|| value.get("action"))
        .and_then(value_to_string);
    let user = value
        .get("userPrincipalName")
        .or_else(|| value.get("userId"))
        .or_else(|| {
            value
                .get("from")
                .and_then(|v| v.get("user"))
                .and_then(|u| u.get("id"))
        })
        .and_then(value_to_string);
    let timestamp = value
        .get("createdDateTime")
        .or_else(|| value.get("lastModifiedDateTime"))
        .or_else(|| value.get("receivedDateTime"))
        .and_then(parse_ts);

    if resource.is_none() && operation.is_none() && user.is_none() {
        return None;
    }

    let entry = GraphApiEntry {
        resource: resource.clone(),
        operation: operation.clone(),
        user: user.clone(),
        timestamp,
        details: Some(value.clone()),
    };

    Some(ParsedArtifact {
        timestamp: entry.timestamp,
        artifact_type: "cloud_export".to_string(),
        description: format!(
            "Graph API {}",
            resource
                .or(operation)
                .unwrap_or_else(|| "entry".to_string())
        ),
        source_path: path.to_string_lossy().to_string(),
        json_data: serde_json::to_value(entry).unwrap_or_default(),
    })
}

fn value_to_string(value: &serde_json::Value) -> Option<String> {
    if let Some(v) = value.as_str() {
        return Some(v.to_string());
    }
    if let Some(v) = value.as_i64() {
        return Some(v.to_string());
    }
    if let Some(v) = value.as_u64() {
        return Some(v.to_string());
    }
    None
}

fn parse_ts(value: &serde_json::Value) -> Option<i64> {
    if let Some(v) = value.as_i64() {
        return Some(normalize_epoch(v));
    }
    if let Some(v) = value.as_u64() {
        return i64::try_from(v).ok().map(normalize_epoch);
    }
    let text = value.as_str()?;
    if let Ok(v) = text.parse::<i64>() {
        return Some(normalize_epoch(v));
    }
    chrono::DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|dt| dt.timestamp())
}

fn normalize_epoch(v: i64) -> i64 {
    if v > 10_000_000_000 {
        v / 1000
    } else {
        v
    }
}
