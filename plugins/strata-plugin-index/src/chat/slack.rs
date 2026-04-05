use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct SlackParser;

impl SlackParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SlackMessageEntry {
    pub message_ts: Option<String>,
    pub channel_id: Option<String>,
    pub user_id: Option<String>,
    pub user_name: Option<String>,
    pub text: Option<String>,
    pub timestamp: Option<i64>,
    pub edited: Option<i64>,
    pub attachments: Vec<String>,
    pub files: Vec<String>,
    pub reactions: Vec<String>,
    pub thread_ts: Option<String>,
    pub reply_count: i32,
    pub is_deleted: bool,
    pub is_starred: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SlackChannelEntry {
    pub channel_id: Option<String>,
    pub channel_name: Option<String>,
    pub channel_type: Option<String>,
    pub is_archived: bool,
    pub member_count: i32,
    pub topic: Option<String>,
    pub purpose: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SlackUserEntry {
    pub user_id: Option<String>,
    pub user_name: Option<String>,
    pub real_name: Option<String>,
    pub email: Option<String>,
    pub team_id: Option<String>,
    pub is_admin: bool,
    pub is_owner: bool,
}

impl Default for SlackParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for SlackParser {
    fn name(&self) -> &str {
        "Slack"
    }

    fn artifact_type(&self) -> &str {
        "chat"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "slack",
            "AppData/Local/Slack",
            "users.json",
            "channels.json",
            ".slack-export",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        parse_slack_json(path, data, &mut artifacts);

        if artifacts.is_empty() && !data.is_empty() {
            let entry = SlackMessageEntry {
                message_ts: None,
                channel_id: None,
                user_id: None,
                user_name: None,
                text: Some(format!("Slack data from: {}", path.display())),
                timestamp: None,
                edited: None,
                attachments: vec![],
                files: vec![],
                reactions: vec![],
                thread_ts: None,
                reply_count: 0,
                is_deleted: false,
                is_starred: false,
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "chat".to_string(),
                description: "Slack message".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

fn parse_slack_json(path: &Path, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };

    if let Some(messages) = value.as_array() {
        for msg in messages.iter().take(20000) {
            if let Some(artifact) = message_from_json(path, msg) {
                out.push(artifact);
            }
        }
        return;
    }

    if let Some(messages) = value.get("messages").and_then(|v| v.as_array()) {
        for msg in messages.iter().take(20000) {
            if let Some(artifact) = message_from_json(path, msg) {
                out.push(artifact);
            }
        }
    }
}

fn message_from_json(path: &Path, value: &serde_json::Value) -> Option<ParsedArtifact> {
    let text = value.get("text").and_then(|v| v.as_str())?;
    let message_ts = value
        .get("ts")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string());
    let timestamp = message_ts
        .as_deref()
        .and_then(parse_slack_ts)
        .or_else(|| value.get("timestamp").and_then(value_to_i64));

    let entry = SlackMessageEntry {
        message_ts: message_ts.clone(),
        channel_id: value
            .get("channel")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
        user_id: value
            .get("user")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
        user_name: value
            .get("username")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
        text: Some(text.to_string()),
        timestamp,
        edited: value
            .get("edited")
            .and_then(|v| v.get("ts"))
            .and_then(|v| v.as_str())
            .and_then(parse_slack_ts),
        attachments: vec![],
        files: value
            .get("files")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|f| {
                        f.get("name")
                            .and_then(|v| v.as_str())
                            .map(|v| v.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default(),
        reactions: value
            .get("reactions")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|r| {
                        r.get("name")
                            .and_then(|v| v.as_str())
                            .map(|v| v.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default(),
        thread_ts: value
            .get("thread_ts")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
        reply_count: value
            .get("reply_count")
            .and_then(value_to_i64)
            .map(|v| v as i32)
            .unwrap_or(0),
        is_deleted: value
            .get("subtype")
            .and_then(|v| v.as_str())
            .map(|v| v == "tombstone")
            .unwrap_or(false),
        is_starred: value
            .get("is_starred")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    };

    Some(ParsedArtifact {
        timestamp: entry.timestamp,
        artifact_type: "chat".to_string(),
        description: format!(
            "Slack message {}",
            message_ts.unwrap_or_else(|| "unknown".to_string())
        ),
        source_path: path.to_string_lossy().to_string(),
        json_data: serde_json::to_value(entry).unwrap_or_default(),
    })
}

fn parse_slack_ts(value: &str) -> Option<i64> {
    let head = value.split('.').next().unwrap_or(value);
    head.parse::<i64>().ok()
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
