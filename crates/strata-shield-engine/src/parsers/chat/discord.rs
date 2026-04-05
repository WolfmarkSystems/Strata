use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct DiscordParser;

impl DiscordParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DiscordMessageEntry {
    pub message_id: Option<String>,
    pub channel_id: Option<String>,
    pub guild_id: Option<String>,
    pub author_id: Option<String>,
    pub author_name: Option<String>,
    pub content: Option<String>,
    pub timestamp: Option<i64>,
    pub edited_timestamp: Option<i64>,
    pub attachments: Vec<String>,
    pub embeds: Vec<String>,
    pub mentions: Vec<String>,
    pub reactions: Vec<String>,
    pub is_deleted: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DiscordChannelEntry {
    pub channel_id: Option<String>,
    pub guild_id: Option<String>,
    pub channel_name: Option<String>,
    pub channel_type: Option<String>,
    pub topic: Option<String>,
    pub message_count: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DiscordUserEntry {
    pub user_id: Option<String>,
    pub username: Option<String>,
    pub discriminator: Option<String>,
    pub nickname: Option<String>,
    pub avatar_url: Option<String>,
    pub joined_at: Option<i64>,
}

impl Default for DiscordParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for DiscordParser {
    fn name(&self) -> &str {
        "Discord"
    }

    fn artifact_type(&self) -> &str {
        "chat"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "discord",
            "AppData/Local/Discord",
            "messages.json",
            "channels.json",
            "discord-export",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        parse_discord_json(path, data, &mut artifacts);

        if artifacts.is_empty() && !data.is_empty() {
            let entry = DiscordMessageEntry {
                message_id: None,
                channel_id: None,
                guild_id: None,
                author_id: None,
                author_name: None,
                content: Some(format!("Discord data from: {}", path.display())),
                timestamp: None,
                edited_timestamp: None,
                attachments: vec![],
                embeds: vec![],
                mentions: vec![],
                reactions: vec![],
                is_deleted: false,
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "chat".to_string(),
                description: "Discord message".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

fn parse_discord_json(path: &Path, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        parse_discord_ndjson(path, data, out);
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

fn parse_discord_ndjson(path: &Path, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    for line in text.lines().take(20000) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) else {
            continue;
        };
        if let Some(artifact) = message_from_json(path, &value) {
            out.push(artifact);
        }
    }
}

fn message_from_json(path: &Path, value: &serde_json::Value) -> Option<ParsedArtifact> {
    let content = value
        .get("content")
        .and_then(|v| v.as_str())
        .or_else(|| value.get("message").and_then(|v| v.as_str()))?;

    let id = value
        .get("id")
        .and_then(value_to_string)
        .or_else(|| value.get("message_id").and_then(value_to_string));
    let author = value.get("author");

    let entry = DiscordMessageEntry {
        message_id: id.clone(),
        channel_id: value.get("channel_id").and_then(value_to_string),
        guild_id: value.get("guild_id").and_then(value_to_string),
        author_id: author
            .and_then(|a| a.get("id"))
            .and_then(value_to_string)
            .or_else(|| value.get("author_id").and_then(value_to_string)),
        author_name: author
            .and_then(|a| a.get("username"))
            .and_then(|v| v.as_str())
            .map(|v| v.to_string())
            .or_else(|| {
                value
                    .get("author")
                    .and_then(|v| v.as_str())
                    .map(|v| v.to_string())
            }),
        content: Some(content.to_string()),
        timestamp: value
            .get("timestamp")
            .and_then(value_to_i64)
            .or_else(|| value.get("timestamp").and_then(parse_iso_ts)),
        edited_timestamp: value
            .get("edited_timestamp")
            .and_then(value_to_i64)
            .or_else(|| value.get("edited_timestamp").and_then(parse_iso_ts)),
        attachments: value
            .get("attachments")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| {
                        x.get("filename")
                            .and_then(|v| v.as_str())
                            .map(|v| v.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default(),
        embeds: vec![],
        mentions: value
            .get("mentions")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| {
                        x.get("username")
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
                    .filter_map(|x| {
                        x.get("emoji")
                            .and_then(|e| e.get("name"))
                            .and_then(|v| v.as_str())
                            .map(|v| v.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default(),
        is_deleted: value
            .get("deleted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    };

    Some(ParsedArtifact {
        timestamp: entry.timestamp,
        artifact_type: "chat".to_string(),
        description: format!(
            "Discord message {}",
            id.unwrap_or_else(|| "unknown".to_string())
        ),
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

fn parse_iso_ts(value: &serde_json::Value) -> Option<i64> {
    let text = value.as_str()?;
    chrono::DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|dt| dt.timestamp())
}
