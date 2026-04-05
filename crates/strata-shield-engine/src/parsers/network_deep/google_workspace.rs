use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct GoogleWorkspaceParser;

impl GoogleWorkspaceParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GoogleWorkspaceAdminEntry {
    pub id: Option<String>,
    pub time: Option<i64>,
    pub name: Option<String>,
    pub parameters: Option<String>,
    pub actor: Option<GoogleActor>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub events: Vec<GoogleEvent>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GoogleActor {
    pub email: Option<String>,
    pub key: Option<String>,
    pub profile_id: Option<String>,
    pub caller_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GoogleEvent {
    pub type_: Option<String>,
    pub name: Option<String>,
    pub parameters: Vec<GoogleParameter>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GoogleParameter {
    pub name: Option<String>,
    pub value: Option<String>,
    pub int_value: Option<i64>,
    pub bool_value: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GoogleDriveActivityEntry {
    pub primary_action: Option<String>,
    pub actors: Vec<GoogleActor>,
    pub targets: Vec<GoogleTarget>,
    pub actions: Vec<GoogleActionDetail>,
    pub time: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GoogleTarget {
    pub drive_item: Option<GoogleDriveItem>,
    pub file: Option<GoogleFile>,
    pub owner: Option<GoogleActor>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GoogleDriveItem {
    pub name: Option<String>,
    pub title: Option<String>,
    pub mime_type: Option<String>,
    pub owner: Option<String>,
    pub file_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GoogleFile {
    pub name: Option<String>,
    pub size: Option<String>,
    pub mime_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GoogleActionDetail {
    pub action_detail_type: Option<String>,
    pub create: Option<GoogleCreateDetails>,
    pub edit: Option<GoogleEditDetails>,
    pub delete: Option<GoogleDeleteDetails>,
    pub move_: Option<GoogleMoveDetails>,
    pub permission_change: Option<GooglePermissionDetails>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GoogleCreateDetails {
    pub type_: Option<String>,
    pub mime_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GoogleEditDetails {
    pub type_: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GoogleDeleteDetails {
    pub type_: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GoogleMoveDetails {
    pub added_parents: Vec<String>,
    pub removed_parents: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GooglePermissionDetails {
    pub role: Option<String>,
    pub permission_type: Option<String>,
}

impl Default for GoogleWorkspaceParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for GoogleWorkspaceParser {
    fn name(&self) -> &str {
        "Google Workspace"
    }

    fn artifact_type(&self) -> &str {
        "cloud_audit"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "google workspace",
            "gworkspace",
            "admin",
            "drive audit",
            "saml",
            "oauth",
            "token",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        parse_workspace_json(path, data, &mut artifacts);

        if artifacts.is_empty() && !data.is_empty() {
            let entry = GoogleWorkspaceAdminEntry {
                id: None,
                time: None,
                name: None,
                parameters: None,
                actor: None,
                ip_address: None,
                user_agent: None,
                events: vec![],
            };
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "cloud_audit".to_string(),
                description: "Google Workspace Admin entry".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

fn parse_workspace_json(path: &Path, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    let items = value
        .get("items")
        .and_then(|v| v.as_array())
        .or_else(|| value.as_array());
    let Some(items) = items else {
        if let Some(artifact) = workspace_entry(path, &value) {
            out.push(artifact);
        }
        return;
    };
    for item in items.iter().take(30000) {
        if let Some(artifact) = workspace_entry(path, item) {
            out.push(artifact);
        }
    }
}

fn workspace_entry(path: &Path, value: &serde_json::Value) -> Option<ParsedArtifact> {
    let event_name = value
        .get("id")
        .and_then(|v| {
            v.get("applicationName")
                .or_else(|| v.get("uniqueQualifier"))
        })
        .and_then(value_to_string)
        .or_else(|| value.get("name").and_then(value_to_string));
    let activity_name = value
        .get("events")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|event| event.get("name"))
        .and_then(value_to_string);
    let main_name = activity_name.or(event_name);

    let actor = value.get("actor").cloned().unwrap_or_default();
    let actor_email = actor.get("email").and_then(value_to_string);
    let ip_address = value.get("ipAddress").and_then(value_to_string);
    let time = value
        .get("id")
        .and_then(|v| v.get("time"))
        .and_then(parse_ts);

    let mut tags = Vec::new();
    let lower_blob = value.to_string().to_ascii_lowercase();
    if lower_blob.contains("saml") || lower_blob.contains("single sign-on") {
        tags.push("saml_sso".to_string());
    }
    if lower_blob.contains("oauth") || lower_blob.contains("token grant") {
        tags.push("oauth_grant".to_string());
    }
    if lower_blob.contains("token revocation") || lower_blob.contains("revoke") {
        tags.push("token_revocation".to_string());
    }
    if lower_blob.contains("drive") && lower_blob.contains("revision") {
        tags.push("drive_revision".to_string());
    }

    let entry = GoogleWorkspaceAdminEntry {
        id: value
            .get("id")
            .and_then(|v| v.get("uniqueQualifier").or_else(|| v.get("id")))
            .and_then(value_to_string),
        time,
        name: main_name.clone(),
        parameters: if tags.is_empty() {
            None
        } else {
            Some(tags.join(","))
        },
        actor: Some(GoogleActor {
            email: actor_email,
            key: actor.get("profileId").and_then(value_to_string),
            profile_id: actor.get("profileId").and_then(value_to_string),
            caller_type: actor.get("callerType").and_then(value_to_string),
        }),
        ip_address,
        user_agent: value
            .get("events")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|evt| evt.get("parameters"))
            .and_then(|v| v.as_array())
            .and_then(|params| {
                params.iter().find_map(|p| {
                    let name = p.get("name").and_then(value_to_string)?;
                    if name.to_ascii_lowercase().contains("user_agent") {
                        p.get("value").and_then(value_to_string)
                    } else {
                        None
                    }
                })
            }),
        events: vec![],
    };

    Some(ParsedArtifact {
        timestamp: entry.time,
        artifact_type: "cloud_audit".to_string(),
        description: format!(
            "Google Workspace {}",
            main_name.unwrap_or_else(|| "event".to_string())
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
