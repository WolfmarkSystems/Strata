use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct CloudAuditParser;

impl CloudAuditParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AwsCloudTrailEntry {
    pub event_time: Option<i64>,
    pub event_name: Option<String>,
    pub event_source: Option<String>,
    pub aws_region: Option<String>,
    pub source_ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub user_identity: Option<String>,
    pub user_arn: Option<String>,
    pub recipient_account_id: Option<String>,
    pub request_parameters: Option<String>,
    pub response_elements: Option<String>,
    pub request_id: Option<String>,
    pub event_id: Option<String>,
    pub event_type: Option<String>,
    pub api_version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AzureActivityLogEntry {
    pub timestamp: Option<i64>,
    pub resource_group: Option<String>,
    pub resource_provider: Option<String>,
    pub resource_type: Option<String>,
    pub resource_name: Option<String>,
    pub operation_name: Option<String>,
    pub category: Option<String>,
    pub caller: Option<String>,
    pub correlation_id: Option<String>,
    pub subscription_id: Option<String>,
    pub status: Option<String>,
    pub authorization: Option<String>,
    pub properties: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GoogleWorkspaceEntry {
    pub timestamp: Option<i64>,
    pub event_name: Option<String>,
    pub event_type: Option<String>,
    pub actor_email: Option<String>,
    pub actor_key: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub resource_name: Option<String>,
    pub parameters: Option<String>,
    pub num_filter_items: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Office365Entry {
    pub timestamp: Option<i64>,
    pub operation: Option<String>,
    pub user_id: Option<String>,
    pub user_key: Option<String>,
    pub work_load: Option<String>,
    pub client_ip: Option<String>,
    pub object_id: Option<String>,
    pub organization_id: Option<String>,
    pub result_status: Option<String>,
    pub azure_ad_session_id: Option<String>,
}

impl Default for CloudAuditParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for CloudAuditParser {
    fn name(&self) -> &str {
        "Cloud Audit"
    }

    fn artifact_type(&self) -> &str {
        "cloud_audit"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "cloudtrail",
            "cloud_audit",
            "azure activity",
            "google workspace",
            "office365",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if !data.is_empty() {
            let entry = AwsCloudTrailEntry {
                event_time: None,
                event_name: Some("Cloud audit event".to_string()),
                event_source: None,
                aws_region: None,
                source_ip_address: None,
                user_agent: None,
                user_identity: None,
                user_arn: None,
                recipient_account_id: None,
                request_parameters: None,
                response_elements: None,
                request_id: None,
                event_id: None,
                event_type: None,
                api_version: None,
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "cloud_audit".to_string(),
                description: "Cloud audit log entry".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}
