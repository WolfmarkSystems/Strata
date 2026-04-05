use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct AwsDeepParser;

impl AwsDeepParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AwsS3AccessEntry {
    pub bucket_name: Option<String>,
    pub key: Option<String>,
    pub requester: Option<String>,
    pub requester_arn: Option<String>,
    pub operation: Option<String>,
    pub http_method: Option<String>,
    pub http_status: Option<i32>,
    pub error_code: Option<String>,
    pub bytes_sent: Option<i64>,
    pub object_size: Option<i64>,
    pub total_time: Option<i64>,
    pub turnaround_time: Option<i64>,
    pub referer: Option<String>,
    pub user_agent: Option<String>,
    pub version_id: Option<String>,
    pub target_arn: Option<String>,
    pub tls_version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AwsCloudTrailDeep {
    pub event_version: Option<String>,
    pub event_time: Option<i64>,
    pub event_name: Option<String>,
    pub event_source: Option<String>,
    pub aws_region: Option<String>,
    pub source_ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub user_identity_type: Option<String>,
    pub user_identity_arn: Option<String>,
    pub user_name: Option<String>,
    pub recipient_account_id: Option<String>,
    pub request_parameters: Option<String>,
    pub response_elements: Option<String>,
    pub request_id: Option<String>,
    pub event_id: Option<String>,
    pub read_only: bool,
    pub event_category: Option<String>,
    pub session_credential_provider: Option<String>,
    pub mfa_used: bool,
    pub resources: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AwsVPCFlowEntry {
    pub version: Option<i32>,
    pub account_id: Option<String>,
    pub interface_id: Option<String>,
    pub srcaddr: Option<String>,
    pub dstaddr: Option<String>,
    pub srcport: Option<i32>,
    pub dstport: Option<i32>,
    pub protocol: Option<i32>,
    pub packets: Option<i64>,
    pub bytes: Option<i64>,
    pub start_time: Option<i64>,
    pub end_time: Option<i64>,
    pub action: Option<String>,
    pub log_status: Option<String>,
}

impl Default for AwsDeepParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for AwsDeepParser {
    fn name(&self) -> &str {
        "AWS Deep"
    }

    fn artifact_type(&self) -> &str {
        "cloud_audit"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["aws", "s3", "cloudtrail", "vpc flow"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if !data.is_empty() {
            let entry = AwsS3AccessEntry {
                bucket_name: None,
                key: None,
                requester: None,
                requester_arn: None,
                operation: Some("AWS access".to_string()),
                http_method: None,
                http_status: None,
                error_code: None,
                bytes_sent: None,
                object_size: None,
                total_time: None,
                turnaround_time: None,
                referer: None,
                user_agent: None,
                version_id: None,
                target_arn: None,
                tls_version: None,
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "cloud_audit".to_string(),
                description: "AWS S3 access log".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}
