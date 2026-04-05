use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct AzureDeepParser;

impl AzureDeepParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AzureActivityLogEntry {
    pub resource_id: Option<String>,
    pub subscription_id: Option<String>,
    pub event_timestamp: Option<i64>,
    pub event_name: Option<AzureEventName>,
    pub category: Option<String>,
    pub operation_name: Option<String>,
    pub operation_id: Option<String>,
    pub resource_group: Option<String>,
    pub resource_provider: Option<String>,
    pub resource_type: Option<String>,
    pub resource_name: Option<String>,
    pub caller: Option<String>,
    pub caller_ip_address: Option<String>,
    pub correlation_id: Option<String>,
    pub identity: Option<String>,
    pub authorization: Option<AzureAuthorization>,
    pub properties: Option<String>,
    pub status: Option<String>,
    pub sub_status: Option<String>,
    pub http_request: Option<AzureHttpRequest>,
    pub level: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AzureEventName {
    pub value: Option<String>,
    pub localized_value: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AzureAuthorization {
    pub scope: Option<String>,
    pub action: Option<String>,
    pub evidence: Option<Vec<AzureRoleAssignment>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AzureRoleAssignment {
    pub role_definition_id: Option<String>,
    pub role_name: Option<String>,
    pub principal_id: Option<String>,
    pub principal_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AzureHttpRequest {
    pub method: Option<String>,
    pub client_request_id: Option<String>,
    pub uri: Option<String>,
    pub server_request_id: Option<String>,
    pub status_code: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AzureSignInEntry {
    pub id: Option<String>,
    pub created_at: Option<i64>,
    pub user_display_name: Option<String>,
    pub user_principal_name: Option<String>,
    pub user_id: Option<String>,
    pub app_display_name: Option<String>,
    pub app_id: Option<String>,
    pub ip_address: Option<String>,
    pub location: Option<String>,
    pub client_app_used: Option<String>,
    pub device_detail: Option<AzureDeviceDetail>,
    pub conditional_access_status: Option<String>,
    pub conditional_access_policies: Vec<String>,
    pub mfa_requirement: Option<String>,
    pub mfa_result: Option<String>,
    pub user_agent: Option<String>,
    pub sign_in_error: Option<String>,
    pub risk_detail: Option<String>,
    pub risk_level: Option<String>,
    pub risk_state: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AzureDeviceDetail {
    pub device_id: Option<String>,
    pub device_browser: Option<String>,
    pub device_os: Option<String>,
    pub device_trust_type: Option<String>,
    pub is_compliant: Option<bool>,
    pub is_managed: Option<bool>,
}

impl Default for AzureDeepParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for AzureDeepParser {
    fn name(&self) -> &str {
        "Azure Deep"
    }

    fn artifact_type(&self) -> &str {
        "cloud_audit"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "azure",
            "activity log",
            "signin",
            "signinlogs",
            "aadsignin",
            "audit",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        parse_azure_json(path, data, &mut artifacts);

        if artifacts.is_empty() && !data.is_empty() {
            let entry = AzureActivityLogEntry {
                resource_id: None,
                subscription_id: None,
                event_timestamp: None,
                event_name: None,
                category: None,
                operation_name: None,
                operation_id: None,
                resource_group: None,
                resource_provider: None,
                resource_type: None,
                resource_name: None,
                caller: None,
                caller_ip_address: None,
                correlation_id: None,
                identity: None,
                authorization: None,
                properties: None,
                status: None,
                sub_status: None,
                http_request: None,
                level: None,
            };
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "cloud_audit".to_string(),
                description: "Azure Activity Log entry".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

fn parse_azure_json(path: &Path, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    let entries = value
        .get("value")
        .and_then(|v| v.as_array())
        .or_else(|| value.as_array());
    let Some(entries) = entries else {
        if let Some(artifact) = parse_entry(path, &value) {
            out.push(artifact);
        }
        return;
    };
    for entry in entries.iter().take(30000) {
        if let Some(artifact) = parse_entry(path, entry) {
            out.push(artifact);
        }
    }
}

fn parse_entry(path: &Path, value: &serde_json::Value) -> Option<ParsedArtifact> {
    if value.get("userPrincipalName").is_some()
        || value.get("conditionalAccessStatus").is_some()
        || value.get("authenticationRequirement").is_some()
    {
        let entry = AzureSignInEntry {
            id: value.get("id").and_then(value_to_string),
            created_at: value
                .get("createdDateTime")
                .or_else(|| value.get("timeGenerated"))
                .and_then(parse_ts),
            user_display_name: value.get("userDisplayName").and_then(value_to_string),
            user_principal_name: value.get("userPrincipalName").and_then(value_to_string),
            user_id: value.get("userId").and_then(value_to_string),
            app_display_name: value.get("appDisplayName").and_then(value_to_string),
            app_id: value.get("appId").and_then(value_to_string),
            ip_address: value.get("ipAddress").and_then(value_to_string),
            location: value
                .get("location")
                .and_then(|v| v.get("city").or_else(|| v.get("countryOrRegion")))
                .and_then(value_to_string),
            client_app_used: value.get("clientAppUsed").and_then(value_to_string),
            device_detail: None,
            conditional_access_status: value
                .get("conditionalAccessStatus")
                .and_then(value_to_string),
            conditional_access_policies: value
                .get("appliedConditionalAccessPolicies")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|p| p.get("displayName").and_then(value_to_string))
                        .collect()
                })
                .unwrap_or_default(),
            mfa_requirement: value
                .get("authenticationRequirement")
                .and_then(value_to_string),
            mfa_result: value
                .get("status")
                .and_then(|v| v.get("failureReason").or_else(|| v.get("errorCode")))
                .and_then(value_to_string),
            user_agent: value
                .get("userAgent")
                .or_else(|| value.get("clientAppUsed"))
                .and_then(value_to_string),
            sign_in_error: value
                .get("status")
                .and_then(|v| v.get("failureReason"))
                .and_then(value_to_string),
            risk_detail: value.get("riskDetail").and_then(value_to_string),
            risk_level: value.get("riskLevelAggregated").and_then(value_to_string),
            risk_state: value.get("riskState").and_then(value_to_string),
        };
        return Some(ParsedArtifact {
            timestamp: entry.created_at,
            artifact_type: "cloud_audit".to_string(),
            description: format!(
                "Azure AD sign-in {}",
                entry
                    .user_principal_name
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string())
            ),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
    }

    let entry = AzureActivityLogEntry {
        resource_id: value.get("resourceId").and_then(value_to_string),
        subscription_id: value.get("subscriptionId").and_then(value_to_string),
        event_timestamp: value
            .get("eventTimestamp")
            .or_else(|| value.get("time"))
            .and_then(parse_ts),
        event_name: None,
        category: value.get("category").and_then(value_to_string),
        operation_name: value
            .get("operationName")
            .and_then(|v| v.get("value").or_else(|| Some(v)))
            .and_then(value_to_string),
        operation_id: value.get("operationId").and_then(value_to_string),
        resource_group: value.get("resourceGroupName").and_then(value_to_string),
        resource_provider: value.get("resourceProviderName").and_then(value_to_string),
        resource_type: value.get("resourceType").and_then(value_to_string),
        resource_name: value.get("resourceName").and_then(value_to_string),
        caller: value.get("caller").and_then(value_to_string),
        caller_ip_address: value.get("callerIpAddress").and_then(value_to_string),
        correlation_id: value.get("correlationId").and_then(value_to_string),
        identity: value.get("claims").and_then(value_to_string),
        authorization: None,
        properties: value.get("properties").map(|v| v.to_string()),
        status: value
            .get("status")
            .and_then(|v| v.get("value").or_else(|| Some(v)))
            .and_then(value_to_string),
        sub_status: value
            .get("subStatus")
            .and_then(|v| v.get("value").or_else(|| Some(v)))
            .and_then(value_to_string),
        http_request: None,
        level: value.get("level").and_then(value_to_string),
    };
    Some(ParsedArtifact {
        timestamp: entry.event_timestamp,
        artifact_type: "cloud_audit".to_string(),
        description: format!(
            "Azure Activity {}",
            entry
                .operation_name
                .clone()
                .unwrap_or_else(|| "event".to_string())
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
