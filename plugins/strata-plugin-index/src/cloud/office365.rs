use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct Office365Parser;

impl Office365Parser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Office365AuditEntry {
    pub creation_time: Option<i64>,
    pub operation: Option<String>,
    pub user_id: Option<String>,
    pub workload: Option<String>,
    pub client_ip: Option<String>,
    pub object_id: Option<String>,
    pub organization_id: Option<String>,
    pub result_status: Option<String>,
    pub record_type: Option<String>,
    pub user_agent: Option<String>,
    pub mailbox: Option<String>,
    pub mail_items_accessed: Vec<String>,
    pub sharepoint_site_url: Option<String>,
    pub sharepoint_file_path: Option<String>,
    pub decoded_details: Option<serde_json::Value>,
}

impl Default for Office365Parser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for Office365Parser {
    fn name(&self) -> &str {
        "Office 365"
    }

    fn artifact_type(&self) -> &str {
        "cloud_export"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "o365",
            "office365",
            "microsoft 365",
            "unifiedauditlog",
            "auditlog",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        parse_o365_json(path, data, &mut artifacts);
        if artifacts.is_empty() {
            parse_o365_csv(path, data, &mut artifacts);
        }

        if artifacts.is_empty() && !data.is_empty() {
            let entry = Office365AuditEntry {
                creation_time: None,
                operation: None,
                user_id: None,
                workload: None,
                client_ip: None,
                object_id: None,
                organization_id: None,
                result_status: None,
                record_type: None,
                user_agent: None,
                mailbox: None,
                mail_items_accessed: vec![],
                sharepoint_site_url: None,
                sharepoint_file_path: None,
                decoded_details: None,
            };
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "cloud_export".to_string(),
                description: "Office 365 audit artifact".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

fn parse_o365_json(path: &Path, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };

    if let Some(entries) = value.get("Records").and_then(|v| v.as_array()) {
        for record in entries.iter().take(30000) {
            if let Some(artifact) = record_from_json(path, record) {
                out.push(artifact);
            }
        }
        return;
    }

    if let Some(entries) = value.as_array() {
        for record in entries.iter().take(30000) {
            if let Some(artifact) = record_from_json(path, record) {
                out.push(artifact);
            }
        }
        return;
    }

    if let Some(artifact) = record_from_json(path, &value) {
        out.push(artifact);
    }
}

fn parse_o365_csv(path: &Path, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let mut lines = text.lines();
    let Some(header_line) = lines.next() else {
        return;
    };

    let headers: Vec<String> = header_line
        .split(',')
        .map(|v| v.trim().trim_matches('"').to_ascii_lowercase())
        .collect();
    if headers.is_empty() {
        return;
    }

    let ts_idx = headers
        .iter()
        .position(|h| h == "creationtime" || h == "timegenerated" || h == "timestamp");
    let op_idx = headers.iter().position(|h| h == "operation");
    let user_idx = headers.iter().position(|h| h == "userid" || h == "user");
    let workload_idx = headers.iter().position(|h| h == "workload");
    let ip_idx = headers.iter().position(|h| h == "clientip");
    let status_idx = headers
        .iter()
        .position(|h| h == "resultstatus" || h == "status");

    for line in lines.take(30000) {
        let cols: Vec<&str> = line.split(',').collect();
        if cols.is_empty() {
            continue;
        }
        let entry = Office365AuditEntry {
            creation_time: ts_idx
                .and_then(|i| cols.get(i).copied())
                .and_then(|v| parse_iso_or_numeric_text(v.trim().trim_matches('"'))),
            operation: op_idx
                .and_then(|i| cols.get(i).copied())
                .map(|v| v.trim().trim_matches('"').to_string())
                .filter(|v| !v.is_empty()),
            user_id: user_idx
                .and_then(|i| cols.get(i).copied())
                .map(|v| v.trim().trim_matches('"').to_string())
                .filter(|v| !v.is_empty()),
            workload: workload_idx
                .and_then(|i| cols.get(i).copied())
                .map(|v| v.trim().trim_matches('"').to_string())
                .filter(|v| !v.is_empty()),
            client_ip: ip_idx
                .and_then(|i| cols.get(i).copied())
                .map(|v| v.trim().trim_matches('"').to_string())
                .filter(|v| !v.is_empty()),
            object_id: None,
            organization_id: None,
            result_status: status_idx
                .and_then(|i| cols.get(i).copied())
                .map(|v| v.trim().trim_matches('"').to_string())
                .filter(|v| !v.is_empty()),
            record_type: Some("csv".to_string()),
            user_agent: None,
            mailbox: None,
            mail_items_accessed: vec![],
            sharepoint_site_url: None,
            sharepoint_file_path: None,
            decoded_details: None,
        };

        if entry.creation_time.is_none() && entry.operation.is_none() {
            continue;
        }

        out.push(ParsedArtifact {
            timestamp: entry.creation_time,
            artifact_type: "cloud_export".to_string(),
            description: format!(
                "Office365 operation {}",
                entry
                    .operation
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string())
            ),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
    }
}

fn record_from_json(path: &Path, value: &serde_json::Value) -> Option<ParsedArtifact> {
    let operation = value
        .get("Operation")
        .or_else(|| value.get("operation"))
        .and_then(|v| v.as_str())
        .map(|v| v.to_string());
    let audit_data = parse_audit_data(value);
    let mail_items_accessed = decode_mail_items_accessed(&audit_data);
    let (sharepoint_site_url, sharepoint_file_path) = decode_sharepoint_file_operation(&audit_data);

    let entry = Office365AuditEntry {
        creation_time: value
            .get("CreationTime")
            .and_then(parse_iso_or_numeric_ts)
            .or_else(|| value.get("creation_time").and_then(parse_iso_or_numeric_ts))
            .or_else(|| value.get("Timestamp").and_then(parse_iso_or_numeric_ts)),
        operation: operation.clone(),
        user_id: value
            .get("UserId")
            .or_else(|| value.get("user_id"))
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
        workload: value
            .get("Workload")
            .or_else(|| value.get("workload"))
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
        client_ip: value
            .get("ClientIP")
            .or_else(|| value.get("client_ip"))
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
        object_id: value
            .get("ObjectId")
            .or_else(|| value.get("object_id"))
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
        organization_id: value
            .get("OrganizationId")
            .or_else(|| value.get("organization_id"))
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
        result_status: value
            .get("ResultStatus")
            .or_else(|| value.get("result_status"))
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
        record_type: value
            .get("RecordType")
            .and_then(value_to_string)
            .or_else(|| value.get("record_type").and_then(value_to_string)),
        user_agent: audit_data
            .as_ref()
            .and_then(|v| v.get("UserAgent"))
            .or_else(|| audit_data.as_ref().and_then(|v| v.get("ClientAppId")))
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
        mailbox: audit_data
            .as_ref()
            .and_then(|v| v.get("MailboxOwnerUPN"))
            .or_else(|| audit_data.as_ref().and_then(|v| v.get("MailboxGuid")))
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
        mail_items_accessed,
        sharepoint_site_url,
        sharepoint_file_path,
        decoded_details: audit_data,
    };

    if entry.creation_time.is_none() && entry.operation.is_none() && entry.user_id.is_none() {
        return None;
    }

    Some(ParsedArtifact {
        timestamp: entry.creation_time,
        artifact_type: "cloud_export".to_string(),
        description: format!(
            "Office365 {}",
            entry
                .operation
                .clone()
                .unwrap_or_else(|| "operation".to_string())
        ),
        source_path: path.to_string_lossy().to_string(),
        json_data: serde_json::to_value(entry).unwrap_or_default(),
    })
}

fn parse_audit_data(value: &serde_json::Value) -> Option<serde_json::Value> {
    let audit_data = value.get("AuditData")?;
    if audit_data.is_object() {
        return Some(audit_data.clone());
    }
    let text = audit_data.as_str()?;
    serde_json::from_str::<serde_json::Value>(text).ok()
}

fn decode_mail_items_accessed(audit_data: &Option<serde_json::Value>) -> Vec<String> {
    let Some(audit_data) = audit_data else {
        return vec![];
    };
    let mut items = Vec::new();
    if let Some(accessed) = audit_data.get("Folders").and_then(|v| v.as_array()) {
        for folder in accessed {
            if let Some(folder_id) = folder.get("FolderId").and_then(|v| v.as_str()) {
                items.push(format!("folder:{folder_id}"));
            }
            if let Some(messages) = folder.get("Messages").and_then(|v| v.as_array()) {
                for msg in messages.iter().take(200) {
                    if let Some(internet_id) = msg.get("InternetMessageId").and_then(|v| v.as_str())
                    {
                        items.push(internet_id.to_string());
                    } else if let Some(id) = msg.get("Id").and_then(|v| v.as_str()) {
                        items.push(id.to_string());
                    }
                }
            }
        }
    }
    if items.is_empty() {
        if let Some(item) = audit_data.get("ItemId").and_then(|v| v.as_str()) {
            items.push(item.to_string());
        }
        if let Some(item) = audit_data.get("InternetMessageId").and_then(|v| v.as_str()) {
            items.push(item.to_string());
        }
    }
    items
}

fn decode_sharepoint_file_operation(
    audit_data: &Option<serde_json::Value>,
) -> (Option<String>, Option<String>) {
    let Some(audit_data) = audit_data else {
        return (None, None);
    };
    let site = audit_data
        .get("SiteUrl")
        .or_else(|| audit_data.get("Site"))
        .and_then(|v| v.as_str())
        .map(|v| v.to_string());
    let file = audit_data
        .get("SourceFileName")
        .or_else(|| audit_data.get("ObjectId"))
        .or_else(|| audit_data.get("SourceRelativeUrl"))
        .and_then(|v| v.as_str())
        .map(|v| v.to_string());
    (site, file)
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

fn parse_iso_or_numeric_ts(value: &serde_json::Value) -> Option<i64> {
    if let Some(v) = value.as_i64() {
        return Some(v);
    }
    if let Some(v) = value.as_u64() {
        return i64::try_from(v).ok();
    }
    if let Some(v) = value.as_str() {
        return parse_iso_or_numeric_text(v);
    }
    None
}

fn parse_iso_or_numeric_text(value: &str) -> Option<i64> {
    if let Ok(num) = value.parse::<i64>() {
        return Some(num);
    }
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.timestamp())
}
