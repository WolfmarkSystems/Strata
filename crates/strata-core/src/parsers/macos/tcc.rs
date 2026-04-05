use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::sqlite_utils::{table_exists, with_sqlite_connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct MacosTccParser;

impl MacosTccParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TccAccessEntry {
    pub service: Option<String>,
    pub service_human: Option<String>,
    pub client: Option<String>,
    pub auth_value: Option<i64>,
    pub auth_status: Option<String>,
    pub auth_reason: Option<i64>,
    pub prompt_count: Option<i64>,
    pub last_modified: Option<i64>,
}

impl Default for MacosTccParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosTccParser {
    fn name(&self) -> &str {
        "macOS TCC"
    }

    fn artifact_type(&self) -> &str {
        "macos_tcc"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "tcc.db",
            "com.apple.tcc",
            "transparency",
            "consent",
            "control",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let sqlite_result = with_sqlite_connection(path, data, |conn| {
            let mut parsed = Vec::new();
            if table_exists(conn, "access") {
                let mut stmt = conn.prepare(
                    "SELECT service, client, auth_value, auth_reason, prompt_count, last_modified FROM access LIMIT 10000",
                ).map_err(|e| ParserError::Database(e.to_string()))?;
                let rows = stmt
                    .query_map([], |row| {
                        let service: Option<String> = row.get(0).ok();
                        let auth_val: Option<i64> = row.get(2).ok();
                        Ok(TccAccessEntry {
                            service_human: service.as_deref().map(map_tcc_service),
                            service,
                            client: row.get(1).ok(),
                            auth_status: auth_val.map(map_tcc_status),
                            auth_value: auth_val,
                            auth_reason: row.get(3).ok(),
                            prompt_count: row.get(4).ok(),
                            last_modified: row.get::<_, i64>(5).ok().map(normalize_apple_epoch),
                        })
                    })
                    .map_err(|e| ParserError::Database(e.to_string()))?;
                for row in rows.flatten() {
                    parsed.push(ParsedArtifact {
                        timestamp: row.last_modified,
                        artifact_type: "macos_tcc".to_string(),
                        description: format!(
                            "TCC [{}] {} -> {}",
                            row.auth_status.as_deref().unwrap_or("?"),
                            row.client.as_deref().unwrap_or("unknown"),
                            row.service_human
                                .as_deref()
                                .unwrap_or_else(|| row.service.as_deref().unwrap_or("unknown"))
                        ),
                        source_path: path.to_string_lossy().to_string(),
                        json_data: serde_json::to_value(row).unwrap_or_default(),
                    });
                }
            }
            Ok(parsed)
        });

        if let Ok(mut parsed) = sqlite_result {
            artifacts.append(&mut parsed);
        }
        Ok(artifacts)
    }
}

fn map_tcc_service(s: &str) -> String {
    match s {
        "kTCCServiceCamera" => "Camera".to_string(),
        "kTCCServiceMicrophone" => "Microphone".to_string(),
        "kTCCServiceSystemPolicyAllFiles" => "Full Disk Access".to_string(),
        "kTCCServiceScreenCapture" => "Screen Recording".to_string(),
        "kTCCServiceAddressBook" => "Contacts".to_string(),
        "kTCCServiceCalendar" => "Calendar".to_string(),
        "kTCCServiceReminders" => "Reminders".to_string(),
        "kTCCServicePhotos" => "Photos".to_string(),
        s if s.starts_with("kTCCService") => s.replace("kTCCService", ""),
        _ => s.to_string(),
    }
}

fn map_tcc_status(v: i64) -> String {
    match v {
        0 => "Denied".to_string(),
        1 => "Unknown".to_string(),
        2 => "Allowed".to_string(),
        3 => "Limited".to_string(),
        _ => format!("Code: {}", v),
    }
}

fn normalize_apple_epoch(v: i64) -> i64 {
    if v > 10_000_000_000 {
        v / 1000
    } else {
        v + 978_307_200
    }
}
