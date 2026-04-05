use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Android ADB Backup Parser
///
/// Format: ADB backup files (.ab) start with "ANDROID BACKUP\n" header
/// followed by version, compression flag, encryption flag, then
/// optionally deflate-compressed tar archive.
///
/// Forensic value: ADB backups contain app data, SMS, call logs, settings,
/// and other user data. Common extraction method when physical acquisition
/// is not possible.
pub struct AdbBackupParser;

impl Default for AdbBackupParser {
    fn default() -> Self {
        Self::new()
    }
}

impl AdbBackupParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdbBackupHeader {
    pub version: Option<i32>,
    pub compressed: bool,
    pub encrypted: bool,
    pub encryption_type: Option<String>,
    pub file_size: usize,
    pub estimated_content_size: usize,
    pub apps_detected: Vec<String>,
}

const ADB_MAGIC: &[u8] = b"ANDROID BACKUP\n";

impl ArtifactParser for AdbBackupParser {
    fn name(&self) -> &str {
        "Android ADB Backup Parser"
    }

    fn artifact_type(&self) -> &str {
        "mobile_backup"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["*.ab", "backup.ab", "android_backup*"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();

        if data.len() < ADB_MAGIC.len() || &data[..ADB_MAGIC.len()] != ADB_MAGIC {
            return Ok(artifacts);
        }

        // Parse header lines
        let header_text = String::from_utf8_lossy(&data[..data.len().min(512)]);
        let lines: Vec<&str> = header_text.lines().collect();

        let version = lines.get(1).and_then(|l| l.trim().parse::<i32>().ok());
        let compressed = lines.get(2).map(|l| l.trim() == "1").unwrap_or(false);
        let encrypted = lines.get(3).map(|l| l.trim() != "none").unwrap_or(false);
        let encryption_type = lines.get(3).map(|l| l.trim().to_string()).filter(|s| s != "none");

        // Scan for package names in the data (apps/com.xxx patterns)
        let mut apps = Vec::new();
        let text_scan = String::from_utf8_lossy(data);
        for segment in text_scan.split("apps/") {
            if let Some(end) = segment.find('/') {
                let app_name = &segment[..end];
                if app_name.contains('.') && app_name.len() > 5 && app_name.len() < 100 {
                    let app = app_name.to_string();
                    if !apps.contains(&app) {
                        apps.push(app);
                    }
                }
            }
            if apps.len() >= 200 {
                break;
            }
        }

        let header = AdbBackupHeader {
            version,
            compressed,
            encrypted,
            encryption_type: encryption_type.clone(),
            file_size: data.len(),
            estimated_content_size: if compressed { data.len() * 3 } else { data.len() },
            apps_detected: apps.clone(),
        };

        let mut desc = format!(
            "ADB Backup: v{} ({}, {}) {} bytes, {} apps detected",
            version.unwrap_or(0),
            if compressed { "compressed" } else { "uncompressed" },
            if encrypted { "ENCRYPTED" } else { "unencrypted" },
            data.len(),
            apps.len(),
        );

        if encrypted {
            desc.push_str(" [ENCRYPTED — password required for extraction]");
        }

        // Flag forensically interesting apps
        let interesting_apps: Vec<&str> = apps
            .iter()
            .filter_map(|app| {
                let lower = app.to_lowercase();
                if lower.contains("whatsapp")
                    || lower.contains("telegram")
                    || lower.contains("signal")
                    || lower.contains("messenger")
                    || lower.contains("banking")
                    || lower.contains("crypto")
                    || lower.contains("wallet")
                    || lower.contains("tinder")
                    || lower.contains("snapchat")
                    || lower.contains("kik")
                {
                    Some(app.as_str())
                } else {
                    None
                }
            })
            .collect();

        if !interesting_apps.is_empty() {
            desc.push_str(&format!(
                " [Notable: {}]",
                interesting_apps.join(", ")
            ));
        }

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "mobile_backup".to_string(),
            description: desc,
            source_path: source.clone(),
            json_data: serde_json::to_value(&header).unwrap_or_default(),
        });

        // Individual app entries
        for app in &apps {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "mobile_app".to_string(),
                description: format!("ADB Backup App: {}", app),
                source_path: source.clone(),
                json_data: serde_json::json!({
                    "package_name": app,
                    "source": "adb_backup",
                }),
            });
        }

        Ok(artifacts)
    }
}
