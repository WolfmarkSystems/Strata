use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::plist_utils::parse_plist_data;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct MacosFileVaultParser;

impl MacosFileVaultParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileVaultKeyInfo {
    pub volume_uuid: String,
    pub key_type: String,
    pub recovery_key_hint: Option<String>,
    pub encrypted_root_plist_path: String,
}

impl Default for MacosFileVaultParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosFileVaultParser {
    fn name(&self) -> &str {
        "macOS FileVault"
    }

    fn artifact_type(&self) -> &str {
        "encryption_metadata"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "encryptedroot.plist",
            "applecustomerrecovery.plist",
            "filevault",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let path_str = path.to_string_lossy().to_lowercase();

        if path_str.ends_with("encryptedroot.plist") {
            if let Ok(plist_val) = parse_plist_data(data) {
                let uuid = plist_val
                    .as_dictionary()
                    .and_then(|d| d.get("VolumeUUID"))
                    .and_then(|v| v.as_string())
                    .unwrap_or("unknown")
                    .to_string();

                let info = FileVaultKeyInfo {
                    volume_uuid: uuid,
                    key_type: "FV2 Recovery Blob".to_string(),
                    recovery_key_hint: plist_val
                        .as_dictionary()
                        .and_then(|d| d.get("RecoveryKeyHint"))
                        .and_then(|v| v.as_string())
                        .map(|s| s.to_string()),
                    encrypted_root_plist_path: path.to_string_lossy().to_string(),
                };

                artifacts.push(ParsedArtifact {
                    timestamp: None,
                    artifact_type: "encryption_metadata".to_string(),
                    description: format!(
                        "FileVault 2 Recovery Blob for Volume {}",
                        info.volume_uuid
                    ),
                    source_path: path.to_string_lossy().to_string(),
                    json_data: serde_json::to_value(info).unwrap_or_default(),
                });
            }
        }

        Ok(artifacts)
    }
}
