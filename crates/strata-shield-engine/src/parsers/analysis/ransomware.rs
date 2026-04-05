use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct RansomwareParser;

impl RansomwareParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RansomwareIndicator {
    pub file_path: Option<String>,
    pub file_name: Option<String>,
    pub file_size: i64,
    pub file_hash: Option<String>,
    pub ransomware_family: Option<String>,
    pub detection_method: Option<String>,
    pub confidence: f32,
    pub is_encrypted: bool,
    pub encrypted_extension: Option<String>,
    pub ransom_note_found: bool,
    pub ransom_note_name: Option<String>,
    pub encryption_algorithm: Option<String>,
    pub key_recovery_available: bool,
    pub suspicious_behaviors: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RansomNote {
    pub found: bool,
    pub file_name: Option<String>,
    pub content_preview: Option<String>,
    pub bitcoin_address: Option<String>,
    pub ransom_amount: Option<String>,
    pub contact_info: Option<String>,
    pub language: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedFile {
    pub original_path: Option<String>,
    pub encrypted_path: Option<String>,
    pub original_extension: Option<String>,
    pub new_extension: Option<String>,
    pub encryption_time: Option<i64>,
    pub file_size_before: Option<i64>,
    pub file_size_after: Option<i64>,
}

impl Default for RansomwareParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for RansomwareParser {
    fn name(&self) -> &str {
        "Ransomware Detection"
    }

    fn artifact_type(&self) -> &str {
        "malware"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "ransomware",
            "encrypted",
            "lock",
            ".locked",
            ".encrypted",
            "readme",
            "how_to_recover",
            "recovery_instructions",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let path_str = path.to_string_lossy().to_lowercase();

        let is_ransom_note = path_str.contains("readme")
            || path_str.contains("recovery")
            || path_str.contains("how_to")
            || path_str.contains(" decrypt");

        let is_encrypted = path_str.contains(".encrypted")
            || path_str.contains(".locked")
            || path_str.contains(".lock");

        let mut family = None;
        let mut confidence = 0.0;

        if is_ransom_note {
            family = detect_ransomware_family(&path_str);
            confidence = 0.9;
        } else if is_encrypted {
            family = Some("Unknown Ransomware".to_string());
            confidence = 0.6;
        }

        let indicator = RansomwareIndicator {
            file_path: Some(path.to_string_lossy().to_string()),
            file_name: path.file_name().map(|n| n.to_string_lossy().to_string()),
            file_size: data.len() as i64,
            file_hash: None,
            ransomware_family: family,
            detection_method: if is_ransom_note {
                Some("ransom note".to_string())
            } else {
                Some("extension analysis".to_string())
            },
            confidence,
            is_encrypted,
            encrypted_extension: if is_encrypted {
                path.extension().map(|e| e.to_string_lossy().to_string())
            } else {
                None
            },
            ransom_note_found: is_ransom_note,
            ransom_note_name: if is_ransom_note {
                path.file_name().map(|n| n.to_string_lossy().to_string())
            } else {
                None
            },
            encryption_algorithm: None,
            key_recovery_available: false,
            suspicious_behaviors: vec![],
        };

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "malware".to_string(),
            description: "Ransomware indicator".to_string(),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(&indicator).unwrap_or_default(),
        });

        Ok(artifacts)
    }
}

fn detect_ransomware_family(path: &str) -> Option<String> {
    if path.contains("lockbit") || path.contains("lockbit") {
        Some("LockBit".to_string())
    } else if path.contains("conti") {
        Some("Conti".to_string())
    } else if path.contains("revil") || path.contains("revil") {
        Some("REvil".to_string())
    } else if path.contains("clop") {
        Some("Clop".to_string())
    } else if path.contains("wannacry") {
        Some("WannaCry".to_string())
    } else if path.contains("petya") || path.contains("notpetya") {
        Some("Petya".to_string())
    } else if path.contains("ryuk") {
        Some("Ryuk".to_string())
    } else if path.contains(" Maze") || path.contains("maze") {
        Some("Maze".to_string())
    } else {
        Some("Unknown Ransomware".to_string())
    }
}
