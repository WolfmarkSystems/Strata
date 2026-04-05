use crate::plist_utils::parse_plist_data;
use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct MacosBluetoothParser;

impl MacosBluetoothParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BluetoothDevice {
    pub mac_address: String,
    pub name: Option<String>,
    pub last_seen: Option<String>,
    pub services: Vec<String>,
}

impl Default for MacosBluetoothParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosBluetoothParser {
    fn name(&self) -> &str {
        "macOS Bluetooth Audit"
    }

    fn artifact_type(&self) -> &str {
        "network_config"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "com.apple.bluetooth.services.cloud.plist",
            "com.apple.Bluetooth.plist",
            "bluetooth",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let plist_val = parse_plist_data(data)?;

        // com.apple.Bluetooth.plist contains paired devices
        if let Some(dict) = plist_val.as_dictionary() {
            if let Some(paired) = dict.get("PairedDevices").and_then(|v| v.as_array()) {
                for mac in paired {
                    if let Some(mac_str) = mac.as_string() {
                        artifacts.push(ParsedArtifact {
                            timestamp: None,
                            artifact_type: "network_config".to_string(),
                            description: format!("Paired Bluetooth Device: {}", mac_str),
                            source_path: path.to_string_lossy().to_string(),
                            json_data: serde_json::json!({ "mac": mac_str, "status": "paired" }),
                        });
                    }
                }
            }

            // Device names
            if let Some(names) = dict.get("DeviceNames").and_then(|v| v.as_dictionary()) {
                for (mac, name) in names {
                    if let Some(name_str) = name.as_string() {
                        artifacts.push(ParsedArtifact {
                            timestamp: None,
                            artifact_type: "network_config".to_string(),
                            description: format!(
                                "Bluetooth Device Name Recovery: {} is {}",
                                mac, name_str
                            ),
                            source_path: path.to_string_lossy().to_string(),
                            json_data: serde_json::json!({ "mac": mac, "name": name_str }),
                        });
                    }
                }
            }
        }

        Ok(artifacts)
    }
}
