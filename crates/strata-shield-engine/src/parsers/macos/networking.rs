use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::plist_utils::{parse_plist_data, get_string_from_plist};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct MacosNetworkingParser;

impl MacosNetworkingParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WifiNetwork {
    pub ssid: String,
    pub last_connected: Option<String>,
    pub security_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BluetoothDevice {
    pub name: Option<String>,
    pub address: String,
    pub last_connected: Option<String>,
}

impl Default for MacosNetworkingParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosNetworkingParser {
    fn name(&self) -> &str {
        "macOS Networking"
    }

    fn artifact_type(&self) -> &str {
        "network_config"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["com.apple.airport.preferences.plist", "com.apple.Bluetooth.plist"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let plist_val = parse_plist_data(data)?;
        let path_str = path.to_string_lossy().to_lowercase();

        if path_str.contains("airport.preferences") {
            if let Some(known_networks) = plist_val.as_dictionary().and_then(|d| d.get("KnownNetworks")).and_then(|v| v.as_dictionary()) {
                for (id, network) in known_networks {
                    let ssid = get_string_from_plist(network, "SSIDString").unwrap_or_else(|| id.clone());
                    let security = get_string_from_plist(network, "SecurityType");
                    let last_conn = get_string_from_plist(network, "LastConnected");

                    artifacts.push(ParsedArtifact {
                        timestamp: None,
                        artifact_type: "network_config".to_string(),
                        description: format!("Wi-Fi Network: {}", ssid),
                        source_path: path.to_string_lossy().to_string(),
                        json_data: serde_json::to_value(WifiNetwork {
                            ssid,
                            last_connected: last_conn,
                            security_type: security,
                        }).unwrap_or_default(),
                    });
                }
            }
        } else if path_str.contains("bluetooth") {
             if let Some(devices) = plist_val.as_dictionary().and_then(|d| d.get("DeviceCache")).and_then(|v| v.as_dictionary()) {
                for (address, device) in devices {
                    let name = get_string_from_plist(device, "Name");
                    let last_conn = get_string_from_plist(device, "LastInquiryUpdate");

                    artifacts.push(ParsedArtifact {
                        timestamp: None,
                        artifact_type: "network_config".to_string(),
                        description: format!("Bluetooth Device: {} ({})", name.as_deref().unwrap_or("unknown"), address),
                        source_path: path.to_string_lossy().to_string(),
                        json_data: serde_json::to_value(BluetoothDevice {
                            name,
                            address: address.clone(),
                            last_connected: last_conn,
                        }).unwrap_or_default(),
                    });
                }
            }
        }

        Ok(artifacts)
    }
}
