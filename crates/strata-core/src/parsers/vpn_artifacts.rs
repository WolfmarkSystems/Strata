use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// VPN Client Artifact Parser
///
/// Parses configuration and log files from common VPN clients:
///   - OpenVPN: .ovpn configs, openvpn.log
///   - WireGuard: .conf files
///   - Cisco AnyConnect: preferences.xml, profile.xml
///   - Generic: VPN connection logs
///
/// Forensic value: VPN usage indicates intent to route traffic through
/// encrypted tunnels. Configuration files reveal server endpoints,
/// authentication methods, and routing rules. Log files show connection
/// timestamps and data transfer volumes.
pub struct VpnArtifactsParser;

impl Default for VpnArtifactsParser {
    fn default() -> Self {
        Self::new()
    }
}

impl VpnArtifactsParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VpnConfigEntry {
    pub vpn_type: String,
    pub server: Option<String>,
    pub port: Option<String>,
    pub protocol: Option<String>,
    pub auth_method: Option<String>,
    pub dns_servers: Vec<String>,
    pub routes: Vec<String>,
    pub interface_name: Option<String>,
    pub private_key_present: bool,
    pub certificate_present: bool,
    pub forensic_flags: Vec<String>,
}

impl ArtifactParser for VpnArtifactsParser {
    fn name(&self) -> &str {
        "VPN Client Artifact Parser"
    }

    fn artifact_type(&self) -> &str {
        "network_config"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "*.ovpn",
            "*.conf",
            "openvpn.log",
            "openvpn*.log",
            "wireguard*.conf",
            "wg0.conf",
            "wg1.conf",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
            .to_lowercase();

        let text = String::from_utf8_lossy(data);
        let path_str = path.to_string_lossy().to_lowercase();

        if filename.ends_with(".ovpn") || text.contains("remote ") && text.contains("dev tun") {
            self.parse_openvpn_config(path, &text)
        } else if (filename.contains("wireguard") || filename.starts_with("wg"))
            && text.contains("[Interface]")
        {
            self.parse_wireguard_config(path, &text)
        } else if filename.contains("openvpn") && filename.contains("log") {
            self.parse_openvpn_log(path, &text)
        } else if text.contains("[Interface]")
            && text.contains("PrivateKey")
            && (path_str.contains("wireguard") || path_str.contains("wg"))
        {
            self.parse_wireguard_config(path, &text)
        } else {
            Ok(vec![])
        }
    }
}

impl VpnArtifactsParser {
    fn parse_openvpn_config(
        &self,
        path: &Path,
        text: &str,
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();

        let mut entry = VpnConfigEntry {
            vpn_type: "OpenVPN".to_string(),
            server: None,
            port: None,
            protocol: None,
            auth_method: None,
            dns_servers: Vec::new(),
            routes: Vec::new(),
            interface_name: None,
            private_key_present: text.contains("<key>") || text.contains("key "),
            certificate_present: text.contains("<cert>") || text.contains("cert "),
            forensic_flags: vec!["VPN_CONFIG — OpenVPN configuration detected".to_string()],
        };

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }

            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            match parts[0] {
                "remote" => {
                    if parts.len() >= 2 {
                        entry.server = Some(parts[1].to_string());
                    }
                    if parts.len() >= 3 {
                        entry.port = Some(parts[2].to_string());
                    }
                }
                "proto" => {
                    entry.protocol = parts.get(1).map(|p| p.to_string());
                }
                "auth-user-pass" => {
                    entry.auth_method = Some("username/password".to_string());
                }
                "route" => {
                    entry.routes.push(parts[1..].join(" "));
                }
                "dhcp-option" => {
                    if parts.len() >= 3 && parts[1] == "DNS" {
                        entry.dns_servers.push(parts[2].to_string());
                    }
                }
                "dev" => {
                    entry.interface_name = parts.get(1).map(|p| p.to_string());
                }
                _ => {}
            }
        }

        if entry.private_key_present {
            entry
                .forensic_flags
                .push("PRIVATE_KEY_EMBEDDED — Key material in config file".to_string());
        }

        let server = entry.server.as_deref().unwrap_or("unknown");
        let mut desc = format!(
            "OpenVPN Config: {} ({}:{}) [{}]",
            path.file_name().unwrap_or_default().to_string_lossy(),
            server,
            entry.port.as_deref().unwrap_or("1194"),
            entry.protocol.as_deref().unwrap_or("udp"),
        );
        for flag in &entry.forensic_flags {
            desc.push_str(&format!(" [{}]", flag));
        }

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "vpn_config".to_string(),
            description: desc,
            source_path: source,
            json_data: serde_json::to_value(&entry).unwrap_or_default(),
        });

        Ok(artifacts)
    }

    fn parse_wireguard_config(
        &self,
        path: &Path,
        text: &str,
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();

        let mut entry = VpnConfigEntry {
            vpn_type: "WireGuard".to_string(),
            server: None,
            port: None,
            protocol: Some("UDP".to_string()),
            auth_method: Some("public_key".to_string()),
            dns_servers: Vec::new(),
            routes: Vec::new(),
            interface_name: path.file_stem().map(|s| s.to_string_lossy().to_string()),
            private_key_present: false,
            certificate_present: false,
            forensic_flags: vec!["VPN_CONFIG — WireGuard configuration detected".to_string()],
        };

        let mut in_peer = false;

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if trimmed == "[Peer]" {
                in_peer = true;
                continue;
            }
            if trimmed == "[Interface]" {
                in_peer = false;
                continue;
            }

            if let Some(eq_pos) = trimmed.find('=') {
                let key = trimmed[..eq_pos].trim().to_lowercase();
                let value = trimmed[eq_pos + 1..].trim();

                match key.as_str() {
                    "privatekey" => {
                        entry.private_key_present = true;
                        entry
                            .forensic_flags
                            .push("PRIVATE_KEY — WireGuard private key present".to_string());
                    }
                    "dns" => {
                        for dns in value.split(',') {
                            entry.dns_servers.push(dns.trim().to_string());
                        }
                    }
                    "endpoint" if in_peer => {
                        entry.server = Some(value.to_string());
                        if let Some(colon) = value.rfind(':') {
                            entry.port = Some(value[colon + 1..].to_string());
                        }
                    }
                    "allowedips" if in_peer => {
                        for route in value.split(',') {
                            entry.routes.push(route.trim().to_string());
                        }
                        if value.contains("0.0.0.0/0") || value.contains("::/0") {
                            entry
                                .forensic_flags
                                .push("FULL_TUNNEL — All traffic routed through VPN".to_string());
                        }
                    }
                    _ => {}
                }
            }
        }

        let mut desc = format!(
            "WireGuard Config: {} -> {}",
            entry.interface_name.as_deref().unwrap_or("wg"),
            entry.server.as_deref().unwrap_or("unknown"),
        );
        for flag in &entry.forensic_flags {
            desc.push_str(&format!(" [{}]", flag));
        }

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "vpn_config".to_string(),
            description: desc,
            source_path: source,
            json_data: serde_json::to_value(&entry).unwrap_or_default(),
        });

        Ok(artifacts)
    }

    fn parse_openvpn_log(
        &self,
        path: &Path,
        text: &str,
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();

        let mut connected_count = 0;
        let mut disconnected_count = 0;

        for line in text.lines() {
            let lower = line.to_lowercase();
            if lower.contains("initialization sequence completed") {
                connected_count += 1;
                artifacts.push(ParsedArtifact {
                    timestamp: None,
                    artifact_type: "vpn_connection".to_string(),
                    description: format!("OpenVPN Connected: {}", line.trim()),
                    source_path: source.clone(),
                    json_data: serde_json::json!({
                        "event": "connected",
                        "raw_line": line.trim(),
                    }),
                });
            } else if lower.contains("process exiting") || lower.contains("sigterm") {
                disconnected_count += 1;
                artifacts.push(ParsedArtifact {
                    timestamp: None,
                    artifact_type: "vpn_connection".to_string(),
                    description: format!("OpenVPN Disconnected: {}", line.trim()),
                    source_path: source.clone(),
                    json_data: serde_json::json!({
                        "event": "disconnected",
                        "raw_line": line.trim(),
                    }),
                });
            }

            if artifacts.len() >= 5000 {
                break;
            }
        }

        if connected_count > 0 || disconnected_count > 0 {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "vpn_summary".to_string(),
                description: format!(
                    "OpenVPN Log: {} connections, {} disconnections",
                    connected_count, disconnected_count,
                ),
                source_path: source,
                json_data: serde_json::json!({
                    "connected_count": connected_count,
                    "disconnected_count": disconnected_count,
                }),
            });
        }

        Ok(artifacts)
    }
}
