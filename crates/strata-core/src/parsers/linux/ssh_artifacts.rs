use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// SSH Artifact Parser for Linux and macOS
///
/// Parses:
///   - authorized_keys: Public keys authorized for login (proves who can access)
///   - known_hosts: Servers previously connected to (proves outbound connections)
///   - ssh config: Connection presets and proxy configurations
///   - sshd_config: Server-side authentication settings
///
/// Forensic value: SSH is the primary remote access mechanism on Linux/macOS.
/// authorized_keys proves who was granted access, known_hosts proves what
/// servers were connected to, and config files reveal tunneling/proxy setups.
pub struct SshArtifactsParser;

impl Default for SshArtifactsParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SshArtifactsParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizedKeyEntry {
    pub key_type: String,
    pub key_fingerprint: String,
    pub comment: Option<String>,
    pub options: Option<String>,
    pub line_number: usize,
    pub forensic_flags: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KnownHostEntry {
    pub hostname: String,
    pub key_type: String,
    pub key_fingerprint: String,
    pub is_hashed: bool,
    pub line_number: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SshConfigEntry {
    pub host_pattern: String,
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<String>,
    pub identity_file: Option<String>,
    pub proxy_command: Option<String>,
    pub proxy_jump: Option<String>,
    pub local_forward: Option<String>,
    pub remote_forward: Option<String>,
    pub dynamic_forward: Option<String>,
    pub forensic_flags: Vec<String>,
}

impl ArtifactParser for SshArtifactsParser {
    fn name(&self) -> &str {
        "SSH Artifacts Parser"
    }

    fn artifact_type(&self) -> &str {
        "remote_access"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "authorized_keys",
            "authorized_keys2",
            "known_hosts",
            "ssh_config",
            "sshd_config",
            ".ssh/config",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
            .to_lowercase();

        let path_str = path.to_string_lossy().to_lowercase();
        let text = String::from_utf8_lossy(data);

        if filename.contains("authorized_keys") {
            self.parse_authorized_keys(path, &text)
        } else if filename.contains("known_hosts") {
            self.parse_known_hosts(path, &text)
        } else if filename == "config" && path_str.contains(".ssh") {
            self.parse_ssh_config(path, &text)
        } else if filename == "ssh_config" || filename == "sshd_config" {
            self.parse_sshd_config(path, &text, filename.starts_with("sshd"))
        } else {
            Ok(vec![])
        }
    }
}

impl SshArtifactsParser {
    fn parse_authorized_keys(
        &self,
        path: &Path,
        text: &str,
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();

        for (idx, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let mut forensic_flags = Vec::new();
            let mut options = None;
            let mut remaining = trimmed;

            // Check for options prefix (e.g., command="...", no-pty, etc.)
            let key_types = [
                "ssh-rsa",
                "ssh-ed25519",
                "ssh-dss",
                "ecdsa-sha2-nistp256",
                "ecdsa-sha2-nistp384",
                "ecdsa-sha2-nistp521",
                "sk-ssh-ed25519@openssh.com",
                "sk-ecdsa-sha2-nistp256@openssh.com",
            ];

            let key_type_start = key_types.iter().find_map(|&kt| {
                remaining.find(kt).map(|pos| (pos, kt))
            });

            if let Some((pos, _)) = key_type_start {
                if pos > 0 {
                    let opt_str = remaining[..pos].trim().trim_end_matches(',');
                    options = Some(opt_str.to_string());

                    // Flag suspicious options
                    if opt_str.contains("command=") {
                        forensic_flags.push("FORCED_COMMAND — key restricted to specific command".to_string());
                    }
                    if opt_str.contains("no-pty") {
                        forensic_flags.push("NO_PTY — no terminal allocated".to_string());
                    }
                    if opt_str.contains("from=") {
                        forensic_flags.push("SOURCE_RESTRICTED — key limited to specific IPs".to_string());
                    }
                }
                remaining = &remaining[pos..];
            }

            let parts: Vec<&str> = remaining.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }

            let key_type = parts[0].to_string();
            // Truncate key for fingerprint display
            let key_data = parts[1];
            let key_fingerprint = if key_data.len() > 20 {
                format!("{}...{}", &key_data[..10], &key_data[key_data.len() - 10..])
            } else {
                key_data.to_string()
            };
            let comment = parts.get(2..).map(|p| p.join(" ")).filter(|s| !s.is_empty());

            let entry = AuthorizedKeyEntry {
                key_type: key_type.clone(),
                key_fingerprint: key_fingerprint.clone(),
                comment: comment.clone(),
                options,
                line_number: idx + 1,
                forensic_flags: forensic_flags.clone(),
            };

            let mut desc = format!(
                "SSH Authorized Key: {} [{}]",
                comment.as_deref().unwrap_or("no comment"),
                key_type,
            );
            for flag in &forensic_flags {
                desc.push_str(&format!(" [{}]", flag));
            }

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "ssh_authorized_key".to_string(),
                description: desc,
                source_path: source.clone(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }

    fn parse_known_hosts(
        &self,
        path: &Path,
        text: &str,
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();

        for (idx, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }

            let hostname = parts[0].to_string();
            let is_hashed = hostname.starts_with("|1|");
            let key_type = parts[1].to_string();
            let key_data = parts[2];
            let key_fingerprint = if key_data.len() > 20 {
                format!("{}...{}", &key_data[..10], &key_data[key_data.len() - 10..])
            } else {
                key_data.to_string()
            };

            let display_host = if is_hashed {
                "HASHED_HOSTNAME".to_string()
            } else {
                hostname.clone()
            };

            let entry = KnownHostEntry {
                hostname: hostname.clone(),
                key_type: key_type.clone(),
                key_fingerprint,
                is_hashed,
                line_number: idx + 1,
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "ssh_known_host".to_string(),
                description: format!(
                    "SSH Known Host: {} [{}]{}",
                    display_host,
                    key_type,
                    if is_hashed { " [HASHED]" } else { "" }
                ),
                source_path: source.clone(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }

    fn parse_ssh_config(
        &self,
        path: &Path,
        text: &str,
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();

        let mut current_host: Option<SshConfigEntry> = None;

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = trimmed.splitn(2, char::is_whitespace).collect();
            if parts.len() < 2 {
                continue;
            }

            let key = parts[0].to_lowercase();
            let value = parts[1].trim().to_string();

            if key == "host" {
                // Flush previous host block
                if let Some(entry) = current_host.take() {
                    if let Some(a) = self.config_entry_to_artifact(&entry, &source) {
                        artifacts.push(a);
                    }
                }
                current_host = Some(SshConfigEntry {
                    host_pattern: value,
                    hostname: None,
                    user: None,
                    port: None,
                    identity_file: None,
                    proxy_command: None,
                    proxy_jump: None,
                    local_forward: None,
                    remote_forward: None,
                    dynamic_forward: None,
                    forensic_flags: Vec::new(),
                });
            } else if let Some(ref mut entry) = current_host {
                match key.as_str() {
                    "hostname" => entry.hostname = Some(value),
                    "user" => entry.user = Some(value),
                    "port" => entry.port = Some(value),
                    "identityfile" => entry.identity_file = Some(value),
                    "proxycommand" => {
                        entry.proxy_command = Some(value);
                        entry.forensic_flags.push("PROXY_COMMAND — traffic may be tunneled".to_string());
                    }
                    "proxyjump" => {
                        entry.proxy_jump = Some(value);
                        entry.forensic_flags.push("PROXY_JUMP — multi-hop SSH connection".to_string());
                    }
                    "localforward" => {
                        entry.local_forward = Some(value);
                        entry.forensic_flags.push("LOCAL_FORWARD — port forwarding configured".to_string());
                    }
                    "remoteforward" => {
                        entry.remote_forward = Some(value);
                        entry.forensic_flags.push("REMOTE_FORWARD — reverse tunnel configured".to_string());
                    }
                    "dynamicforward" => {
                        entry.dynamic_forward = Some(value);
                        entry.forensic_flags.push("DYNAMIC_FORWARD — SOCKS proxy configured".to_string());
                    }
                    _ => {}
                }
            }
        }

        // Flush last entry
        if let Some(entry) = current_host.take() {
            if let Some(a) = self.config_entry_to_artifact(&entry, &source) {
                artifacts.push(a);
            }
        }

        Ok(artifacts)
    }

    fn config_entry_to_artifact(
        &self,
        entry: &SshConfigEntry,
        source: &str,
    ) -> Option<ParsedArtifact> {
        let mut desc = format!(
            "SSH Config: Host {} -> {}",
            entry.host_pattern,
            entry.hostname.as_deref().unwrap_or("(default)"),
        );
        if let Some(ref user) = entry.user {
            desc.push_str(&format!(" (user: {})", user));
        }
        for flag in &entry.forensic_flags {
            desc.push_str(&format!(" [{}]", flag));
        }

        Some(ParsedArtifact {
            timestamp: None,
            artifact_type: "ssh_config".to_string(),
            description: desc,
            source_path: source.to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        })
    }

    fn parse_sshd_config(
        &self,
        path: &Path,
        text: &str,
        is_server: bool,
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();
        let mut forensic_flags = Vec::new();

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = trimmed.splitn(2, char::is_whitespace).collect();
            if parts.len() < 2 {
                continue;
            }

            let key = parts[0].to_lowercase();
            let value = parts[1].trim().to_lowercase();

            // Flag security-relevant settings
            match key.as_str() {
                "permitrootlogin" if value == "yes" => {
                    forensic_flags
                        .push("ROOT_LOGIN_ENABLED — root can SSH directly".to_string());
                }
                "passwordauthentication" if value == "yes" => {
                    forensic_flags.push(
                        "PASSWORD_AUTH — password-based login enabled (brute-force risk)"
                            .to_string(),
                    );
                }
                "permitemptypasswords" if value == "yes" => {
                    forensic_flags
                        .push("EMPTY_PASSWORDS — empty passwords allowed".to_string());
                }
                "x11forwarding" if value == "yes" => {
                    forensic_flags
                        .push("X11_FORWARDING — GUI forwarding enabled".to_string());
                }
                "gatewayports" if value == "yes" => {
                    forensic_flags.push(
                        "GATEWAY_PORTS — remote hosts can connect to forwarded ports".to_string(),
                    );
                }
                "allowtcpforwarding" if value == "yes" => {
                    forensic_flags
                        .push("TCP_FORWARDING — port forwarding allowed".to_string());
                }
                _ => {}
            }
        }

        let config_type = if is_server { "sshd_config" } else { "ssh_config" };
        let mut desc = format!(
            "SSH {} Configuration: {}",
            if is_server { "Server" } else { "Client" },
            path.file_name().unwrap_or_default().to_string_lossy()
        );
        for flag in &forensic_flags {
            desc.push_str(&format!(" [{}]", flag));
        }

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "ssh_config".to_string(),
            description: desc,
            source_path: source,
            json_data: serde_json::json!({
                "config_type": config_type,
                "forensic_flags": forensic_flags,
                "file": path.file_name().unwrap_or_default().to_string_lossy(),
            }),
        });

        Ok(artifacts)
    }
}
