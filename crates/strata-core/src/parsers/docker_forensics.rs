use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Docker/Container Forensics Parser
///
/// Parses:
///   - Container configs: /var/lib/docker/containers/*/config.v2.json
///   - Image manifests: /var/lib/docker/image/overlay2/repositories.json
///   - Docker daemon logs: dockerd logs
///   - Dockerfile: Build instructions
///   - docker-compose.yml: Multi-container configurations
///   - Container layer metadata
///
/// Forensic value: Containerized environments are increasingly common in
/// enterprise IR. Attackers use containers for persistence, data staging,
/// crypto mining, and C2 infrastructure. No competitor does this well.
pub struct DockerForensicsParser;

impl Default for DockerForensicsParser {
    fn default() -> Self {
        Self::new()
    }
}

impl DockerForensicsParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContainerConfig {
    pub container_id: Option<String>,
    pub image: Option<String>,
    pub name: Option<String>,
    pub hostname: Option<String>,
    pub created: Option<String>,
    pub started: Option<String>,
    pub finished: Option<String>,
    pub state_running: Option<bool>,
    pub state_status: Option<String>,
    pub restart_count: Option<i32>,
    pub command: Option<Vec<String>>,
    pub entrypoint: Option<Vec<String>>,
    pub env_vars: Vec<String>,
    pub exposed_ports: Vec<String>,
    pub volumes: Vec<String>,
    pub network_mode: Option<String>,
    pub privileged: Option<bool>,
    pub pid_mode: Option<String>,
    pub ipc_mode: Option<String>,
    pub forensic_flags: Vec<String>,
}

impl ArtifactParser for DockerForensicsParser {
    fn name(&self) -> &str {
        "Docker/Container Forensics Parser"
    }

    fn artifact_type(&self) -> &str {
        "container"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "config.v2.json",
            "hostconfig.json",
            "repositories.json",
            "Dockerfile",
            "dockerfile",
            "docker-compose.yml",
            "docker-compose.yaml",
            "manifest.json",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
            .to_lowercase();

        if filename == "config.v2.json" {
            self.parse_container_config(path, data)
        } else if filename == "repositories.json" {
            self.parse_repositories(path, data)
        } else if filename == "manifest.json" {
            self.parse_manifest(path, data)
        } else if filename.starts_with("dockerfile") {
            self.parse_dockerfile(path, data)
        } else if filename.starts_with("docker-compose") {
            self.parse_compose(path, data)
        } else if filename == "hostconfig.json" {
            self.parse_hostconfig(path, data)
        } else {
            Ok(vec![])
        }
    }
}

impl DockerForensicsParser {
    fn parse_container_config(
        &self,
        path: &Path,
        data: &[u8],
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();

        let Ok(json) = serde_json::from_slice::<serde_json::Value>(data) else {
            return Ok(artifacts);
        };

        let mut forensic_flags = Vec::new();

        let state = json.get("State");
        let config = json.get("Config");

        let container_id = json
            .get("ID")
            .and_then(|v| v.as_str())
            .map(|s| s[..s.len().min(12)].to_string());
        let name = json
            .get("Name")
            .and_then(|v| v.as_str())
            .map(|s| s.trim_start_matches('/').to_string());
        let image = config
            .and_then(|c| c.get("Image"))
            .and_then(|v| v.as_str())
            .map(String::from);
        let hostname = config
            .and_then(|c| c.get("Hostname"))
            .and_then(|v| v.as_str())
            .map(String::from);
        let created = json
            .get("Created")
            .and_then(|v| v.as_str())
            .map(String::from);

        let state_running = state
            .and_then(|s| s.get("Running"))
            .and_then(|v| v.as_bool());
        let state_status = state
            .and_then(|s| s.get("Status"))
            .and_then(|v| v.as_str())
            .map(String::from);

        // Extract command
        let command: Option<Vec<String>> = config
            .and_then(|c| c.get("Cmd"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            });

        // Extract environment variables (filter sensitive ones)
        let env_vars: Vec<String> = config
            .and_then(|c| c.get("Env"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| {
                        // Redact values that look like secrets
                        if let Some(eq_pos) = s.find('=') {
                            let key = &s[..eq_pos].to_lowercase();
                            if key.contains("password")
                                || key.contains("secret")
                                || key.contains("token")
                                || key.contains("key")
                                || key.contains("api_key")
                            {
                                forensic_flags.push(format!(
                                    "SENSITIVE_ENV: {} contains potential credentials",
                                    &s[..eq_pos]
                                ));
                                return format!("{}=[REDACTED]", &s[..eq_pos]);
                            }
                        }
                        s.to_string()
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Extract exposed ports
        let exposed_ports: Vec<String> = config
            .and_then(|c| c.get("ExposedPorts"))
            .and_then(|v| v.as_object())
            .map(|obj| obj.keys().cloned().collect())
            .unwrap_or_default();

        // Check for security-relevant configurations
        let host_config = json.get("HostConfig");
        let privileged = host_config
            .and_then(|h| h.get("Privileged"))
            .and_then(|v| v.as_bool());
        if privileged == Some(true) {
            forensic_flags.push("PRIVILEGED — Container has full host access".to_string());
        }

        let pid_mode = host_config
            .and_then(|h| h.get("PidMode"))
            .and_then(|v| v.as_str())
            .map(String::from);
        if pid_mode.as_deref() == Some("host") {
            forensic_flags.push("HOST_PID — Container shares host PID namespace".to_string());
        }

        let network_mode = host_config
            .and_then(|h| h.get("NetworkMode"))
            .and_then(|v| v.as_str())
            .map(String::from);
        if network_mode.as_deref() == Some("host") {
            forensic_flags.push("HOST_NETWORK — Container shares host network".to_string());
        }

        // Volume mounts
        let volumes: Vec<String> = host_config
            .and_then(|h| h.get("Binds"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        for vol in &volumes {
            if vol.starts_with("/:/") || vol.contains("/etc:") || vol.contains("/var/run/docker") {
                forensic_flags.push(format!("DANGEROUS_MOUNT: {}", vol));
            }
        }

        let entry = ContainerConfig {
            container_id: container_id.clone(),
            image: image.clone(),
            name: name.clone(),
            hostname,
            created: created.clone(),
            started: state
                .and_then(|s| s.get("StartedAt"))
                .and_then(|v| v.as_str())
                .map(String::from),
            finished: state
                .and_then(|s| s.get("FinishedAt"))
                .and_then(|v| v.as_str())
                .map(String::from),
            state_running,
            state_status: state_status.clone(),
            restart_count: state
                .and_then(|s| s.get("RestartCount"))
                .and_then(|v| v.as_i64())
                .map(|v| v as i32),
            command,
            entrypoint: config
                .and_then(|c| c.get("Entrypoint"))
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                }),
            env_vars,
            exposed_ports,
            volumes,
            network_mode,
            privileged,
            pid_mode,
            ipc_mode: host_config
                .and_then(|h| h.get("IpcMode"))
                .and_then(|v| v.as_str())
                .map(String::from),
            forensic_flags: forensic_flags.clone(),
        };

        let mut desc = format!(
            "Docker Container: {} ({}) [{}] image={}",
            name.as_deref().unwrap_or("unnamed"),
            container_id.as_deref().unwrap_or("?"),
            state_status.as_deref().unwrap_or("unknown"),
            image.as_deref().unwrap_or("unknown"),
        );
        for flag in &forensic_flags {
            desc.push_str(&format!(" [{}]", flag));
        }

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "container_config".to_string(),
            description: desc,
            source_path: source,
            json_data: serde_json::to_value(&entry).unwrap_or_default(),
        });

        Ok(artifacts)
    }

    fn parse_repositories(
        &self,
        path: &Path,
        data: &[u8],
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();

        let Ok(json) = serde_json::from_slice::<serde_json::Value>(data) else {
            return Ok(artifacts);
        };

        if let Some(repos) = json.get("Repositories").and_then(|r| r.as_object()) {
            for (repo_name, tags) in repos {
                if let Some(tag_map) = tags.as_object() {
                    for (tag, digest) in tag_map {
                        artifacts.push(ParsedArtifact {
                            timestamp: None,
                            artifact_type: "container_image".to_string(),
                            description: format!(
                                "Docker Image: {}:{} ({})",
                                repo_name,
                                tag,
                                digest.as_str().unwrap_or("unknown"),
                            ),
                            source_path: source.clone(),
                            json_data: serde_json::json!({
                                "repository": repo_name,
                                "tag": tag,
                                "digest": digest,
                            }),
                        });
                    }
                }
            }
        }

        Ok(artifacts)
    }

    fn parse_manifest(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();

        let Ok(json) = serde_json::from_slice::<serde_json::Value>(data) else {
            return Ok(artifacts);
        };

        let items = if json.is_array() {
            json.as_array().cloned().unwrap_or_default()
        } else {
            vec![json]
        };

        for item in items {
            let config = item.get("Config").and_then(|c| c.as_str());
            let repo_tags: Vec<String> = item
                .get("RepoTags")
                .and_then(|r| r.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let layers: Vec<String> = item
                .get("Layers")
                .and_then(|l| l.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "container_manifest".to_string(),
                description: format!(
                    "Docker Manifest: {} ({} layers)",
                    repo_tags.first().map(String::as_str).unwrap_or("untagged"),
                    layers.len(),
                ),
                source_path: source.clone(),
                json_data: serde_json::json!({
                    "config": config,
                    "repo_tags": repo_tags,
                    "layer_count": layers.len(),
                }),
            });
        }

        Ok(artifacts)
    }

    fn parse_dockerfile(
        &self,
        path: &Path,
        data: &[u8],
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();
        let text = String::from_utf8_lossy(data);
        let mut forensic_flags = Vec::new();

        let mut from_image = None;
        let mut run_commands = Vec::new();
        let mut exposed_ports = Vec::new();

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let upper = trimmed.to_uppercase();
            if upper.starts_with("FROM ") {
                from_image = Some(trimmed[5..].trim().to_string());
            } else if upper.starts_with("RUN ") {
                let cmd = trimmed[4..].trim();
                run_commands.push(cmd.to_string());
                if cmd.contains("curl") || cmd.contains("wget") {
                    forensic_flags.push(format!("NETWORK_DOWNLOAD: {}", cmd));
                }
                if cmd.contains("chmod 777") || cmd.contains("chmod +x") {
                    forensic_flags.push(format!("PERMISSION_CHANGE: {}", cmd));
                }
            } else if upper.starts_with("EXPOSE ") {
                exposed_ports.push(trimmed[7..].trim().to_string());
            }
        }

        let mut desc = format!(
            "Dockerfile: FROM {} ({} RUN commands, {} ports)",
            from_image.as_deref().unwrap_or("unknown"),
            run_commands.len(),
            exposed_ports.len(),
        );
        for flag in &forensic_flags {
            desc.push_str(&format!(" [{}]", flag));
        }

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "container_build".to_string(),
            description: desc,
            source_path: source,
            json_data: serde_json::json!({
                "from_image": from_image,
                "run_commands": run_commands,
                "exposed_ports": exposed_ports,
                "forensic_flags": forensic_flags,
            }),
        });

        Ok(artifacts)
    }

    fn parse_compose(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();
        let text = String::from_utf8_lossy(data);

        // Simple YAML parsing for service names and images
        let mut services = Vec::new();
        let mut current_service = None;
        let mut in_services = false;

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed == "services:" {
                in_services = true;
                continue;
            }
            if in_services
                && !line.starts_with(' ')
                && !line.starts_with('\t')
                && !trimmed.is_empty()
            {
                in_services = false;
            }
            if in_services {
                // Two-space indent = service name
                if line.starts_with("  ") && !line.starts_with("    ") && trimmed.ends_with(':') {
                    if let Some(svc) = current_service.take() {
                        services.push(svc);
                    }
                    current_service = Some(trimmed.trim_end_matches(':').to_string());
                }
            }
        }
        if let Some(svc) = current_service {
            services.push(svc);
        }

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "container_compose".to_string(),
            description: format!(
                "Docker Compose: {} services [{}]",
                services.len(),
                services.join(", "),
            ),
            source_path: source,
            json_data: serde_json::json!({
                "services": services,
                "service_count": services.len(),
            }),
        });

        Ok(artifacts)
    }

    fn parse_hostconfig(
        &self,
        path: &Path,
        data: &[u8],
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();

        let Ok(json) = serde_json::from_slice::<serde_json::Value>(data) else {
            return Ok(artifacts);
        };

        let mut forensic_flags = Vec::new();

        let privileged = json
            .get("Privileged")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if privileged {
            forensic_flags.push("PRIVILEGED MODE".to_string());
        }

        let cap_add: Vec<String> = json
            .get("CapAdd")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        for cap in &cap_add {
            if cap == "SYS_ADMIN" || cap == "SYS_PTRACE" || cap == "NET_ADMIN" {
                forensic_flags.push(format!("DANGEROUS_CAP: {}", cap));
            }
        }

        let mut desc = format!("Docker HostConfig: privileged={}", privileged);
        if !cap_add.is_empty() {
            desc.push_str(&format!(" caps=[{}]", cap_add.join(",")));
        }
        for flag in &forensic_flags {
            desc.push_str(&format!(" [{}]", flag));
        }

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "container_hostconfig".to_string(),
            description: desc,
            source_path: source,
            json_data: serde_json::json!({
                "privileged": privileged,
                "cap_add": cap_add,
                "forensic_flags": forensic_flags,
            }),
        });

        Ok(artifacts)
    }
}
