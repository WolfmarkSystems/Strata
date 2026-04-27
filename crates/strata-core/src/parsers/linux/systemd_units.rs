use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Systemd Unit File Parser (Linux Persistence — MITRE T1543.002)
///
/// Parses systemd service, timer, socket, and path unit files.
/// Locations:
///   - /etc/systemd/system/ — Admin-created (highest priority)
///   - /usr/lib/systemd/system/ — Package-installed
///   - ~/.config/systemd/user/ — User-level services
///   - /run/systemd/system/ — Runtime-only
///
/// Forensic value: Systemd services are the primary persistence mechanism
/// on modern Linux. Attackers create .service files to survive reboots.
/// Timer units replace cron for scheduled execution. Socket activation
/// provides on-demand backdoor capabilities.
pub struct SystemdUnitParser;

impl Default for SystemdUnitParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemdUnitParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SystemdUnitEntry {
    pub unit_type: String,
    pub description: Option<String>,
    pub exec_start: Option<String>,
    pub exec_start_pre: Option<String>,
    pub exec_stop: Option<String>,
    pub working_directory: Option<String>,
    pub user: Option<String>,
    pub group: Option<String>,
    pub restart_policy: Option<String>,
    pub wanted_by: Vec<String>,
    pub after: Vec<String>,
    pub requires: Vec<String>,
    pub environment: Vec<String>,
    pub on_calendar: Option<String>,
    pub on_boot_sec: Option<String>,
    pub listen_stream: Option<String>,
    pub path_changed: Option<String>,
    pub forensic_flags: Vec<String>,
}

impl ArtifactParser for SystemdUnitParser {
    fn name(&self) -> &str {
        "Systemd Unit File Parser"
    }

    fn artifact_type(&self) -> &str {
        "persistence"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["*.service", "*.timer", "*.socket", "*.path"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();
        let text = String::from_utf8_lossy(data);

        // Verify this is a systemd unit file
        if !text.contains("[Unit]")
            && !text.contains("[Service]")
            && !text.contains("[Timer]")
            && !text.contains("[Socket]")
            && !text.contains("[Path]")
        {
            return Ok(artifacts);
        }

        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        let unit_type = if filename.ends_with(".service") {
            "service"
        } else if filename.ends_with(".timer") {
            "timer"
        } else if filename.ends_with(".socket") {
            "socket"
        } else if filename.ends_with(".path") {
            "path"
        } else {
            "unknown"
        };

        let mut entry = SystemdUnitEntry {
            unit_type: unit_type.to_string(),
            description: None,
            exec_start: None,
            exec_start_pre: None,
            exec_stop: None,
            working_directory: None,
            user: None,
            group: None,
            restart_policy: None,
            wanted_by: Vec::new(),
            after: Vec::new(),
            requires: Vec::new(),
            environment: Vec::new(),
            on_calendar: None,
            on_boot_sec: None,
            listen_stream: None,
            path_changed: None,
            forensic_flags: Vec::new(),
        };

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('[') {
                continue;
            }

            if let Some(eq_pos) = trimmed.find('=') {
                let key = trimmed[..eq_pos].trim();
                let value = trimmed[eq_pos + 1..].trim().to_string();

                match key {
                    "Description" => entry.description = Some(value),
                    "ExecStart" => entry.exec_start = Some(value.clone()),
                    "ExecStartPre" => entry.exec_start_pre = Some(value),
                    "ExecStop" => entry.exec_stop = Some(value),
                    "WorkingDirectory" => entry.working_directory = Some(value),
                    "User" => entry.user = Some(value),
                    "Group" => entry.group = Some(value),
                    "Restart" => entry.restart_policy = Some(value),
                    "WantedBy" => {
                        for target in value.split_whitespace() {
                            entry.wanted_by.push(target.to_string());
                        }
                    }
                    "After" => {
                        for dep in value.split_whitespace() {
                            entry.after.push(dep.to_string());
                        }
                    }
                    "Requires" => {
                        for dep in value.split_whitespace() {
                            entry.requires.push(dep.to_string());
                        }
                    }
                    "Environment" => entry.environment.push(value),
                    "EnvironmentFile" => entry.environment.push(format!("file:{}", value)),
                    "OnCalendar" => entry.on_calendar = Some(value),
                    "OnBootSec" => entry.on_boot_sec = Some(value),
                    "ListenStream" => entry.listen_stream = Some(value),
                    "PathChanged" | "PathModified" | "PathExists" => {
                        entry.path_changed = Some(value);
                    }
                    _ => {}
                }
            }
        }

        // Forensic flag analysis
        if let Some(ref exec) = entry.exec_start {
            let exec_lower = exec.to_lowercase();
            if exec_lower.contains("/tmp/")
                || exec_lower.contains("/dev/shm/")
                || exec_lower.contains("/var/tmp/")
            {
                entry
                    .forensic_flags
                    .push("SUSPICIOUS_PATH — Execution from temp directory".to_string());
            }
            if exec_lower.contains("curl")
                || exec_lower.contains("wget")
                || exec_lower.contains("python -c")
                || exec_lower.contains("bash -c")
                || exec_lower.contains("nc ")
                || exec_lower.contains("ncat")
            {
                entry
                    .forensic_flags
                    .push(format!("SUSPICIOUS_COMMAND: {}", exec));
            }
            if exec_lower.contains("base64") || exec_lower.contains("eval") {
                entry
                    .forensic_flags
                    .push("ENCODED_EXECUTION — Possible obfuscated command".to_string());
            }
        }

        if entry.user.as_deref() == Some("root") {
            entry
                .forensic_flags
                .push("ROOT_EXECUTION — Runs as root".to_string());
        }

        if entry.restart_policy.as_deref() == Some("always") {
            entry
                .forensic_flags
                .push("RESTART_ALWAYS — Auto-restart on failure (persistence)".to_string());
        }

        // Check install path for user-created vs system
        let path_lower = source.to_lowercase();
        if path_lower.contains("/etc/systemd/") {
            entry
                .forensic_flags
                .push("ADMIN_CREATED — In /etc/systemd/ (manual installation)".to_string());
        }
        if path_lower.contains("/.config/systemd/user/") {
            entry
                .forensic_flags
                .push("USER_SERVICE — User-level persistence".to_string());
        }

        let unit_name = &filename;
        let exec = entry.exec_start.as_deref().unwrap_or("no command");
        let mut desc = format!(
            "Systemd {}: {} -> {} (T1543.002)",
            unit_type, unit_name, exec,
        );
        for flag in &entry.forensic_flags {
            desc.push_str(&format!(" [{}]", flag));
        }

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "systemd_unit".to_string(),
            description: desc,
            source_path: source,
            json_data: serde_json::to_value(&entry).unwrap_or_default(),
        });

        Ok(artifacts)
    }
}
