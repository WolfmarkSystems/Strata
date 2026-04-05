use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct LinuxIrArtifactsParser;

impl LinuxIrArtifactsParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinuxIrEntry {
    pub category: String,
    pub timestamp: Option<i64>,
    pub user: Option<String>,
    pub source_ip: Option<String>,
    pub command: Option<String>,
    pub service: Option<String>,
    pub status: Option<String>,
    pub details: Option<String>,
}

impl Default for LinuxIrArtifactsParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for LinuxIrArtifactsParser {
    fn name(&self) -> &str {
        "Linux IR Artifacts (systemd/auditd/auth/eBPF/XFS/Btrfs)"
    }

    fn artifact_type(&self) -> &str {
        "linux_ir"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "systemd",
            ".service",
            ".timer",
            "audit.log",
            "auth.log",
            "secure",
            "falco",
            "tetragon",
            "ebpf",
            "xfs",
            "btrfs",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let path_lower = path.to_string_lossy().to_ascii_lowercase();

        parse_systemd(path, &path_lower, data, &mut artifacts);
        parse_auditd(path, &path_lower, data, &mut artifacts);
        parse_auth_logs(path, &path_lower, data, &mut artifacts);
        parse_ebpf(path, &path_lower, data, &mut artifacts);
        parse_fs_signatures(path, data, &mut artifacts);

        Ok(artifacts)
    }
}

fn parse_systemd(path: &Path, path_lower: &str, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    if !(path_lower.contains(".service")
        || path_lower.contains(".timer")
        || path_lower.contains("systemd/user"))
    {
        return;
    }
    let text = String::from_utf8_lossy(data);
    let mut exec = None;
    let mut user = None;
    let mut wanted_by = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(v) = trimmed.strip_prefix("ExecStart=") {
            exec = Some(v.to_string());
        } else if let Some(v) = trimmed.strip_prefix("User=") {
            user = Some(v.to_string());
        } else if let Some(v) = trimmed.strip_prefix("WantedBy=") {
            wanted_by = Some(v.to_string());
        }
    }
    let suspicious = exec
        .as_deref()
        .map(|v| v.contains("/tmp/") || v.contains("curl ") || v.contains("wget "))
        .unwrap_or(false);
    let entry = LinuxIrEntry {
        category: "systemd_persistence".to_string(),
        timestamp: None,
        user,
        source_ip: None,
        command: exec.clone(),
        service: path.file_name().map(|n| n.to_string_lossy().to_string()),
        status: Some(if suspicious { "suspicious" } else { "observed" }.to_string()),
        details: wanted_by,
    };
    out.push(ParsedArtifact {
        timestamp: None,
        artifact_type: "linux_ir".to_string(),
        description: "systemd unit/timer".to_string(),
        source_path: path.to_string_lossy().to_string(),
        json_data: serde_json::to_value(entry).unwrap_or_default(),
    });
}

fn parse_auditd(path: &Path, path_lower: &str, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    if !path_lower.contains("audit.log") {
        return;
    }
    let text = String::from_utf8_lossy(data);
    for line in text.lines().take(100000) {
        if !line.contains("type=") {
            continue;
        }
        let user = extract_kv(line, "auid")
            .or_else(|| extract_kv(line, "uid"))
            .or_else(|| extract_kv(line, "acct"));
        let command = extract_kv(line, "exe").or_else(|| extract_kv(line, "cmd"));
        let ts = line
            .split("msg=audit(")
            .nth(1)
            .and_then(|v| v.split(':').next())
            .and_then(|v| v.split('.').next())
            .and_then(|v| v.parse::<i64>().ok());
        let entry = LinuxIrEntry {
            category: "auditd".to_string(),
            timestamp: ts,
            user,
            source_ip: extract_kv(line, "addr"),
            command,
            service: None,
            status: extract_kv(line, "res"),
            details: Some(line.to_string()),
        };
        out.push(ParsedArtifact {
            timestamp: entry.timestamp,
            artifact_type: "linux_ir".to_string(),
            description: "auditd event".to_string(),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
    }
}

fn parse_auth_logs(path: &Path, path_lower: &str, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    if !(path_lower.contains("auth.log") || path_lower.ends_with("secure")) {
        return;
    }
    let text = String::from_utf8_lossy(data);
    for line in text.lines().take(100000) {
        let lower = line.to_ascii_lowercase();
        if !(lower.contains("sshd")
            || lower.contains("sudo")
            || lower.contains("failed password")
            || lower.contains("accepted"))
        {
            continue;
        }
        let status = if lower.contains("failed") {
            Some("failed".to_string())
        } else if lower.contains("accepted") {
            Some("accepted".to_string())
        } else {
            None
        };
        let entry = LinuxIrEntry {
            category: "auth_ssh".to_string(),
            timestamp: None,
            user: extract_after_token(line, "for"),
            source_ip: extract_after_token(line, "from"),
            command: if lower.contains("sudo") {
                extract_after_token(line, "COMMAND=")
            } else {
                None
            },
            service: Some("sshd/sudo".to_string()),
            status,
            details: Some(line.to_string()),
        };
        out.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "linux_ir".to_string(),
            description: "auth/ssh session event".to_string(),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
    }
}

fn parse_ebpf(path: &Path, path_lower: &str, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    if !(path_lower.contains("falco")
        || path_lower.contains("tetragon")
        || path_lower.contains("ebpf"))
    {
        return;
    }
    let text = String::from_utf8_lossy(data);
    for line in text.lines().take(100000) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
            let ts = value
                .get("time")
                .or_else(|| value.get("timestamp"))
                .and_then(parse_json_ts);
            let user = value
                .get("user")
                .or_else(|| value.get("process").and_then(|v| v.get("uid")))
                .and_then(value_to_string);
            let cmd = value
                .get("process")
                .and_then(|v| v.get("cmdline"))
                .or_else(|| value.get("output"))
                .and_then(value_to_string);
            let entry = LinuxIrEntry {
                category: "ebpf_trace".to_string(),
                timestamp: ts,
                user,
                source_ip: value.get("source").and_then(value_to_string),
                command: cmd,
                service: value.get("event_type").and_then(value_to_string),
                status: value.get("priority").and_then(value_to_string),
                details: Some(value.to_string()),
            };
            out.push(ParsedArtifact {
                timestamp: entry.timestamp,
                artifact_type: "linux_ir".to_string(),
                description: "eBPF trace event".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(entry).unwrap_or_default(),
            });
        }
    }
}

fn parse_fs_signatures(path: &Path, data: &[u8], out: &mut Vec<ParsedArtifact>) {
    if data.len() >= 4 && &data[..4] == b"XFSB" {
        let entry = LinuxIrEntry {
            category: "filesystem_xfs".to_string(),
            timestamp: None,
            user: None,
            source_ip: None,
            command: None,
            service: None,
            status: Some("detected".to_string()),
            details: Some("XFS superblock signature found".to_string()),
        };
        out.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "linux_ir".to_string(),
            description: "XFS filesystem detected".to_string(),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
    }
    if data.len() > 0x10040 + 8 && &data[0x10040..0x10040 + 8] == b"_BHRfS_M" {
        let entry = LinuxIrEntry {
            category: "filesystem_btrfs".to_string(),
            timestamp: None,
            user: None,
            source_ip: None,
            command: None,
            service: None,
            status: Some("detected".to_string()),
            details: Some("Btrfs superblock signature found".to_string()),
        };
        out.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "linux_ir".to_string(),
            description: "Btrfs filesystem detected".to_string(),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
    }
}

fn extract_kv(line: &str, key: &str) -> Option<String> {
    for token in line.split_whitespace() {
        if let Some(value) = token.strip_prefix(&format!("{key}=")) {
            return Some(value.trim_matches('"').to_string());
        }
    }
    None
}

fn extract_after_token(line: &str, token: &str) -> Option<String> {
    let idx = line.find(token)?;
    let rest = &line[idx + token.len()..];
    let value = rest.split_whitespace().next().unwrap_or("").trim();
    if value.is_empty() {
        None
    } else {
        Some(value.trim_matches(':').trim_matches('"').to_string())
    }
}

fn value_to_string(value: &serde_json::Value) -> Option<String> {
    if let Some(v) = value.as_str() {
        return Some(v.to_string());
    }
    if let Some(v) = value.as_i64() {
        return Some(v.to_string());
    }
    if let Some(v) = value.as_u64() {
        return Some(v.to_string());
    }
    None
}

fn parse_json_ts(value: &serde_json::Value) -> Option<i64> {
    if let Some(v) = value.as_i64() {
        return Some(if v > 10_000_000_000 { v / 1000 } else { v });
    }
    if let Some(v) = value.as_u64() {
        return i64::try_from(v)
            .ok()
            .map(|x| if x > 10_000_000_000 { x / 1000 } else { x });
    }
    if let Some(s) = value.as_str() {
        if let Ok(v) = s.parse::<i64>() {
            return Some(if v > 10_000_000_000 { v / 1000 } else { v });
        }
        return chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| dt.timestamp());
    }
    None
}
