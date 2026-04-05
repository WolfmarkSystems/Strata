use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Windows BITS (Background Intelligent Transfer Service) Parser — MITRE T1197
///
/// Parses BITS job queue files: qmgr0.dat, qmgr1.dat
/// Also parses BITS event log entries and custom BITS databases.
///
/// BITS is a legitimate Windows service for background file transfers.
/// Malware abuses BITS for:
///   - Stealthy file downloads (survives reboots)
///   - Persistence via notification commands (execute on job completion)
///   - Data exfiltration (upload jobs)
///
/// Forensic value: BITS jobs persist across reboots. The queue files
/// contain URLs, local paths, and job metadata even for completed jobs.
pub struct BitsParser;

impl Default for BitsParser {
    fn default() -> Self {
        Self::new()
    }
}

impl BitsParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BitsJobEntry {
    pub job_id: Option<String>,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub job_type: Option<String>,
    pub job_state: Option<String>,
    pub url: Option<String>,
    pub local_path: Option<String>,
    pub creation_time: Option<i64>,
    pub modification_time: Option<i64>,
    pub bytes_transferred: Option<u64>,
    pub bytes_total: Option<u64>,
    pub owner_sid: Option<String>,
    pub notification_command: Option<String>,
    pub forensic_flags: Vec<String>,
    pub mitre_technique: String,
}

impl ArtifactParser for BitsParser {
    fn name(&self) -> &str {
        "Windows BITS Transfer Parser"
    }

    fn artifact_type(&self) -> &str {
        "data_transfer"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "qmgr0.dat",
            "qmgr1.dat",
            "QMGR0.DAT",
            "QMGR1.DAT",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();

        if data.len() < 16 {
            return Ok(artifacts);
        }

        // BITS queue files are ESE databases (Extensible Storage Engine)
        // For now, scan the binary data for embedded URLs and paths
        // that indicate BITS job records

        let text = String::from_utf8_lossy(data);
        let mut jobs = Vec::new();

        // Scan for URL patterns in the binary data
        let url_patterns = ["http://", "https://", "ftp://"];
        for pattern in &url_patterns {
            let mut search_start = 0;
            while let Some(pos) = text[search_start..].find(pattern) {
                let abs_pos = search_start + pos;
                // Extract URL until whitespace or null
                let url_end = text[abs_pos..]
                    .find(|c: char| c.is_whitespace() || c == '\0' || c as u32 > 127)
                    .map(|e| abs_pos + e)
                    .unwrap_or(text.len().min(abs_pos + 2048));

                let url = &text[abs_pos..url_end];
                if url.len() > 10 && url.len() < 2048 {
                    let mut forensic_flags = Vec::new();

                    // Flag suspicious URLs
                    let url_lower = url.to_lowercase();
                    if url_lower.contains(".exe")
                        || url_lower.contains(".dll")
                        || url_lower.contains(".ps1")
                        || url_lower.contains(".bat")
                    {
                        forensic_flags.push("EXECUTABLE_DOWNLOAD — Downloads executable file".to_string());
                    }
                    if url_lower.contains("pastebin")
                        || url_lower.contains("raw.githubusercontent")
                        || url_lower.contains("transfer.sh")
                        || url_lower.contains("file.io")
                    {
                        forensic_flags
                            .push("SUSPICIOUS_HOST — Known malware delivery/staging host".to_string());
                    }

                    // Try to find associated local path nearby
                    let local_path = find_local_path_nearby(&text, abs_pos);

                    let entry = BitsJobEntry {
                        job_id: None,
                        display_name: None,
                        description: None,
                        job_type: Some("download".to_string()),
                        job_state: None,
                        url: Some(url.to_string()),
                        local_path,
                        creation_time: None,
                        modification_time: None,
                        bytes_transferred: None,
                        bytes_total: None,
                        owner_sid: None,
                        notification_command: None,
                        forensic_flags: forensic_flags.clone(),
                        mitre_technique: "T1197".to_string(),
                    };

                    if !jobs.iter().any(|j: &BitsJobEntry| j.url == entry.url) {
                        jobs.push(entry);
                    }
                }

                search_start = abs_pos + 1;
                if jobs.len() >= 500 {
                    break;
                }
            }
        }

        // Also scan for notification commands (persistence mechanism)
        let cmd_patterns = [".exe", ".bat", ".cmd", ".ps1", ".vbs"];
        // Look for command strings near "notify" or "command" markers
        for marker in &["notify", "command", "NotifyCmdLine"] {
            if let Some(pos) = text.to_lowercase().find(&marker.to_lowercase()) {
                let context = &text[pos..text.len().min(pos + 512)];
                for cmd_pattern in &cmd_patterns {
                    if let Some(cmd_pos) = context.to_lowercase().find(cmd_pattern) {
                        // Extract command path
                        let cmd_start = context[..cmd_pos]
                            .rfind(|c: char| c.is_whitespace() || c == '\0')
                            .map(|p| p + 1)
                            .unwrap_or(0);
                        let cmd_end = cmd_pos + cmd_pattern.len();
                        if cmd_end > cmd_start {
                            let cmd = context[cmd_start..cmd_end].trim();
                            if !cmd.is_empty() {
                                let entry = BitsJobEntry {
                                    job_id: None,
                                    display_name: Some("BITS Notification Command".to_string()),
                                    description: None,
                                    job_type: Some("notification".to_string()),
                                    job_state: None,
                                    url: None,
                                    local_path: None,
                                    creation_time: None,
                                    modification_time: None,
                                    bytes_transferred: None,
                                    bytes_total: None,
                                    owner_sid: None,
                                    notification_command: Some(cmd.to_string()),
                                    forensic_flags: vec![
                                        "BITS_NOTIFICATION — Command executed on job completion (persistence)".to_string(),
                                    ],
                                    mitre_technique: "T1197".to_string(),
                                };
                                jobs.push(entry);
                            }
                        }
                    }
                }
            }
        }

        for job in &jobs {
            let mut desc = format!(
                "BITS Job: {} -> {} (T1197)",
                job.url.as_deref().unwrap_or("unknown"),
                job.local_path.as_deref().unwrap_or("unknown"),
            );
            if let Some(ref notify) = job.notification_command {
                desc = format!("BITS Notification: {} (T1197)", notify);
            }
            for flag in &job.forensic_flags {
                desc.push_str(&format!(" [{}]", flag));
            }

            artifacts.push(ParsedArtifact {
                timestamp: job.creation_time,
                artifact_type: "bits_transfer".to_string(),
                description: desc,
                source_path: source.clone(),
                json_data: serde_json::to_value(job).unwrap_or_default(),
            });
        }

        if artifacts.is_empty() && data.len() > 100 {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "bits_queue".to_string(),
                description: format!(
                    "BITS Queue: {} ({} bytes) — ESE database, full parsing requires ESE library",
                    path.file_name().unwrap_or_default().to_string_lossy(),
                    data.len(),
                ),
                source_path: source,
                json_data: serde_json::json!({
                    "note": "BITS queue file detected. Contains ESE database with job records.",
                    "size_bytes": data.len(),
                    "mitre_technique": "T1197",
                }),
            });
        }

        Ok(artifacts)
    }
}

fn find_local_path_nearby(text: &str, url_pos: usize) -> Option<String> {
    // Search nearby (+/- 512 bytes) for Windows paths
    let start = url_pos.saturating_sub(512);
    let end = text.len().min(url_pos + 512);
    let context = &text[start..end];

    // Look for drive letter paths
    for i in 0..context.len().saturating_sub(4) {
        if context.as_bytes().get(i + 1) == Some(&b':')
            && context.as_bytes().get(i + 2) == Some(&b'\\')
            && context.as_bytes()[i].is_ascii_alphabetic()
        {
            let path_end = context[i..]
                .find(|c: char| c == '\0' || c == '\n' || c == '\r' || c as u32 > 127)
                .map(|e| i + e)
                .unwrap_or(context.len().min(i + 260));
            let path = &context[i..path_end];
            if path.len() > 5 {
                return Some(path.trim().to_string());
            }
        }
    }

    None
}
