use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Windows Scheduled Tasks XML Parser (MITRE T1053.005)
///
/// Path: C:\Windows\System32\Tasks\* and C:\Windows\Tasks\*.job
///
/// Parses XML task definition files to extract task name, triggers,
/// actions (commands), creation date, author, and security context.
///
/// Forensic value: Scheduled tasks are a primary persistence mechanism.
/// Attackers create tasks to execute payloads on reboot, at logon, or
/// on a schedule. Task XML files persist even after task deletion in
/// some cases.
pub struct ScheduledTasksParser;

impl Default for ScheduledTasksParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ScheduledTasksParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScheduledTaskEntry {
    pub task_name: Option<String>,
    pub author: Option<String>,
    pub description: Option<String>,
    pub date_created: Option<String>,
    pub uri: Option<String>,
    pub triggers: Vec<TaskTrigger>,
    pub actions: Vec<TaskAction>,
    pub security_principal: Option<String>,
    pub run_level: Option<String>,
    pub hidden: bool,
    pub enabled: bool,
    pub forensic_flags: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TaskTrigger {
    pub trigger_type: String,
    pub start_boundary: Option<String>,
    pub end_boundary: Option<String>,
    pub repetition_interval: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TaskAction {
    pub action_type: String,
    pub command: Option<String>,
    pub arguments: Option<String>,
    pub working_directory: Option<String>,
}

impl ArtifactParser for ScheduledTasksParser {
    fn name(&self) -> &str {
        "Windows Scheduled Tasks XML Parser"
    }

    fn artifact_type(&self) -> &str {
        "persistence"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "*.xml",
            "*.job",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();
        let text = String::from_utf8_lossy(data);

        // Only parse files that look like task XML
        if !text.contains("<Task") && !text.contains("<task") {
            return Ok(artifacts);
        }

        let mut entry = ScheduledTaskEntry {
            task_name: path
                .file_stem()
                .map(|s| s.to_string_lossy().to_string()),
            author: extract_xml_value(&text, "Author"),
            description: extract_xml_value(&text, "Description"),
            date_created: extract_xml_value(&text, "Date"),
            uri: extract_xml_value(&text, "URI"),
            triggers: Vec::new(),
            actions: Vec::new(),
            security_principal: extract_xml_value(&text, "UserId")
                .or_else(|| extract_xml_value(&text, "GroupId")),
            run_level: extract_xml_value(&text, "RunLevel"),
            hidden: extract_xml_value(&text, "Hidden")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(false),
            enabled: extract_xml_value(&text, "Enabled")
                .map(|v| v.to_lowercase() != "false")
                .unwrap_or(true),
            forensic_flags: Vec::new(),
        };

        // Parse triggers
        let trigger_types = [
            "CalendarTrigger",
            "TimeTrigger",
            "LogonTrigger",
            "BootTrigger",
            "IdleTrigger",
            "RegistrationTrigger",
            "SessionStateChangeTrigger",
            "EventTrigger",
        ];

        for trigger_type in &trigger_types {
            if text.contains(&format!("<{}", trigger_type)) {
                let start_boundary = extract_xml_value_in_section(&text, trigger_type, "StartBoundary");
                let end_boundary = extract_xml_value_in_section(&text, trigger_type, "EndBoundary");
                let repetition = extract_xml_value_in_section(&text, trigger_type, "Interval");
                let enabled = extract_xml_value_in_section(&text, trigger_type, "Enabled")
                    .map(|v| v.to_lowercase() != "false")
                    .unwrap_or(true);

                entry.triggers.push(TaskTrigger {
                    trigger_type: trigger_type.to_string(),
                    start_boundary,
                    end_boundary,
                    repetition_interval: repetition,
                    enabled,
                });
            }
        }

        // Parse actions
        if let Some(exec_section) = extract_section(&text, "Exec") {
            let command = extract_xml_value(&exec_section, "Command");
            let arguments = extract_xml_value(&exec_section, "Arguments");
            let working_dir = extract_xml_value(&exec_section, "WorkingDirectory");

            // Flag suspicious commands
            if let Some(ref cmd) = command {
                let cmd_lower = cmd.to_lowercase();
                if cmd_lower.contains("powershell")
                    || cmd_lower.contains("cmd.exe")
                    || cmd_lower.contains("mshta")
                    || cmd_lower.contains("wscript")
                    || cmd_lower.contains("cscript")
                    || cmd_lower.contains("rundll32")
                    || cmd_lower.contains("regsvr32")
                    || cmd_lower.contains("certutil")
                {
                    entry.forensic_flags.push(format!("LOLBIN: {}", cmd));
                }
                if cmd_lower.contains("\\temp\\")
                    || cmd_lower.contains("\\tmp\\")
                    || cmd_lower.contains("\\appdata\\")
                    || cmd_lower.contains("\\public\\")
                {
                    entry.forensic_flags.push("SUSPICIOUS_PATH".to_string());
                }
            }

            if let Some(ref args) = arguments {
                let args_lower = args.to_lowercase();
                if args_lower.contains("-encoded")
                    || args_lower.contains("-enc ")
                    || args_lower.contains("downloadstring")
                    || args_lower.contains("invoke-expression")
                    || args_lower.contains("hidden")
                {
                    entry.forensic_flags.push(format!("SUSPICIOUS_ARGS: {}", args));
                }
            }

            entry.actions.push(TaskAction {
                action_type: "Exec".to_string(),
                command,
                arguments,
                working_directory: working_dir,
            });
        }

        // Additional flags
        if entry.hidden {
            entry.forensic_flags.push("HIDDEN — Task configured as hidden".to_string());
        }
        if entry.run_level.as_deref() == Some("HighestAvailable") {
            entry.forensic_flags.push("ELEVATED — Runs with highest privileges".to_string());
        }
        if entry.security_principal.as_deref() == Some("S-1-5-18")
            || entry.security_principal.as_deref() == Some("SYSTEM")
        {
            entry.forensic_flags.push("SYSTEM — Runs as SYSTEM account".to_string());
        }

        let task_name = entry.task_name.as_deref().unwrap_or("unknown");
        let cmd = entry
            .actions
            .first()
            .and_then(|a| a.command.as_deref())
            .unwrap_or("no command");
        let mut desc = format!(
            "Scheduled Task: {} -> {} (T1053.005)",
            task_name, cmd,
        );
        for flag in &entry.forensic_flags {
            desc.push_str(&format!(" [{}]", flag));
        }

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "scheduled_task".to_string(),
            description: desc,
            source_path: source,
            json_data: serde_json::to_value(&entry).unwrap_or_default(),
        });

        Ok(artifacts)
    }
}

fn extract_xml_value(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}", tag);
    let close = format!("</{}>", tag);

    let start_pos = xml.find(&open)?;
    let after_tag = &xml[start_pos + open.len()..];
    let content_start = after_tag.find('>')? + 1;
    let content = &after_tag[content_start..];
    let end_pos = content.find(&close)?;
    let value = content[..end_pos].trim();

    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn extract_xml_value_in_section(xml: &str, section: &str, tag: &str) -> Option<String> {
    let section_content = extract_section(xml, section)?;
    extract_xml_value(&section_content, tag)
}

fn extract_section(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}", tag);
    let close = format!("</{}>", tag);

    let start = xml.find(&open)?;
    let end = xml[start..].find(&close)? + start + close.len();
    Some(xml[start..end].to_string())
}
