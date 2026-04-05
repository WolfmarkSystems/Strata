use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct LaunchdParser {
    agent_type: LaunchdType,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LaunchdType {
    LaunchAgent,
    LaunchDaemon,
}

impl LaunchdType {
    pub fn from_path(path: &Path) -> Option<Self> {
        let path_str = path.to_string_lossy().to_lowercase();
        if path_str.contains("launchagents") {
            Some(LaunchdType::LaunchAgent)
        } else if path_str.contains("launchdaemons") {
            Some(LaunchdType::LaunchDaemon)
        } else {
            None
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            LaunchdType::LaunchAgent => "LaunchAgent",
            LaunchdType::LaunchDaemon => "LaunchDaemon",
        }
    }
}

impl LaunchdParser {
    pub fn new(agent_type: LaunchdType) -> Self {
        Self { agent_type }
    }

    pub fn for_agent() -> Self {
        Self {
            agent_type: LaunchdType::LaunchAgent,
        }
    }

    pub fn for_daemon() -> Self {
        Self {
            agent_type: LaunchdType::LaunchDaemon,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LaunchdEntry {
    pub label: Option<String>,
    pub program: Option<String>,
    pub program_arguments: Vec<String>,
    pub run_at_load: bool,
    pub keep_alive: bool,
    pub disabled: bool,
    pub start_interval: Option<i64>,
    pub working_directory: Option<String>,
    pub root_directory: Option<String>,
}

impl ArtifactParser for LaunchdParser {
    fn name(&self) -> &str {
        self.agent_type.name()
    }

    fn artifact_type(&self) -> &str {
        "persistence"
    }

    fn target_patterns(&self) -> Vec<&str> {
        match self.agent_type {
            LaunchdType::LaunchAgent => vec!["launchagents", ".plist"],
            LaunchdType::LaunchDaemon => vec!["launchdaemons", ".plist"],
        }
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        use crate::plist_utils::{
            get_bool_from_plist, get_int_from_plist, get_string_from_plist, parse_plist_data,
        };

        let mut artifacts = Vec::new();
        let plist_val = parse_plist_data(data)?;

        let mut entry = LaunchdEntry {
            label: get_string_from_plist(&plist_val, "Label"),
            program: get_string_from_plist(&plist_val, "Program"),
            program_arguments: Vec::new(),
            run_at_load: get_bool_from_plist(&plist_val, "RunAtLoad").unwrap_or(false),
            keep_alive: get_bool_from_plist(&plist_val, "KeepAlive").unwrap_or(false),
            disabled: get_bool_from_plist(&plist_val, "Disabled").unwrap_or(false),
            start_interval: get_int_from_plist(&plist_val, "StartInterval"),
            working_directory: get_string_from_plist(&plist_val, "WorkingDirectory"),
            root_directory: get_string_from_plist(&plist_val, "RootDirectory"),
        };

        // Extract ProgramArguments if available
        if let Some(args) = plist_val
            .as_dictionary()
            .and_then(|d| d.get("ProgramArguments"))
            .and_then(|v| v.as_array())
        {
            for arg in args {
                if let Some(s) = arg.as_string() {
                    entry.program_arguments.push(s.to_string());
                }
            }
        }

        if entry.label.is_none() {
            entry.label = path.file_stem().map(|s| s.to_string_lossy().to_string());
        }

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "persistence".to_string(),
            description: format!(
                "macOS {} ({})",
                self.agent_type.name(),
                entry.label.as_deref().unwrap_or("unknown")
            ),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(&entry).unwrap_or_default(),
        });

        Ok(artifacts)
    }
}
