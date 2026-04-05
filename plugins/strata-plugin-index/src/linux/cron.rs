use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct CronParser;

impl CronParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CronEntry {
    pub minute: Option<String>,
    pub hour: Option<String>,
    pub day_of_month: Option<String>,
    pub month: Option<String>,
    pub day_of_week: Option<String>,
    pub command: Option<String>,
    pub user: Option<String>,
    pub crontab_file: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AtJobEntry {
    pub job_number: Option<i32>,
    pub command: Option<String>,
    pub queue: Option<String>,
    pub runtime: Option<i64>,
}

impl Default for CronParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for CronParser {
    fn name(&self) -> &str {
        "Cron Jobs"
    }

    fn artifact_type(&self) -> &str {
        "scheduled_task"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["cron", "crontab", "at"]
    }

    fn parse_file(&self, path: &Path, _data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        let entry = CronEntry {
            minute: None,
            hour: None,
            day_of_month: None,
            month: None,
            day_of_week: None,
            command: Some(format!("Cron job from: {}", path.display())),
            user: None,
            crontab_file: Some(path.to_string_lossy().to_string()),
        };

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "scheduled_task".to_string(),
            description: "Cron scheduled task".to_string(),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(&entry).unwrap_or_default(),
        });

        Ok(artifacts)
    }
}
