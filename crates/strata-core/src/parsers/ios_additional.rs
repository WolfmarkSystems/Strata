use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct IosScreenTimeParser;

impl IosScreenTimeParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScreenTimeData {
    pub total_screen_time_minutes: i64,
    pub device_name: Option<String>,
    pub date: Option<String>,
}

impl Default for IosScreenTimeParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for IosScreenTimeParser {
    fn name(&self) -> &str {
        "iOS Screen Time"
    }

    fn artifact_type(&self) -> &str {
        "ios_screentime"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["Library/ApplicationSupport/com.apple.ScreenTimeAgent/State.sqlite"]
    }

    fn parse_file(
        &self,
        path: &Path,
        data: &[u8],
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        
        if data.is_empty() {
            return Ok(artifacts);
        }

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "ios_screentime".to_string(),
            description: "iOS Screen Time data".to_string(),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::json!({
                "path": path.display().to_string(),
                "size": data.len(),
            }),
        });

        Ok(artifacts)
    }
}

pub struct IosAppUsageParser;

impl IosAppUsageParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for IosAppUsageParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for IosAppUsageParser {
    fn name(&self) -> &str {
        "iOS App Usage"
    }

    fn artifact_type(&self) -> &str {
        "ios_app_usage"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["Library/ApplicationUsageUsageStatistics.sqlite", "usage.sqlite"]
    }

    fn parse_file(
        &self,
        path: &Path,
        data: &[u8],
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        
        if data.is_empty() {
            return Ok(artifacts);
        }

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "ios_app_usage".to_string(),
            description: "iOS Application Usage statistics".to_string(),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::json!({
                "path": path.display().to_string(),
                "size": data.len(),
            }),
        });

        Ok(artifacts)
    }
}

pub struct IosWalletParser;

impl IosWalletParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for IosWalletParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for IosWalletParser {
    fn name(&self) -> &str {
        "iOS Wallet"
    }

    fn artifact_type(&self) -> &str {
        "ios_wallet"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["Library/Passes/passes.db", "Wallet/wallet.db"]
    }

    fn parse_file(
        &self,
        path: &Path,
        data: &[u8],
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        
        if data.is_empty() {
            return Ok(artifacts);
        }

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "ios_wallet".to_string(),
            description: "iOS Wallet passes and cards".to_string(),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::json!({
                "path": path.display().to_string(),
                "size": data.len(),
            }),
        });

        Ok(artifacts)
    }
}

pub struct IosAppGroupParser;

impl IosAppGroupParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for IosAppGroupParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for IosAppGroupParser {
    fn name(&self) -> &str {
        "iOS App Group"
    }

    fn artifact_type(&self) -> &str {
        "ios_appgroup"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["AppGroup/*/Documents/*", "Library/ApplicationSupport/AppGroup/*"]
    }

    fn parse_file(
        &self,
        path: &Path,
        data: &[u8],
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        
        if data.is_empty() {
            return Ok(artifacts);
        }

        let app_group = path.to_string_lossy()
            .split("AppGroup/")
            .nth(1)
            .map(|s| s.split('/').next().unwrap_or("unknown"))
            .unwrap_or("unknown")
            .to_string();

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "ios_appgroup".to_string(),
            description: format!("iOS App Group container: {}", app_group),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::json!({
                "app_group": app_group,
                "path": path.display().to_string(),
                "size": data.len(),
            }),
        });

        Ok(artifacts)
    }
}

pub struct IosRemindersParser;

impl IosRemindersParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for IosRemindersParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for IosRemindersParser {
    fn name(&self) -> &str {
        "iOS Reminders"
    }

    fn artifact_type(&self) -> &str {
        "ios_reminders"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["Library/Reminders/Reminders.sqlite", "Reminders/reminders.db"]
    }

    fn parse_file(
        &self,
        path: &Path,
        data: &[u8],
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        
        if data.is_empty() {
            return Ok(artifacts);
        }

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "ios_reminders".to_string(),
            description: "iOS Reminders database".to_string(),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::json!({
                "path": path.display().to_string(),
                "size": data.len(),
            }),
        });

        Ok(artifacts)
    }
}
