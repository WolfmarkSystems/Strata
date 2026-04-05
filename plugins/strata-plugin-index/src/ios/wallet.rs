use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

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

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
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
        vec!["Library/ApplicationSupport/AppGroup/*", "AppGroup/*"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if data.is_empty() {
            return Ok(artifacts);
        }

        let app_group = path
            .to_string_lossy()
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
        vec![
            "Library/Reminders/Reminders.sqlite",
            "Reminders/reminders.db",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
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

pub struct IosKeychainParser;

impl IosKeychainParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for IosKeychainParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for IosKeychainParser {
    fn name(&self) -> &str {
        "iOS Keychain"
    }

    fn artifact_type(&self) -> &str {
        "ios_keychain"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["Library/Keychains/keychain-2.db", "keychain/keychain-2.db"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if data.is_empty() {
            return Ok(artifacts);
        }

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "ios_keychain".to_string(),
            description: "iOS Keychain database".to_string(),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::json!({
                "path": path.display().to_string(),
                "size": data.len(),
            }),
        });

        Ok(artifacts)
    }
}
