use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::plist_utils::{get_string_from_plist, parse_plist_data};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct MacosAuthParser;

impl MacosAuthParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginEvent {
    pub user: String,
    pub timestamp: Option<i64>,
    pub source: String, // e.g. "com.apple.loginwindow" or "system.log"
}

impl Default for MacosAuthParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosAuthParser {
    fn name(&self) -> &str {
        "macOS Auth History"
    }

    fn artifact_type(&self) -> &str {
        "auth_event"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["com.apple.loginwindow.plist", "auth.log", "/var/log/secure"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let path_str = path.to_string_lossy().to_lowercase();

        if path_str.contains("loginwindow") {
            let plist_val = parse_plist_data(data)?;
            if let Some(last_user) = get_string_from_plist(&plist_val, "lastUserName") {
                artifacts.push(ParsedArtifact {
                    timestamp: None,
                    artifact_type: "auth_event".to_string(),
                    description: format!("Last logged in user: {}", last_user),
                    source_path: path.to_string_lossy().to_string(),
                    json_data: serde_json::to_value(LoginEvent {
                        user: last_user,
                        timestamp: None,
                        source: "com.apple.loginwindow.plist".to_string(),
                    })
                    .unwrap_or_default(),
                });
            }
        } else if path_str.contains("auth.log") || path_str.contains("secure") {
            let text = String::from_utf8_lossy(data);
            for line in text.lines().take(50000) {
                if line.contains("Accepted password") || line.contains("session opened") {
                    artifacts.push(ParsedArtifact {
                        timestamp: None,
                        artifact_type: "auth_event".to_string(),
                        description: format!("Auth event (log): {}", line),
                        source_path: path.to_string_lossy().to_string(),
                        json_data: serde_json::json!({
                            "line": line,
                            "source": "auth_log"
                        }),
                    });
                }
            }
        }

        Ok(artifacts)
    }
}
