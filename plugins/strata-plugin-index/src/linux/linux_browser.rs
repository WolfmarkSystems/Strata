use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct LinuxBrowserParser {
    browser: LinuxBrowser,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LinuxBrowser {
    Firefox,
    Chrome,
}

impl LinuxBrowser {
    pub fn name(&self) -> &'static str {
        match self {
            LinuxBrowser::Firefox => "Firefox (Linux)",
            LinuxBrowser::Chrome => "Chrome (Linux)",
        }
    }
}

impl LinuxBrowserParser {
    pub fn new(browser: LinuxBrowser) -> Self {
        Self { browser }
    }

    pub fn for_firefox() -> Self {
        Self {
            browser: LinuxBrowser::Firefox,
        }
    }

    pub fn for_chrome() -> Self {
        Self {
            browser: LinuxBrowser::Chrome,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinuxBrowserHistoryEntry {
    pub url: Option<String>,
    pub title: Option<String>,
    pub visit_time: Option<i64>,
    pub visit_count: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinuxBrowserCookieEntry {
    pub host: Option<String>,
    pub name: Option<String>,
    pub value: Option<String>,
    pub path: Option<String>,
    pub expiration: Option<i64>,
}

impl ArtifactParser for LinuxBrowserParser {
    fn name(&self) -> &str {
        self.browser.name()
    }

    fn artifact_type(&self) -> &str {
        "browser"
    }

    fn target_patterns(&self) -> Vec<&str> {
        match self.browser {
            LinuxBrowser::Firefox => vec!["firefox", ".mozilla", "places.sqlite"],
            LinuxBrowser::Chrome => vec!["google-chrome", "chrome", "default/history"],
        }
    }

    fn parse_file(&self, path: &Path, _data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        let entry = LinuxBrowserHistoryEntry {
            url: Some(path.to_string_lossy().to_string()),
            title: Some(format!("{} history entry", self.browser.name())),
            visit_time: None,
            visit_count: 0,
        };

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "browser".to_string(),
            description: format!("{} browser artifact", self.browser.name()),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(&entry).unwrap_or_default(),
        });

        Ok(artifacts)
    }
}
