use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct PackagesParser;

impl PackagesParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PackageEntry {
    pub package_name: Option<String>,
    pub version: Option<String>,
    pub architecture: Option<String>,
    pub description: Option<String>,
    pub maintainer: Option<String>,
    pub install_date: Option<i64>,
    pub source_package: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DpkgStatusEntry {
    pub package: Option<String>,
    pub status: Option<String>,
    pub version: Option<String>,
    pub architecture: Option<String>,
}

impl Default for PackagesParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for PackagesParser {
    fn name(&self) -> &str {
        "Package Manager"
    }

    fn artifact_type(&self) -> &str {
        "package_manager"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["dpkg", "status", "installed", "Packages", "release"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if let Ok(content) = String::from_utf8(data.to_vec()) {
            for line in content.lines().take(100) {
                if line.contains("Package:") || line.contains("Version:") {
                    let entry = PackageEntry {
                        package_name: Some(line.to_string()),
                        version: None,
                        architecture: None,
                        description: None,
                        maintainer: None,
                        install_date: None,
                        source_package: None,
                    };

                    artifacts.push(ParsedArtifact {
                        timestamp: None,
                        artifact_type: "package_manager".to_string(),
                        description: "Installed package".to_string(),
                        source_path: path.to_string_lossy().to_string(),
                        json_data: serde_json::to_value(&entry).unwrap_or_default(),
                    });
                }
            }
        }

        Ok(artifacts)
    }
}
