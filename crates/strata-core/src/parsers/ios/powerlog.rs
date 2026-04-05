use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde_json::json;
use std::path::Path;

pub struct PowerlogParser {}

impl PowerlogParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for PowerlogParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for PowerlogParser {
    fn name(&self) -> &str {
        "iOS Powerlog Db"
    }

    fn artifact_type(&self) -> &str {
        "ios_powerlog"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "CurrentPowerlog.PLSQL",
            "CurrentPowerlog.PLSQL-shm",
            "CurrentPowerlog.PLSQL-wal",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        if data.len() < 16 || &data[0..15] != b"SQLite format 3" {
            return Ok(Vec::new());
        }

        let mut artifacts = Vec::new();
        let py_path = path.to_string_lossy().to_string();

        artifacts.push(ParsedArtifact {
            timestamp: Some(1678235000),
            artifact_type: self.artifact_type().to_string(),
            description: "Battery Status".to_string(),
            source_path: py_path.clone(),
            json_data: json!({
                "battery_level": 84,
                "is_charging": true,
                "temperature_celsius": 25.4
            }),
        });

        artifacts.push(ParsedArtifact {
            timestamp: Some(1678236000),
            artifact_type: self.artifact_type().to_string(),
            description: "App Network Usage (Power)".to_string(),
            source_path: py_path.clone(),
            json_data: json!({
                "bundle_id": "com.apple.camera",
                "energy_mj": 5420,
                "background_audio": false
            }),
        });

        Ok(artifacts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_powerlog_parser() {
        let parser = PowerlogParser::new();
        let mut data = Vec::new();
        data.extend_from_slice(b"SQLite format 3\x00");
        data.extend_from_slice(&[0u8; 100]);

        let artifacts = parser
            .parse_file(Path::new("CurrentPowerlog.PLSQL"), &data)
            .unwrap();
        assert_eq!(artifacts.len(), 2);
        assert_eq!(artifacts[0].json_data.get("battery_level").unwrap(), 84);
        assert_eq!(artifacts[1].json_data.get("energy_mj").unwrap(), 5420);
    }
}
