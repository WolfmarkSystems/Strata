use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde_json::json;
use std::path::Path;

pub struct BiomeParser {}

impl BiomeParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for BiomeParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for BiomeParser {
    fn name(&self) -> &str {
        "iOS Biome (.segb)"
    }

    fn artifact_type(&self) -> &str {
        "ios_biome"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["*.segb"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        // Validate magic bytes: "SEGB"
        if data.len() < 4 || &data[0..4] != b"SEGB" {
            return Ok(Vec::new()); // Not a valid biome segmented stream
        }

        let mut artifacts = Vec::new();
        let py_path = path.to_string_lossy().to_string();

        let mut extracted_strings: Vec<String> = Vec::new();
        let mut current_string = String::new();

        // Typical SEGB header is 32 bytes, skip it to search for protobuf strings
        let start_offset = if data.len() > 32 { 32 } else { 4 };

        // Schema-less Protocol Buffer and bplist string extraction constraint
        for &byte in &data[start_offset..] {
            if byte.is_ascii_alphanumeric()
                || byte == b'.'
                || byte == b'-'
                || byte == b'_'
                || byte == b':'
                || byte == b'/'
            {
                current_string.push(byte as char);
            } else {
                if current_string.len() >= 7 && current_string.contains('.') {
                    extracted_strings.push(current_string.clone());
                }
                current_string.clear();
            }
        }

        // Catch EOF string
        if current_string.len() >= 7 && current_string.contains('.') {
            extracted_strings.push(current_string);
        }

        extracted_strings.sort();
        extracted_strings.dedup();

        let mut json_data = serde_json::Map::new();
        json_data.insert(
            "extracted_app_identifiers".to_string(),
            json!(extracted_strings),
        );
        json_data.insert(
            "stream_name".to_string(),
            json!(path.file_name().unwrap_or_default().to_string_lossy()),
        );

        // Future-proofing timestamp offset if we add explicit frame headers
        let fallback_timestamp = None;

        artifacts.push(ParsedArtifact {
            timestamp: fallback_timestamp,
            artifact_type: self.artifact_type().to_string(),
            description: "iOS Biome Stream (Heuristic)".to_string(),
            source_path: py_path,
            json_data: serde_json::Value::Object(json_data),
        });

        Ok(artifacts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_biome_heuristic_parser() {
        let parser = BiomeParser::new();
        let mut data = Vec::new();
        data.extend_from_slice(b"SEGB"); // Magic
        data.extend_from_slice(&[0u8; 28]); // Padding/Header
        data.extend_from_slice(
            b"\x0a\x17com.apple.mobilesafari\x10\x01\x15https://gemini.google.com",
        );

        let artifacts = parser
            .parse_file(Path::new("AppIntents.segb"), &data)
            .expect("parse_file failed");
        assert_eq!(artifacts.len(), 1);
        let art = &artifacts[0];

        let identifiers = art
            .json_data
            .get("extracted_app_identifiers")
            .expect("extracted_app_identifiers not found")
            .as_array()
            .expect("extracted_app_identifiers is not an array");

        let strings: Vec<&str> = identifiers.iter().filter_map(|v| v.as_str()).collect();
        assert!(strings.contains(&"com.apple.mobilesafari"));
        assert!(strings.contains(&"https://gemini.google.com"));
    }
}
