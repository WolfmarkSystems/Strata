use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct SteganographyParser;

impl SteganographyParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StegoDetectionResult {
    pub file_path: Option<String>,
    pub file_name: Option<String>,
    pub file_size: i64,
    pub has_hidden_data: bool,
    pub confidence: f32,
    pub method: Option<String>,
    pub detected_patterns: Vec<String>,
    pub entropy_score: Option<f32>,
    pub chi_square_score: Option<f32>,
    pub lsb_anomaly_detected: bool,
    pub image_dimensions: Option<(u32, u32)>,
    pub color_anomalies: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StegoIndicator {
    pub indicator_type: Option<String>,
    pub description: Option<String>,
    pub severity: Option<String>,
    pub location: Option<String>,
}

impl Default for SteganographyParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for SteganographyParser {
    fn name(&self) -> &str {
        "Steganography Detection"
    }

    fn artifact_type(&self) -> &str {
        "analysis"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp", ".stego",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if data.len() > 0 {
            let file_size = data.len() as i64;

            let entropy_score = calculate_entropy(data);
            let chi_square = calculate_chi_square(data);

            let has_hidden = entropy_score > 7.8 || chi_square > 0.1;
            let confidence = if has_hidden { 0.75 } else { 0.1 };

            let result = StegoDetectionResult {
                file_path: Some(path.to_string_lossy().to_string()),
                file_name: path.file_name().map(|n| n.to_string_lossy().to_string()),
                file_size,
                has_hidden_data: has_hidden,
                confidence,
                method: if has_hidden {
                    Some("entropy/chi-square".to_string())
                } else {
                    None
                },
                detected_patterns: vec![],
                entropy_score: Some(entropy_score),
                chi_square_score: Some(chi_square),
                lsb_anomaly_detected: false,
                image_dimensions: None,
                color_anomalies: vec![],
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "analysis".to_string(),
                description: "Steganography detection result".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&result).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

fn calculate_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequency = [0u64; 256];
    for &byte in data {
        frequency[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &frequency {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy as f32
}

fn calculate_chi_square(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequency = [0u64; 256];
    for &byte in data {
        frequency[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let expected = len / 256.0;
    let mut chi_square = 0.0;

    for &count in &frequency {
        let diff = count as f64 - expected;
        chi_square += (diff * diff) / expected;
    }

    chi_square as f32
}
