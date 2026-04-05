use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct AiTriageParser;

impl AiTriageParser {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze_artifact(&self, path: &Path, data: &[u8], artifact_type: &str) -> TriageResult {
        let mut result = TriageResult {
            severity: TriageSeverity::Low,
            category: "Unknown".to_string(),
            summary: String::new(),
            key_findings: vec![],
            iocs: vec![],
            recommendations: vec![],
            confidence: 0.5,
        };

        let path_str = path.to_string_lossy().to_lowercase();
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        if artifact_type.contains("malware")
            || artifact_type.contains("ransomware")
            || artifact_type.contains("trojan")
        {
            result.severity = TriageSeverity::Critical;
            result.category = "Malware/Ransomware".to_string();
            result.confidence = 0.95;
            result.summary = "Malicious artifact detected - immediate review required".to_string();
            result
                .key_findings
                .push("Known malware indicator".to_string());
            result
                .recommendations
                .push("Isolate system and conduct full forensic analysis".to_string());
            result
                .recommendations
                .push("Check for lateral movement indicators".to_string());
        } else if artifact_type.contains("keychain")
            || artifact_type.contains("password")
            || artifact_type.contains("credential")
        {
            result.severity = TriageSeverity::High;
            result.category = "Credentials".to_string();
            result.confidence = 0.85;
            result.summary = "Credential material detected - sensitive data access".to_string();
            result
                .key_findings
                .push("Password/keychain data found".to_string());
            result
                .recommendations
                .push("Review access patterns".to_string());
            result
                .recommendations
                .push("Check for unauthorized access".to_string());
        } else if artifact_type.contains("phone_acquisition") || artifact_type.contains("backup") {
            result.severity = TriageSeverity::Medium;
            result.category = "Phone Data".to_string();
            result.confidence = 0.8;
            result.summary = "Mobile device acquisition data".to_string();
            result
                .key_findings
                .push("Phone backup or extraction".to_string());

            if path_str.contains("graykey") {
                result
                    .key_findings
                    .push("GrayKey extraction - bypassed passcode".to_string());
                result.severity = TriageSeverity::High;
            } else if path_str.contains("cellebrite") || path_str.contains("ufed") {
                result
                    .key_findings
                    .push("Cellebrite UFED extraction".to_string());
                result.severity = TriageSeverity::High;
            }
        } else if artifact_type.contains("location") || artifact_type.contains("gps") {
            result.severity = TriageSeverity::Medium;
            result.category = "Location Data".to_string();
            result.confidence = 0.75;
            result.summary = "Geographic location data found".to_string();
            result.key_findings.push("GPS/Location history".to_string());
        } else if artifact_type.contains("message")
            || artifact_type.contains("sms")
            || artifact_type.contains("imessage")
        {
            result.severity = TriageSeverity::Medium;
            result.category = "Communications".to_string();
            result.confidence = 0.8;
            result.summary = "Messaging/communication data".to_string();
            result
                .key_findings
                .push("Message content found".to_string());

            if path_str.contains("whatsapp") {
                result.key_findings.push("WhatsApp messages".to_string());
            } else if path_str.contains("signal") {
                result
                    .key_findings
                    .push("Signal messages - encrypted at rest".to_string());
            }
        } else if artifact_type.contains("browser") || artifact_type.contains("history") {
            result.severity = TriageSeverity::Low;
            result.category = "Browser Activity".to_string();
            result.confidence = 0.9;
            result.summary = "Web browsing history".to_string();
            result
                .key_findings
                .push("Browser history/bookmarks".to_string());

            if path_str.contains("chrome") {
                result.key_findings.push("Google Chrome data".to_string());
            } else if path_str.contains("safari") {
                result.key_findings.push("Safari data".to_string());
            }
        } else if artifact_type.contains("contact") {
            result.severity = TriageSeverity::Low;
            result.category = "Contacts".to_string();
            result.confidence = 0.9;
            result.summary = "Contact information".to_string();
            result.key_findings.push("Address book data".to_string());
        } else if artifact_type.contains("photo")
            || artifact_type.contains("image")
            || artifact_type.contains("video")
        {
            result.severity = TriageSeverity::Low;
            result.category = "Media".to_string();
            result.confidence = 0.85;
            result.summary = "Photo/video media files".to_string();
            result.key_findings.push("Multimedia content".to_string());
        } else if artifact_type.contains("call") {
            result.severity = TriageSeverity::Medium;
            result.category = "Call Logs".to_string();
            result.confidence = 0.85;
            result.summary = "Phone call history".to_string();
            result.key_findings.push("Call log entries".to_string());
        } else if artifact_type.contains("health") {
            result.severity = TriageSeverity::Medium;
            result.category = "Health Data".to_string();
            result.confidence = 0.8;
            result.summary = "Health/fitness data".to_string();
            result
                .key_findings
                .push("HealthKit/Health data".to_string());
        } else {
            result.category = "General".to_string();
            result.summary = "General artifact".to_string();

            if file_name.contains("suspicious")
                || file_name.contains("malware")
                || file_name.contains("trojan")
            {
                result.severity = TriageSeverity::High;
                result.key_findings.push("Suspicious filename".to_string());
            }
        }

        if data.len() > 1024 * 1024 {
            result
                .key_findings
                .push(format!("Large file: {} bytes", data.len()));
        }

        result
    }

    pub fn generate_summary(&self, results: &[TriageResult]) -> AiSummary {
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;

        for r in results {
            match r.severity {
                TriageSeverity::Critical => critical += 1,
                TriageSeverity::High => high += 1,
                TriageSeverity::Medium => medium += 1,
                TriageSeverity::Low => low += 1,
            }
        }

        let overall_severity = if critical > 0 {
            "CRITICAL".to_string()
        } else if high > 0 {
            "HIGH".to_string()
        } else if medium > 0 {
            "MEDIUM".to_string()
        } else {
            "LOW".to_string()
        };

        AiSummary {
            total_artifacts: results.len(),
            critical_count: critical,
            high_count: high,
            medium_count: medium,
            low_count: low,
            overall_severity,
            executive_summary: format!(
                "Analyzed {} artifacts: {} critical, {} high, {} medium, {} low severity items require attention.",
                results.len(), critical, high, medium, low
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TriageSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageResult {
    pub severity: TriageSeverity,
    pub category: String,
    pub summary: String,
    pub key_findings: Vec<String>,
    pub iocs: Vec<String>,
    pub recommendations: Vec<String>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiSummary {
    pub total_artifacts: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub overall_severity: String,
    pub executive_summary: String,
}

impl Default for AiTriageParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for AiTriageParser {
    fn name(&self) -> &str {
        "AI Triage"
    }

    fn artifact_type(&self) -> &str {
        "analysis"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["*"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if data.len() > 0 {
            let result = self.analyze_artifact(path, data, "general");

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "ai_triage".to_string(),
                description: result.summary.clone(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&result).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}
