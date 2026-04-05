use crate::errors::ForensicError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonReport {
    pub report_type: String,
    pub generated_at: String,
    pub version: String,
    pub case_info: Option<CaseInfo>,
    pub findings: Vec<Finding>,
    pub timeline: Vec<TimelineEvent>,
    pub statistics: ReportStatistics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseInfo {
    pub case_number: String,
    pub examiner: String,
    pub description: String,
    pub evidence_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub category: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub source: String,
    pub timestamp: Option<u64>,
    pub artifacts: Vec<Artifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub name: String,
    pub value: String,
    pub artifact_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: u64,
    pub source: String,
    pub event_type: String,
    pub description: String,
    pub details: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportStatistics {
    pub total_files_analyzed: u64,
    pub total_bytes_analyzed: u64,
    pub total_artifacts_found: u64,
    pub suspicious_files: u64,
    pub encrypted_files: u64,
    pub hidden_files: u64,
}

pub fn create_json_report(
    report_type: &str,
    findings: Vec<Finding>,
    timeline: Vec<TimelineEvent>,
    stats: ReportStatistics,
) -> Result<String, ForensicError> {
    let report = JsonReport {
        report_type: report_type.to_string(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        version: "1.0".to_string(),
        case_info: None,
        findings,
        timeline,
        statistics: stats,
    };

    serde_json::to_string_pretty(&report)
        .map_err(|e| ForensicError::Io(std::io::Error::other(e.to_string())))
}

pub fn create_json_report_with_case(
    case_info: CaseInfo,
    findings: Vec<Finding>,
    timeline: Vec<TimelineEvent>,
    stats: ReportStatistics,
) -> Result<String, ForensicError> {
    let report = JsonReport {
        report_type: "forensic_analysis".to_string(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        version: "1.0".to_string(),
        case_info: Some(case_info),
        findings,
        timeline,
        statistics: stats,
    };

    serde_json::to_string_pretty(&report)
        .map_err(|e| ForensicError::Io(std::io::Error::other(e.to_string())))
}

pub fn parse_json_report(json_data: &str) -> Result<JsonReport, ForensicError> {
    serde_json::from_str(json_data)
        .map_err(|e| ForensicError::Io(std::io::Error::other(e.to_string())))
}

pub fn export_findings_to_json(findings: &[Finding]) -> Result<String, ForensicError> {
    serde_json::to_string_pretty(findings)
        .map_err(|e| ForensicError::Io(std::io::Error::other(e.to_string())))
}

pub fn export_timeline_to_json(timeline: &[TimelineEvent]) -> Result<String, ForensicError> {
    serde_json::to_string_pretty(timeline)
        .map_err(|e| ForensicError::Io(std::io::Error::other(e.to_string())))
}

pub fn filter_findings_by_severity(findings: &[Finding], severity: &str) -> Vec<Finding> {
    findings
        .iter()
        .filter(|f| f.severity.to_lowercase() == severity.to_lowercase())
        .cloned()
        .collect()
}

pub fn filter_findings_by_category(findings: &[Finding], category: &str) -> Vec<Finding> {
    findings
        .iter()
        .filter(|f| f.category.to_lowercase() == category.to_lowercase())
        .cloned()
        .collect()
}

pub fn calculate_report_statistics(
    findings: &[Finding],
    total_files: u64,
    total_bytes: u64,
) -> ReportStatistics {
    ReportStatistics {
        total_files_analyzed: total_files,
        total_bytes_analyzed: total_bytes,
        total_artifacts_found: findings.len() as u64,
        suspicious_files: findings
            .iter()
            .filter(|f| f.severity == "high" || f.severity == "critical")
            .count() as u64,
        encrypted_files: 0,
        hidden_files: 0,
    }
}
