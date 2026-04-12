use serde::{Deserialize, Serialize};

/// A single anomaly finding from the ML detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyFinding {
    pub finding_id: String,
    pub artifact_ref: ArtifactRef,
    pub anomaly_type: AnomalyType,
    /// Confidence score 0.0-1.0 — statistical confidence, NOT forensic certainty.
    pub confidence: f32,
    pub explanation: String,
    pub evidence_points: Vec<String>,
    pub suggested_followup: Vec<String>,
    pub detection_method: DetectionMethod,
    /// Always true — ML findings are always advisory.
    pub is_advisory: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AnomalyType {
    TemporalOutlier,
    StealthExecution,
    TimestampManipulation,
    AbnormalDataTransfer,
    AntiForensicBehavior,
    UncorroboratedActivity,
    EvidenceDeletion,
    AutomatedBehavior,
}

impl AnomalyType {
    /// Human-readable label for UI and reports.
    pub fn label(&self) -> &'static str {
        match self {
            Self::TemporalOutlier => "TEMPORAL OUTLIER",
            Self::StealthExecution => "STEALTH EXECUTION",
            Self::TimestampManipulation => "TIMESTAMP MANIPULATION",
            Self::AbnormalDataTransfer => "ABNORMAL DATA TRANSFER",
            Self::AntiForensicBehavior => "ANTI-FORENSIC BEHAVIOR",
            Self::UncorroboratedActivity => "UNCORROBORATED ACTIVITY",
            Self::EvidenceDeletion => "EVIDENCE DELETION",
            Self::AutomatedBehavior => "AUTOMATED BEHAVIOR",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRef {
    pub plugin_name: String,
    pub artifact_category: String,
    pub artifact_id: String,
    pub timestamp: Option<String>,
    pub file_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DetectionMethod {
    Statistical,
    OnnxModel,
}

/// Result of running the anomaly detector on a case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyReport {
    pub case_id: String,
    pub analyzed_at: String,
    pub artifact_count: usize,
    pub findings: Vec<AnomalyFinding>,
    pub baseline_summary: BaselineSummary,
    pub high_confidence_count: usize,
    pub medium_confidence_count: usize,
    pub detection_method: DetectionMethod,
    pub advisory_notice: String,
}

/// Statistical baseline computed from the artifact set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineSummary {
    pub activity_hours: Vec<u8>,
    pub activity_days: Vec<String>,
    pub avg_daily_executions: f32,
    pub avg_network_transfer_bytes: f64,
    pub artifact_date_range: (String, String),
    pub total_timeline_days: u32,
}

impl Default for BaselineSummary {
    fn default() -> Self {
        Self {
            activity_hours: Vec::new(),
            activity_days: Vec::new(),
            avg_daily_executions: 0.0,
            avg_network_transfer_bytes: 0.0,
            artifact_date_range: (String::new(), String::new()),
            total_timeline_days: 0,
        }
    }
}
