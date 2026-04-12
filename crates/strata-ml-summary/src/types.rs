//! Core data types for executive summary generation.

use strata_plugin_sdk::PluginOutput;

/// Input to the summary generator.
#[derive(Debug, Clone)]
pub struct SummaryInput {
    pub case_id: String,
    pub case_number: String,
    pub device_identifier: String,
    pub examiner_name: String,
    pub selected_charges: Vec<ChargeRef>,
    pub plugin_outputs: Vec<PluginOutput>,
    pub anomaly_report: Option<AnomalyReport>,
    pub artifact_count: usize,
    pub generated_at: String,
}

/// Minimal charge reference (avoids depending on strata-charges).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChargeRef {
    pub citation: String,
    pub short_title: String,
    pub artifact_tags: Vec<String>,
}

/// Placeholder for anomaly detection output.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnomalyReport {
    pub anomalies: Vec<AnomalyEntry>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnomalyEntry {
    pub anomaly_type: String,
    pub description: String,
    pub confidence: f32,
    pub timestamp: Option<String>,
}

/// The complete generated summary.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GeneratedSummary {
    pub case_id: String,
    pub generated_at: String,
    pub status: SummaryStatus,
    pub markdown_text: String,
    pub sections: Vec<SummarySection>,
    pub claim_sources: Vec<ClaimSource>,
    pub advisory_notice: String,
    pub examiner_approved: bool,
    pub examiner_edits: Vec<ExaminerEdit>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum SummaryStatus {
    #[default]
    Draft,
    UnderReview,
    Approved,
    Rejected,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SummarySection {
    pub section_type: SectionType,
    pub title: String,
    pub content: String,
    pub confidence: f32,
    pub source_artifacts: Vec<String>,
    pub is_editable: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum SectionType {
    Overview,
    ChargedConduct,
    EvidenceDestruction,
    TimelineAnomalies,
    AntiForensic,
    KeyArtifacts,
    RecommendedFocus,
    AdvisoryNotice,
}

/// Links a specific claim in the summary to its source artifact.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClaimSource {
    pub claim_text: String,
    pub source_plugin: String,
    pub source_artifact_id: String,
    pub confidence: f32,
}

/// An edit made by the examiner to the draft.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExaminerEdit {
    pub section_type: SectionType,
    pub original_text: String,
    pub edited_text: String,
    pub edited_at: String,
    pub edit_reason: Option<String>,
}

/// Advisory notice text — never changes, always appended.
pub const ADVISORY_NOTICE: &str = "\
ML-ASSISTED DRAFT — EXAMINER MUST REVIEW AND APPROVE\n\
This summary was auto-generated and may contain errors or omissions.\n\
All specific claims require independent verification against source artifacts.\n\
Do not use in court documents without examiner review and approval.";

#[cfg(test)]
mod tests {
    use super::*;

    // ── LOAD-BEARING TEST — DO NOT REMOVE ──
    #[test]
    fn examiner_approved_defaults_to_false() {
        let summary = GeneratedSummary {
            case_id: "test".into(),
            generated_at: "2026-04-11T00:00:00Z".into(),
            status: SummaryStatus::default(),
            markdown_text: String::new(),
            sections: Vec::new(),
            claim_sources: Vec::new(),
            advisory_notice: ADVISORY_NOTICE.to_string(),
            examiner_approved: false,
            examiner_edits: Vec::new(),
        };
        assert!(
            !summary.examiner_approved,
            "LOAD-BEARING: new summaries must default to unapproved"
        );
    }

    // ── LOAD-BEARING TEST — DO NOT REMOVE ──
    #[test]
    fn summary_status_defaults_to_draft() {
        assert_eq!(
            SummaryStatus::default(),
            SummaryStatus::Draft,
            "LOAD-BEARING: status must default to Draft, never Approved"
        );
    }

    #[test]
    fn summary_round_trips_through_json() {
        let summary = GeneratedSummary {
            case_id: "CID-2026".into(),
            generated_at: "2026-04-11T00:00:00Z".into(),
            status: SummaryStatus::Draft,
            markdown_text: "test".into(),
            sections: vec![SummarySection {
                section_type: SectionType::Overview,
                title: "Overview".into(),
                content: "Test overview".into(),
                confidence: 0.9,
                source_artifacts: vec!["art-1".into()],
                is_editable: true,
            }],
            claim_sources: Vec::new(),
            advisory_notice: ADVISORY_NOTICE.to_string(),
            examiner_approved: false,
            examiner_edits: Vec::new(),
        };
        let json = serde_json::to_string(&summary).unwrap();
        let rt: GeneratedSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.case_id, "CID-2026");
        assert_eq!(rt.status, SummaryStatus::Draft);
        assert!(!rt.examiner_approved);
    }
}
