use serde::{Deserialize, Serialize};
use strata_charges::{ChargeEntry, ChargeSet, ChargeSeverity};

pub const ADVISORY_NOTICE: &str =
    "ADVISORY \u{2014} For investigative guidance only. \
     Charging decisions require review by legal counsel.";

/// Full charge-evidence analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChargeEvidenceAnalysis {
    pub case_id: String,
    pub analyzed_at: String,
    pub selected_charge_support: Vec<ChargeSupport>,
    pub suggested_charges: Vec<ChargeSuggestion>,
    pub evidence_gaps: Vec<EvidenceGap>,
    pub matrix: ChargeEvidenceMatrix,
    pub advisory_notice: String,
    /// Always true — charge analysis is always advisory.
    pub is_advisory: bool,
}

/// Evidence support for a single selected charge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChargeSupport {
    pub charge: ChargeEntry,
    pub support_level: SupportLevel,
    pub supporting_artifacts: Vec<SupportingArtifact>,
    pub narrative: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SupportLevel {
    Strong,
    Moderate,
    Weak,
    None,
}

impl SupportLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Strong => "STRONG",
            Self::Moderate => "MODERATE",
            Self::Weak => "WEAK",
            Self::None => "NONE",
        }
    }
}

/// A suggested additional charge based on artifact patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChargeSuggestion {
    pub charge: ChargeEntry,
    pub basis: String,
    pub supporting_artifacts: Vec<SupportingArtifact>,
    pub confidence: SuggestionConfidence,
    pub investigative_note: String,
    /// Always true.
    pub is_advisory: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SuggestionConfidence {
    High,
    Medium,
    Low,
}

impl SuggestionConfidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
        }
    }
}

/// A gap in evidence for a specific charge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceGap {
    pub charge: ChargeEntry,
    pub missing_artifact_type: String,
    pub why_expected: String,
    pub investigative_recommendation: String,
}

/// A reference to an artifact that supports a charge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportingArtifact {
    pub plugin_name: String,
    pub artifact_description: String,
    pub artifact_id: String,
    pub timestamp: Option<String>,
    pub relevance_explanation: String,
}

/// Structured matrix for report inclusion.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChargeEvidenceMatrix {
    pub rows: Vec<MatrixRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixRow {
    pub charge_citation: String,
    pub charge_title: String,
    pub evidence_count: usize,
    pub support_level: SupportLevel,
    pub key_artifacts: Vec<String>,
    pub gaps: Vec<String>,
    pub is_suggested: bool,
}

/// Helper to build a ChargeEntry for rules that suggest new charges.
#[allow(clippy::too_many_arguments)]
pub fn make_suggested_charge(
    citation: &str,
    short_title: &str,
    description: &str,
    code_set: ChargeSet,
    title: Option<u32>,
    section: &str,
    category: &str,
    severity: ChargeSeverity,
) -> ChargeEntry {
    ChargeEntry {
        id: 0,
        code_set,
        title,
        section: section.to_string(),
        subsection: None,
        citation: citation.to_string(),
        short_title: short_title.to_string(),
        description: description.to_string(),
        category: category.to_string(),
        artifact_tags: Vec::new(),
        severity,
        state_code: None,
        max_penalty: None,
        notes: None,
    }
}
