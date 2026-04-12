use crate::types::*;

impl ChargeEvidenceMatrix {
    /// Build the matrix from a completed analysis.
    pub fn from_analysis(analysis: &ChargeEvidenceAnalysis) -> Self {
        let mut rows = Vec::new();

        for support in &analysis.selected_charge_support {
            rows.push(MatrixRow {
                charge_citation: support.charge.citation.clone(),
                charge_title: support.charge.short_title.clone(),
                evidence_count: support.supporting_artifacts.len(),
                support_level: support.support_level.clone(),
                key_artifacts: support
                    .supporting_artifacts
                    .iter()
                    .take(3)
                    .map(|a| a.artifact_description.clone())
                    .collect(),
                gaps: analysis
                    .evidence_gaps
                    .iter()
                    .filter(|g| g.charge.citation == support.charge.citation)
                    .take(2)
                    .map(|g| g.missing_artifact_type.clone())
                    .collect(),
                is_suggested: false,
            });
        }

        for suggestion in &analysis.suggested_charges {
            rows.push(MatrixRow {
                charge_citation: format!("{} (suggested)", suggestion.charge.citation),
                charge_title: suggestion.charge.short_title.clone(),
                evidence_count: suggestion.supporting_artifacts.len(),
                support_level: match suggestion.confidence {
                    SuggestionConfidence::High => SupportLevel::Strong,
                    SuggestionConfidence::Medium => SupportLevel::Moderate,
                    SuggestionConfidence::Low => SupportLevel::Weak,
                },
                key_artifacts: suggestion
                    .supporting_artifacts
                    .iter()
                    .take(3)
                    .map(|a| a.artifact_description.clone())
                    .collect(),
                gaps: Vec::new(),
                is_suggested: true,
            });
        }

        Self { rows }
    }
}
