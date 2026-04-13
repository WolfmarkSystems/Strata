use strata_charges::{ChargeEntry, SelectedCharges};
use strata_plugin_sdk::PluginOutput;

use crate::gap_analyzer::EvidenceGapAnalyzer;
use crate::rules;
use crate::types::*;

/// Run charge-evidence analysis against the selected charges and
/// plugin outputs. Returns a full advisory analysis.
pub fn analyze(
    case_id: &str,
    selected: &SelectedCharges,
    outputs: &[PluginOutput],
) -> ChargeEvidenceAnalysis {
    let mut charge_support = Vec::new();
    let mut all_gaps = Vec::new();

    // Evaluate support for each selected charge
    for charge in &selected.charges {
        let (support_level, artifacts) = evaluate_charge_support(charge, outputs);
        let narrative = build_narrative(charge, &support_level, &artifacts);
        charge_support.push(ChargeSupport {
            charge: charge.clone(),
            support_level,
            supporting_artifacts: artifacts,
            narrative,
        });

        let gaps = EvidenceGapAnalyzer::analyze(charge, outputs);
        all_gaps.extend(gaps);
    }

    // Run all suggestion rules
    let mut suggestions: Vec<ChargeSuggestion> = Vec::new();
    let selected_citations: Vec<&str> = selected
        .charges
        .iter()
        .map(|c| c.citation.as_str())
        .collect();

    for rule in rules::all_rules() {
        if selected_citations
            .iter()
            .any(|c| c.contains(rule.section))
        {
            continue;
        }
        if let Some(suggestion) = rule.evaluate(outputs) {
            suggestions.push(suggestion);
        }
    }

    let mut analysis = ChargeEvidenceAnalysis {
        case_id: case_id.to_string(),
        analyzed_at: chrono::Utc::now().to_rfc3339(),
        selected_charge_support: charge_support,
        suggested_charges: suggestions,
        evidence_gaps: all_gaps,
        matrix: ChargeEvidenceMatrix::default(),
        advisory_notice: ADVISORY_NOTICE.to_string(),
        is_advisory: true,
    };

    analysis.matrix = ChargeEvidenceMatrix::from_analysis(&analysis);
    analysis
}

fn evaluate_charge_support(
    charge: &ChargeEntry,
    outputs: &[PluginOutput],
) -> (SupportLevel, Vec<SupportingArtifact>) {
    let mut artifacts = Vec::new();
    let mut plugin_names = std::collections::HashSet::new();

    let tags: Vec<String> = charge.artifact_tags.iter().map(|t| t.to_lowercase()).collect();
    let section_lower = charge.section.to_lowercase();
    let category_lower = charge.category.to_lowercase();

    for output in outputs {
        for record in &output.artifacts {
            let record_text = format!(
                "{} {} {} {}",
                record.title, record.detail, record.subcategory, record.source_path
            )
            .to_lowercase();

            let matches = tags.iter().any(|tag| record_text.contains(tag))
                || record_text.contains(&section_lower)
                || record_text.contains(&category_lower);

            if matches {
                plugin_names.insert(output.plugin_name.clone());
                artifacts.push(SupportingArtifact {
                    plugin_name: output.plugin_name.clone(),
                    artifact_description: record.title.clone(),
                    artifact_id: record.subcategory.clone(),
                    timestamp: record
                        .timestamp
                        .and_then(|t| chrono::DateTime::from_timestamp(t, 0).map(|d| d.to_rfc3339())),
                    relevance_explanation: format!(
                        "Matches charge artifact tags for {}",
                        charge.short_title
                    ),
                });
            }
        }
    }

    let level = if artifacts.len() >= 5 && plugin_names.len() >= 2 {
        SupportLevel::Strong
    } else if artifacts.len() >= 2 {
        SupportLevel::Moderate
    } else if !artifacts.is_empty() {
        SupportLevel::Weak
    } else {
        SupportLevel::None
    };

    (level, artifacts)
}

fn build_narrative(
    charge: &ChargeEntry,
    level: &SupportLevel,
    artifacts: &[SupportingArtifact],
) -> String {
    if artifacts.is_empty() {
        return format!(
            "No supporting artifacts found for {}. Further investigation may be needed.",
            charge.citation
        );
    }
    let plugins: Vec<&str> = artifacts
        .iter()
        .map(|a| a.plugin_name.as_str())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    format!(
        "{} support for {} \u{2014} {} artifact(s) from {} plugin(s): {}.",
        level.as_str(),
        charge.citation,
        artifacts.len(),
        plugins.len(),
        plugins.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use strata_charges::*;
    use strata_plugin_sdk::*;

    fn sample_charge_2252() -> ChargeEntry {
        ChargeEntry {
            id: 1,
            code_set: ChargeSet::USC,
            title: Some(18),
            section: "2252".to_string(),
            subsection: None,
            citation: "18 U.S.C. \u{00a7} 2252".to_string(),
            short_title: "Sexual Exploitation of Minors".to_string(),
            description: "CSAM possession/distribution".to_string(),
            category: "CSAM".to_string(),
            artifact_tags: vec!["csam".to_string(), "csam hit".to_string()],
            severity: ChargeSeverity::Felony,
            state_code: None,
            max_penalty: Some("20 years".to_string()),
            notes: None,
        }
    }

    #[allow(dead_code)]
    fn sample_charge_ucmj_92() -> ChargeEntry {
        ChargeEntry {
            id: 100,
            code_set: ChargeSet::UCMJ,
            title: None,
            section: "92".to_string(),
            subsection: None,
            citation: "UCMJ Art. 92".to_string(),
            short_title: "Failure to Obey Order".to_string(),
            description: "Failure to obey lawful order".to_string(),
            category: "Military Discipline".to_string(),
            artifact_tags: vec!["unauthorized".to_string()],
            severity: ChargeSeverity::UCMJArticle,
            state_code: None,
            max_penalty: None,
            notes: None,
        }
    }

    fn csam_outputs() -> Vec<PluginOutput> {
        vec![
            PluginOutput {
                plugin_name: "CSAM Sentinel".to_string(),
                plugin_version: "1.0".to_string(),
                executed_at: String::new(),
                duration_ms: 0,
                artifacts: vec![
                    make_record("CSAM Hit", "CSAM hash match — sha256", "csam"),
                    make_record("CSAM Hit", "CSAM hash match — sha256", "csam"),
                    make_record("CSAM Hit", "CSAM hash match — sha256", "csam"),
                ],
                summary: PluginSummary {
                    total_artifacts: 3, suspicious_count: 3,
                    categories_populated: vec![], headline: String::new(),
                },
                warnings: vec![],
            },
            PluginOutput {
                plugin_name: "Chronicle".to_string(),
                plugin_version: "1.0".to_string(),
                executed_at: String::new(),
                duration_ms: 0,
                artifacts: vec![
                    make_record("Browser History", "Chrome download of CSAM material", "browser"),
                    make_record("Browser History", "Chrome history — file sharing site", "browser"),
                    make_record("Browser History", "Chrome history — file sharing site", "browser"),
                ],
                summary: PluginSummary {
                    total_artifacts: 3, suspicious_count: 2,
                    categories_populated: vec![], headline: String::new(),
                },
                warnings: vec![],
            },
        ]
    }

    fn vss_outputs() -> Vec<PluginOutput> {
        vec![PluginOutput {
            plugin_name: "Remnant".to_string(),
            plugin_version: "1.0".to_string(),
            executed_at: String::new(),
            duration_ms: 0,
            artifacts: vec![
                make_record("Execution", "vssadmin delete shadows /all", "vss"),
                make_record("Execution", "wevtutil cl Security — log clearing", "evtx"),
            ],
            summary: PluginSummary {
                total_artifacts: 2, suspicious_count: 2,
                categories_populated: vec![], headline: String::new(),
            },
            warnings: vec![],
        }]
    }

    fn make_record(subcat: &str, detail: &str, path: &str) -> ArtifactRecord {
        ArtifactRecord {
            category: ArtifactCategory::SystemActivity,
            subcategory: subcat.to_string(),
            timestamp: Some(1700000000),
            title: detail.to_string(),
            detail: detail.to_string(),
            source_path: path.to_string(),
            forensic_value: ForensicValue::High,
            mitre_technique: None,
            is_suspicious: true,
            raw_data: None,
            confidence: 0,
        }
    }

    #[test]
    fn analyzer_finds_support_for_csam_charge() {
        let selected = SelectedCharges {
            charges: vec![sample_charge_2252()],
            examiner_notes: String::new(),
            selected_at: String::new(),
        };
        let result = analyze("test", &selected, &csam_outputs());
        assert_eq!(result.selected_charge_support.len(), 1);
        let support = &result.selected_charge_support[0];
        assert!(!support.supporting_artifacts.is_empty());
        assert!(
            support.support_level == SupportLevel::Strong
                || support.support_level == SupportLevel::Moderate
        );
    }

    #[test]
    fn analyzer_suggests_destruction_charge_from_vss() {
        let selected = SelectedCharges {
            charges: vec![sample_charge_2252()],
            examiner_notes: String::new(),
            selected_at: String::new(),
        };
        let result = analyze("test", &selected, &vss_outputs());
        let has_1519 = result
            .suggested_charges
            .iter()
            .any(|s| s.charge.section == "1519");
        assert!(has_1519, "Expected § 1519 suggestion from VSS deletion");
    }

    #[test]
    fn analyzer_identifies_browser_history_gap() {
        let outputs = vec![PluginOutput {
            plugin_name: "CSAM Sentinel".to_string(),
            plugin_version: "1.0".to_string(),
            executed_at: String::new(),
            duration_ms: 0,
            artifacts: vec![make_record("CSAM Hit", "csam hash match", "csam")],
            summary: PluginSummary {
                total_artifacts: 1, suspicious_count: 1,
                categories_populated: vec![], headline: String::new(),
            },
            warnings: vec![],
        }];
        let selected = SelectedCharges {
            charges: vec![sample_charge_2252()],
            examiner_notes: String::new(),
            selected_at: String::new(),
        };
        let result = analyze("test", &selected, &outputs);
        let has_browser_gap = result
            .evidence_gaps
            .iter()
            .any(|g| g.missing_artifact_type.contains("Browser"));
        assert!(has_browser_gap, "Expected browser history gap for CSAM charge");
    }

    #[test]
    fn analyzer_no_suggestions_for_clean_artifacts() {
        let outputs = vec![PluginOutput {
            plugin_name: "test".to_string(),
            plugin_version: "1.0".to_string(),
            executed_at: String::new(),
            duration_ms: 0,
            artifacts: vec![make_record("Normal", "normal file activity", "clean")],
            summary: PluginSummary {
                total_artifacts: 1, suspicious_count: 0,
                categories_populated: vec![], headline: String::new(),
            },
            warnings: vec![],
        }];
        let selected = SelectedCharges::default();
        let result = analyze("test", &selected, &outputs);
        assert!(result.suggested_charges.is_empty());
    }

    #[test]
    fn matrix_builds_correctly_from_analysis() {
        let selected = SelectedCharges {
            charges: vec![sample_charge_2252()],
            examiner_notes: String::new(),
            selected_at: String::new(),
        };
        let result = analyze("test", &selected, &csam_outputs());
        assert!(!result.matrix.rows.is_empty());
        assert_eq!(result.matrix.rows[0].charge_citation, "18 U.S.C. \u{00a7} 2252");
    }

    // LOAD-BEARING — charge analysis must always be advisory.
    #[test]
    fn is_advisory_always_true() {
        let selected = SelectedCharges {
            charges: vec![sample_charge_2252()],
            examiner_notes: String::new(),
            selected_at: String::new(),
        };
        let result = analyze("test", &selected, &vss_outputs());
        assert!(result.is_advisory, "ChargeEvidenceAnalysis.is_advisory must always be true");
        assert!(
            result.advisory_notice.contains("ADVISORY"),
            "Advisory notice must contain 'ADVISORY'"
        );
        for suggestion in &result.suggested_charges {
            assert!(
                suggestion.is_advisory,
                "ChargeSuggestion.is_advisory must always be true for {}",
                suggestion.charge.citation
            );
        }
    }

    #[test]
    fn suggestions_require_supporting_artifacts() {
        let selected = SelectedCharges::default();
        let result = analyze("test", &selected, &[]);
        for suggestion in &result.suggested_charges {
            assert!(
                !suggestion.supporting_artifacts.is_empty(),
                "Suggestion {} has no supporting artifacts",
                suggestion.charge.citation
            );
        }
    }

    #[test]
    fn military_rules_fire_for_ucmj_charges() {
        let outputs = vec![PluginOutput {
            plugin_name: "Recon".to_string(),
            plugin_version: "1.0".to_string(),
            executed_at: String::new(),
            duration_ms: 0,
            artifacts: vec![
                make_record("Network", ".mil domain access — unauthorized access detected", "mil"),
                make_record("Network", "personal device artifact on classified network siprnet", "sipr"),
            ],
            summary: PluginSummary {
                total_artifacts: 2, suspicious_count: 2,
                categories_populated: vec![], headline: String::new(),
            },
            warnings: vec![],
        }];
        let selected = SelectedCharges::default();
        let result = analyze("test", &selected, &outputs);
        let has_ucmj = result
            .suggested_charges
            .iter()
            .any(|s| s.charge.code_set == ChargeSet::UCMJ);
        assert!(has_ucmj, "Expected UCMJ charge suggestion from .mil artifacts");
    }

    #[test]
    fn gap_analyzer_recommends_cloud_warrant() {
        let outputs = vec![PluginOutput {
            plugin_name: "Nimbus".to_string(),
            plugin_version: "1.0".to_string(),
            executed_at: String::new(),
            duration_ms: 0,
            artifacts: vec![
                make_record("Cloud", "OneDrive sync detected — csam related", "cloud"),
            ],
            summary: PluginSummary {
                total_artifacts: 1, suspicious_count: 1,
                categories_populated: vec![], headline: String::new(),
            },
            warnings: vec![],
        }];
        let selected = SelectedCharges {
            charges: vec![sample_charge_2252()],
            examiner_notes: String::new(),
            selected_at: String::new(),
        };
        let result = analyze("test", &selected, &outputs);
        let has_cloud_gap = result
            .evidence_gaps
            .iter()
            .any(|g| g.investigative_recommendation.to_lowercase().contains("warrant"));
        assert!(has_cloud_gap, "Expected cloud warrant recommendation");
    }

    #[test]
    fn support_level_strong_requires_multiple_plugin_types() {
        // Single plugin can't produce Strong — needs 2+
        let single_plugin = vec![PluginOutput {
            plugin_name: "CSAM Sentinel".to_string(),
            plugin_version: "1.0".to_string(),
            executed_at: String::new(),
            duration_ms: 0,
            artifacts: (0..10)
                .map(|i| make_record("CSAM Hit", &format!("csam match {}", i), "csam"))
                .collect(),
            summary: PluginSummary {
                total_artifacts: 10, suspicious_count: 10,
                categories_populated: vec![], headline: String::new(),
            },
            warnings: vec![],
        }];
        let selected = SelectedCharges {
            charges: vec![sample_charge_2252()],
            examiner_notes: String::new(),
            selected_at: String::new(),
        };
        let result = analyze("test", &selected, &single_plugin);
        // Single plugin with 10 artifacts: >= 5 artifacts but only 1 plugin → Moderate, not Strong
        assert_ne!(
            result.selected_charge_support[0].support_level,
            SupportLevel::Strong,
            "Strong requires 2+ plugin types"
        );
    }
}
