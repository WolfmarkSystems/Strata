//! Summary generator pipeline — assembles findings, templates, and
//! claim sources into a complete `GeneratedSummary`.

use crate::extractor::*;
use crate::template_engine::*;
use crate::types::*;

pub struct SummaryGenerator {
    templates: TemplateEngine,
}

impl SummaryGenerator {
    pub fn new() -> Result<Self, anyhow::Error> {
        Ok(Self {
            templates: TemplateEngine::new()?,
        })
    }

    /// Generate a complete executive summary from case artifacts.
    /// The result is always `SummaryStatus::Draft` and `examiner_approved = false`.
    pub fn generate(&self, input: &SummaryInput) -> Result<GeneratedSummary, anyhow::Error> {
        // Phase 1: Structured extraction
        let charge_findings =
            FindingExtractor::extract_charge_relevant(&input.plugin_outputs, &input.selected_charges);
        let destruction_events =
            FindingExtractor::extract_destruction_events(&input.plugin_outputs);
        let highlights = FindingExtractor::extract_highlights(&input.plugin_outputs);
        let _timeline = FindingExtractor::extract_narrative_timeline(&input.plugin_outputs);
        let focus_recs = FindingExtractor::generate_focus_recommendations(
            &input.plugin_outputs,
            input.anomaly_report.as_ref(),
            &input.selected_charges,
        );

        // Phase 2: Template rendering
        let mut sections = Vec::new();
        let mut claim_sources = Vec::new();

        // Overview section
        let significance = if charge_findings.is_empty() {
            "digital artifacts of potential interest".to_string()
        } else {
            format!(
                "significant digital evidence ({} charge-relevant findings)",
                charge_findings.len()
            )
        };
        let charge_summary = if input.selected_charges.is_empty() {
            "the pending investigation".to_string()
        } else {
            input
                .selected_charges
                .iter()
                .map(|c| c.citation.clone())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let primary_finding = if !destruction_events.is_empty() {
            format!(
                "evidence of {} destruction event(s) alongside {} artifacts of interest",
                destruction_events.len(),
                charge_findings.len()
            )
        } else if !charge_findings.is_empty() {
            format!("{} artifacts supporting the charged conduct", charge_findings.len())
        } else {
            format!(
                "{} artifacts across {} plugins",
                input.artifact_count,
                input.plugin_outputs.len()
            )
        };

        let overview_text = self.templates.render_overview(&OverviewData {
            device_identifier: input.device_identifier.clone(),
            significance_statement: significance,
            charge_summary,
            artifact_count: input.artifact_count,
            plugin_count: input.plugin_outputs.len(),
            primary_finding,
        })?;

        sections.push(SummarySection {
            section_type: SectionType::Overview,
            title: "OVERVIEW".into(),
            content: overview_text,
            confidence: 1.0,
            source_artifacts: Vec::new(),
            is_editable: true,
        });

        // Charged conduct section
        if !charge_findings.is_empty() {
            let content = self.templates.render_charged_conduct(&charge_findings)?;
            for f in &charge_findings {
                for aid in &f.artifact_ids {
                    claim_sources.push(ClaimSource {
                        claim_text: f.description.clone(),
                        source_plugin: f.source_plugin.clone(),
                        source_artifact_id: aid.clone(),
                        confidence: match f.significance {
                            SignificanceLevel::Critical => 0.95,
                            SignificanceLevel::High => 0.85,
                            SignificanceLevel::Medium => 0.7,
                            SignificanceLevel::Low => 0.5,
                        },
                    });
                }
            }

            sections.push(SummarySection {
                section_type: SectionType::ChargedConduct,
                title: "EVIDENCE OF CHARGED CONDUCT".into(),
                content,
                confidence: 0.9,
                source_artifacts: charge_findings
                    .iter()
                    .flat_map(|f| f.artifact_ids.clone())
                    .collect(),
                is_editable: true,
            });
        }

        // Evidence destruction section
        if !destruction_events.is_empty() {
            let content = self.templates.render_destruction_events(&destruction_events)?;
            for ev in &destruction_events {
                claim_sources.push(ClaimSource {
                    claim_text: format!("{}: {}", ev.event_type, ev.scope),
                    source_plugin: ev.source_plugin.clone(),
                    source_artifact_id: ev.artifact_id.clone(),
                    confidence: ev.confidence,
                });
            }
            sections.push(SummarySection {
                section_type: SectionType::EvidenceDestruction,
                title: "EVIDENCE DESTRUCTION".into(),
                content,
                confidence: 0.85,
                source_artifacts: destruction_events
                    .iter()
                    .map(|e| e.artifact_id.clone())
                    .collect(),
                is_editable: true,
            });
        }

        // Timeline anomalies
        if let Some(anomaly_report) = &input.anomaly_report {
            if !anomaly_report.anomalies.is_empty() {
                let content = anomaly_report
                    .anomalies
                    .iter()
                    .enumerate()
                    .map(|(i, a)| {
                        format!(
                            "{}. {} (confidence: {:.0}%)\n   {}",
                            i + 1,
                            a.anomaly_type,
                            a.confidence * 100.0,
                            a.description
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n\n");

                sections.push(SummarySection {
                    section_type: SectionType::TimelineAnomalies,
                    title: "TIMELINE ANOMALIES (ML-ASSISTED)".into(),
                    content,
                    confidence: 0.7,
                    source_artifacts: Vec::new(),
                    is_editable: true,
                });
            }
        }

        // Key artifacts
        let key_highlights: Vec<&PluginHighlight> = highlights
            .iter()
            .filter(|h| h.suspicious_count > 0 || h.most_significant.is_some())
            .collect();
        if !key_highlights.is_empty() {
            let content = key_highlights
                .iter()
                .map(|h| {
                    format!(
                        "- {} — {} artifacts ({} suspicious){}",
                        h.plugin_name,
                        h.artifact_count,
                        h.suspicious_count,
                        h.most_significant
                            .as_ref()
                            .map(|s| format!(": {}", s))
                            .unwrap_or_default()
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");

            sections.push(SummarySection {
                section_type: SectionType::KeyArtifacts,
                title: "KEY ARTIFACTS".into(),
                content,
                confidence: 0.9,
                source_artifacts: Vec::new(),
                is_editable: true,
            });
        }

        // Recommended focus
        if !focus_recs.is_empty() {
            let content = self.templates.render_focus_recommendations(&focus_recs)?;
            sections.push(SummarySection {
                section_type: SectionType::RecommendedFocus,
                title: "RECOMMENDED EXAMINER FOCUS".into(),
                content,
                confidence: 0.8,
                source_artifacts: Vec::new(),
                is_editable: true,
            });
        }

        // Advisory notice — ALWAYS last, NEVER editable
        let advisory_text = self.templates.render_advisory_notice(input.artifact_count)?;
        sections.push(SummarySection {
            section_type: SectionType::AdvisoryNotice,
            title: "ADVISORY".into(),
            content: advisory_text.clone(),
            confidence: 1.0,
            source_artifacts: Vec::new(),
            is_editable: false,
        });

        // Build full markdown
        let markdown = sections
            .iter()
            .map(|s| format!("## {}\n\n{}", s.title, s.content))
            .collect::<Vec<_>>()
            .join("\n\n");

        Ok(GeneratedSummary {
            case_id: input.case_id.clone(),
            generated_at: input.generated_at.clone(),
            status: SummaryStatus::Draft,
            markdown_text: markdown,
            sections,
            claim_sources,
            advisory_notice: advisory_text,
            examiner_approved: false,
            examiner_edits: Vec::new(),
        })
    }

    /// Regenerate a specific section only.
    pub fn regenerate_section(
        &self,
        section: SectionType,
        input: &SummaryInput,
    ) -> Result<SummarySection, anyhow::Error> {
        let full = self.generate(input)?;
        full.sections
            .into_iter()
            .find(|s| s.section_type == section)
            .ok_or_else(|| anyhow::anyhow!("Section {:?} not generated", section))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use strata_plugin_sdk::*;

    fn test_input() -> SummaryInput {
        SummaryInput {
            case_id: "CID-2026-0412".into(),
            case_number: "2026-CASE-001".into(),
            device_identifier: "DELL-WS-4821".into(),
            examiner_name: "SA Randolph".into(),
            selected_charges: vec![ChargeRef {
                citation: "18 U.S.C. § 2252".into(),
                short_title: "Child Exploitation".into(),
                artifact_tags: vec!["Media".into()],
            }],
            plugin_outputs: vec![PluginOutput {
                plugin_name: "CSAM Sentinel".into(),
                plugin_version: "1.0.0".into(),
                executed_at: "2026-04-11T00:00:00Z".into(),
                duration_ms: 500,
                artifacts: vec![
                    ArtifactRecord {
                        category: ArtifactCategory::Media,
                        subcategory: "CSAM Hit".into(),
                        timestamp: Some(1_700_000_000),
                        title: "CSAM hash match on image.jpg".into(),
                        detail: "Known CSAM hash match".into(),
                        source_path: "/evidence/image.jpg".into(),
                        forensic_value: ForensicValue::Critical,
                        mitre_technique: None,
                        is_suspicious: true,
                        raw_data: None,
                        confidence: 0,
                    },
                    ArtifactRecord {
                        category: ArtifactCategory::SystemActivity,
                        subcategory: "VSS".into(),
                        timestamp: Some(1_700_100_000),
                        title: "VSS shadow copies deleted".into(),
                        detail: "vssadmin delete shadows /all".into(),
                        source_path: "/evidence/prefetch".into(),
                        forensic_value: ForensicValue::High,
                        mitre_technique: Some("T1490".into()),
                        is_suspicious: true,
                        raw_data: None,
                        confidence: 0,
                    },
                ],
                summary: PluginSummary {
                    total_artifacts: 2,
                    suspicious_count: 2,
                    categories_populated: vec!["Media".into()],
                    headline: "2 artifacts".into(),
                },
                warnings: Vec::new(),
            }],
            anomaly_report: Some(AnomalyReport {
                anomalies: vec![AnomalyEntry {
                    anomaly_type: "Timestamp mismatch".into(),
                    description: "$SI/$FN mismatch on 14 files".into(),
                    confidence: 0.85,
                    timestamp: Some("2025-12-04".into()),
                }],
            }),
            artifact_count: 847,
            generated_at: "2026-04-11T14:23:00Z".into(),
        }
    }

    #[test]
    fn generator_produces_all_sections() {
        let gen = SummaryGenerator::new().unwrap();
        let summary = gen.generate(&test_input()).unwrap();
        let types: Vec<SectionType> = summary.sections.iter().map(|s| s.section_type.clone()).collect();
        assert!(types.contains(&SectionType::Overview));
        assert!(types.contains(&SectionType::AdvisoryNotice));
        assert!(types.contains(&SectionType::ChargedConduct));
        assert!(types.contains(&SectionType::EvidenceDestruction));
    }

    #[test]
    fn generator_status_is_draft_on_creation() {
        let gen = SummaryGenerator::new().unwrap();
        let summary = gen.generate(&test_input()).unwrap();
        assert_eq!(summary.status, SummaryStatus::Draft);
        assert!(!summary.examiner_approved);
    }

    // ── LOAD-BEARING TEST — DO NOT REMOVE ──
    #[test]
    fn advisory_notice_always_present_in_output() {
        let gen = SummaryGenerator::new().unwrap();
        let summary = gen.generate(&test_input()).unwrap();
        assert!(
            summary
                .sections
                .iter()
                .any(|s| s.section_type == SectionType::AdvisoryNotice),
            "LOAD-BEARING: advisory notice section must always be present"
        );
        assert!(
            !summary.advisory_notice.is_empty(),
            "LOAD-BEARING: advisory_notice text must not be empty"
        );
        assert!(
            summary.advisory_notice.contains("EXAMINER MUST REVIEW"),
            "LOAD-BEARING: advisory must contain review requirement"
        );
        // Advisory must be the LAST section
        let last = summary.sections.last().unwrap();
        assert_eq!(
            last.section_type,
            SectionType::AdvisoryNotice,
            "LOAD-BEARING: advisory notice must be the last section"
        );
        assert!(
            !last.is_editable,
            "LOAD-BEARING: advisory notice must not be editable"
        );
    }

    #[test]
    fn generator_claim_sources_populated() {
        let gen = SummaryGenerator::new().unwrap();
        let summary = gen.generate(&test_input()).unwrap();
        assert!(
            !summary.claim_sources.is_empty(),
            "claim sources should be populated for charge-relevant findings"
        );
    }

    #[test]
    fn generator_advisory_notice_always_last_section() {
        let gen = SummaryGenerator::new().unwrap();
        let summary = gen.generate(&test_input()).unwrap();
        let last = summary.sections.last().unwrap();
        assert_eq!(last.section_type, SectionType::AdvisoryNotice);
    }

    #[test]
    fn summary_requires_approval_for_report_inclusion() {
        let gen = SummaryGenerator::new().unwrap();
        let summary = gen.generate(&test_input()).unwrap();
        assert!(!summary.examiner_approved);
        assert_eq!(summary.status, SummaryStatus::Draft);
    }

    #[test]
    fn edit_tracked_with_timestamp() {
        let gen = SummaryGenerator::new().unwrap();
        let mut summary = gen.generate(&test_input()).unwrap();
        let original = summary.sections[0].content.clone();
        let edited = "Examiner-corrected overview text".to_string();
        let now = chrono::Utc::now().to_rfc3339();
        summary.examiner_edits.push(ExaminerEdit {
            section_type: SectionType::Overview,
            original_text: original,
            edited_text: edited.clone(),
            edited_at: now.clone(),
            edit_reason: Some("Corrected device name".into()),
        });
        summary.sections[0].content = edited;
        assert_eq!(summary.examiner_edits.len(), 1);
        assert_eq!(summary.examiner_edits[0].edited_at, now);
    }

    #[test]
    fn edit_revokes_approval_automatically() {
        let gen = SummaryGenerator::new().unwrap();
        let mut summary = gen.generate(&test_input()).unwrap();
        summary.examiner_approved = true;
        summary.status = SummaryStatus::Approved;
        // Simulate an edit — approval is revoked
        summary.examiner_edits.push(ExaminerEdit {
            section_type: SectionType::Overview,
            original_text: "old".into(),
            edited_text: "new".into(),
            edited_at: chrono::Utc::now().to_rfc3339(),
            edit_reason: None,
        });
        summary.examiner_approved = false;
        summary.status = SummaryStatus::UnderReview;
        assert!(!summary.examiner_approved);
        assert_eq!(summary.status, SummaryStatus::UnderReview);
    }

    #[test]
    fn unapproved_summary_excluded_from_report() {
        let gen = SummaryGenerator::new().unwrap();
        let summary = gen.generate(&test_input()).unwrap();
        let include_in_report = summary.examiner_approved;
        assert!(
            !include_in_report,
            "unapproved summaries must never be included in reports"
        );
    }
}
