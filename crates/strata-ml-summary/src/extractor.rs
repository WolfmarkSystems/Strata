//! Finding extractor — deterministic extraction of significant findings
//! from plugin outputs for executive summary generation.

use crate::types::*;
use strata_plugin_sdk::{ForensicValue, PluginOutput};

/// Extracts the most significant findings from plugin outputs.
pub struct FindingExtractor;

#[derive(Debug, Clone)]
pub struct ExtractedFinding {
    pub finding_type: FindingType,
    pub significance: SignificanceLevel,
    pub description: String,
    pub timestamp: Option<String>,
    pub source_plugin: String,
    pub artifact_ids: Vec<String>,
    pub charge_citations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FindingType {
    ChargeRelevant,
    EvidenceDestruction,
    AntiForensic,
    SuspiciousActivity,
    KeyArtifact,
}

#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub enum SignificanceLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct DestructionEvent {
    pub event_type: String,
    pub timestamp: String,
    pub tool_used: Option<String>,
    pub scope: String,
    pub confidence: f32,
    pub source_plugin: String,
    pub artifact_id: String,
}

#[derive(Debug, Clone)]
pub struct PluginHighlight {
    pub plugin_name: String,
    pub artifact_count: usize,
    pub suspicious_count: usize,
    pub most_significant: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct NarrativeEvent {
    pub timestamp: String,
    pub description: String,
    pub source_plugin: String,
    pub significance: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FocusRecommendation {
    pub priority: u8,
    pub area: String,
    pub reason: String,
    pub specific_path: Option<String>,
}

impl FindingExtractor {
    /// Extract findings relevant to selected charges.
    pub fn extract_charge_relevant(
        outputs: &[PluginOutput],
        charges: &[ChargeRef],
    ) -> Vec<ExtractedFinding> {
        let charge_tags: Vec<(&str, &str)> = charges
            .iter()
            .flat_map(|c| {
                c.artifact_tags
                    .iter()
                    .map(move |t| (t.as_str(), c.citation.as_str()))
            })
            .collect();

        let mut findings = Vec::new();
        for output in outputs {
            for artifact in &output.artifacts {
                if !artifact.is_suspicious
                    && !matches!(
                        artifact.forensic_value,
                        ForensicValue::Critical | ForensicValue::High
                    )
                {
                    continue;
                }
                let cat_str = artifact.category.as_str();
                let matching_charges: Vec<String> = charge_tags
                    .iter()
                    .filter(|(tag, _)| cat_str.contains(tag))
                    .map(|(_, citation)| citation.to_string())
                    .collect();

                if matching_charges.is_empty() && !artifact.is_suspicious {
                    continue;
                }

                findings.push(ExtractedFinding {
                    finding_type: if !matching_charges.is_empty() {
                        FindingType::ChargeRelevant
                    } else {
                        FindingType::SuspiciousActivity
                    },
                    significance: match artifact.forensic_value {
                        ForensicValue::Critical => SignificanceLevel::Critical,
                        ForensicValue::High => SignificanceLevel::High,
                        _ => SignificanceLevel::Medium,
                    },
                    description: artifact.detail.clone(),
                    timestamp: artifact.timestamp.map(|ts| {
                        chrono::DateTime::from_timestamp(ts, 0)
                            .map(|dt| dt.to_rfc3339())
                            .unwrap_or_else(|| format!("epoch:{}", ts))
                    }),
                    source_plugin: output.plugin_name.clone(),
                    artifact_ids: vec![format!("{}:{}", output.plugin_name, artifact.source_path)],
                    charge_citations: matching_charges,
                });
            }
        }

        findings.sort_by(|a, b| b.significance.partial_cmp(&a.significance).unwrap());
        findings
    }

    /// Extract evidence destruction events.
    pub fn extract_destruction_events(outputs: &[PluginOutput]) -> Vec<DestructionEvent> {
        let destruction_keywords = [
            "vss",
            "shadow cop",
            "deleted shadow",
            "log clear",
            "event log",
            "wevtutil",
            "ccleaner",
            "bleachbit",
            "sdelete",
            "cipher /w",
            "eraser",
            "dban",
            "timestomp",
            "timestamp manipulat",
        ];

        let mut events = Vec::new();
        for output in outputs {
            for artifact in &output.artifacts {
                let detail_lower = artifact.detail.to_lowercase();
                let title_lower = artifact.title.to_lowercase();

                let matched = destruction_keywords
                    .iter()
                    .any(|kw| detail_lower.contains(kw) || title_lower.contains(kw));

                if !matched {
                    continue;
                }

                let event_type = classify_destruction(&detail_lower);
                let tool = detect_tool(&detail_lower);

                events.push(DestructionEvent {
                    event_type,
                    timestamp: artifact
                        .timestamp
                        .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        .unwrap_or_else(|| "unknown".into()),
                    tool_used: tool,
                    scope: artifact.title.clone(),
                    confidence: if artifact.is_suspicious { 0.9 } else { 0.7 },
                    source_plugin: output.plugin_name.clone(),
                    artifact_id: format!("{}:{}", output.plugin_name, artifact.source_path),
                });
            }
        }
        events
    }

    /// Extract the most significant artifact from each plugin.
    pub fn extract_highlights(outputs: &[PluginOutput]) -> Vec<PluginHighlight> {
        outputs
            .iter()
            .map(|o| {
                let suspicious = o.artifacts.iter().filter(|a| a.is_suspicious).count();
                let most_sig = o
                    .artifacts
                    .iter()
                    .filter(|a| {
                        matches!(
                            a.forensic_value,
                            ForensicValue::Critical | ForensicValue::High
                        )
                    })
                    .max_by_key(|a| match a.forensic_value {
                        ForensicValue::Critical => 4,
                        ForensicValue::High => 3,
                        _ => 1,
                    })
                    .map(|a| a.title.clone());

                PluginHighlight {
                    plugin_name: o.plugin_name.clone(),
                    artifact_count: o.artifacts.len(),
                    suspicious_count: suspicious,
                    most_significant: most_sig,
                }
            })
            .collect()
    }

    /// Build a chronological narrative timeline (top 10 events).
    pub fn extract_narrative_timeline(outputs: &[PluginOutput]) -> Vec<NarrativeEvent> {
        let mut events: Vec<(i64, NarrativeEvent)> = Vec::new();

        for output in outputs {
            for artifact in &output.artifacts {
                if !artifact.is_suspicious
                    && !matches!(
                        artifact.forensic_value,
                        ForensicValue::Critical | ForensicValue::High
                    )
                {
                    continue;
                }
                let Some(ts) = artifact.timestamp else {
                    continue;
                };
                let ts_str = chrono::DateTime::from_timestamp(ts, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| format!("epoch:{}", ts));

                events.push((
                    ts,
                    NarrativeEvent {
                        timestamp: ts_str,
                        description: artifact.title.clone(),
                        source_plugin: output.plugin_name.clone(),
                        significance: format!("{:?}", artifact.forensic_value),
                    },
                ));
            }
        }

        events.sort_by_key(|(ts, _)| *ts);
        events.into_iter().map(|(_, e)| e).take(10).collect()
    }

    /// Generate recommended examiner focus areas.
    pub fn generate_focus_recommendations(
        outputs: &[PluginOutput],
        anomalies: Option<&AnomalyReport>,
        charges: &[ChargeRef],
    ) -> Vec<FocusRecommendation> {
        let mut recs = Vec::new();
        let mut priority = 1u8;

        // CSAM-related charges → recommend media review
        if charges.iter().any(|c| {
            c.citation.contains("2252")
                || c.citation.contains("2251")
                || c.citation.contains("1466A")
                || c.citation.contains("Child Pornography")
        }) {
            recs.push(FocusRecommendation {
                priority,
                area: "Media file hash analysis".into(),
                reason: "CSAM charges selected — complete hash verification of all media files recommended".into(),
                specific_path: None,
            });
            priority += 1;
        }

        // Check for destruction events → recommend recovery
        let destruction_count = outputs
            .iter()
            .flat_map(|o| &o.artifacts)
            .filter(|a| {
                let d = a.detail.to_lowercase();
                d.contains("vss") || d.contains("shadow") || d.contains("log clear")
            })
            .count();
        if destruction_count > 0 {
            recs.push(FocusRecommendation {
                priority,
                area: "Deleted file recovery".into(),
                reason: format!(
                    "{} evidence destruction events detected — VSS/log recovery recommended",
                    destruction_count
                ),
                specific_path: None,
            });
            priority += 1;
        }

        // Anomalies → recommend timeline analysis
        if let Some(report) = anomalies {
            if !report.anomalies.is_empty() {
                recs.push(FocusRecommendation {
                    priority,
                    area: "Timeline anomaly investigation".into(),
                    reason: format!(
                        "{} statistical anomalies detected — manual timeline review recommended",
                        report.anomalies.len()
                    ),
                    specific_path: None,
                });
                priority += 1;
            }
        }

        // Suspicious artifacts → recommend review
        let suspicious_total: usize = outputs
            .iter()
            .map(|o| o.artifacts.iter().filter(|a| a.is_suspicious).count())
            .sum();
        if suspicious_total > 0 {
            recs.push(FocusRecommendation {
                priority,
                area: "Suspicious artifact review".into(),
                reason: format!(
                    "{} artifacts flagged as suspicious across {} plugins",
                    suspicious_total,
                    outputs.len()
                ),
                specific_path: None,
            });
            let _ = priority;
        }

        recs
    }
}

fn classify_destruction(detail: &str) -> String {
    if detail.contains("vss") || detail.contains("shadow cop") {
        "VSS Deletion".into()
    } else if detail.contains("log clear")
        || detail.contains("wevtutil")
        || detail.contains("event log")
    {
        "Log Clearing".into()
    } else if detail.contains("ccleaner") || detail.contains("bleachbit") {
        "Anti-forensic Tool".into()
    } else if detail.contains("timestomp") || detail.contains("timestamp") {
        "Timestamp Manipulation".into()
    } else if detail.contains("sdelete")
        || detail.contains("cipher /w")
        || detail.contains("eraser")
    {
        "Secure Deletion".into()
    } else {
        "Evidence Destruction".into()
    }
}

fn detect_tool(detail: &str) -> Option<String> {
    if detail.contains("ccleaner") {
        Some("CCleaner".into())
    } else if detail.contains("bleachbit") {
        Some("BleachBit".into())
    } else if detail.contains("sdelete") {
        Some("SDelete".into())
    } else if detail.contains("wevtutil") {
        Some("wevtutil".into())
    } else if detail.contains("vssadmin") {
        Some("vssadmin".into())
    } else if detail.contains("eraser") {
        Some("Eraser".into())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use strata_plugin_sdk::*;

    fn make_output(name: &str, artifacts: Vec<ArtifactRecord>) -> PluginOutput {
        PluginOutput {
            plugin_name: name.into(),
            plugin_version: "1.0.0".into(),
            executed_at: "2026-04-11T00:00:00Z".into(),
            duration_ms: 100,
            artifacts,
            summary: PluginSummary {
                total_artifacts: 0,
                suspicious_count: 0,
                categories_populated: Vec::new(),
                headline: String::new(),
            },
            warnings: Vec::new(),
        }
    }

    fn csam_artifact() -> ArtifactRecord {
        ArtifactRecord {
            category: ArtifactCategory::Media,
            subcategory: "CSAM Hit".into(),
            timestamp: Some(1_700_000_000),
            title: "CSAM hash match".into(),
            detail: "Known CSAM hash match SHA256:abcdef".into(),
            source_path: "/evidence/image.jpg".into(),
            forensic_value: ForensicValue::Critical,
            mitre_technique: None,
            is_suspicious: true,
            raw_data: None,
            confidence: 0,
        }
    }

    fn vss_deletion_artifact() -> ArtifactRecord {
        ArtifactRecord {
            category: ArtifactCategory::SystemActivity,
            subcategory: "VSS".into(),
            timestamp: Some(1_700_100_000),
            title: "VSS shadow copies deleted".into(),
            detail: "vssadmin delete shadows /all executed".into(),
            source_path: "/evidence/prefetch".into(),
            forensic_value: ForensicValue::High,
            mitre_technique: Some("T1490".into()),
            is_suspicious: true,
            raw_data: None,
            confidence: 0,
        }
    }

    #[test]
    fn extractor_finds_csam_evidence_in_outputs() {
        let outputs = vec![make_output("CSAM Sentinel", vec![csam_artifact()])];
        let charges = vec![ChargeRef {
            citation: "18 U.S.C. § 2252".into(),
            short_title: "Child Exploitation".into(),
            artifact_tags: vec!["Media".into()],
        }];
        let findings = FindingExtractor::extract_charge_relevant(&outputs, &charges);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].finding_type, FindingType::ChargeRelevant);
        assert!(findings[0]
            .charge_citations
            .contains(&"18 U.S.C. § 2252".to_string()));
    }

    #[test]
    fn extractor_finds_vss_deletion_event() {
        let outputs = vec![make_output("Trace", vec![vss_deletion_artifact()])];
        let events = FindingExtractor::extract_destruction_events(&outputs);
        assert!(!events.is_empty());
        assert_eq!(events[0].event_type, "VSS Deletion");
        assert_eq!(events[0].tool_used, Some("vssadmin".into()));
    }

    #[test]
    fn extractor_generates_focus_recommendations() {
        let outputs = vec![make_output("Trace", vec![vss_deletion_artifact()])];
        let charges = vec![ChargeRef {
            citation: "18 U.S.C. § 2252".into(),
            short_title: "CSAM".into(),
            artifact_tags: vec!["Media".into()],
        }];
        let recs = FindingExtractor::generate_focus_recommendations(&outputs, None, &charges);
        assert!(
            recs.len() >= 2,
            "expected media + recovery recs, got {}",
            recs.len()
        );
        assert!(recs.iter().any(|r| r.area.contains("Media")));
        assert!(recs.iter().any(|r| r.area.contains("Deleted file")));
    }

    #[test]
    fn extractor_builds_narrative_timeline() {
        let outputs = vec![make_output(
            "Trace",
            vec![csam_artifact(), vss_deletion_artifact()],
        )];
        let timeline = FindingExtractor::extract_narrative_timeline(&outputs);
        assert_eq!(timeline.len(), 2);
        assert!(timeline[0].timestamp < timeline[1].timestamp);
    }
}
