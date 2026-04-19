//! # Advisory Analytics plugin
//!
//! v16 Session 2 — ML-WIRE-1. Wires the previously-orphaned
//! `strata-ml-anomaly`, `strata-ml-obstruction`, and
//! `strata-ml-summary` crates into the primary plugin pipeline that
//! `strata ingest run` orchestrates.
//!
//! ## Pipeline position
//!
//! Registered in `strata_engine_adapter::plugins::build_plugins()`
//! immediately BEFORE `SigmaPlugin`. The static plugin vector is
//! executed in registration order; `ctx.prior_results` accumulates
//! each preceding plugin's `PluginOutput`. By the time this plugin
//! runs, every forensic plugin (Phantom, Chronicle, Trace, …) has
//! already produced its artifacts; by the time Sigma runs next,
//! this plugin's advisory records are in `ctx.prior_results` and
//! rules 30 / 31 / 32 fire against them.
//!
//! ## What's emitted
//!
//! Each advisory finding becomes an `ArtifactRecord` with:
//!
//! - `subcategory` = `"ML Anomaly"` / `"ML Obstruction"` /
//!   `"ML Summary"` — matches the exact-string filters in
//!   `plugins/strata-plugin-sigma/src/lib.rs` lines 885/912/939.
//! - `detail` contains bracket-delimited tokens the Sigma
//!   `parse_ml_confidence` helper + rule filters consume:
//!   `[anomaly_type=TemporalOutlier]` and `[confidence=0.82]`.
//! - `forensic_value` = Medium / High based on finding confidence.
//! - `is_suspicious` = true — examiner attention.
//! - `mitre_technique` populated where the ML module maps one.
//!
//! ## Forensic framing
//!
//! Findings are ADVISORY. The `is_advisory` invariant from
//! strata-ml-anomaly / strata-ml-obstruction is preserved — each
//! emitted detail string includes `[ML-ASSISTED — ADVISORY ONLY]`.
//! No findings are presented as forensic conclusions; the cross-
//! artifact correlation belongs to Sigma in the subsequent plugin.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use std::collections::HashSet;

use chrono::Utc;

use strata_plugin_sdk::{
    Artifact, ArtifactCategory, ArtifactRecord, ForensicValue, PluginCapability, PluginContext,
    PluginError, PluginOutput, PluginResult, PluginSummary, PluginType, StrataPlugin,
};

use strata_ml_anomaly::{
    AnomalyConfig, AnomalyEngine, AnomalyFinding, AnomalyType, DetectionMethod,
};
use strata_ml_obstruction::{AntiForensicDetector, ObstructionScorer};
use strata_ml_summary::{
    AnomalyEntry as SummaryAnomalyEntry, AnomalyReport as SummaryAnomalyReport, ChargeRef,
    GeneratedSummary, SectionType, SummaryGenerator, SummaryInput, SummaryStatus,
};

/// Subcategory constants — referenced by Sigma rule filters
/// (`plugins/strata-plugin-sigma/src/lib.rs` rules 30/31/32 match
/// on these exact strings). Changing them here requires coordinated
/// changes on the Sigma side + a tripwire test update.
pub const SUBCATEGORY_ANOMALY: &str = "ML Anomaly";
pub const SUBCATEGORY_OBSTRUCTION: &str = "ML Obstruction";
pub const SUBCATEGORY_SUMMARY: &str = "ML Summary";

pub struct AdvisoryPlugin {
    name: String,
    version: String,
}

impl Default for AdvisoryPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl AdvisoryPlugin {
    pub fn new() -> Self {
        Self {
            name: "Strata Advisory Analytics".to_string(),
            version: "1.0.0".to_string(),
        }
    }
}

impl StrataPlugin for AdvisoryPlugin {
    fn name(&self) -> &str {
        &self.name
    }
    fn version(&self) -> &str {
        &self.version
    }
    fn plugin_type(&self) -> PluginType {
        PluginType::Analyzer
    }
    fn capabilities(&self) -> Vec<PluginCapability> {
        vec![PluginCapability::ArtifactExtraction]
    }
    fn description(&self) -> &str {
        "Advisory analytics — deterministic anomaly detection, anti-forensic \
         obstruction scoring, and templated executive summaries. Reads prior \
         plugin artifacts via ctx.prior_results; emits advisory findings that \
         Sigma rules 30/31/32 correlate in the subsequent plugin."
    }
    fn supported_inputs(&self) -> Vec<String> {
        vec!["plugin_output_stream".to_string()]
    }

    fn run(&self, ctx: PluginContext) -> PluginResult {
        let mut artifacts: Vec<Artifact> = Vec::new();

        // ── Anomaly detection ──────────────────────────────────
        let anomaly_engine = AnomalyEngine::new(AnomalyConfig::default());
        let anomaly_report = anomaly_engine.analyze("case", &ctx.prior_results);
        for finding in &anomaly_report.findings {
            artifacts.push(anomaly_finding_to_artifact(finding));
        }
        log::info!(
            "advisory: {} anomaly finding(s) from {} prior plugin outputs",
            anomaly_report.findings.len(),
            ctx.prior_results.len()
        );

        // ── Obstruction scoring ────────────────────────────────
        let behaviors = AntiForensicDetector::detect(&ctx.prior_results);
        let assessment = ObstructionScorer::score("case", &behaviors, None);
        artifacts.push(obstruction_assessment_to_artifact(&assessment));
        log::info!(
            "advisory: obstruction assessment score={} ({:?})",
            assessment.score,
            assessment.severity
        );

        // ── Summary generation (template-backed, not LLM) ──────
        //
        // The summary generator takes structured plugin output and
        // charge references and renders Handlebars templates into a
        // GeneratedSummary. For the in-pipeline case we always pass
        // an empty charge set — the CLI caller can regenerate with
        // selected charges downstream if desired.
        if let Ok(generator) = SummaryGenerator::new() {
            // strata-ml-summary has its own (simpler) AnomalyReport
            // type local to the crate — it's not the one from
            // strata-ml-anomaly. Bridge them by copying the finding
            // list into the summary-facing shape.
            let bridge = SummaryAnomalyReport {
                anomalies: anomaly_report
                    .findings
                    .iter()
                    .map(|f| SummaryAnomalyEntry {
                        anomaly_type: anomaly_type_variant_name(&f.anomaly_type).to_string(),
                        description: f.explanation.clone(),
                        confidence: f.confidence,
                        timestamp: None,
                    })
                    .collect(),
            };
            let input = SummaryInput {
                case_id: "case".to_string(),
                case_number: String::new(),
                device_identifier: ctx.root_path.clone(),
                examiner_name: String::new(),
                selected_charges: Vec::<ChargeRef>::new(),
                plugin_outputs: ctx.prior_results.clone(),
                anomaly_report: Some(bridge),
                artifact_count: ctx
                    .prior_results
                    .iter()
                    .map(|o| o.artifacts.len())
                    .sum(),
                generated_at: Utc::now().to_rfc3339(),
            };
            if let Ok(summary) = generator.generate(&input) {
                artifacts.push(summary_to_artifact(&summary));
                log::info!(
                    "advisory: summary generated ({} section(s))",
                    summary.sections.len()
                );
            }
        }

        Ok(artifacts)
    }

    fn execute(&self, context: PluginContext) -> Result<PluginOutput, PluginError> {
        let start = std::time::Instant::now();
        let artifacts = self.run(context)?;
        let mut records: Vec<ArtifactRecord> = Vec::new();
        let mut cats: HashSet<String> = HashSet::new();
        let mut suspicious = 0usize;
        for a in &artifacts {
            let subcategory = a
                .data
                .get("subcategory")
                .cloned()
                .unwrap_or_default();
            // Advisory analytics findings flow under SystemActivity —
            // they analyse system-wide behavioural signals. The
            // `subcategory` string (ML Anomaly / ML Obstruction / ML
            // Summary) is what Sigma rules 30/31/32 match on, not the
            // top-level category.
            let category = ArtifactCategory::SystemActivity;
            cats.insert(category.as_str().to_string());
            let is_sus = a
                .data
                .get("suspicious")
                .map(|v| v == "true")
                .unwrap_or(false);
            if is_sus {
                suspicious += 1;
            }
            let fv = match a.data.get("forensic_value").map(|s| s.as_str()) {
                Some("Critical") => ForensicValue::Critical,
                Some("High") => ForensicValue::High,
                Some("Low") => ForensicValue::Low,
                _ => ForensicValue::Medium,
            };
            records.push(ArtifactRecord {
                category,
                subcategory,
                timestamp: a.timestamp.map(|t| t as i64),
                title: a
                    .data
                    .get("title")
                    .cloned()
                    .unwrap_or_else(|| a.source.clone()),
                detail: a.data.get("detail").cloned().unwrap_or_default(),
                source_path: a.source.clone(),
                forensic_value: fv,
                mitre_technique: a.data.get("mitre").cloned(),
                is_suspicious: is_sus,
                raw_data: None,
                confidence: 0,
            });
        }
        let total = records.len();
        Ok(PluginOutput {
            plugin_name: self.name().to_string(),
            plugin_version: self.version().to_string(),
            executed_at: Utc::now().to_rfc3339(),
            duration_ms: start.elapsed().as_millis() as u64,
            artifacts: records,
            summary: PluginSummary {
                total_artifacts: total,
                suspicious_count: suspicious,
                categories_populated: cats.into_iter().collect(),
                headline: format!(
                    "Advisory Analytics: {} finding(s) ({} high-risk)",
                    total, suspicious
                ),
            },
            warnings: vec![],
        })
    }
}

// ── Artifact encoders ───────────────────────────────────────────

fn anomaly_finding_to_artifact(finding: &AnomalyFinding) -> Artifact {
    // Detail format MUST match the Sigma rule 30/31/32 filter
    // expectations:
    //   [anomaly_type=<VariantName>]  — literal Rust enum variant
    //   [confidence=0.XX]              — float formatted to 2 places
    // See plugins/strata-plugin-sigma/src/lib.rs:886 + 1146
    // (parse_ml_confidence).
    let variant_name = anomaly_type_variant_name(&finding.anomaly_type);
    let detail = format!(
        "[anomaly_type={}] [confidence={:.2}] [method={}] {} \
         [ML-ASSISTED — ADVISORY ONLY]",
        variant_name,
        finding.confidence,
        detection_method_label(&finding.detection_method),
        finding.explanation
    );
    let mut a = Artifact::new(finding.anomaly_type.label(), &finding.artifact_ref.plugin_name);
    a.add_field("subcategory", SUBCATEGORY_ANOMALY);
    a.add_field("title", &format!(
        "Anomaly: {} ({})",
        finding.anomaly_type.label(),
        variant_name
    ));
    a.add_field("detail", &detail);
    a.add_field("suspicious", "true");
    let fv = if finding.confidence >= 0.85 {
        "High"
    } else if finding.confidence >= 0.5 {
        "Medium"
    } else {
        "Low"
    };
    a.add_field("forensic_value", fv);
    // MITRE mapping per anomaly type — matches what Sigma rules 30/31/32
    // assign to their own fired records.
    let mitre = match finding.anomaly_type {
        AnomalyType::TemporalOutlier => "T1059",
        AnomalyType::StealthExecution => "T1059.001",
        AnomalyType::TimestampManipulation => "T1070.006",
        AnomalyType::AbnormalDataTransfer => "T1041",
        AnomalyType::AntiForensicBehavior => "T1070",
        AnomalyType::EvidenceDeletion => "T1070.004",
        AnomalyType::UncorroboratedActivity | AnomalyType::AutomatedBehavior => "T1204",
    };
    a.add_field("mitre", mitre);
    a
}

fn obstruction_assessment_to_artifact(
    assessment: &strata_ml_obstruction::ObstructionAssessment,
) -> Artifact {
    let detail = format!(
        "[obstruction_score={}] [severity={}] [factors={}] {} \
         [ML-ASSISTED — ADVISORY ONLY]",
        assessment.score,
        assessment.severity.label(),
        assessment.factors.len(),
        assessment.interpretation
    );
    let mut a = Artifact::new("Obstruction Assessment", "advisory");
    a.add_field("subcategory", SUBCATEGORY_OBSTRUCTION);
    a.add_field(
        "title",
        &format!(
            "Anti-Forensic Obstruction: {} (score {})",
            assessment.severity.label(),
            assessment.score
        ),
    );
    a.add_field("detail", &detail);
    let suspicious = assessment.score >= 41; // Moderate+ in the scorer's banding
    a.add_field("suspicious", if suspicious { "true" } else { "false" });
    let fv = if assessment.score >= 81 {
        "Critical"
    } else if assessment.score >= 61 {
        "High"
    } else if assessment.score >= 21 {
        "Medium"
    } else {
        "Low"
    };
    a.add_field("forensic_value", fv);
    a.add_field("mitre", "T1070");
    a
}

fn summary_to_artifact(summary: &GeneratedSummary) -> Artifact {
    let overview = summary
        .sections
        .iter()
        .find(|s| matches!(s.section_type, SectionType::Overview))
        .map(|s| s.content.clone())
        .unwrap_or_else(|| "(no overview section rendered)".to_string());
    let detail = format!(
        "[status={}] [sections={}] [approved={}] {} \
         [ML-ASSISTED — ADVISORY ONLY]",
        summary_status_label(&summary.status),
        summary.sections.len(),
        summary.examiner_approved,
        // Truncate the overview so the detail string stays reasonable
        // for the artifact row display.
        overview.chars().take(400).collect::<String>()
    );
    let mut a = Artifact::new("Case Summary", "advisory");
    a.add_field("subcategory", SUBCATEGORY_SUMMARY);
    a.add_field(
        "title",
        &format!(
            "Executive Summary: {} section(s), status={}",
            summary.sections.len(),
            summary_status_label(&summary.status)
        ),
    );
    a.add_field("detail", &detail);
    // A summary is informational, not suspicious.
    a.add_field("suspicious", "false");
    a.add_field("forensic_value", "Medium");
    a
}

fn anomaly_type_variant_name(t: &AnomalyType) -> &'static str {
    // EXACT Rust variant names — must match the
    // `detail.contains("[anomaly_type=TemporalOutlier]")` literals
    // in Sigma rule 30/31/32 filters.
    match t {
        AnomalyType::TemporalOutlier => "TemporalOutlier",
        AnomalyType::StealthExecution => "StealthExecution",
        AnomalyType::TimestampManipulation => "TimestampManipulation",
        AnomalyType::AbnormalDataTransfer => "AbnormalDataTransfer",
        AnomalyType::AntiForensicBehavior => "AntiForensicBehavior",
        AnomalyType::UncorroboratedActivity => "UncorroboratedActivity",
        AnomalyType::EvidenceDeletion => "EvidenceDeletion",
        AnomalyType::AutomatedBehavior => "AutomatedBehavior",
    }
}

fn detection_method_label(m: &DetectionMethod) -> &'static str {
    match m {
        DetectionMethod::Statistical => "Statistical",
        DetectionMethod::OnnxModel => "OnnxModel",
    }
}

fn summary_status_label(s: &SummaryStatus) -> &'static str {
    match s {
        SummaryStatus::Draft => "Draft",
        SummaryStatus::UnderReview => "UnderReview",
        SummaryStatus::Approved => "Approved",
        SummaryStatus::Rejected => "Rejected",
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_metadata_shape() {
        let p = AdvisoryPlugin::new();
        assert_eq!(p.name(), "Strata Advisory Analytics");
        assert_eq!(p.version(), "1.0.0");
        assert!(!p.description().is_empty());
        assert!(matches!(p.plugin_type(), PluginType::Analyzer));
    }

    #[test]
    fn empty_prior_results_produces_at_least_summary() {
        let p = AdvisoryPlugin::new();
        let ctx = PluginContext {
            root_path: "/tmp/case".to_string(),
            vfs: None,
            config: std::collections::HashMap::new(),
            prior_results: Vec::new(),
        };
        let output = p.execute(ctx).expect("execute");
        // Even with no prior plugins, the obstruction assessment
        // (score=0, Minimal) + the summary should be emitted, so
        // the advisory plugin always produces at least one record
        // that downstream consumers (Sigma, artifact persistence,
        // UI panels) can surface.
        assert!(
            !output.artifacts.is_empty(),
            "advisory plugin must always emit at least one record"
        );
    }

    #[test]
    fn anomaly_detail_format_matches_sigma_rule_regex() {
        // Tripwire: the detail-string format is load-bearing for
        // Sigma rules 30/31/32. If this test fails, the Sigma rules
        // will silently stop firing — the examiner sees no
        // cross-artifact correlation even though the ML plugin
        // produced findings. Changing the detail format requires
        // coordinated changes on the Sigma side.
        use strata_ml_anomaly::{ArtifactRef, DetectionMethod};

        let finding = AnomalyFinding {
            finding_id: "f-001".to_string(),
            artifact_ref: ArtifactRef {
                plugin_name: "Strata Trace".to_string(),
                artifact_category: "ExecutionHistory".to_string(),
                artifact_id: "a-001".to_string(),
                timestamp: None,
                file_path: None,
            },
            anomaly_type: AnomalyType::TemporalOutlier,
            confidence: 0.88,
            explanation: "probe".to_string(),
            evidence_points: vec![],
            suggested_followup: vec![],
            detection_method: DetectionMethod::Statistical,
            is_advisory: true,
        };
        let a = anomaly_finding_to_artifact(&finding);
        let detail = a.data.get("detail").expect("detail");
        assert!(
            detail.contains("[anomaly_type=TemporalOutlier]"),
            "Sigma rule 30 filter requires exact literal; got: {detail}"
        );
        assert!(
            detail.contains("[confidence=0.88]"),
            "parse_ml_confidence requires [confidence=X.XX] format; got: {detail}"
        );
        assert_eq!(
            a.data.get("subcategory").map(|s| s.as_str()),
            Some("ML Anomaly"),
            "Sigma rule filters match subcategory == \"ML Anomaly\" exactly"
        );
    }

    #[test]
    fn anomaly_variant_names_match_rust_enum_exactly() {
        // The literal strings in Sigma rule filters ([anomaly_type=X])
        // are case-sensitive and must match the Rust variant names
        // one-for-one. This test guards against accidental drift
        // (e.g., someone rename-refactoring one side without the
        // other).
        assert_eq!(
            anomaly_type_variant_name(&AnomalyType::TemporalOutlier),
            "TemporalOutlier"
        );
        assert_eq!(
            anomaly_type_variant_name(&AnomalyType::StealthExecution),
            "StealthExecution"
        );
        assert_eq!(
            anomaly_type_variant_name(&AnomalyType::TimestampManipulation),
            "TimestampManipulation"
        );
    }

    #[test]
    fn obstruction_artifact_has_score_and_severity_in_detail() {
        let behaviors = vec![];
        let assessment = ObstructionScorer::score("case", &behaviors, None);
        let a = obstruction_assessment_to_artifact(&assessment);
        let detail = a.data.get("detail").expect("detail");
        assert!(detail.contains("[obstruction_score="));
        assert!(detail.contains("[severity="));
        assert_eq!(
            a.data.get("subcategory").map(|s| s.as_str()),
            Some("ML Obstruction")
        );
    }

    #[test]
    fn summary_artifact_carries_status_and_section_count() {
        let gen = SummaryGenerator::new().expect("generator");
        let input = SummaryInput {
            case_id: "probe".to_string(),
            case_number: String::new(),
            device_identifier: "probe".to_string(),
            examiner_name: String::new(),
            selected_charges: vec![],
            plugin_outputs: vec![],
            anomaly_report: None,
            artifact_count: 0,
            generated_at: Utc::now().to_rfc3339(),
        };
        let summary = gen.generate(&input).expect("generate");
        let a = summary_to_artifact(&summary);
        let detail = a.data.get("detail").expect("detail");
        assert!(detail.contains("[status="));
        assert!(detail.contains("[sections="));
        assert_eq!(
            a.data.get("subcategory").map(|s| s.as_str()),
            Some("ML Summary")
        );
    }

    #[test]
    fn execute_emits_system_activity_category_records() {
        // Advisory findings land under ArtifactCategory::SystemActivity;
        // Sigma rule matching is on the subcategory string, not the
        // top-level category.
        let p = AdvisoryPlugin::new();
        let ctx = PluginContext {
            root_path: "/tmp".to_string(),
            vfs: None,
            config: std::collections::HashMap::new(),
            prior_results: vec![],
        };
        let out = p.execute(ctx).expect("exec");
        assert!(out
            .artifacts
            .iter()
            .all(|r| matches!(r.category, ArtifactCategory::SystemActivity)));
    }
}
