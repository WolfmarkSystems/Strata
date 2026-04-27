use strata_plugin_sdk::PluginOutput;

use crate::detectors::{antiforensic, deletion, stealth, temporal, timestamps};
use crate::features::FeatureExtractor;
use crate::types::*;

/// Advisory notice — always included in output. LOAD-BEARING.
pub const ADVISORY_NOTICE: &str = "These findings are ML-ASSISTED and ADVISORY ONLY. \
     Statistical anomalies require examiner review and independent \
     corroboration before inclusion in forensic reports. \
     Anomaly detection does not constitute a forensic finding.";

/// Which detectors to run.
#[derive(Debug, Clone, Default)]
pub enum DetectorSet {
    #[default]
    All,
    Only(Vec<AnomalyType>),
}

/// Configuration for the anomaly engine.
#[derive(Debug, Clone)]
pub struct AnomalyConfig {
    pub min_confidence: f32,
    pub max_findings: usize,
    pub include_medium: bool,
    pub detectors: DetectorSet,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.5,
            max_findings: 50,
            include_medium: true,
            detectors: DetectorSet::All,
        }
    }
}

/// The main anomaly detection engine.
pub struct AnomalyEngine {
    config: AnomalyConfig,
}

impl AnomalyEngine {
    pub fn new(config: AnomalyConfig) -> Self {
        Self { config }
    }

    /// Run all detectors against a set of plugin outputs.
    pub fn analyze(&self, case_id: &str, outputs: &[PluginOutput]) -> AnomalyReport {
        let timeline = FeatureExtractor::extract_timeline(outputs);
        let executions = FeatureExtractor::extract_executions(outputs);
        let transfers = FeatureExtractor::extract_transfers(outputs);
        let clusters = FeatureExtractor::extract_timestamp_clusters(outputs);
        let baseline = FeatureExtractor::build_baseline_summary(&timeline, &executions, &transfers);

        let mut all_findings: Vec<AnomalyFinding> = Vec::new();

        let should_run = |at: &AnomalyType| match &self.config.detectors {
            DetectorSet::All => true,
            DetectorSet::Only(types) => types.contains(at),
        };

        if should_run(&AnomalyType::TemporalOutlier) {
            all_findings.extend(temporal::TemporalOutlierDetector::run(&timeline, &baseline));
        }

        if should_run(&AnomalyType::StealthExecution) {
            all_findings.extend(stealth::StealthExecutionDetector::run(
                &executions,
                &timeline,
            ));
        }

        if should_run(&AnomalyType::TimestampManipulation) {
            all_findings.extend(timestamps::TimestampManipulationDetector::run(
                &clusters, &timeline,
            ));
        }

        if should_run(&AnomalyType::AntiForensicBehavior) {
            all_findings.extend(antiforensic::AntiForensicBehaviorDetector::run(outputs));
        }

        if should_run(&AnomalyType::EvidenceDeletion) {
            all_findings.extend(deletion::EvidenceDeletionDetector::run(outputs));
        }

        // Filter by confidence threshold.
        all_findings.retain(|f| f.confidence >= self.config.min_confidence);

        // Sort by confidence descending.
        all_findings.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Cap at max_findings.
        all_findings.truncate(self.config.max_findings);

        // Ensure is_advisory is always true on every finding.
        for finding in &mut all_findings {
            finding.is_advisory = true;
        }

        let high_count = all_findings.iter().filter(|f| f.confidence >= 0.8).count();
        let medium_count = all_findings
            .iter()
            .filter(|f| f.confidence >= 0.5 && f.confidence < 0.8)
            .count();

        let artifact_count: usize = outputs.iter().map(|o| o.artifacts.len()).sum();

        AnomalyReport {
            case_id: case_id.to_string(),
            analyzed_at: chrono::Utc::now().to_rfc3339(),
            artifact_count,
            findings: all_findings,
            baseline_summary: baseline,
            high_confidence_count: high_count,
            medium_confidence_count: medium_count,
            detection_method: DetectionMethod::Statistical,
            advisory_notice: ADVISORY_NOTICE.to_string(),
        }
    }

    /// Run a single detector type only.
    pub fn analyze_type(
        &self,
        anomaly_type: AnomalyType,
        outputs: &[PluginOutput],
    ) -> Vec<AnomalyFinding> {
        let config = AnomalyConfig {
            detectors: DetectorSet::Only(vec![anomaly_type]),
            ..self.config.clone()
        };
        let engine = AnomalyEngine::new(config);
        engine.analyze("single", outputs).findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use strata_plugin_sdk::*;

    fn empty_outputs() -> Vec<PluginOutput> {
        vec![PluginOutput {
            plugin_name: "test".to_string(),
            plugin_version: "1.0".to_string(),
            executed_at: String::new(),
            duration_ms: 0,
            artifacts: vec![],
            summary: PluginSummary {
                total_artifacts: 0,
                suspicious_count: 0,
                categories_populated: vec![],
                headline: String::new(),
            },
            warnings: vec![],
        }]
    }

    fn make_vss_outputs() -> Vec<PluginOutput> {
        vec![PluginOutput {
            plugin_name: "Trace".to_string(),
            plugin_version: "1.0".to_string(),
            executed_at: String::new(),
            duration_ms: 0,
            artifacts: vec![ArtifactRecord {
                category: ArtifactCategory::SystemActivity,
                subcategory: "Execution".to_string(),
                timestamp: Some(1700000000),
                title: "vssadmin delete shadows /all".to_string(),
                detail: "VSS snapshot deletion".to_string(),
                source_path: String::new(),
                forensic_value: ForensicValue::Critical,
                mitre_technique: Some("T1490".to_string()),
                is_suspicious: true,
                raw_data: None,
                confidence: 0,
            }],
            summary: PluginSummary {
                total_artifacts: 1,
                suspicious_count: 1,
                categories_populated: vec!["SystemActivity".to_string()],
                headline: String::new(),
            },
            warnings: vec![],
        }]
    }

    #[test]
    fn engine_returns_empty_for_clean_artifact_set() {
        let engine = AnomalyEngine::new(AnomalyConfig::default());
        let report = engine.analyze("test-case", &empty_outputs());
        assert!(report.findings.is_empty());
        assert_eq!(report.high_confidence_count, 0);
    }

    #[test]
    fn engine_respects_min_confidence_threshold() {
        let engine = AnomalyEngine::new(AnomalyConfig {
            min_confidence: 0.99,
            ..Default::default()
        });
        let report = engine.analyze("test-case", &make_vss_outputs());
        // VSS finding is ~0.88 confidence, should be filtered out at 0.99
        let vss = report
            .findings
            .iter()
            .any(|f| f.anomaly_type == AnomalyType::AntiForensicBehavior);
        assert!(!vss);
    }

    #[test]
    fn engine_advisory_notice_always_present() {
        let engine = AnomalyEngine::new(AnomalyConfig::default());
        let report = engine.analyze("test-case", &empty_outputs());
        assert!(!report.advisory_notice.is_empty());
        assert!(report.advisory_notice.contains("ADVISORY ONLY"));
    }

    #[test]
    fn engine_findings_sorted_by_confidence_descending() {
        let engine = AnomalyEngine::new(AnomalyConfig::default());
        let report = engine.analyze("test-case", &make_vss_outputs());
        for w in report.findings.windows(2) {
            assert!(w[0].confidence >= w[1].confidence);
        }
    }

    // ── LOAD-BEARING TESTS — DO NOT REMOVE ─────────────────────────
    // These guarantee ML findings are never presented as definitive.

    /// Every finding in every report must carry the advisory notice.
    /// Court inadmissibility of uncorroborated ML output depends on this.
    #[test]
    fn advisory_notice_present_in_all_findings() {
        let engine = AnomalyEngine::new(AnomalyConfig::default());
        let report = engine.analyze("test-case", &make_vss_outputs());
        assert!(
            report.advisory_notice.contains("ADVISORY ONLY"),
            "Advisory notice must contain 'ADVISORY ONLY'"
        );
        assert!(
            report.advisory_notice.contains("ML-ASSISTED"),
            "Advisory notice must contain 'ML-ASSISTED'"
        );
        assert!(
            report.advisory_notice.contains("examiner review"),
            "Advisory notice must mention examiner review"
        );
    }

    /// AnomalyFinding.is_advisory must always be true. This field
    /// signals to the UI and report generator that the finding
    /// requires examiner review before inclusion in court documents.
    #[test]
    fn is_advisory_always_true() {
        let engine = AnomalyEngine::new(AnomalyConfig::default());
        let report = engine.analyze("test-case", &make_vss_outputs());
        for finding in &report.findings {
            assert!(
                finding.is_advisory,
                "is_advisory must ALWAYS be true, but was false for finding: {}",
                finding.finding_id
            );
        }
    }
}
