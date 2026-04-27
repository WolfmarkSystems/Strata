use strata_plugin_sdk::PluginOutput;

use crate::types::*;

/// Detects behavioral patterns indicating deliberate evidence destruction.
pub struct AntiForensicBehaviorDetector;

const SECURE_DELETE_TOOLS: &[&str] = &[
    "eraser",
    "ccleaner",
    "sdelete",
    "cipher /w",
    "bleachbit",
    "privazer",
    "wise disk cleaner",
    "dban",
    "killdisk",
];

const VSS_DELETION_INDICATORS: &[&str] = &[
    "vssadmin delete shadows",
    "vssadmin.exe delete",
    "wmic shadowcopy delete",
    "diskshadow",
];

const LOG_CLEARING_INDICATORS: &[&str] = &[
    "wevtutil cl",
    "wevtutil clear-log",
    "clear-eventlog",
    "Remove-EventLog",
];

impl AntiForensicBehaviorDetector {
    pub fn run(outputs: &[PluginOutput]) -> Vec<AnomalyFinding> {
        let mut findings = Vec::new();
        let all_details: Vec<(&str, &str, &str, Option<i64>)> = outputs
            .iter()
            .flat_map(|o| {
                o.artifacts.iter().map(|r| {
                    (
                        r.detail.as_str(),
                        r.title.as_str(),
                        r.source_path.as_str(),
                        r.timestamp,
                    )
                })
            })
            .collect();

        // Pattern 1: VSS deletion
        for (detail, title, path, ts) in &all_details {
            let combined = format!("{} {} {}", detail, title, path).to_lowercase();
            for indicator in VSS_DELETION_INDICATORS {
                if combined.contains(indicator) {
                    findings.push(Self::make_finding(
                        &format!("antiforensic-vss-{}", findings.len()),
                        title,
                        path,
                        *ts,
                        0.88,
                        format!(
                            "Volume Shadow Copy deletion detected: {}. \
                             VSS snapshots are a primary forensic recovery mechanism.",
                            title
                        ),
                        vec!["VSS deletion command in artifact".to_string()],
                        vec![
                            "Check if VSS snapshots still exist".to_string(),
                            "Review Remnant plugin for shadow copy remnants".to_string(),
                        ],
                    ));
                    break;
                }
            }
        }

        // Pattern 2: log clearing sequence
        let mut log_clear_events: Vec<(&str, Option<i64>)> = Vec::new();
        for (detail, title, _path, ts) in &all_details {
            let combined = format!("{} {}", detail, title).to_lowercase();
            for indicator in LOG_CLEARING_INDICATORS {
                if combined.contains(indicator) {
                    log_clear_events.push((title, *ts));
                    break;
                }
            }
        }
        if log_clear_events.len() >= 2 {
            let timestamps: Vec<i64> = log_clear_events.iter().filter_map(|(_, ts)| *ts).collect();
            let within_window = if timestamps.len() >= 2 {
                let min = timestamps.iter().min().unwrap();
                let max = timestamps.iter().max().unwrap();
                (max - min) < 600
            } else {
                true
            };
            let confidence = if within_window { 0.92 } else { 0.75 };
            findings.push(Self::make_finding(
                &format!("antiforensic-logclear-{}", findings.len()),
                "Log clearing chain",
                "",
                timestamps.first().copied(),
                confidence,
                format!(
                    "{} log clearing events detected{}. \
                     Sequential log destruction pattern.",
                    log_clear_events.len(),
                    if within_window {
                        " within 10-minute window"
                    } else {
                        ""
                    }
                ),
                log_clear_events
                    .iter()
                    .map(|(t, _)| t.to_string())
                    .collect(),
                vec![
                    "Review EVTX gap analysis".to_string(),
                    "Check for EventLog service restart events".to_string(),
                ],
            ));
        }

        // Pattern 3: secure deletion tool execution
        for (detail, title, path, ts) in &all_details {
            let combined = format!("{} {} {}", detail, title, path).to_lowercase();
            for tool in SECURE_DELETE_TOOLS {
                if combined.contains(tool) {
                    findings.push(Self::make_finding(
                        &format!("antiforensic-tool-{}", findings.len()),
                        title,
                        path,
                        *ts,
                        0.80,
                        format!(
                            "Secure deletion tool detected: {}. \
                             These tools are designed to destroy forensic evidence.",
                            tool
                        ),
                        vec![format!("Tool '{}' found in artifact", tool)],
                        vec!["Check Prefetch and Registry for execution evidence".to_string()],
                    ));
                    break;
                }
            }
        }

        // Pattern 4: browser history deletion with cache present
        let _has_browser_history = all_details.iter().any(|(_, _, _, _)| false);
        let has_cache = all_details.iter().any(|(d, t, _, _)| {
            let combined = format!("{} {}", d, t).to_lowercase();
            combined.contains("cache") && combined.contains("browser")
        });
        let history_deleted = all_details.iter().any(|(d, t, _, _)| {
            let combined = format!("{} {}", d, t).to_lowercase();
            (combined.contains("history") && combined.contains("deleted"))
                || (combined.contains("history") && combined.contains("cleared"))
        });
        if history_deleted && has_cache {
            findings.push(Self::make_finding(
                &format!("antiforensic-browser-{}", findings.len()),
                "Browser history deletion",
                "",
                None,
                0.75,
                "Browser history deleted but cache entries remain. \
                 Partial cleanup suggests intentional history destruction."
                    .to_string(),
                vec![
                    "Browser history absent or cleared".to_string(),
                    "Browser cache still present".to_string(),
                ],
                vec!["Reconstruct browsing activity from cache".to_string()],
            ));
        }

        findings
    }

    #[allow(clippy::too_many_arguments)]
    fn make_finding(
        id: &str,
        title: &str,
        path: &str,
        ts: Option<i64>,
        confidence: f64,
        explanation: String,
        evidence: Vec<String>,
        followup: Vec<String>,
    ) -> AnomalyFinding {
        AnomalyFinding {
            finding_id: id.to_string(),
            artifact_ref: ArtifactRef {
                plugin_name: "Multiple".to_string(),
                artifact_category: "Anti-Forensic".to_string(),
                artifact_id: title.to_string(),
                timestamp: ts
                    .and_then(|t| chrono::DateTime::from_timestamp(t, 0).map(|d| d.to_rfc3339())),
                file_path: if path.is_empty() {
                    None
                } else {
                    Some(path.to_string())
                },
            },
            anomaly_type: AnomalyType::AntiForensicBehavior,
            confidence: confidence as f32,
            explanation,
            evidence_points: evidence,
            suggested_followup: followup,
            detection_method: DetectionMethod::Statistical,
            is_advisory: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use strata_plugin_sdk::*;

    fn make_output(title: &str, detail: &str) -> PluginOutput {
        PluginOutput {
            plugin_name: "test".to_string(),
            plugin_version: "1.0".to_string(),
            executed_at: String::new(),
            duration_ms: 0,
            artifacts: vec![ArtifactRecord {
                category: ArtifactCategory::SystemActivity,
                subcategory: "test".to_string(),
                timestamp: Some(1700000000),
                title: title.to_string(),
                detail: detail.to_string(),
                source_path: String::new(),
                forensic_value: ForensicValue::High,
                mitre_technique: None,
                is_suspicious: true,
                raw_data: None,
                confidence: 0,
            }],
            summary: PluginSummary {
                total_artifacts: 1,
                suspicious_count: 1,
                categories_populated: vec![],
                headline: String::new(),
            },
            warnings: vec![],
        }
    }

    #[test]
    fn antiforensic_detector_flags_vss_deletion() {
        let outputs = vec![make_output(
            "vssadmin delete shadows /all",
            "Volume shadow copy deletion",
        )];
        let findings = AntiForensicBehaviorDetector::run(&outputs);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].anomaly_type, AnomalyType::AntiForensicBehavior);
    }

    #[test]
    fn antiforensic_detector_flags_log_clearing_chain() {
        let outputs = vec![
            make_output("wevtutil cl Security", "Event log cleared"),
            make_output("wevtutil cl System", "Event log cleared"),
        ];
        let findings = AntiForensicBehaviorDetector::run(&outputs);
        assert!(findings
            .iter()
            .any(|f| f.explanation.contains("log clearing")),);
    }

    #[test]
    fn antiforensic_detector_flags_ccleaner_execution() {
        let outputs = vec![make_output("CCleaner.exe", "Prefetch execution")];
        let findings = AntiForensicBehaviorDetector::run(&outputs);
        assert!(findings
            .iter()
            .any(|f| f.explanation.to_lowercase().contains("ccleaner")),);
    }

    #[test]
    fn antiforensic_detector_high_confidence_for_chain() {
        let outputs = vec![
            make_output("wevtutil cl Security", "cleared"),
            make_output("wevtutil cl System", "cleared"),
            make_output("wevtutil cl Application", "cleared"),
        ];
        let findings = AntiForensicBehaviorDetector::run(&outputs);
        let chain = findings
            .iter()
            .find(|f| f.explanation.contains("log clearing"));
        assert!(chain.is_some());
        assert!(chain.unwrap().confidence >= 0.90);
    }
}
