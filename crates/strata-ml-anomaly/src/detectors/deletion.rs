use strata_plugin_sdk::PluginOutput;

use crate::types::*;

const FORENSIC_EXTENSIONS: &[&str] = &[
    ".msg", ".pst", ".ost", ".log", ".evt", ".evtx", ".db", ".sqlite",
    ".sqlite3", ".edb", ".dat", ".reg", ".hve",
];

/// Detects systematic deletion patterns suggesting deliberate cleanup.
pub struct EvidenceDeletionDetector;

impl EvidenceDeletionDetector {
    pub fn run(outputs: &[PluginOutput]) -> Vec<AnomalyFinding> {
        let mut findings = Vec::new();

        let mut recycle_entries: Vec<(Option<i64>, String)> = Vec::new();
        let _creation_deletion_pairs: Vec<(String, i64, i64)> = Vec::new();
        let mut forensic_deletions: Vec<(String, Option<i64>)> = Vec::new();

        for output in outputs {
            for record in &output.artifacts {
                let detail_lower = record.detail.to_lowercase();
                let title_lower = record.title.to_lowercase();
                let path_lower = record.source_path.to_lowercase();

                // Recycle Bin entries
                if record.subcategory.contains("Recycle")
                    || path_lower.contains("$recycle.bin")
                    || title_lower.contains("recycle")
                {
                    recycle_entries.push((record.timestamp, record.source_path.clone()));
                }

                // Deletion of forensically significant file types
                if (detail_lower.contains("deleted") || title_lower.contains("deleted"))
                    && FORENSIC_EXTENSIONS
                        .iter()
                        .any(|ext| path_lower.ends_with(ext) || detail_lower.contains(ext))
                {
                    forensic_deletions.push((record.source_path.clone(), record.timestamp));
                }
            }
        }

        // Pattern 1: Large number of Recycle Bin entries in short window
        if recycle_entries.len() >= 20 {
            let timestamps: Vec<i64> = recycle_entries
                .iter()
                .filter_map(|(ts, _)| *ts)
                .collect();
            if timestamps.len() >= 10 {
                let mut sorted = timestamps.clone();
                sorted.sort();
                let span = sorted.last().unwrap_or(&0) - sorted.first().unwrap_or(&0);
                let within_hour = span < 3600;
                let confidence = if within_hour { 0.85 } else { 0.65 };

                findings.push(AnomalyFinding {
                    finding_id: format!("deletion-bulk-{}", findings.len()),
                    artifact_ref: ArtifactRef {
                        plugin_name: "Remnant".to_string(),
                        artifact_category: "Recycle Bin".to_string(),
                        artifact_id: "bulk-deletion".to_string(),
                        timestamp: sorted.first().and_then(|&t| {
                            chrono::DateTime::from_timestamp(t, 0).map(|d| d.to_rfc3339())
                        }),
                        file_path: None,
                    },
                    anomaly_type: AnomalyType::EvidenceDeletion,
                    confidence: confidence as f32,
                    explanation: format!(
                        "{} Recycle Bin entries found{}. \
                         Bulk deletion suggests deliberate cleanup.",
                        recycle_entries.len(),
                        if within_hour {
                            " within a 1-hour window"
                        } else {
                            ""
                        }
                    ),
                    evidence_points: vec![
                        format!("{} entries in Recycle Bin", recycle_entries.len()),
                        format!("Time span: {} seconds", span),
                    ],
                    suggested_followup: vec![
                        "Examine $I/$R file pairs for original paths".to_string(),
                        "Check USN Journal for deletion records".to_string(),
                    ],
                    detection_method: DetectionMethod::Statistical,
                    is_advisory: true,
                });
            }
        }

        // Pattern 2: Deletion of forensically significant files
        if forensic_deletions.len() >= 3 {
            findings.push(AnomalyFinding {
                finding_id: format!("deletion-forensic-{}", findings.len()),
                artifact_ref: ArtifactRef {
                    plugin_name: "Multiple".to_string(),
                    artifact_category: "Evidence Deletion".to_string(),
                    artifact_id: "forensic-file-deletion".to_string(),
                    timestamp: forensic_deletions
                        .first()
                        .and_then(|(_, ts)| {
                            ts.and_then(|t| chrono::DateTime::from_timestamp(t, 0).map(|d| d.to_rfc3339()))
                        }),
                    file_path: forensic_deletions.first().map(|(p, _)| p.clone()),
                },
                anomaly_type: AnomalyType::EvidenceDeletion,
                confidence: 0.80,
                explanation: format!(
                    "{} forensically significant files deleted ({}).",
                    forensic_deletions.len(),
                    forensic_deletions
                        .iter()
                        .take(5)
                        .map(|(p, _)| p.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
                evidence_points: forensic_deletions
                    .iter()
                    .take(10)
                    .map(|(p, _)| format!("Deleted: {}", p))
                    .collect(),
                suggested_followup: vec![
                    "Attempt recovery from unallocated space".to_string(),
                    "Check VSS snapshots for pre-deletion copies".to_string(),
                ],
                detection_method: DetectionMethod::Statistical,
                is_advisory: true,
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use strata_plugin_sdk::*;

    fn make_recycle_output(count: usize) -> PluginOutput {
        let mut artifacts = Vec::new();
        for i in 0..count {
            artifacts.push(ArtifactRecord {
                category: ArtifactCategory::DeletedRecovered,
                subcategory: "Recycle Bin".to_string(),
                timestamp: Some(1700000000 + i as i64),
                title: format!("Recycled file {}", i),
                detail: "deleted".to_string(),
                source_path: format!("C:\\$Recycle.Bin\\file{}.txt", i),
                forensic_value: ForensicValue::Medium,
                mitre_technique: None,
                is_suspicious: false,
                raw_data: None,
            });
        }
        PluginOutput {
            plugin_name: "Remnant".to_string(),
            plugin_version: "1.0".to_string(),
            executed_at: String::new(),
            duration_ms: 0,
            artifacts,
            summary: PluginSummary {
                total_artifacts: count,
                suspicious_count: 0,
                categories_populated: vec![],
                headline: String::new(),
            },
            warnings: vec![],
        }
    }

    #[test]
    fn deletion_detector_flags_bulk_recycle() {
        let outputs = vec![make_recycle_output(25)];
        let findings = EvidenceDeletionDetector::run(&outputs);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].anomaly_type, AnomalyType::EvidenceDeletion);
    }

    #[test]
    fn deletion_detector_no_flag_for_few_entries() {
        let outputs = vec![make_recycle_output(5)];
        let findings = EvidenceDeletionDetector::run(&outputs);
        assert!(findings.is_empty());
    }
}
