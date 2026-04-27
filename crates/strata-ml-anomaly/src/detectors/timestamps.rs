use crate::features::{TimelineEntry, TimestampCluster};
use crate::types::*;
use chrono::Utc;

/// Detects impossible or suspicious timestamp patterns.
pub struct TimestampManipulationDetector;

impl TimestampManipulationDetector {
    pub fn run(
        clusters: &[TimestampCluster],
        full_timeline: &[TimelineEntry],
    ) -> Vec<AnomalyFinding> {
        let mut findings = Vec::new();

        // Pattern A: impossible clustering — 10+ files within 2 seconds.
        for cluster in clusters {
            if cluster.file_count < 10 {
                continue;
            }
            let confidence = if cluster.file_count >= 50 {
                0.97
            } else if cluster.file_count >= 20 {
                0.95
            } else {
                0.90
            };

            findings.push(AnomalyFinding {
                finding_id: format!("ts-cluster-{}", findings.len()),
                artifact_ref: ArtifactRef {
                    plugin_name: "Timeline".to_string(),
                    artifact_category: "Timestamp".to_string(),
                    artifact_id: format!("cluster-{}", cluster.representative_time.timestamp()),
                    timestamp: Some(cluster.representative_time.to_rfc3339()),
                    file_path: cluster.paths.first().cloned(),
                },
                anomaly_type: AnomalyType::TimestampManipulation,
                confidence: confidence as f32,
                explanation: format!(
                    "{} files with timestamps within {:.1}s of each other at {}. \
                     Real user activity cannot produce this density. \
                     Indicates bulk timestamp modification.",
                    cluster.file_count,
                    cluster.span_seconds,
                    cluster.representative_time.format("%Y-%m-%d %H:%M:%S UTC"),
                ),
                evidence_points: vec![
                    format!(
                        "{} files in {:.1}s window",
                        cluster.file_count, cluster.span_seconds
                    ),
                    format!(
                        "Representative paths: {}",
                        cluster
                            .paths
                            .iter()
                            .take(3)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                ],
                suggested_followup: vec![
                    "Compare $STANDARD_INFORMATION vs $FILE_NAME timestamps in MFT".to_string(),
                    "Check USN Journal for corresponding entries".to_string(),
                ],
                detection_method: DetectionMethod::Statistical,
                is_advisory: true,
            });
        }

        // Pattern B: future timestamps (after "now" as a proxy for
        // acquisition date when the actual acquisition date is unavailable).
        let now = Utc::now();
        for entry in full_timeline {
            if entry.timestamp > now {
                findings.push(AnomalyFinding {
                    finding_id: format!("ts-future-{}", findings.len()),
                    artifact_ref: ArtifactRef {
                        plugin_name: entry.plugin.clone(),
                        artifact_category: entry.artifact_type.clone(),
                        artifact_id: entry.title.clone(),
                        timestamp: Some(entry.timestamp.to_rfc3339()),
                        file_path: Some(entry.source_path.clone()),
                    },
                    anomaly_type: AnomalyType::TimestampManipulation,
                    confidence: 0.99,
                    explanation: format!(
                        "Timestamp {} is in the future. \
                         Timestamps cannot be in the future relative to analysis date.",
                        entry.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                    ),
                    evidence_points: vec![format!(
                        "Timestamp {} > current time {}",
                        entry.timestamp.to_rfc3339(),
                        now.to_rfc3339()
                    )],
                    suggested_followup: vec![
                        "Verify evidence acquisition date".to_string(),
                        "Check for timezone misconfiguration".to_string(),
                    ],
                    detection_method: DetectionMethod::Statistical,
                    is_advisory: true,
                });
            }
        }

        // Pattern C: $SI vs $FN mismatch detection.
        // We look for artifacts whose detail mentions $SI/$FN or timestomp.
        for entry in full_timeline {
            let detail_lower = entry.detail.to_lowercase();
            if detail_lower.contains("$standard_information")
                && detail_lower.contains("$file_name")
                && (detail_lower.contains("predate") || detail_lower.contains("mismatch"))
            {
                findings.push(AnomalyFinding {
                    finding_id: format!("ts-si-fn-{}", findings.len()),
                    artifact_ref: ArtifactRef {
                        plugin_name: entry.plugin.clone(),
                        artifact_category: entry.artifact_type.clone(),
                        artifact_id: entry.title.clone(),
                        timestamp: Some(entry.timestamp.to_rfc3339()),
                        file_path: Some(entry.source_path.clone()),
                    },
                    anomaly_type: AnomalyType::TimestampManipulation,
                    confidence: 0.90,
                    explanation: format!(
                        "$STANDARD_INFORMATION timestamps predate $FILE_NAME. \
                         $FN timestamps cannot be modified without kernel access. \
                         This indicates userland timestomping. File: {}",
                        entry.source_path,
                    ),
                    evidence_points: vec![
                        "$SI Created < $FN Created (impossible without manipulation)".to_string(),
                        format!("Detail: {}", &entry.detail[..entry.detail.len().min(200)]),
                    ],
                    suggested_followup: vec![
                        "Review MFT entry for this file".to_string(),
                        "Check USN Journal sequence gap".to_string(),
                    ],
                    detection_method: DetectionMethod::Statistical,
                    is_advisory: true,
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::TimelineEntry;
    use chrono::NaiveDateTime;

    fn make_cluster(count: usize, span: f64) -> TimestampCluster {
        let dt = NaiveDateTime::new(
            chrono::NaiveDate::from_ymd_opt(2024, 6, 15).unwrap(),
            chrono::NaiveTime::from_hms_opt(14, 23, 7).unwrap(),
        )
        .and_utc();
        TimestampCluster {
            representative_time: dt,
            file_count: count,
            span_seconds: span,
            paths: (0..count).map(|i| format!("C:\\file{}.exe", i)).collect(),
        }
    }

    fn make_entry_with_detail(detail: &str) -> TimelineEntry {
        let dt = NaiveDateTime::new(
            chrono::NaiveDate::from_ymd_opt(2024, 6, 15).unwrap(),
            chrono::NaiveTime::from_hms_opt(10, 0, 0).unwrap(),
        )
        .and_utc();
        TimelineEntry {
            timestamp: dt,
            artifact_type: "MFT".to_string(),
            plugin: "Trace".to_string(),
            title: "strata.exe".to_string(),
            detail: detail.to_string(),
            source_path: "C:\\strata.exe".to_string(),
            is_suspicious: false,
        }
    }

    #[test]
    fn timestamp_detector_flags_impossible_clustering() {
        let clusters = vec![make_cluster(15, 1.5)];
        let findings = TimestampManipulationDetector::run(&clusters, &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].anomaly_type, AnomalyType::TimestampManipulation);
        assert!(findings[0].confidence >= 0.90);
    }

    #[test]
    fn timestamp_detector_flags_future_timestamps() {
        let future_dt = Utc::now() + chrono::Duration::days(365);
        let entry = TimelineEntry {
            timestamp: future_dt,
            artifact_type: "test".to_string(),
            plugin: "test".to_string(),
            title: "future.exe".to_string(),
            detail: String::new(),
            source_path: String::new(),
            is_suspicious: false,
        };
        let findings = TimestampManipulationDetector::run(&[], &[entry]);
        assert!(!findings.is_empty());
        assert!(findings[0].confidence >= 0.99);
    }

    #[test]
    fn timestamp_detector_flags_si_fn_mismatch() {
        let entry = make_entry_with_detail(
            "$STANDARD_INFORMATION Created predate $FILE_NAME Created by 847 days. Mismatch detected."
        );
        let findings = TimestampManipulationDetector::run(&[], &[entry]);
        assert!(!findings.is_empty());
        assert!(findings[0].explanation.contains("timestomping"));
    }

    #[test]
    fn timestamp_detector_high_confidence_for_mismatch() {
        let entry = make_entry_with_detail(
            "$STANDARD_INFORMATION timestamps predate $FILE_NAME timestamps",
        );
        let findings = TimestampManipulationDetector::run(&[], &[entry]);
        assert!(!findings.is_empty());
        assert!(findings[0].confidence >= 0.90);
    }
}
