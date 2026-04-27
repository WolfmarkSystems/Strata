use crate::features::{FeatureExtractor, TimelineEntry};
use crate::types::*;
use chrono::Timelike;

/// Detects activity that occurs outside the device's normal time window.
pub struct TemporalOutlierDetector;

impl TemporalOutlierDetector {
    pub fn run(timeline: &[TimelineEntry], _baseline: &BaselineSummary) -> Vec<AnomalyFinding> {
        if timeline.len() < 10 {
            return Vec::new();
        }

        let dist = FeatureExtractor::hourly_distribution(timeline);
        let (start, end) = FeatureExtractor::normal_activity_window(&dist);
        let total: u32 = dist.iter().sum();

        let mut findings = Vec::new();

        for entry in timeline {
            let hour = entry.timestamp.hour() as u8;
            let in_window = if start <= end {
                hour >= start && hour <= end
            } else {
                hour >= start || hour <= end
            };
            if in_window {
                continue;
            }

            let hour_count = dist[hour as usize];
            let hour_pct = if total > 0 {
                hour_count as f64 / total as f64
            } else {
                0.0
            };

            let hours_outside = if start <= end {
                if hour < start {
                    start - hour
                } else {
                    hour - end
                }
            } else if hour > end && hour < start {
                (hour - end).min(start - hour)
            } else {
                continue;
            };

            if hours_outside < 2 {
                continue;
            }

            let confidence = if hour_pct == 0.0 {
                0.90
            } else if hour_pct < 0.01 {
                0.80
            } else if hour_pct < 0.03 {
                0.65
            } else {
                0.50
            };

            if confidence < 0.50 {
                continue;
            }

            findings.push(AnomalyFinding {
                finding_id: format!("temporal-{}", findings.len()),
                artifact_ref: ArtifactRef {
                    plugin_name: entry.plugin.clone(),
                    artifact_category: entry.artifact_type.clone(),
                    artifact_id: entry.title.clone(),
                    timestamp: Some(entry.timestamp.to_rfc3339()),
                    file_path: Some(entry.source_path.clone()),
                },
                anomaly_type: AnomalyType::TemporalOutlier,
                confidence: confidence as f32,
                explanation: format!(
                    "{} at {:02}:{:02}. Device shows {:.1}% activity at this hour \
                     across {} artifacts analyzed. Normal window: {:02}:00\u{2013}{:02}:00.",
                    entry.title,
                    entry.timestamp.hour(),
                    entry.timestamp.minute(),
                    hour_pct * 100.0,
                    total,
                    start,
                    end
                ),
                evidence_points: vec![
                    format!("Hour {} has {} of {} total events", hour, hour_count, total),
                    format!(
                        "Normal activity window: {:02}:00\u{2013}{:02}:00",
                        start, end
                    ),
                    format!("{} hours outside normal window", hours_outside),
                ],
                suggested_followup: vec![
                    "Review surrounding timeline entries for corroborating activity".to_string(),
                    "Check parent process via SRUM or Prefetch".to_string(),
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
    use crate::features::TimelineEntry;
    use chrono::NaiveDateTime;

    fn make_entry(hour: u32, min: u32, title: &str) -> TimelineEntry {
        let dt = NaiveDateTime::new(
            chrono::NaiveDate::from_ymd_opt(2024, 6, 15).unwrap(),
            chrono::NaiveTime::from_hms_opt(hour, min, 0).unwrap(),
        )
        .and_utc();
        TimelineEntry {
            timestamp: dt,
            artifact_type: "Prefetch".to_string(),
            plugin: "Trace".to_string(),
            title: title.to_string(),
            detail: String::new(),
            source_path: String::new(),
            is_suspicious: false,
        }
    }

    fn make_baseline(start: u8, end: u8) -> BaselineSummary {
        BaselineSummary {
            activity_hours: (start..=end).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn temporal_detector_flags_3am_activity() {
        let mut timeline: Vec<TimelineEntry> = (9..=17)
            .flat_map(|h| vec![make_entry(h, 0, "normal.exe"); 10])
            .collect();
        timeline.push(make_entry(3, 17, "suspicious.exe"));

        let baseline = make_baseline(9, 17);
        let findings = TemporalOutlierDetector::run(&timeline, &baseline);
        assert!(
            findings.iter().any(|f| f.explanation.contains("03:17")),
            "expected a 3am finding, got {:?}",
            findings.iter().map(|f| &f.explanation).collect::<Vec<_>>()
        );
    }

    #[test]
    fn temporal_detector_no_flag_for_normal_hours() {
        let timeline: Vec<TimelineEntry> = (9..=17)
            .flat_map(|h| vec![make_entry(h, 0, "normal.exe"); 10])
            .collect();
        let baseline = make_baseline(9, 17);
        let findings = TemporalOutlierDetector::run(&timeline, &baseline);
        assert!(findings.is_empty());
    }

    #[test]
    fn temporal_detector_confidence_scales_with_deviation() {
        let mut timeline: Vec<TimelineEntry> = (9..=17)
            .flat_map(|h| vec![make_entry(h, 0, "work.exe"); 50])
            .collect();
        timeline.push(make_entry(3, 0, "night.exe"));
        let baseline = make_baseline(9, 17);
        let findings = TemporalOutlierDetector::run(&timeline, &baseline);
        let night = findings.iter().find(|f| f.explanation.contains("03:00"));
        assert!(night.is_some());
        assert!(night.unwrap().confidence >= 0.80);
    }
}
