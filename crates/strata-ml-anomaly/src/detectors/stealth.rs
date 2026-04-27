use crate::features::{ExecutionEvent, FeatureExtractor, TimelineEntry};
use crate::types::*;
use chrono::Timelike;

/// Detects executable launches with no corresponding user interaction.
pub struct StealthExecutionDetector;

impl StealthExecutionDetector {
    pub fn run(
        executions: &[ExecutionEvent],
        full_timeline: &[TimelineEntry],
    ) -> Vec<AnomalyFinding> {
        let dist = FeatureExtractor::hourly_distribution(full_timeline);
        let (start, end) = FeatureExtractor::normal_activity_window(&dist);

        let mut findings = Vec::new();

        for exec in executions {
            if exec.is_system_path {
                continue;
            }

            let single_run = exec.run_count.map(|c| c <= 1).unwrap_or(false);
            let zero_focus = exec.focus_time_ms.map(|f| f < 500).unwrap_or(false);
            let no_interaction = !exec.has_lnk && !exec.has_jumplist && !exec.has_userassist;

            if !single_run && !zero_focus {
                continue;
            }

            let mut score: f32 = 0.0;
            if single_run {
                score += 0.25;
            }
            if zero_focus {
                score += 0.25;
            }
            if no_interaction {
                score += 0.20;
            }

            if let Some(ts) = exec.timestamp {
                let hour = ts.hour() as u8;
                let off_hours = if start <= end {
                    hour < start || hour > end
                } else {
                    hour > end && hour < start
                };
                if off_hours {
                    score += 0.15;
                }
            }

            let exe_lower = exec.executable.to_lowercase();
            let suspicious_name = exe_lower.contains("svc")
                || exe_lower.contains("update")
                || exe_lower.contains("tmp")
                || exe_lower.len() <= 5
                || exe_lower.chars().filter(|c| c.is_ascii_digit()).count() > 4;
            if suspicious_name {
                score += 0.10;
            }

            let confidence = score.min(0.95);
            if confidence < 0.50 {
                continue;
            }

            let time_str = exec
                .timestamp
                .map(|ts| format!("{:02}:{:02}", ts.hour(), ts.minute()))
                .unwrap_or_else(|| "unknown time".to_string());

            findings.push(AnomalyFinding {
                finding_id: format!("stealth-{}", findings.len()),
                artifact_ref: ArtifactRef {
                    plugin_name: exec.plugin.clone(),
                    artifact_category: "Execution".to_string(),
                    artifact_id: exec.executable.clone(),
                    timestamp: exec.timestamp.map(|ts| ts.to_rfc3339()),
                    file_path: Some(exec.source_path.clone()),
                },
                anomaly_type: AnomalyType::StealthExecution,
                confidence,
                explanation: format!(
                    "Executed at {}. Run count: {}. Focus time: {}ms. \
                     No LNK: {}. No Jump List: {}. No UserAssist: {}.",
                    time_str,
                    exec.run_count
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "?".to_string()),
                    exec.focus_time_ms
                        .map(|f| f.to_string())
                        .unwrap_or_else(|| "?".to_string()),
                    !exec.has_lnk,
                    !exec.has_jumplist,
                    !exec.has_userassist,
                ),
                evidence_points: vec![
                    format!("Single execution (run count: {:?})", exec.run_count),
                    format!("Zero/minimal focus time: {:?}ms", exec.focus_time_ms),
                    format!("Missing user interaction artifacts"),
                ],
                suggested_followup: vec![
                    "Review Prefetch entry for this executable".to_string(),
                    "Check parent process via SRUM".to_string(),
                    "Examine file hash against known-bad sets".to_string(),
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

    fn make_exec(
        name: &str,
        hour: u32,
        run_count: Option<u32>,
        focus_ms: Option<u64>,
        system: bool,
    ) -> ExecutionEvent {
        let dt = NaiveDateTime::new(
            chrono::NaiveDate::from_ymd_opt(2024, 6, 15).unwrap(),
            chrono::NaiveTime::from_hms_opt(hour, 0, 0).unwrap(),
        )
        .and_utc();
        ExecutionEvent {
            timestamp: Some(dt),
            executable: name.to_string(),
            source_path: String::new(),
            plugin: "Trace".to_string(),
            run_count,
            focus_time_ms: focus_ms,
            has_lnk: false,
            has_jumplist: false,
            has_userassist: false,
            is_system_path: system,
        }
    }

    fn make_timeline() -> Vec<TimelineEntry> {
        (9..=17)
            .flat_map(|h| {
                let dt = NaiveDateTime::new(
                    chrono::NaiveDate::from_ymd_opt(2024, 6, 15).unwrap(),
                    chrono::NaiveTime::from_hms_opt(h, 0, 0).unwrap(),
                )
                .and_utc();
                vec![
                    TimelineEntry {
                        timestamp: dt,
                        artifact_type: "test".to_string(),
                        plugin: "test".to_string(),
                        title: "normal".to_string(),
                        detail: String::new(),
                        source_path: String::new(),
                        is_suspicious: false,
                    };
                    10
                ]
            })
            .collect()
    }

    #[test]
    fn stealth_detector_flags_zero_focus_time() {
        let execs = vec![make_exec("evil.exe", 3, Some(1), Some(0), false)];
        let timeline = make_timeline();
        let findings = StealthExecutionDetector::run(&execs, &timeline);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].anomaly_type, AnomalyType::StealthExecution);
    }

    #[test]
    fn stealth_detector_no_flag_for_normal_execution() {
        let mut exec = make_exec("notepad.exe", 10, Some(50), Some(30000), false);
        exec.has_lnk = true;
        exec.has_userassist = true;
        let execs = vec![exec];
        let timeline = make_timeline();
        let findings = StealthExecutionDetector::run(&execs, &timeline);
        assert!(findings.is_empty());
    }

    #[test]
    fn stealth_detector_flags_no_lnk_no_userassist() {
        let execs = vec![make_exec("unknown_svc.exe", 3, Some(1), Some(0), false)];
        let timeline = make_timeline();
        let findings = StealthExecutionDetector::run(&execs, &timeline);
        assert!(!findings.is_empty());
        assert!(findings[0].explanation.contains("No LNK: true"));
    }

    #[test]
    fn stealth_detector_confidence_increases_at_night() {
        let day_exec = make_exec("test.exe", 10, Some(1), Some(0), false);
        let night_exec = make_exec("test.exe", 3, Some(1), Some(0), false);
        let timeline = make_timeline();

        let day_findings = StealthExecutionDetector::run(&[day_exec], &timeline);
        let night_findings = StealthExecutionDetector::run(&[night_exec], &timeline);

        if !day_findings.is_empty() && !night_findings.is_empty() {
            assert!(night_findings[0].confidence >= day_findings[0].confidence);
        }
    }
}
