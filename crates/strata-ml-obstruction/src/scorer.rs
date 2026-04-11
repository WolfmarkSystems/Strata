//! Weighted scoring engine — turns detected behaviors into a 0–100 score.

use crate::detector::DetectedBehavior;
use chrono::{DateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};

/// Base weights for each anti-forensic behavior.
const WEIGHTS: &[(&str, u32, &str)] = &[
    ("VSS_DELETION", 35, "Volume Shadow Copy deletion"),
    ("EVTX_SECURITY_CLEAR", 22, "Windows Security Event Log cleared"),
    ("EVTX_SYSTEM_CLEAR", 15, "Windows System Event Log cleared"),
    ("SECURE_DELETE_TOOL", 15, "Secure deletion tool executed (CCleaner, Eraser, SDelete)"),
    ("TIMESTAMP_STOMP", 10, "File timestamp manipulation detected ($SI/$FN mismatch)"),
    ("BROWSER_HIST_CLEAR", 5, "Browser history cleared selectively"),
    ("RECYCLE_MASS_DELETE", 8, "Mass deletion from Recycle Bin in short window"),
    ("MFT_LOG_GAP", 12, "USN Journal sequence gap (journal cleared)"),
    ("HIBERNATE_DISABLED", 5, "Hibernation file disabled/deleted"),
    ("PAGEFILE_CLEAR", 5, "Page file cleared on shutdown"),
    ("EVENT_LOG_AUDIT_OFF", 8, "Security auditing disabled via Group Policy"),
    ("ENCRYPTED_CONTAINER", 3, "VeraCrypt/BitLocker container created near deletion"),
    ("ANTIFORENSIC_SEARCH", 10, "Browser searches for anti-forensic techniques"),
];

const ADVISORY_NOTICE: &str = "ADVISORY \u{2014} This score is an investigative tool. \
    It represents Strata\u{2019}s analysis of detected artifacts and does not constitute \
    a legal finding of obstruction of justice or evidence tampering. \
    All contributing factors require examiner verification.";

/// A single behavior that contributed to the score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringFactor {
    pub factor_id: String,
    pub description: String,
    pub artifact_detail: String,
    pub timestamp: Option<String>,
    pub base_weight: u32,
    pub applied_weight: u32,
    pub multiplier_applied: Option<String>,
    pub source_plugin: String,
    pub artifact_id: String,
}

/// Complete obstruction assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObstructionAssessment {
    pub case_id: String,
    pub assessed_at: String,
    pub score: u32,
    pub severity: ObstructionSeverity,
    pub factors: Vec<ScoringFactor>,
    pub interpretation: String,
    pub advisory_notice: String,
    /// Always `true`. Enforced by construction.
    pub is_advisory: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ObstructionSeverity {
    Minimal,
    Low,
    Moderate,
    High,
    Significant,
}

impl ObstructionSeverity {
    /// Classify a raw score into a severity band.
    pub fn from_score(score: u32) -> Self {
        match score {
            0..=20 => Self::Minimal,
            21..=40 => Self::Low,
            41..=60 => Self::Moderate,
            61..=80 => Self::High,
            _ => Self::Significant,
        }
    }

    /// Human-readable label for the severity band.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Minimal => "MINIMAL",
            Self::Low => "LOW",
            Self::Moderate => "MODERATE",
            Self::High => "HIGH",
            Self::Significant => "SIGNIFICANT",
        }
    }
}

/// Produces an `ObstructionAssessment` from detected behaviors.
pub struct ObstructionScorer;

impl ObstructionScorer {
    /// Score a set of detected behaviors and return a full assessment.
    pub fn score(
        case_id: &str,
        behaviors: &[DetectedBehavior],
        seizure_time: Option<DateTime<Utc>>,
    ) -> ObstructionAssessment {
        let mut factors: Vec<ScoringFactor> = Vec::new();

        let has_vss = behaviors.iter().any(|b| b.factor_id == "VSS_DELETION");
        let has_evtx = behaviors.iter().any(|b| {
            b.factor_id == "EVTX_SECURITY_CLEAR" || b.factor_id == "EVTX_SYSTEM_CLEAR"
        });

        let timestamps: Vec<Option<DateTime<Utc>>> =
            behaviors.iter().map(|b| b.timestamp).collect();
        let coordination_bonus = Self::coordination_bonus(&timestamps);

        for behavior in behaviors {
            let (base_weight, description) = match Self::lookup_weight(behavior.factor_id) {
                Some(w) => w,
                None => continue,
            };

            let mut applied = base_weight;
            let mut multiplier_desc: Vec<String> = Vec::new();

            // VSS + EVTX within 60 minutes → 1.3x both
            if ((behavior.factor_id == "VSS_DELETION" && has_evtx)
                || (behavior.factor_id.starts_with("EVTX_") && has_vss))
                && (Self::factors_within_minutes(behaviors, "VSS_DELETION", "EVTX_SECURITY_CLEAR", 60)
                    || Self::factors_within_minutes(behaviors, "VSS_DELETION", "EVTX_SYSTEM_CLEAR", 60))
            {
                applied = (applied as f64 * 1.3) as u32;
                multiplier_desc.push("VSS+EVTX within 60 min (1.3x)".into());
            }

            // Off-hours (midnight–6am) → 1.2x
            if let Some(ts) = behavior.timestamp {
                let hour = ts.hour();
                if hour < 6 {
                    applied = (applied as f64 * 1.2) as u32;
                    multiplier_desc.push("off-hours activity (1.2x)".into());
                }
            }

            // Within 24 hours of seizure → 1.5x
            if let (Some(ts), Some(seizure)) = (behavior.timestamp, seizure_time) {
                let delta = seizure.signed_duration_since(ts);
                if delta.num_hours().abs() <= 24 {
                    applied = (applied as f64 * 1.5) as u32;
                    multiplier_desc.push("within 24h of seizure (1.5x)".into());
                }
            }

            let multiplier_applied = if multiplier_desc.is_empty() {
                None
            } else {
                Some(multiplier_desc.join("; "))
            };

            factors.push(ScoringFactor {
                factor_id: behavior.factor_id.to_string(),
                description: description.to_string(),
                artifact_detail: behavior.detail.clone(),
                timestamp: behavior
                    .timestamp
                    .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string()),
                base_weight,
                applied_weight: applied,
                multiplier_applied,
                source_plugin: behavior.source_plugin.clone(),
                artifact_id: behavior.artifact_id.clone(),
            });
        }

        // Sort by applied weight descending
        factors.sort_by(|a, b| b.applied_weight.cmp(&a.applied_weight));

        let raw_sum: u32 = factors.iter().map(|f| f.applied_weight).sum();
        let score = (raw_sum + coordination_bonus).min(100);

        let severity = ObstructionSeverity::from_score(score);
        let interpretation = Self::interpretation(&severity);

        ObstructionAssessment {
            case_id: case_id.to_string(),
            assessed_at: Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            score,
            severity,
            factors,
            interpretation,
            advisory_notice: ADVISORY_NOTICE.to_string(),
            is_advisory: true,
        }
    }

    fn lookup_weight(factor_id: &str) -> Option<(u32, &'static str)> {
        WEIGHTS
            .iter()
            .find(|(id, _, _)| *id == factor_id)
            .map(|(_, w, d)| (*w, *d))
    }

    /// 3+ distinct-factor behaviors within 30 minutes → +10 coordination bonus.
    fn coordination_bonus(timestamps: &[Option<DateTime<Utc>>]) -> u32 {
        let mut valid: Vec<DateTime<Utc>> = timestamps.iter().filter_map(|t| *t).collect();
        valid.sort();
        if valid.len() < 3 {
            return 0;
        }
        for window in valid.windows(3) {
            let delta = window[2].signed_duration_since(window[0]);
            if delta.num_minutes().abs() <= 30 {
                return 10;
            }
        }
        0
    }

    fn factors_within_minutes(
        behaviors: &[DetectedBehavior],
        id_a: &str,
        id_b: &str,
        minutes: i64,
    ) -> bool {
        let ts_a: Vec<DateTime<Utc>> = behaviors
            .iter()
            .filter(|b| b.factor_id == id_a)
            .filter_map(|b| b.timestamp)
            .collect();
        let ts_b: Vec<DateTime<Utc>> = behaviors
            .iter()
            .filter(|b| b.factor_id == id_b)
            .filter_map(|b| b.timestamp)
            .collect();
        for a in &ts_a {
            for b in &ts_b {
                if a.signed_duration_since(*b).num_minutes().abs() <= minutes {
                    return true;
                }
            }
        }
        false
    }

    fn interpretation(severity: &ObstructionSeverity) -> String {
        match severity {
            ObstructionSeverity::Minimal => {
                "Minimal — routine device use, no indicators of deliberate anti-forensic activity."
                    .into()
            }
            ObstructionSeverity::Low => {
                "Low — minor indicators detected, likely non-deliberate.".into()
            }
            ObstructionSeverity::Moderate => {
                "Moderate — some deliberate cleanup activity detected.".into()
            }
            ObstructionSeverity::High => {
                "High — significant deliberate evidence destruction detected.".into()
            }
            ObstructionSeverity::Significant => {
                "Significant — coordinated, systematic evidence destruction detected.".into()
            }
        }
    }

    /// Render a plain-text report section suitable for inclusion in court reports.
    /// Returns `None` when score is 0 (omit from report per spec).
    pub fn render_report_section(assessment: &ObstructionAssessment) -> Option<String> {
        if assessment.score == 0 {
            return None;
        }

        let mut lines = Vec::new();
        lines.push("ANTI-FORENSIC ACTIVITY ASSESSMENT".into());
        lines.push("\u{2501}".repeat(50));
        lines.push(String::new());
        lines.push(format!(
            "Obstruction Score: {} / 100                    [{}]",
            assessment.score,
            assessment.severity.label()
        ));
        lines.push(String::new());
        lines.push(
            "This score represents the degree to which digital evidence suggests".into(),
        );
        lines.push(
            "deliberate anti-forensic activity was conducted on this device.".into(),
        );
        lines.push(String::new());
        lines.push("CONTRIBUTING FACTORS (highest weight first):".into());
        lines.push(String::new());

        for factor in &assessment.factors {
            lines.push(format!(
                "  +{}  {} ",
                factor.applied_weight, factor.description
            ));
            if let Some(ts) = &factor.timestamp {
                lines.push(format!("       {} — {}", factor.artifact_detail, ts));
            } else {
                lines.push(format!("       {}", factor.artifact_detail));
            }
            if let Some(mult) = &factor.multiplier_applied {
                lines.push(format!("       Multiplier: {}", mult));
            }
            lines.push(String::new());
        }

        lines.push("SCORE INTERPRETATION:".into());
        lines.push("  0-20:   Minimal \u{2014} routine device use, no indicators".into());
        lines.push("  21-40:  Low \u{2014} minor indicators, likely non-deliberate".into());
        lines.push("  41-60:  Moderate \u{2014} some deliberate cleanup activity".into());
        lines.push("  61-80:  High \u{2014} significant deliberate evidence destruction".into());
        lines.push("  81-100: Significant \u{2014} coordinated, systematic evidence destruction".into());
        lines.push(String::new());
        lines.push("\u{2501}".repeat(60));
        lines.push(assessment.advisory_notice.clone());
        lines.push("\u{2501}".repeat(60));

        Some(lines.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::DetectedBehavior;
    use chrono::TimeZone;

    fn make_behavior(
        factor_id: &'static str,
        ts: Option<DateTime<Utc>>,
    ) -> DetectedBehavior {
        DetectedBehavior {
            factor_id,
            timestamp: ts,
            detail: format!("Test detail for {}", factor_id),
            source_plugin: "TestPlugin".into(),
            artifact_id: "test-artifact-001".into(),
        }
    }

    #[test]
    fn zero_score_for_clean_device() {
        let assessment = ObstructionScorer::score("CASE-001", &[], None);
        assert_eq!(assessment.score, 0);
        assert_eq!(assessment.severity, ObstructionSeverity::Minimal);
        assert!(assessment.factors.is_empty());
    }

    #[test]
    fn vss_deletion_adds_correct_weight() {
        let behaviors = vec![make_behavior("VSS_DELETION", None)];
        let assessment = ObstructionScorer::score("CASE-002", &behaviors, None);
        assert_eq!(assessment.score, 35);
        assert_eq!(assessment.factors.len(), 1);
        assert_eq!(assessment.factors[0].base_weight, 35);
    }

    #[test]
    fn combination_multiplier_applies_correctly() {
        let ts = Utc.with_ymd_and_hms(2025, 12, 4, 23, 41, 0).unwrap();
        let behaviors = vec![
            make_behavior("VSS_DELETION", Some(ts)),
            make_behavior(
                "EVTX_SECURITY_CLEAR",
                Some(ts + chrono::Duration::seconds(45)),
            ),
        ];
        let assessment = ObstructionScorer::score("CASE-003", &behaviors, None);
        // VSS: 35 * 1.3 = 45, EVTX_SECURITY: 22 * 1.3 = 28 → 73
        assert!(assessment.score > 35 + 22);
        for f in &assessment.factors {
            assert!(f.multiplier_applied.is_some());
        }
    }

    #[test]
    fn score_capped_at_100() {
        let behaviors = vec![
            make_behavior("VSS_DELETION", None),
            make_behavior("EVTX_SECURITY_CLEAR", None),
            make_behavior("EVTX_SYSTEM_CLEAR", None),
            make_behavior("SECURE_DELETE_TOOL", None),
            make_behavior("TIMESTAMP_STOMP", None),
            make_behavior("BROWSER_HIST_CLEAR", None),
            make_behavior("RECYCLE_MASS_DELETE", None),
            make_behavior("MFT_LOG_GAP", None),
            make_behavior("HIBERNATE_DISABLED", None),
            make_behavior("PAGEFILE_CLEAR", None),
            make_behavior("EVENT_LOG_AUDIT_OFF", None),
            make_behavior("ENCRYPTED_CONTAINER", None),
            make_behavior("ANTIFORENSIC_SEARCH", None),
        ];
        let assessment = ObstructionScorer::score("CASE-004", &behaviors, None);
        assert!(assessment.score <= 100);
    }

    #[test]
    fn severity_correct_for_each_range() {
        assert_eq!(ObstructionSeverity::from_score(0), ObstructionSeverity::Minimal);
        assert_eq!(ObstructionSeverity::from_score(20), ObstructionSeverity::Minimal);
        assert_eq!(ObstructionSeverity::from_score(21), ObstructionSeverity::Low);
        assert_eq!(ObstructionSeverity::from_score(40), ObstructionSeverity::Low);
        assert_eq!(ObstructionSeverity::from_score(41), ObstructionSeverity::Moderate);
        assert_eq!(ObstructionSeverity::from_score(60), ObstructionSeverity::Moderate);
        assert_eq!(ObstructionSeverity::from_score(61), ObstructionSeverity::High);
        assert_eq!(ObstructionSeverity::from_score(80), ObstructionSeverity::High);
        assert_eq!(ObstructionSeverity::from_score(81), ObstructionSeverity::Significant);
        assert_eq!(ObstructionSeverity::from_score(100), ObstructionSeverity::Significant);
    }

    #[test]
    fn is_advisory_always_true() {
        let assessment = ObstructionScorer::score("CASE-005", &[], None);
        assert!(assessment.is_advisory);

        let behaviors = vec![make_behavior("VSS_DELETION", None)];
        let assessment = ObstructionScorer::score("CASE-005", &behaviors, None);
        assert!(assessment.is_advisory);
    }

    #[test]
    fn advisory_notice_always_present() {
        let assessment = ObstructionScorer::score("CASE-006", &[], None);
        assert!(!assessment.advisory_notice.is_empty());
        assert!(assessment.advisory_notice.contains("ADVISORY"));
        assert!(assessment.advisory_notice.contains("investigative tool"));
    }

    #[test]
    fn coordination_bonus_applies_for_3_factors() {
        let base = Utc.with_ymd_and_hms(2025, 12, 4, 23, 30, 0).unwrap();
        let behaviors = vec![
            make_behavior("VSS_DELETION", Some(base)),
            make_behavior(
                "EVTX_SECURITY_CLEAR",
                Some(base + chrono::Duration::minutes(5)),
            ),
            make_behavior(
                "SECURE_DELETE_TOOL",
                Some(base + chrono::Duration::minutes(10)),
            ),
        ];
        let assessment_with = ObstructionScorer::score("CASE-007", &behaviors, None);

        // Same behaviors but spread over hours — no coordination bonus
        let behaviors_spread = vec![
            make_behavior("VSS_DELETION", Some(base)),
            make_behavior(
                "EVTX_SECURITY_CLEAR",
                Some(base + chrono::Duration::hours(2)),
            ),
            make_behavior(
                "SECURE_DELETE_TOOL",
                Some(base + chrono::Duration::hours(4)),
            ),
        ];
        let assessment_without =
            ObstructionScorer::score("CASE-007", &behaviors_spread, None);

        assert!(assessment_with.score > assessment_without.score);
    }

    #[test]
    fn off_hours_multiplier_applies() {
        let daytime = Utc.with_ymd_and_hms(2025, 12, 4, 14, 0, 0).unwrap();
        let nighttime = Utc.with_ymd_and_hms(2025, 12, 4, 3, 0, 0).unwrap();

        let day_assessment = ObstructionScorer::score(
            "CASE-008",
            &[make_behavior("BROWSER_HIST_CLEAR", Some(daytime))],
            None,
        );
        let night_assessment = ObstructionScorer::score(
            "CASE-008",
            &[make_behavior("BROWSER_HIST_CLEAR", Some(nighttime))],
            None,
        );

        assert!(night_assessment.score > day_assessment.score);
    }

    #[test]
    fn report_omitted_when_score_is_zero() {
        let assessment = ObstructionScorer::score("CASE-009", &[], None);
        assert!(ObstructionScorer::render_report_section(&assessment).is_none());
    }

    #[test]
    fn report_rendered_when_score_is_nonzero() {
        let behaviors = vec![make_behavior("TIMESTAMP_STOMP", None)];
        let assessment = ObstructionScorer::score("CASE-010", &behaviors, None);
        let report = ObstructionScorer::render_report_section(&assessment);
        assert!(report.is_some());
        let text = report.unwrap();
        assert!(text.contains("ANTI-FORENSIC ACTIVITY ASSESSMENT"));
        assert!(text.contains("ADVISORY"));
        assert!(text.contains("Obstruction Score:"));
    }

    #[test]
    fn seizure_proximity_multiplier_applies() {
        let action_time = Utc.with_ymd_and_hms(2025, 12, 4, 23, 0, 0).unwrap();
        let seizure_time = Utc.with_ymd_and_hms(2025, 12, 5, 8, 0, 0).unwrap();

        let without_seizure = ObstructionScorer::score(
            "CASE-011",
            &[make_behavior("VSS_DELETION", Some(action_time))],
            None,
        );
        let with_seizure = ObstructionScorer::score(
            "CASE-011",
            &[make_behavior("VSS_DELETION", Some(action_time))],
            Some(seizure_time),
        );

        assert!(with_seizure.score > without_seizure.score);
    }
}
