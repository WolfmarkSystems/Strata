//! Triage mode — fast high-value artifact screening (WF-1).
//!
//! Produces a one-page HTML summary in under the caller-specified
//! time budget (default 60 s). Never a substitute for full
//! examination; every output carries the mandatory triage caveat.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

pub const DEFAULT_BUDGET_SECS: u64 = 60;
pub const TRIAGE_CAVEAT: &str =
    "TRIAGE MODE: Preliminary findings only. Full examination required for evidentiary use.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    High,
    Medium,
    Low,
    Unknown,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::High => "High",
            RiskLevel::Medium => "Medium",
            RiskLevel::Low => "Low",
            RiskLevel::Unknown => "Unknown",
        }
    }

    pub fn escalate(self, other: RiskLevel) -> RiskLevel {
        use RiskLevel::*;
        match (self, other) {
            (High, _) | (_, High) => High,
            (Medium, _) | (_, Medium) => Medium,
            (Low, _) | (_, Low) => Low,
            _ => Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriageFinding {
    pub category: String,
    pub summary: String,
    pub artifact_count: usize,
    pub risk_contribution: RiskLevel,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TriageResult {
    pub image_path: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub duration_secs: f64,
    pub checks_completed: Vec<String>,
    pub checks_skipped: Vec<String>,
    pub findings: Vec<TriageFinding>,
    pub risk_level: RiskLevel,
    pub recommended_action: String,
}

/// A single triage check — a name and a closure that returns 0..n
/// findings. Runs until the time budget is exhausted.
pub struct TriageCheck {
    pub name: &'static str,
    pub check: Box<dyn Fn() -> Vec<TriageFinding> + Send + Sync>,
}

/// Ordered list of the 12 standard triage checks. Callers can provide
/// their own boxed closures that wrap plugin calls; for unit tests we
/// accept any closures.
pub fn standard_check_names() -> Vec<&'static str> {
    vec![
        "hash_check",
        "partition_table",
        "recent_files",
        "browser_history",
        "usb_history",
        "anti_forensic_tools",
        "photo_vault_apps",
        "csam_hash_check",
        "suspicious_processes",
        "communication_apps",
        "cloud_sync",
        "encryption_indicators",
    ]
}

/// Run a sequence of checks until either all complete or the time
/// budget is exhausted. Never panics.
pub fn run_triage(
    image_path: &str,
    checks: Vec<TriageCheck>,
    budget: Duration,
) -> TriageResult {
    let start = Utc::now();
    let clock = Instant::now();
    let mut findings = Vec::new();
    let mut completed = Vec::new();
    let mut skipped = Vec::new();
    let mut risk = RiskLevel::Unknown;
    for check in checks {
        if clock.elapsed() >= budget {
            skipped.push(check.name.to_string());
            continue;
        }
        let hits = (check.check)();
        for f in &hits {
            risk = risk.escalate(f.risk_contribution);
        }
        findings.extend(hits);
        completed.push(check.name.to_string());
    }
    let end = Utc::now();
    let duration = clock.elapsed().as_secs_f64();
    let recommended_action = recommend(&risk, &completed, &skipped);
    TriageResult {
        image_path: image_path.to_string(),
        start_time: start,
        end_time: end,
        duration_secs: duration,
        checks_completed: completed,
        checks_skipped: skipped,
        findings,
        risk_level: risk,
        recommended_action,
    }
}

fn recommend(
    risk: &RiskLevel,
    completed: &[String],
    skipped: &[String],
) -> String {
    let mut reco = match risk {
        RiskLevel::High => "HIGH RISK — escalate for full examination immediately.".to_string(),
        RiskLevel::Medium => "Medium risk — schedule full examination.".to_string(),
        RiskLevel::Low => "Low-risk indicators — full examination still recommended.".to_string(),
        RiskLevel::Unknown => "No indicators surfaced in triage window.".to_string(),
    };
    if !skipped.is_empty() {
        reco.push_str(&format!(
            " Checks completed: {}/{}. Remaining checks require full examination.",
            completed.len(),
            completed.len() + skipped.len()
        ));
    }
    reco
}

pub fn render_html(result: &TriageResult) -> String {
    let mut out = String::new();
    out.push_str("<!DOCTYPE html><html><head><meta charset=\"utf-8\">\n");
    out.push_str("<title>Strata Triage Summary</title>\n");
    out.push_str("<style>body{font-family:sans-serif;margin:1em;}.caveat{background:#ffe;border:1px solid #aa3;padding:0.5em;}</style>\n");
    out.push_str("</head><body>\n");
    out.push_str(&format!(
        "<p class=\"caveat\"><strong>{}</strong></p>\n",
        escape(TRIAGE_CAVEAT)
    ));
    out.push_str(&format!(
        "<h1>Triage Summary — {}</h1>\n",
        escape(&result.image_path)
    ));
    out.push_str(&format!(
        "<p>Risk level: <strong>{}</strong></p>\n",
        result.risk_level.as_str()
    ));
    out.push_str(&format!(
        "<p>Duration: {:.2}s | Checks completed: {} | Skipped: {}</p>\n",
        result.duration_secs,
        result.checks_completed.len(),
        result.checks_skipped.len()
    ));
    if !result.findings.is_empty() {
        out.push_str("<table border=\"1\" cellpadding=\"4\"><tr><th>Category</th><th>Summary</th><th>Count</th><th>Risk</th></tr>\n");
        for f in &result.findings {
            out.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                escape(&f.category),
                escape(&f.summary),
                f.artifact_count,
                f.risk_contribution.as_str()
            ));
        }
        out.push_str("</table>\n");
    }
    out.push_str(&format!(
        "<h2>Recommended Action</h2>\n<p>{}</p>\n",
        escape(&result.recommended_action)
    ));
    out.push_str("</body></html>\n");
    out
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_escalation_follows_severity_order() {
        use RiskLevel::*;
        assert_eq!(Low.escalate(High), High);
        assert_eq!(Unknown.escalate(Medium), Medium);
        assert_eq!(Medium.escalate(Low), Medium);
        assert_eq!(Unknown.escalate(Unknown), Unknown);
    }

    #[test]
    fn run_triage_runs_all_checks_within_budget() {
        let checks = vec![
            TriageCheck {
                name: "hash_check",
                check: Box::new(|| {
                    vec![TriageFinding {
                        category: "Hash".into(),
                        summary: "matched NSRL".into(),
                        artifact_count: 1,
                        risk_contribution: RiskLevel::Low,
                    }]
                }),
            },
            TriageCheck {
                name: "anti_forensic_tools",
                check: Box::new(|| {
                    vec![TriageFinding {
                        category: "Anti-Forensic".into(),
                        summary: "CCleaner present".into(),
                        artifact_count: 1,
                        risk_contribution: RiskLevel::High,
                    }]
                }),
            },
        ];
        let r = run_triage("/evidence/img", checks, Duration::from_secs(5));
        assert_eq!(r.checks_completed.len(), 2);
        assert_eq!(r.risk_level, RiskLevel::High);
        assert_eq!(r.findings.len(), 2);
    }

    #[test]
    fn run_triage_skips_when_budget_exhausted() {
        let checks = vec![
            TriageCheck {
                name: "slow_check",
                check: Box::new(|| {
                    std::thread::sleep(Duration::from_millis(120));
                    Vec::new()
                }),
            },
            TriageCheck {
                name: "second_check",
                check: Box::new(Vec::new),
            },
        ];
        let r = run_triage("/evidence", checks, Duration::from_millis(50));
        assert!(r.checks_skipped.contains(&"second_check".to_string())
            || r.checks_skipped.contains(&"slow_check".to_string()));
    }

    #[test]
    fn render_html_includes_caveat_and_risk() {
        let r = TriageResult {
            image_path: "/evidence/img".into(),
            start_time: Utc::now(),
            end_time: Utc::now(),
            duration_secs: 1.0,
            checks_completed: vec!["hash_check".into()],
            checks_skipped: Vec::new(),
            findings: vec![TriageFinding {
                category: "Hash".into(),
                summary: "ok".into(),
                artifact_count: 1,
                risk_contribution: RiskLevel::Low,
            }],
            risk_level: RiskLevel::Low,
            recommended_action: "standard follow-up".into(),
        };
        let html = render_html(&r);
        assert!(html.contains(TRIAGE_CAVEAT));
        assert!(html.contains("Low"));
    }

    #[test]
    fn standard_check_names_covers_twelve_checks() {
        assert_eq!(standard_check_names().len(), 12);
    }

    #[test]
    fn recommend_includes_skipped_note_when_over_budget() {
        let r = recommend(
            &RiskLevel::Unknown,
            &["hash_check".to_string()],
            &["usb_history".to_string()],
        );
        assert!(r.contains("Checks completed"));
    }
}
