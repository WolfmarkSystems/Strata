//! Expert witness report mode (WF-10).
//!
//! Plain-language report for judges and juries. Removes technical
//! jargon, presents findings as chronological key events, and
//! surfaces examiner qualifications + methodology summary.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyFinding {
    pub title: String,
    pub summary: String,
    pub supporting_artifacts: Vec<String>,
    pub confidence: String,
    pub case_impact: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineEventPlain {
    pub when: DateTime<Utc>,
    pub what: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExaminerQualifications {
    pub name: String,
    pub title: String,
    pub credentials: Vec<String>,
    pub years_of_experience: u32,
    pub prior_examinations: u32,
    pub training: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpertWitnessReport {
    pub case_number: String,
    pub executive_summary: String,
    pub key_findings: Vec<KeyFinding>,
    pub timeline: Vec<TimelineEventPlain>,
    pub qualifications: Option<ExaminerQualifications>,
    pub methodology_summary: String,
    pub limitations: Vec<String>,
}

impl ExpertWitnessReport {
    pub fn to_html(&self) -> String {
        let mut out = String::from(
            "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Expert Witness Report</title>\n\
             <style>body{font-family:Georgia,serif;margin:1in;}h2{margin-top:1.5em;}\n\
             .finding{border-left:4px solid #444;padding-left:1em;margin:1em 0;page-break-inside:avoid;}\n\
             .timeline-item{margin:0.4em 0;}</style></head><body>\n",
        );
        out.push_str(&format!("<h1>Expert Witness Report — Case {}</h1>\n", escape(&self.case_number)));
        out.push_str("<section><h2>Executive Summary</h2>\n");
        out.push_str(&format!("<p>{}</p>\n</section>\n", escape(&self.executive_summary)));
        if !self.key_findings.is_empty() {
            out.push_str("<section><h2>Key Findings</h2>\n");
            for f in &self.key_findings {
                out.push_str("<div class=\"finding\">\n");
                out.push_str(&format!("<h3>{}</h3>\n", escape(&f.title)));
                out.push_str(&format!("<p>{}</p>\n", escape(&f.summary)));
                if !f.supporting_artifacts.is_empty() {
                    out.push_str("<p>Supporting evidence:</p><ul>\n");
                    for s in &f.supporting_artifacts {
                        out.push_str(&format!("<li>{}</li>\n", escape(s)));
                    }
                    out.push_str("</ul>\n");
                }
                out.push_str(&format!(
                    "<p>Confidence: {} — {}</p>\n",
                    escape(&f.confidence),
                    escape(&f.case_impact)
                ));
                out.push_str("</div>\n");
            }
            out.push_str("</section>\n");
        }
        if !self.timeline.is_empty() {
            out.push_str("<section><h2>Timeline of Events</h2>\n<ol>\n");
            for t in &self.timeline {
                out.push_str(&format!(
                    "<li class=\"timeline-item\"><strong>{}</strong> — {}</li>\n",
                    t.when.format("%Y-%m-%d %H:%M"),
                    escape(&t.what)
                ));
            }
            out.push_str("</ol></section>\n");
        }
        if let Some(q) = &self.qualifications {
            out.push_str("<section><h2>Examiner Qualifications</h2>\n");
            out.push_str(&format!(
                "<p>{}, {}. Credentials: {}.</p>\n",
                escape(&q.name),
                escape(&q.title),
                escape(&q.credentials.join(", "))
            ));
            out.push_str(&format!(
                "<p>{} years of experience; {} prior examinations.</p>\n",
                q.years_of_experience, q.prior_examinations
            ));
            if !q.training.is_empty() {
                out.push_str("<p>Training: ");
                out.push_str(&escape(&q.training.join(", ")));
                out.push_str("</p>\n");
            }
            out.push_str("</section>\n");
        }
        out.push_str("<section><h2>Methodology</h2>\n");
        out.push_str(&format!("<p>{}</p>\n", escape(&self.methodology_summary)));
        out.push_str("</section>\n");
        out.push_str("<section><h2>Limitations</h2>\n<ul>\n");
        for l in &self.limitations {
            out.push_str(&format!("<li>{}</li>\n", escape(l)));
        }
        out.push_str("</ul></section>\n");
        let glossary = glossary_from(&self.key_findings, &self.timeline);
        if !glossary.is_empty() {
            out.push_str("<section><h2>Glossary</h2>\n<dl>\n");
            for (term, defn) in &glossary {
                out.push_str(&format!(
                    "<dt>{}</dt><dd>{}</dd>\n",
                    escape(term),
                    escape(defn)
                ));
            }
            out.push_str("</dl></section>\n");
        }
        out.push_str("</body></html>\n");
        out
    }
}

pub fn glossary_from(
    findings: &[KeyFinding],
    timeline: &[TimelineEventPlain],
) -> BTreeMap<String, String> {
    let seed: &[(&str, &str)] = &[
        (
            "Prefetch",
            "A Windows cache that records when programmes were launched, the number of times they ran, and which files they opened.",
        ),
        (
            "MITRE ATT&CK",
            "A globally-used catalogue of computer-attack techniques used by security professionals.",
        ),
        (
            "EXIF",
            "Metadata automatically embedded by a camera or phone into a photo file (date, location, device).",
        ),
        (
            "SHA-256",
            "A 64-character fingerprint that uniquely identifies a specific file; two different files cannot have the same SHA-256.",
        ),
        (
            "Chain of Custody",
            "A log proving who handled the evidence and when, from seizure to court.",
        ),
        (
            "Artifact",
            "A piece of data left on a device that documents what happened — emails, chat logs, photos, login records, etc.",
        ),
    ];
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let corpus = format!(
        "{} {}",
        findings
            .iter()
            .map(|f| format!("{} {}", f.title, f.summary))
            .collect::<Vec<_>>()
            .join(" "),
        timeline
            .iter()
            .map(|t| t.what.clone())
            .collect::<Vec<_>>()
            .join(" "),
    );
    let lower = corpus.to_ascii_lowercase();
    for (term, defn) in seed {
        if lower.contains(&term.to_ascii_lowercase()) {
            out.insert(term.to_string(), defn.to_string());
        }
    }
    out
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_html_contains_all_required_sections() {
        let report = ExpertWitnessReport {
            case_number: "X-1".into(),
            executive_summary: "Summary".into(),
            key_findings: vec![KeyFinding {
                title: "Account Compromise".into(),
                summary: "suspect's account was used".into(),
                supporting_artifacts: vec!["Prefetch records of suspicious executions".into()],
                confidence: "High".into(),
                case_impact: "proves unauthorised access".into(),
            }],
            timeline: vec![TimelineEventPlain {
                when: DateTime::<Utc>::from_timestamp(1_717_243_200, 0).expect("ts"),
                what: "EXIF metadata shows photograph taken on suspect's phone".into(),
            }],
            qualifications: Some(ExaminerQualifications {
                name: "Jane Doe".into(),
                title: "Senior Examiner".into(),
                credentials: vec!["GCFE".into()],
                years_of_experience: 10,
                prior_examinations: 200,
                training: vec!["SANS FOR508".into()],
            }),
            methodology_summary: "Strata examined the image and the findings were verified.".into(),
            limitations: vec!["Did not examine network captures".into()],
        };
        let html = report.to_html();
        assert!(html.contains("Executive Summary"));
        assert!(html.contains("Key Findings"));
        assert!(html.contains("Timeline of Events"));
        assert!(html.contains("Examiner Qualifications"));
        assert!(html.contains("Methodology"));
        assert!(html.contains("Limitations"));
        assert!(html.contains("Glossary"));
    }

    #[test]
    fn glossary_auto_populates_from_findings() {
        let findings = vec![KeyFinding {
            title: "Prefetch shows execution".into(),
            summary: "SHA-256 fingerprint matched".into(),
            supporting_artifacts: Vec::new(),
            confidence: "High".into(),
            case_impact: "ties device to user".into(),
        }];
        let g = glossary_from(&findings, &[]);
        assert!(g.contains_key("Prefetch"));
        assert!(g.contains_key("SHA-256"));
    }

    #[test]
    fn glossary_excludes_unused_terms() {
        let findings = vec![KeyFinding {
            title: "General notes".into(),
            summary: "plain text only".into(),
            supporting_artifacts: Vec::new(),
            confidence: "Low".into(),
            case_impact: "none".into(),
        }];
        let g = glossary_from(&findings, &[]);
        assert!(!g.contains_key("Prefetch"));
    }

    #[test]
    fn report_default_is_empty() {
        let report = ExpertWitnessReport::default();
        let html = report.to_html();
        assert!(html.contains("Expert Witness Report"));
        assert!(!html.contains("Key Findings"));
    }
}
