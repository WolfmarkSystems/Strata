//! FACT Attribution Framework report fields (COC-3).
//!
//! Brett Shavers' FACT framework separates technical identification
//! from investigative attribution and legal attribution. This module
//! provides the data structures — examiners populate them explicitly
//! rather than have Strata draw conclusions for them.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfidenceLevel {
    High,
    Medium,
    Low,
    Inconclusive,
}

impl ConfidenceLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConfidenceLevel::High => "High",
            ConfidenceLevel::Medium => "Medium",
            ConfidenceLevel::Low => "Low",
            ConfidenceLevel::Inconclusive => "Inconclusive",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hypothesis {
    pub label: String,
    pub description: String,
    pub is_primary: bool,
    pub support_count: usize,
    pub contradict_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FactAnalysis {
    pub technical_findings: Vec<String>,
    pub hypotheses: Vec<Hypothesis>,
    pub supporting_artifacts: Vec<String>,
    pub contradicting_artifacts: Vec<String>,
    pub confidence: ConfidenceLevel,
    pub limitations: Vec<String>,
    pub evidence_gaps: Vec<String>,
    pub ai_assisted: bool,
    pub ai_tools_used: Option<String>,
}

impl Default for FactAnalysis {
    fn default() -> Self {
        Self {
            technical_findings: Vec::new(),
            hypotheses: Vec::new(),
            supporting_artifacts: Vec::new(),
            contradicting_artifacts: Vec::new(),
            confidence: ConfidenceLevel::Inconclusive,
            limitations: Vec::new(),
            evidence_gaps: Vec::new(),
            ai_assisted: false,
            ai_tools_used: None,
        }
    }
}

/// Minimal artifact summary used for auto-population — carries only
/// the fields FACT analysis needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactSnippet {
    pub title: String,
    pub forensic_value: String,
}

/// Auto-populate the `technical_findings` section from the top 10
/// highest-forensic-value artifacts. Examiner reviews + edits.
pub fn auto_populate_findings(analysis: &mut FactAnalysis, artifacts: &[ArtifactSnippet]) {
    let mut top: Vec<(&ArtifactSnippet, u8)> = artifacts
        .iter()
        .map(|a| (a, forensic_rank(&a.forensic_value)))
        .collect();
    top.sort_by(|a, b| b.1.cmp(&a.1));
    for (snippet, _) in top.iter().take(10) {
        let line = format!("[{}] {}", snippet.forensic_value, snippet.title);
        if !analysis.technical_findings.contains(&line) {
            analysis.technical_findings.push(line);
        }
    }
}

fn forensic_rank(level: &str) -> u8 {
    match level {
        "Critical" => 4,
        "High" => 3,
        "Medium" => 2,
        "Low" => 1,
        _ => 0,
    }
}

/// Rendered HTML for the optional Examiner Analysis section.
pub fn render_html(analysis: &FactAnalysis) -> String {
    let mut out = String::from("<section class=\"examiner-analysis\"><h2>Examiner Analysis</h2>\n");
    if analysis.ai_assisted {
        out.push_str(
            "<p class=\"ai-disclosure\"><strong>NOTICE:</strong> AI tools were used in the analysis of this case. All AI-assisted findings have been independently reviewed and verified by the examiner.",
        );
        if let Some(tools) = &analysis.ai_tools_used {
            out.push_str(&format!(" Tools: {}.", escape(tools)));
        }
        out.push_str("</p>\n");
    }
    render_list(&mut out, "Technical Findings", &analysis.technical_findings);
    if !analysis.hypotheses.is_empty() {
        out.push_str("<h3>Hypotheses Considered</h3>\n<ul>\n");
        for h in &analysis.hypotheses {
            out.push_str(&format!(
                "<li><strong>{}</strong>{}: {} (supporting: {}, contradicting: {})</li>\n",
                escape(&h.label),
                if h.is_primary { " [primary]" } else { "" },
                escape(&h.description),
                h.support_count,
                h.contradict_count,
            ));
        }
        out.push_str("</ul>\n");
    }
    render_list(
        &mut out,
        "Supporting Artifacts",
        &analysis.supporting_artifacts,
    );
    render_list(
        &mut out,
        "Contradicting Artifacts",
        &analysis.contradicting_artifacts,
    );
    render_list(&mut out, "Limitations and Caveats", &analysis.limitations);
    render_list(&mut out, "Evidence Gaps", &analysis.evidence_gaps);
    out.push_str(&format!(
        "<p><strong>Confidence in primary hypothesis: {}</strong></p>\n",
        analysis.confidence.as_str()
    ));
    out.push_str("</section>\n");
    out
}

fn render_list(out: &mut String, title: &str, items: &[String]) {
    if items.is_empty() {
        return;
    }
    out.push_str(&format!("<h3>{}</h3>\n<ul>\n", title));
    for item in items {
        out.push_str(&format!("<li>{}</li>\n", escape(item)));
    }
    out.push_str("</ul>\n");
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
    fn auto_populate_picks_top_artifacts_by_rank() {
        let mut a = FactAnalysis::default();
        let arts: Vec<ArtifactSnippet> = (0..15)
            .map(|i| ArtifactSnippet {
                title: format!("art-{}", i),
                forensic_value: if i < 3 {
                    "Critical".into()
                } else if i < 7 {
                    "High".into()
                } else {
                    "Low".into()
                },
            })
            .collect();
        auto_populate_findings(&mut a, &arts);
        assert_eq!(a.technical_findings.len(), 10);
        assert!(a.technical_findings[0].starts_with("[Critical]"));
    }

    #[test]
    fn render_html_includes_ai_disclosure_when_flagged() {
        let a = FactAnalysis {
            ai_assisted: true,
            ai_tools_used: Some("Claude".into()),
            ..Default::default()
        };
        let html = render_html(&a);
        assert!(html.contains("NOTICE"));
        assert!(html.contains("Tools: Claude"));
    }

    #[test]
    fn render_html_omits_empty_sections() {
        let a = FactAnalysis::default();
        let html = render_html(&a);
        assert!(!html.contains("Supporting Artifacts"));
        assert!(html.contains("Inconclusive"));
    }

    #[test]
    fn render_html_renders_hypotheses_with_counts() {
        let a = FactAnalysis {
            hypotheses: vec![Hypothesis {
                label: "Insider".into(),
                description: "Authorised user exfiltrated".into(),
                is_primary: true,
                support_count: 3,
                contradict_count: 1,
            }],
            ..Default::default()
        };
        let html = render_html(&a);
        assert!(html.contains("Insider"));
        assert!(html.contains("primary"));
        assert!(html.contains("supporting: 3"));
    }

    #[test]
    fn confidence_as_str_maps_all_variants() {
        assert_eq!(ConfidenceLevel::High.as_str(), "High");
        assert_eq!(ConfidenceLevel::Medium.as_str(), "Medium");
        assert_eq!(ConfidenceLevel::Low.as_str(), "Low");
        assert_eq!(ConfidenceLevel::Inconclusive.as_str(), "Inconclusive");
    }
}
