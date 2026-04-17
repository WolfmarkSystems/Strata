//! UCMJ court-martial report format (UX-1).
//!
//! Military Criminal Investigative Organisations (Army CID, NCIS,
//! AFOSI, CGIS, DCIS) require a DD Form 2922-aligned digital evidence
//! report. This differs from the civilian format in its jurisdiction
//! and authority section, UCMJ article tagging, and examiner
//! certification block.
//!
//! Output format: HTML with print-ready CSS.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const UCMJ_ARTICLES: &[(&str, &str)] = &[
    ("Article 80", "Attempts"),
    ("Article 81", "Conspiracy"),
    ("Article 92", "Failure to obey order or regulation"),
    ("Article 107", "False official statements"),
    ("Article 117a", "Wrongful broadcast or distribution of intimate images"),
    ("Article 119", "Manslaughter"),
    ("Article 120", "Rape and sexual assault"),
    ("Article 120b", "Rape and sexual assault of a child"),
    ("Article 121", "Larceny and wrongful appropriation"),
    ("Article 130", "Stalking"),
    ("Article 134", "General article (catch-all)"),
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dd2922Fields {
    pub evidence_item_number: String,
    pub media_description: String,
    pub make_model: String,
    pub serial_number: Option<String>,
    pub acquisition_method: String,
    pub acquisition_tool: String,
    pub md5_hash: String,
    pub sha256_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactSummary {
    pub kind: String,
    pub count: usize,
    pub forensic_value: String,
    pub mitre_techniques: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UcmjReport {
    pub case_number: String,
    pub classification: String,
    pub agency: String,
    pub examiner_name: String,
    pub examiner_rank: String,
    pub examiner_credentials: String,
    pub examination_date: DateTime<Utc>,
    pub ucmj_articles: Vec<String>,
    pub authorizing_official: String,
    pub authorization_type: String,
    pub dd2922_fields: Dd2922Fields,
    pub artifacts: Vec<ArtifactSummary>,
}

impl UcmjReport {
    /// Render the report to a self-contained HTML document with
    /// print-ready CSS.
    pub fn to_html(&self) -> String {
        let mut html = String::new();
        html.push_str("<!DOCTYPE html>\n<html lang=\"en\"><head>\n");
        html.push_str("<meta charset=\"utf-8\">\n");
        html.push_str(&format!(
            "<title>UCMJ Digital Evidence Report — {}</title>\n",
            html_escape(&self.case_number)
        ));
        html.push_str("<style>\n");
        html.push_str(CSS);
        html.push_str("</style>\n</head><body>\n");

        // Classification banner (top).
        html.push_str(&format!(
            "<div class=\"classification\">{}</div>\n",
            html_escape(&self.classification)
        ));

        // Cover page.
        html.push_str("<section class=\"cover\">\n");
        html.push_str("<h1>UCMJ Digital Evidence Examination Report</h1>\n");
        html.push_str(&format!(
            "<p class=\"case\">Case Number: <strong>{}</strong></p>\n",
            html_escape(&self.case_number)
        ));
        html.push_str(&format!("<p>Agency: {}</p>\n", html_escape(&self.agency)));
        html.push_str(&format!(
            "<p>Examiner: {} {}, {}</p>\n",
            html_escape(&self.examiner_rank),
            html_escape(&self.examiner_name),
            html_escape(&self.examiner_credentials)
        ));
        html.push_str(&format!(
            "<p>Examination Date: {}</p>\n",
            self.examination_date.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        html.push_str("</section>\n");

        // DD Form 2922 block.
        html.push_str("<section><h2>DD Form 2922 Digital Evidence Worksheet</h2>\n");
        html.push_str("<table>\n");
        let rows: &[(&str, &str)] = &[
            ("Evidence Item Number", &self.dd2922_fields.evidence_item_number),
            ("Media Description", &self.dd2922_fields.media_description),
            ("Make/Model", &self.dd2922_fields.make_model),
            (
                "Serial Number",
                self.dd2922_fields.serial_number.as_deref().unwrap_or("N/A"),
            ),
            ("Acquisition Method", &self.dd2922_fields.acquisition_method),
            ("Acquisition Tool", &self.dd2922_fields.acquisition_tool),
            ("MD5 Hash", &self.dd2922_fields.md5_hash),
            ("SHA-256 Hash", &self.dd2922_fields.sha256_hash),
        ];
        for (k, v) in rows {
            html.push_str(&format!(
                "<tr><th>{}</th><td>{}</td></tr>\n",
                html_escape(k),
                html_escape(v)
            ));
        }
        html.push_str("</table></section>\n");

        // Jurisdiction.
        html.push_str(
            "<section><h2>Jurisdiction and Authority</h2>\n<ul class=\"articles\">\n",
        );
        for art in &self.ucmj_articles {
            html.push_str(&format!("<li>{}</li>\n", html_escape(art)));
        }
        html.push_str("</ul>\n");
        html.push_str(&format!(
            "<p>Authorizing Official: {}</p>\n",
            html_escape(&self.authorizing_official)
        ));
        html.push_str(&format!(
            "<p>Authorization Type: {}</p>\n",
            html_escape(&self.authorization_type)
        ));
        html.push_str("</section>\n");

        // Methodology (tool version is static for v1).
        html.push_str("<section><h2>Examination Methodology</h2>\n");
        html.push_str("<p>Tool: Strata Digital Forensic Platform</p>\n");
        html.push_str("<p>All plugin parsers operate read-only; acquired image hashes are verified before and after examination.</p>\n");
        html.push_str("</section>\n");

        // Findings.
        html.push_str("<section><h2>Findings</h2>\n");
        html.push_str("<table><tr><th>Artifact Type</th><th>Count</th><th>Forensic Value</th><th>MITRE Techniques</th></tr>\n");
        for a in &self.artifacts {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                html_escape(&a.kind),
                a.count,
                html_escape(&a.forensic_value),
                html_escape(&a.mitre_techniques.join(", "))
            ));
        }
        html.push_str("</table></section>\n");

        // Certification block.
        html.push_str("<section class=\"certification\"><h2>Examiner Certification</h2>\n");
        html.push_str("<p>I certify that the examination was conducted in accordance with accepted digital forensic standards and that the findings reported herein are accurate to the best of my knowledge.</p>\n");
        html.push_str("<div class=\"signature-block\">\n");
        html.push_str(&format!(
            "<p>Signature: ____________________ Date: ________</p>\n<p>{} {}, {}</p>\n",
            html_escape(&self.examiner_rank),
            html_escape(&self.examiner_name),
            html_escape(&self.agency)
        ));
        html.push_str("</div></section>\n");

        // Classification banner (bottom).
        html.push_str(&format!(
            "<div class=\"classification\">{}</div>\n",
            html_escape(&self.classification)
        ));
        html.push_str("</body></html>\n");
        html
    }
}

const CSS: &str = r#"
body { font-family: 'Times New Roman', serif; margin: 1in; color: #111; }
h1, h2 { color: #004080; }
.classification { text-align: center; font-weight: bold; padding: 0.25em;
    background: #fffae6; border: 1px solid #aa7; margin: 0.5em 0; }
.cover h1 { font-size: 24pt; text-align: center; }
.cover .case { font-size: 14pt; text-align: center; }
table { border-collapse: collapse; width: 100%; margin: 0.5em 0; }
th, td { border: 1px solid #aaa; padding: 4px 8px; text-align: left; }
.articles { list-style: square; margin-left: 1.5em; }
.certification { margin-top: 2em; page-break-before: auto; }
.signature-block { margin-top: 1em; border-top: 1px solid #333; padding-top: 0.5em; }
@media print { body { margin: 0.75in; } }
"#;

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> UcmjReport {
        UcmjReport {
            case_number: "CID-2026-0001".into(),
            classification: "UNCLASSIFIED".into(),
            agency: "U.S. Army CID".into(),
            examiner_name: "Doe, John".into(),
            examiner_rank: "SA".into(),
            examiner_credentials: "CFCE".into(),
            examination_date: DateTime::<Utc>::from_timestamp(1_717_243_200, 0)
                .expect("ts"),
            ucmj_articles: vec!["Article 120".into()],
            authorizing_official: "LTC Smith".into(),
            authorization_type: "SearchAuth".into(),
            dd2922_fields: Dd2922Fields {
                evidence_item_number: "1A".into(),
                media_description: "128 GB USB drive".into(),
                make_model: "SanDisk Cruzer".into(),
                serial_number: Some("ABC123".into()),
                acquisition_method: "Physical".into(),
                acquisition_tool: "Strata v1.4".into(),
                md5_hash: "aabbccdd".into(),
                sha256_hash: "eeff0011".into(),
            },
            artifacts: vec![ArtifactSummary {
                kind: "iMessage".into(),
                count: 3,
                forensic_value: "High".into(),
                mitre_techniques: vec!["T1636.002".into()],
            }],
        }
    }

    #[test]
    fn to_html_contains_required_sections() {
        let html = sample_report().to_html();
        assert!(html.contains("UCMJ Digital Evidence Examination Report"));
        assert!(html.contains("DD Form 2922"));
        assert!(html.contains("Jurisdiction and Authority"));
        assert!(html.contains("Findings"));
        assert!(html.contains("Examiner Certification"));
    }

    #[test]
    fn to_html_renders_case_number_and_classification_banner() {
        let html = sample_report().to_html();
        assert!(html.contains("CID-2026-0001"));
        assert_eq!(html.matches("UNCLASSIFIED").count(), 2);
    }

    #[test]
    fn html_escape_escapes_special_chars() {
        assert_eq!(html_escape("<&>\""), "&lt;&amp;&gt;&quot;");
    }

    #[test]
    fn article_catalogue_covers_core_articles() {
        let titles: Vec<&str> = UCMJ_ARTICLES.iter().map(|(a, _)| *a).collect();
        assert!(titles.contains(&"Article 120"));
        assert!(titles.contains(&"Article 134"));
    }

    #[test]
    fn to_html_includes_artifact_summary_row() {
        let html = sample_report().to_html();
        assert!(html.contains("iMessage"));
        assert!(html.contains("T1636.002"));
    }
}
