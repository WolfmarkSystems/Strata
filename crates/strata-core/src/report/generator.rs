use super::html::court_ready_inline_css;
use crate::errors::ForensicError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub struct ReportGenerator;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CourtReadyReportInput {
    pub case_id: String,
    pub examiner: String,
    pub evidence_source_path: String,
    pub sha256_hash: Option<String>,
    pub hash_verified: bool,
    pub first_loaded_utc: Option<String>,
    pub total_files_indexed: usize,
    pub total_artifacts_extracted: usize,
    pub timeline_event_count: usize,
    pub notable_items_count: usize,
}

impl CourtReadyReportInput {
    pub fn new(case_id: &str, examiner: &str) -> Self {
        Self {
            case_id: case_id.to_string(),
            examiner: examiner.to_string(),
            ..Self::default()
        }
    }
}

impl Default for ReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl ReportGenerator {
    pub fn new() -> Self {
        Self
    }

    /// Compile a court-ready HTML report with examiner, integrity, methodology,
    /// limitations, and signature placeholder sections.
    pub fn generate_html_report(
        &self,
        case_name: &str,
        findings: &[u8],
    ) -> Result<String, ForensicError> {
        let generated_at = Utc::now().to_rfc3339();
        let parsed = parse_findings(findings);
        let examiner = parsed.examiner.clone().unwrap_or_default();
        let evidence_sources = if parsed.evidence_sources.is_empty() {
            vec![fallback_evidence_source(findings)]
        } else {
            parsed.evidence_sources.clone()
        };

        let chain_status = parsed
            .chain_verification
            .as_ref()
            .map(|chain| chain.status.clone())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "not_provided".to_string());

        let chain_details = parsed
            .chain_verification
            .as_ref()
            .and_then(|chain| chain.details.as_deref())
            .and_then(non_empty)
            .unwrap_or_else(|| "No chain-of-custody verification details provided.".to_string());

        let chain_last_verified = parsed
            .chain_verification
            .as_ref()
            .and_then(|chain| chain.last_verified_utc.as_deref())
            .and_then(normalize_rfc3339)
            .unwrap_or_else(|| generated_at.clone());

        let methodology = parsed.methodology.clone().unwrap_or_default();
        let tool_name =
            non_empty(&methodology.tool_name).unwrap_or_else(|| env!("CARGO_PKG_NAME").to_string());
        let tool_version = non_empty(&methodology.tool_version)
            .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());
        let parsing_methodology =
            non_empty(&methodology.parsing_methodology).unwrap_or_else(|| {
                "Structured artifact parsing with read-only evidence access.".to_string()
            });

        let mut limitations = methodology.limitations.clone();
        limitations.extend(parsed.limitations.clone());
        limitations.retain(|value| !value.trim().is_empty());
        limitations.sort();
        limitations.dedup();
        if limitations.is_empty() {
            limitations.push(
                "Scope is limited to acquired evidence, configured modules, and parser coverage at run time."
                    .to_string(),
            );
        }

        let findings_summary = parsed
            .findings_summary
            .clone()
            .or_else(|| non_empty(&parsed.raw_text))
            .unwrap_or_else(|| "No findings summary provided.".to_string());

        let examiner_name = non_empty(&examiner.name).unwrap_or_else(|| "Unassigned".to_string());
        let examiner_title = non_empty(&examiner.title).unwrap_or_else(|| "Examiner".to_string());
        let examiner_agency =
            non_empty(&examiner.agency).unwrap_or_else(|| "Unknown Agency".to_string());
        let examiner_case_number =
            non_empty(&examiner.case_number).unwrap_or_else(|| case_name.to_string());
        let examiner_report_date = examiner
            .report_date_utc
            .as_deref()
            .and_then(normalize_rfc3339)
            .unwrap_or_else(|| generated_at.clone());

        let evidence_integrity_rows = evidence_sources
            .iter()
            .map(|source| {
                format!(
                    "<tr>\
                        <td>{}</td>\
                        <td>{}</td>\
                        <td class=\"mono\">{}</td>\
                        <td class=\"mono\">{}</td>\
                        <td class=\"mono\">{}</td>\
                        <td class=\"mono\">{}</td>\
                        <td>{}</td>\
                    </tr>",
                    html_escape(&source.name),
                    html_escape(&source.path),
                    html_escape(&display_hash(&source.md5)),
                    html_escape(&display_hash(&source.sha1)),
                    html_escape(&display_hash(&source.sha256)),
                    html_escape(&display_hash(&source.blake3)),
                    html_escape(
                        &source
                            .chain_link
                            .clone()
                            .unwrap_or_else(|| "not_provided".to_string())
                    ),
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        let methodology_list = limitations
            .iter()
            .map(|item| format!("<li>{}</li>", html_escape(item)))
            .collect::<Vec<_>>()
            .join("\n");

        let findings_digest = sha256_hex(findings);
        let signature_key_id =
            std::env::var("FORENSIC_REPORT_KEY_ID").unwrap_or_else(|_| "UNASSIGNED".to_string());
        let signature_key = std::env::var("FORENSIC_REPORT_HMAC_KEY")
            .unwrap_or_else(|_| "PLACEHOLDER_KEY".to_string());

        let canonical_signature_payload = format!(
            "case_name={}\ncase_number={}\ngenerated_at={}\nfindings_sha256={}\nchain_status={}",
            case_name, examiner_case_number, generated_at, findings_digest, chain_status
        );
        let signature = hmac_sha256_hex(
            signature_key.as_bytes(),
            canonical_signature_payload.as_bytes(),
        );
        let placeholder_mode = signature_key == "PLACEHOLDER_KEY";

        let sections = [(
                "examiner-information".to_string(),
                "Examiner Information".to_string(),
                format!(
                    "<p><strong>Examiner Name:</strong> {}</p>\
                     <p><strong>Title:</strong> {}</p>\
                     <p><strong>Agency:</strong> {}</p>\
                     <p><strong>Case Number:</strong> {}</p>\
                     <p><strong>Report Date (ISO 8601):</strong> {}</p>",
                    html_escape(&examiner_name),
                    html_escape(&examiner_title),
                    html_escape(&examiner_agency),
                    html_escape(&examiner_case_number),
                    html_escape(&examiner_report_date),
                ),
            ),
            (
                "evidence-integrity".to_string(),
                "Evidence Integrity".to_string(),
                format!(
                    "<p><strong>Chain Verification Status:</strong> {}</p>\
                     <p><strong>Chain Verification Details:</strong> {}</p>\
                     <p><strong>Last Verified (ISO 8601):</strong> {}</p>\
                     <table>\
                       <thead>\
                         <tr>\
                           <th>Source</th>\
                           <th>Path</th>\
                           <th>MD5</th>\
                           <th>SHA1</th>\
                           <th>SHA256</th>\
                           <th>BLAKE3</th>\
                           <th>Chain Link</th>\
                         </tr>\
                       </thead>\
                       <tbody>{}</tbody>\
                     </table>",
                    html_escape(&chain_status),
                    html_escape(&chain_details),
                    html_escape(&chain_last_verified),
                    evidence_integrity_rows
                ),
            ),
            (
                "methodology".to_string(),
                "Methodology".to_string(),
                format!(
                    "<p><strong>Tool:</strong> {} v{}</p>\
                     <p><strong>Parsing Methodology:</strong> {}</p>\
                     <p><strong>Limitations:</strong></p>\
                     <ul>{}</ul>",
                    html_escape(&tool_name),
                    html_escape(&tool_version),
                    html_escape(&parsing_methodology),
                    methodology_list
                ),
            ),
            (
                "findings-summary".to_string(),
                "Findings Summary".to_string(),
                format!("<p>{}</p>", html_escape(&findings_summary)),
            ),
            (
                "digital-signature".to_string(),
                "Digital Signature Placeholder".to_string(),
                format!(
                    "<p><strong>Signature Algorithm:</strong> HMAC-SHA256</p>\
                     <p><strong>Key ID:</strong> {}</p>\
                     <p><strong>Placeholder Mode:</strong> {}</p>\
                     <p><strong>Signature:</strong> <span class=\"mono\">{}</span></p>\
                     <p><strong>Signed Content Digest (SHA256):</strong> <span class=\"mono\">{}</span></p>\
                     <p><strong>Generated At (ISO 8601):</strong> {}</p>",
                    html_escape(&signature_key_id),
                    if placeholder_mode { "true" } else { "false" },
                    html_escape(&signature),
                    html_escape(&findings_digest),
                    html_escape(&generated_at)
                ),
            )];

        let toc_items = sections
            .iter()
            .enumerate()
            .map(|(index, (id, title, _))| {
                format!(
                    "<li><a href=\"#{}\">{}. {}</a></li>",
                    id,
                    index + 1,
                    html_escape(title)
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        let section_blocks = sections
            .iter()
            .enumerate()
            .map(|(index, (id, title, body))| {
                format!(
                    "<section id=\"{}\" class=\"report-section\">\
                        <h2>{}. {}</h2>\
                        <div class=\"section-body\">{}</div>\
                        <div class=\"page-footer\">Page {}</div>\
                     </section>",
                    id,
                    index + 1,
                    html_escape(title),
                    body,
                    index + 2
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        let html = format!(
            "<!DOCTYPE html>\
             <html lang=\"en\">\
             <head>\
               <meta charset=\"UTF-8\">\
               <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\
               <title>{}</title>\
               <style>\
                 body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; background: #f4f6f8; color: #1f2a37; }}\
                 .container {{ max-width: 980px; margin: 24px auto; background: #ffffff; padding: 28px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.08); }}\
                 h1 {{ margin-top: 0; border-bottom: 3px solid #2457a5; padding-bottom: 10px; }}\
                 h2 {{ margin-top: 0; color: #1d3f72; }}\
                 .meta p {{ margin: 4px 0; }}\
                 .toc {{ background: #eef3fb; border: 1px solid #d3def0; border-radius: 6px; padding: 12px 16px; margin: 20px 0; }}\
                 .toc ol {{ margin: 0; padding-left: 18px; }}\
                 .report-section {{ margin-top: 24px; border-top: 1px solid #dce3ee; padding-top: 20px; }}\
                 table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}\
                 th, td {{ border: 1px solid #d6dde8; padding: 8px; text-align: left; vertical-align: top; }}\
                 th {{ background: #f0f4fb; }}\
                 .mono {{ font-family: Consolas, 'Courier New', monospace; font-size: 12px; word-break: break-all; }}\
                 .page-footer {{ margin-top: 16px; font-size: 12px; color: #5f6b7a; text-align: right; }}\
               </style>\
             </head>\
             <body>\
               <div class=\"container\">\
                 <h1>Court-Ready Forensic Report</h1>\
                 <div class=\"meta\">\
                   <p><strong>Case:</strong> {}</p>\
                   <p><strong>Generated (ISO 8601):</strong> {}</p>\
                   <p><strong>Page 1</strong></p>\
                 </div>\
                 <section class=\"toc\" id=\"table-of-contents\">\
                   <h2>Table of Contents</h2>\
                   <ol>{}</ol>\
                 </section>\
                 {}\
               </div>\
             </body>\
             </html>",
            html_escape(case_name),
            html_escape(case_name),
            html_escape(&generated_at),
            toc_items,
            section_blocks
        );

        Ok(html)
    }

    pub fn generate_court_ready_report(
        &self,
        report: &CourtReadyReportInput,
    ) -> Result<String, ForensicError> {
        let generated_at = Utc::now().to_rfc3339();
        let examiner = non_empty(&report.examiner).unwrap_or_else(|| "Examiner".to_string());
        let evidence_source_path =
            non_empty(&report.evidence_source_path).unwrap_or_else(|| "Not available".to_string());
        let sha256_hash = report
            .sha256_hash
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("Not provided");
        let hash_verified = report.hash_verified && sha256_hash != "Not provided";
        let verification_status = if hash_verified {
            "VERIFIED"
        } else {
            "UNVERIFIED"
        };
        let verification_class = if hash_verified {
            "status-verified"
        } else {
            "status-unverified"
        };
        let first_loaded_utc = report
            .first_loaded_utc
            .as_deref()
            .and_then(normalize_rfc3339)
            .unwrap_or_else(|| "Not available".to_string());
        let limitations = "This report reflects the state of analysis at time of generation. Parsers marked Experimental may not capture all artifacts of their type. This tool does not modify evidence sources.";

        let html = format!(
            "<!DOCTYPE html>\
             <html lang=\"en\">\
             <head>\
               <meta charset=\"UTF-8\">\
               <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\
               <title>Digital Forensic Examination Report</title>\
               <style>{}</style>\
             </head>\
             <body>\
               <div class=\"report-shell\">\
                 <header class=\"report-header\">\
                   <h1>Digital Forensic Examination Report</h1>\
                   <div class=\"meta-grid\">\
                     <div class=\"meta-card\"><span class=\"meta-label\">Examiner</span><span class=\"meta-value\">{}</span></div>\
                     <div class=\"meta-card\"><span class=\"meta-label\">Case ID</span><span class=\"meta-value\">{}</span></div>\
                     <div class=\"meta-card\"><span class=\"meta-label\">Generated (UTC)</span><span class=\"meta-value\">{}</span></div>\
                     <div class=\"meta-card\"><span class=\"meta-label\">Report Version</span><span class=\"meta-value\">1.0</span></div>\
                   </div>\
                 </header>\
                 <section class=\"report-section\" id=\"evidence-integrity\">\
                   <h2>Evidence Integrity</h2>\
                   <table class=\"detail-table\">\
                     <tbody>\
                       <tr><th>Evidence source path</th><td>{}</td></tr>\
                       <tr><th>SHA-256 hash of evidence</th><td class=\"mono\">{}</td></tr>\
                       <tr><th>Hash verification status</th><td><span class=\"{}\">{}</span></td></tr>\
                       <tr><th>Date/time evidence was first loaded</th><td>{}</td></tr>\
                     </tbody>\
                   </table>\
                 </section>\
                 <section class=\"report-section\" id=\"methodology\">\
                   <h2>Methodology</h2>\
                   <table class=\"detail-table\">\
                     <tbody>\
                       <tr><th>Tool name</th><td>Strata Forensics</td></tr>\
                       <tr><th>Tool version</th><td>{}</td></tr>\
                       <tr><th>Analysis approach</th><td>Read-only examination of evidence container</td></tr>\
                       <tr><th>Parser maturity note</th><td>Results from Experimental parsers should be corroborated</td></tr>\
                     </tbody>\
                   </table>\
                 </section>\
                 <section class=\"report-section\" id=\"findings-summary\">\
                   <h2>Findings Summary</h2>\
                   <div class=\"summary-grid\">\
                     <div class=\"summary-card\"><span class=\"summary-label\">Total files indexed</span><div class=\"summary-value\">{}</div></div>\
                     <div class=\"summary-card\"><span class=\"summary-label\">Total artifacts extracted</span><div class=\"summary-value\">{}</div></div>\
                     <div class=\"summary-card\"><span class=\"summary-label\">Timeline event count</span><div class=\"summary-value\">{}</div></div>\
                     <div class=\"summary-card\"><span class=\"summary-label\">Notable items count</span><div class=\"summary-value\">{}</div></div>\
                   </div>\
                 </section>\
                 <section class=\"report-section\" id=\"limitations\">\
                   <h2>Limitations</h2>\
                   <div class=\"limitations\">{}</div>\
                 </section>\
                 <section class=\"report-section\" id=\"signature-placeholder\">\
                   <h2>Signature Placeholder</h2>\
                   <p class=\"signature-line\">Examiner Signature: _______________________</p>\
                   <p class=\"signature-line\">Date: _______________________</p>\
                 </section>\
               </div>\
             </body>\
             </html>",
            court_ready_inline_css(),
            html_escape(&examiner),
            html_escape(&report.case_id),
            html_escape(&generated_at),
            html_escape(&evidence_source_path),
            html_escape(sha256_hash),
            verification_class,
            verification_status,
            html_escape(&first_loaded_utc),
            html_escape(env!("CARGO_PKG_VERSION")),
            report.total_files_indexed,
            report.total_artifacts_extracted,
            report.timeline_event_count,
            report.notable_items_count,
            html_escape(limitations)
        );

        Ok(html)
    }
    /// PDF export is currently represented as encoded HTML bytes for downstream renderers.
    pub fn generate_pdf_report(
        &self,
        case_name: &str,
        findings: &[u8],
    ) -> Result<Vec<u8>, ForensicError> {
        let html = self.generate_html_report(case_name, findings)?;
        Ok(html.into_bytes())
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
struct ReportFindingsInput {
    #[serde(default)]
    examiner: Option<ExaminerInfo>,
    #[serde(default)]
    evidence_sources: Vec<EvidenceSource>,
    #[serde(default)]
    methodology: Option<MethodologyInfo>,
    #[serde(default)]
    findings_summary: Option<String>,
    #[serde(default)]
    limitations: Vec<String>,
    #[serde(default)]
    chain_verification: Option<ChainVerification>,
    #[serde(default)]
    raw_text: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct ExaminerInfo {
    #[serde(default)]
    name: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    agency: String,
    #[serde(default)]
    case_number: String,
    #[serde(default)]
    report_date_utc: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct EvidenceSource {
    #[serde(default)]
    name: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    md5: Option<String>,
    #[serde(default)]
    sha1: Option<String>,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    blake3: Option<String>,
    #[serde(default)]
    chain_link: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct MethodologyInfo {
    #[serde(default)]
    tool_name: String,
    #[serde(default)]
    tool_version: String,
    #[serde(default)]
    parsing_methodology: String,
    #[serde(default)]
    limitations: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct ChainVerification {
    #[serde(default)]
    status: String,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    last_verified_utc: Option<String>,
}

fn parse_findings(findings: &[u8]) -> ReportFindingsInput {
    if let Ok(parsed) = serde_json::from_slice::<ReportFindingsInput>(findings) {
        return parsed;
    }

    let raw = String::from_utf8_lossy(findings).trim().to_string();
    ReportFindingsInput {
        findings_summary: if raw.is_empty() {
            None
        } else {
            Some(raw.clone())
        },
        raw_text: raw,
        ..ReportFindingsInput::default()
    }
}

fn fallback_evidence_source(findings: &[u8]) -> EvidenceSource {
    EvidenceSource {
        name: "findings_payload".to_string(),
        path: "in_memory".to_string(),
        md5: None,
        sha1: None,
        sha256: Some(sha256_hex(findings)),
        blake3: None,
        chain_link: Some("not_provided".to_string()),
    }
}

fn normalize_rfc3339(input: &str) -> Option<String> {
    let parsed = DateTime::parse_from_rfc3339(input).ok()?;
    Some(parsed.to_rfc3339())
}

fn non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn display_hash(value: &Option<String>) -> String {
    value
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
        .unwrap_or_else(|| "not_provided".to_string())
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    const BLOCK_SIZE: usize = 64;
    let mut working_key = if key.len() > BLOCK_SIZE {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.finalize().to_vec()
    } else {
        key.to_vec()
    };
    working_key.resize(BLOCK_SIZE, 0);

    let mut ipad = vec![0x36u8; BLOCK_SIZE];
    let mut opad = vec![0x5cu8; BLOCK_SIZE];
    for (dst, src) in ipad.iter_mut().zip(&working_key) {
        *dst ^= *src;
    }
    for (dst, src) in opad.iter_mut().zip(&working_key) {
        *dst ^= *src;
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(inner_digest);
    let digest = outer.finalize();
    digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_court_ready_sections_and_toc() {
        let generator = ReportGenerator::new();
        let findings = serde_json::json!({
            "examiner": {
                "name": "Alex Carter",
                "title": "Digital Forensic Examiner",
                "agency": "Strata Lab",
                "case_number": "CASE-2026-001",
                "report_date_utc": "2026-03-24T13:00:00-04:00"
            },
            "evidence_sources": [{
                "name": "Disk Image A",
                "path": "E:/evidence/imageA.E01",
                "sha256": "abc123"
            }],
            "methodology": {
                "tool_name": "Strata Shield",
                "tool_version": "0.1.0",
                "parsing_methodology": "Read-only forensic parsing.",
                "limitations": ["No live memory capture in this run."]
            },
            "findings_summary": "Suspicious persistence entries were detected.",
            "chain_verification": {
                "status": "verified",
                "details": "Hash chain validated through activity_log table.",
                "last_verified_utc": "2026-03-24T18:00:00Z"
            }
        });

        let html = generator
            .generate_html_report("CASE-2026-001", findings.to_string().as_bytes())
            .expect("generate html");

        assert!(html.contains("Table of Contents"));
        assert!(html.contains("Examiner Information"));
        assert!(html.contains("Evidence Integrity"));
        assert!(html.contains("Methodology"));
        assert!(html.contains("Digital Signature Placeholder"));
        assert!(html.contains("HMAC-SHA256"));
        assert!(html.contains("Page 1"));
    }

    #[test]
    fn generates_court_ready_html_with_required_sections() {
        let generator = ReportGenerator::new();
        let report = CourtReadyReportInput {
            case_id: "CASE-COURT-001".to_string(),
            examiner: "Jane Smith".to_string(),
            evidence_source_path: "D:/evidence/test123.E01".to_string(),
            sha256_hash: Some("abc123".to_string()),
            hash_verified: true,
            first_loaded_utc: Some("2026-03-26T14:00:00Z".to_string()),
            total_files_indexed: 42,
            total_artifacts_extracted: 11,
            timeline_event_count: 7,
            notable_items_count: 3,
        };

        let html = generator
            .generate_court_ready_report(&report)
            .expect("generate court ready html");

        assert!(html.contains("Digital Forensic Examination Report"));
        assert!(html.contains("Evidence Integrity"));
        assert!(html.contains("Methodology"));
        assert!(html.contains("Findings Summary"));
        assert!(html.contains("Limitations"));
        assert!(html.contains("Signature Placeholder"));
        assert!(html.contains("Results from Experimental parsers should be corroborated"));
    }

    #[test]
    fn pdf_report_returns_non_empty_placeholder_payload() {
        let generator = ReportGenerator::new();
        let out = generator
            .generate_pdf_report("CASE-TEST", b"raw findings")
            .expect("generate pdf bytes");
        assert!(!out.is_empty());
    }
}
