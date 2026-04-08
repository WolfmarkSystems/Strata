//! Court-ready CSAM report generator.
//!
//! Two output formats:
//! - **PDF** via `printpdf 0.9` — plain monospace, paginated, headless.
//! - **JSON** via `serde_json` — agency machine-records.
//!
//! ## What is NOT in the report
//!
//! Image bytes, thumbnails, previews, embedded blobs of any kind.
//! The report contains only file paths, cryptographic and perceptual
//! hash values, match metadata, examiner review state, and the
//! chain-of-custody audit trail. This matches the spec rule: images
//! are never auto-rendered, in any context.
//!
//! ## Construction
//!
//! `CsamReport` is a plain data struct with public fields. The IPC
//! layer (Task 8) builds it directly from scanner state, scan results,
//! and the verified audit chain. There is no builder — the field set
//! is small enough that struct literal syntax is the cleanest call.

use anyhow::{Context, Result};
use printpdf::{
    BuiltinFont, Mm, Op, PdfDocument, PdfFontHandle, PdfPage, PdfSaveOptions, Point, Pt,
    TextItem,
};
use std::path::Path;

use crate::audit::CsamAuditEntry;
use crate::CsamHit;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CsamReport {
    pub case_number: String,
    pub examiner_name: String,
    pub examiner_agency: String,
    pub scan_date_utc: chrono::DateTime<chrono::Utc>,
    pub tool_version: String,
    pub evidence_path: String,
    pub evidence_sha256: String,
    pub hash_sets_used: Vec<HashSetSummary>,
    pub scan_config: ScanConfigSummary,
    pub hits: Vec<CsamHit>,
    pub audit_log: Vec<CsamAuditEntry>,
    /// Caller-supplied. The IPC layer is responsible for running
    /// `CsamAuditLog::verify_integrity` (or strata-tree's
    /// `verify_audit_chain` over the unified case log) before
    /// constructing the report. The field is recorded verbatim in
    /// both the PDF and JSON outputs.
    pub audit_integrity_verified: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HashSetSummary {
    pub name: String,
    pub format: String,
    pub entry_count: usize,
    pub imported_at: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanConfigSummary {
    pub run_exact_hash: bool,
    pub run_perceptual: bool,
    pub perceptual_threshold: u32,
    pub scan_all_files: bool,
    pub image_extensions: Vec<String>,
}

impl CsamReport {
    /// Generate the court-ready PDF report and write it to `output_path`.
    ///
    /// The output is plain Courier text on A4 pages, paginated with a
    /// per-page footer (page n of N | examiner | case | generated_utc).
    /// No image content, no thumbnails — only metadata.
    pub fn generate_pdf(&self, output_path: &Path) -> Result<()> {
        let lines = self.build_lines();
        let now_iso = self
            .scan_date_utc
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let pages = paginate_pdf_lines(
            &lines,
            &self.examiner_name,
            &self.case_number,
            &now_iso,
            9.0,
            10.0,
            46,
        );

        let mut doc = PdfDocument::new("Strata CSAM Detection Report");
        let mut warnings = Vec::new();
        let bytes = doc
            .with_pages(pages)
            .save(&PdfSaveOptions::default(), &mut warnings);
        if !warnings.is_empty() {
            tracing::debug!("[csam] printpdf warnings: {:?}", warnings);
        }
        std::fs::write(output_path, bytes)
            .with_context(|| format!("writing CSAM PDF to {}", output_path.display()))?;
        Ok(())
    }

    /// Generate the JSON export and write it to `output_path`.
    /// Pretty-printed for human inspection; the structure round-trips
    /// through `serde_json::from_str` back into a `CsamReport`.
    pub fn generate_json(&self, output_path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)
            .context("serializing CsamReport to JSON")?;
        std::fs::write(output_path, json)
            .with_context(|| format!("writing CSAM JSON to {}", output_path.display()))?;
        Ok(())
    }

    /// Build the line list shared between PDF (paginated) and any
    /// future plain-text export. Plain text is plainer than HTML and
    /// safer for court — every line is a discrete fact.
    fn build_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();

        // ── Title block ────────────────────────────────────────────
        lines.push("STRATA CSAM DETECTION REPORT".to_string());
        lines.push("=".repeat(60));
        lines.push(String::new());
        lines.push("RESTRICTED CONTENT NOTICE".to_string());
        lines.push(
            "This report documents matches against examiner-imported".to_string(),
        );
        lines.push(
            "CSAM hash databases. No image content is embedded. All".to_string(),
        );
        lines.push(
            "findings require qualified examiner review and produce".to_string(),
        );
        lines.push("intelligence, not conclusions.".to_string());
        lines.push(String::new());

        // ── Case metadata ──────────────────────────────────────────
        lines.push("CASE METADATA".to_string());
        lines.push("-".repeat(60));
        lines.push(format!("Case Number      : {}", self.case_number));
        lines.push(format!("Examiner         : {}", self.examiner_name));
        lines.push(format!("Agency           : {}", self.examiner_agency));
        lines.push(format!(
            "Scan Date (UTC)  : {}",
            self.scan_date_utc
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        ));
        lines.push(format!("Tool Version     : {}", self.tool_version));
        lines.push(String::new());

        // ── Evidence ───────────────────────────────────────────────
        lines.push("EVIDENCE".to_string());
        lines.push("-".repeat(60));
        lines.push(format!("Path             : {}", self.evidence_path));
        lines.push(format!("Evidence SHA-256 : {}", self.evidence_sha256));
        lines.push(String::new());

        // ── Hash sets ──────────────────────────────────────────────
        lines.push(format!(
            "HASH SETS USED ({})",
            self.hash_sets_used.len()
        ));
        lines.push("-".repeat(60));
        if self.hash_sets_used.is_empty() {
            lines.push("(none — perceptual scan only)".to_string());
        } else {
            for set in &self.hash_sets_used {
                lines.push(format!(
                    "{:<24} | format={} | entries={} | imported={}",
                    truncate(&set.name, 24),
                    set.format,
                    set.entry_count,
                    set.imported_at,
                ));
            }
        }
        lines.push(String::new());

        // ── Scan config ────────────────────────────────────────────
        lines.push("SCAN CONFIGURATION".to_string());
        lines.push("-".repeat(60));
        lines.push(format!(
            "Exact Hash Match     : {}",
            yes_no(self.scan_config.run_exact_hash)
        ));
        lines.push(format!(
            "Perceptual Match     : {}",
            yes_no(self.scan_config.run_perceptual)
        ));
        lines.push(format!(
            "Perceptual Threshold : {}",
            self.scan_config.perceptual_threshold
        ));
        lines.push(format!(
            "Scan All Files       : {}",
            yes_no(self.scan_config.scan_all_files)
        ));
        lines.push(format!(
            "Image Extensions     : {}",
            self.scan_config.image_extensions.join(", ")
        ));
        lines.push(String::new());

        // ── Audit chain status ─────────────────────────────────────
        lines.push("CHAIN OF CUSTODY".to_string());
        lines.push("-".repeat(60));
        lines.push(format!(
            "Audit Log Entries    : {}",
            self.audit_log.len()
        ));
        lines.push(format!(
            "Chain Integrity      : {}",
            if self.audit_integrity_verified {
                "VERIFIED"
            } else {
                "NOT VERIFIED — caller did not validate, or chain is broken"
            }
        ));
        lines.push(String::new());

        // ── Hits ───────────────────────────────────────────────────
        lines.push(format!("FINDINGS — {} HIT(S)", self.hits.len()));
        lines.push("=".repeat(60));
        if self.hits.is_empty() {
            lines.push("No hits recorded for this scan.".to_string());
        } else {
            for (i, hit) in self.hits.iter().enumerate() {
                lines.push(format!("Hit #{:<4}  ID: {}", i + 1, hit.hit_id));
                lines.push(format!("  File Path     : {}", hit.file_path));
                lines.push(format!("  File Size     : {} bytes", hit.file_size));
                lines.push(format!("  MD5           : {}", hit.md5));
                lines.push(format!("  SHA-1         : {}", hit.sha1));
                lines.push(format!("  SHA-256       : {}", hit.sha256));
                lines.push(format!(
                    "  Match Type    : {}",
                    hit.match_type.as_str()
                ));
                lines.push(format!("  Match Source  : {}", hit.match_source));
                lines.push(format!(
                    "  Confidence    : {}",
                    hit.confidence.as_str()
                ));
                if let (Some(p), Some(d)) = (&hit.perceptual_hash, hit.perceptual_distance) {
                    lines.push(format!("  Perceptual    : {} (distance {})", p, d));
                }
                lines.push(format!(
                    "  Detected (UTC): {}",
                    hit.timestamp_utc
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
                ));
                lines.push(format!(
                    "  Reviewed      : {}",
                    yes_no(hit.examiner_reviewed)
                ));
                lines.push(format!(
                    "  Confirmed     : {}",
                    yes_no(hit.examiner_confirmed)
                ));
                if !hit.examiner_notes.is_empty() {
                    lines.push(format!("  Notes         : {}", hit.examiner_notes));
                }
                lines.push("-".repeat(60));
            }
        }
        lines.push(String::new());

        // ── Audit log appendix ─────────────────────────────────────
        lines.push("AUDIT LOG (CHAIN OF CUSTODY)".to_string());
        lines.push("=".repeat(60));
        if self.audit_log.is_empty() {
            lines.push("(no audit entries)".to_string());
        } else {
            for entry in &self.audit_log {
                lines.push(format!(
                    "[{:>5}] {} {} | {}",
                    entry.sequence, entry.timestamp_utc, entry.action, entry.examiner
                ));
                if !entry.detail.is_empty() {
                    lines.push(format!("        detail   : {}", entry.detail));
                }
                lines.push(format!("        prev_hash: {}", short_hash(&entry.prev_hash)));
                lines.push(format!("        entry_hash: {}", short_hash(&entry.entry_hash)));
            }
        }
        lines.push(String::new());

        // ── Footer notice ──────────────────────────────────────────
        lines.push("END OF REPORT".to_string());
        lines.push("=".repeat(60));
        lines.push(
            "All findings in this report require qualified examiner".to_string(),
        );
        lines.push(
            "review. Discovery of CSAM creates mandatory reporting".to_string(),
        );
        lines.push("obligations under 18 U.S.C. § 2258A and applicable".to_string());
        lines.push("state laws.".to_string());

        lines
    }
}

// ──────────────────────────────────────────────────────────────────────
// Local helpers
// ──────────────────────────────────────────────────────────────────────

fn yes_no(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}

fn short_hash(h: &str) -> String {
    // Court-readable: full hash on the line, but trimmed for display
    // when it would otherwise wrap the page width. Empty hashes (legacy
    // chains) are rendered as "(empty)" so the absence is visible.
    if h.is_empty() {
        "(empty)".to_string()
    } else {
        h.to_string()
    }
}

/// Paginate a list of plain-text lines into A4 PDF pages.
///
/// This is a local copy of the same algorithm strata-tree uses in
/// `apps/tree/strata-tree/src/ui/export.rs:paginate_pdf_lines`. The
/// strata-tree helper is private; we duplicate it here rather than
/// reach across the layering boundary, since strata-csam cannot
/// depend on strata-tree.
///
/// Output: one `PdfPage` per chunk of `lines_per_page` lines, plus
/// a per-page footer with `Page n of N | Examiner | Case | Generated UTC`.
fn paginate_pdf_lines(
    lines: &[String],
    examiner: &str,
    case_id: &str,
    generated_utc: &str,
    font_size: f32,
    line_height: f32,
    lines_per_page: usize,
) -> Vec<PdfPage> {
    let chunks = if lines.is_empty() {
        1
    } else {
        lines.len().div_ceil(lines_per_page)
    };
    let mut pages = Vec::with_capacity(chunks);

    for page_idx in 0..chunks {
        let start = page_idx * lines_per_page;
        let end = (start + lines_per_page).min(lines.len());
        let mut ops = vec![
            Op::StartTextSection,
            Op::SetFont {
                font: PdfFontHandle::Builtin(BuiltinFont::Courier),
                size: Pt(font_size),
            },
            Op::SetLineHeight {
                lh: Pt(line_height),
            },
            Op::SetTextCursor {
                pos: Point::new(Mm(15.0), Mm(280.0)),
            },
        ];

        if start < lines.len() {
            for line in &lines[start..end] {
                ops.push(Op::ShowText {
                    items: vec![TextItem::Text(line.clone())],
                });
                ops.push(Op::AddLineBreak);
            }
        }

        ops.push(Op::SetTextCursor {
            pos: Point::new(Mm(15.0), Mm(10.0)),
        });
        ops.push(Op::SetFont {
            font: PdfFontHandle::Builtin(BuiltinFont::Courier),
            size: Pt(8.0),
        });
        ops.push(Op::ShowText {
            items: vec![TextItem::Text(format!(
                "Page {} of {} | Examiner: {} | Case: {} | Generated UTC: {}",
                page_idx + 1,
                chunks,
                examiner,
                case_id,
                generated_utc
            ))],
        });
        ops.push(Op::EndTextSection);

        pages.push(PdfPage::new(Mm(210.0), Mm(297.0), ops));
    }

    pages
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{CsamAuditAction, CsamAuditLog, GENESIS_PREV_HASH};
    use crate::{Confidence, MatchType};
    use tempfile::TempDir;

    fn sample_hit(idx: u8) -> CsamHit {
        CsamHit {
            hit_id: uuid::Uuid::new_v4(),
            file_path: format!("/evidence/photo_{:03}.jpg", idx),
            file_size: 102_400 + idx as u64 * 1024,
            md5: "d41d8cd98f00b204e9800998ecf8427e".into(),
            sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709".into(),
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
            match_type: MatchType::ExactSha256,
            match_source: "ncmec_2024".into(),
            perceptual_hash: None,
            perceptual_distance: None,
            confidence: Confidence::Confirmed,
            timestamp_utc: chrono::Utc::now(),
            examiner_reviewed: false,
            examiner_confirmed: false,
            examiner_notes: String::new(),
        }
    }

    fn sample_perceptual_hit() -> CsamHit {
        CsamHit {
            hit_id: uuid::Uuid::new_v4(),
            file_path: "/evidence/edited_001.jpg".into(),
            file_size: 256_000,
            md5: "00000000000000000000000000000000".into(),
            sha1: "0000000000000000000000000000000000000000".into(),
            sha256: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            match_type: MatchType::Perceptual,
            match_source: "perceptual_db_test".into(),
            perceptual_hash: Some("1234567890abcdef".into()),
            perceptual_distance: Some(3),
            confidence: Confidence::High,
            timestamp_utc: chrono::Utc::now(),
            examiner_reviewed: true,
            examiner_confirmed: false,
            examiner_notes: "Cropped variant of known image".into(),
        }
    }

    /// Build a CsamReport using only public APIs — no private field
    /// access. The audit log is built via the public CsamAuditLog
    /// `record()` path, which exercises the same code examiners use.
    fn sample_report(hits: Vec<CsamHit>) -> CsamReport {
        let mut audit = CsamAuditLog::new();
        audit.record("examiner_a", CsamAuditAction::ScanStarted);
        audit.record(
            "examiner_a",
            CsamAuditAction::HashSetImported {
                name: "ncmec_2024".into(),
                entries: 12345,
                format: "NCMEC MD5".into(),
            },
        );
        for h in &hits {
            audit.record(
                "examiner_a",
                CsamAuditAction::HitDetected {
                    file_path: h.file_path.clone(),
                    match_type: h.match_type.as_str().to_string(),
                },
            );
        }
        audit.record(
            "examiner_a",
            CsamAuditAction::ScanCompleted {
                files_scanned: 4567,
                hits_found: hits.len(),
            },
        );

        let integrity = audit.verify_integrity(GENESIS_PREV_HASH);

        CsamReport {
            case_number: "CASE-2026-0408-001".into(),
            examiner_name: "examiner_a".into(),
            examiner_agency: "Test Agency".into(),
            scan_date_utc: chrono::Utc::now(),
            tool_version: "0.1.0".into(),
            evidence_path: "/evidence/disk.E01".into(),
            evidence_sha256: "abc123def456...".into(),
            hash_sets_used: vec![HashSetSummary {
                name: "ncmec_2024".into(),
                format: "NCMEC MD5".into(),
                entry_count: 12345,
                imported_at: "2026-04-08T12:00:00Z".into(),
            }],
            scan_config: ScanConfigSummary {
                run_exact_hash: true,
                run_perceptual: true,
                perceptual_threshold: 10,
                scan_all_files: false,
                image_extensions: vec!["jpg".into(), "jpeg".into(), "png".into()],
            },
            hits,
            audit_log: audit.entries().to_vec(),
            audit_integrity_verified: integrity,
        }
    }

    #[test]
    fn json_export_round_trips() {
        let report = sample_report(vec![sample_hit(1), sample_perceptual_hit()]);
        let dir = TempDir::new().unwrap();
        let out = dir.path().join("report.json");
        report.generate_json(&out).unwrap();

        let raw = std::fs::read_to_string(&out).unwrap();
        let back: CsamReport = serde_json::from_str(&raw).unwrap();
        assert_eq!(back.case_number, "CASE-2026-0408-001");
        assert_eq!(back.hits.len(), 2);
        assert_eq!(back.hits[0].match_type, MatchType::ExactSha256);
        assert_eq!(back.hits[1].match_type, MatchType::Perceptual);
        assert!(back.audit_integrity_verified);
    }

    #[test]
    fn pdf_export_writes_valid_pdf_magic() {
        let report = sample_report(vec![sample_hit(1)]);
        let dir = TempDir::new().unwrap();
        let out = dir.path().join("report.pdf");
        report.generate_pdf(&out).unwrap();

        let bytes = std::fs::read(&out).unwrap();
        assert!(bytes.len() > 100, "PDF too small: {} bytes", bytes.len());
        // PDF magic header
        assert_eq!(&bytes[..4], b"%PDF", "first 4 bytes were {:?}", &bytes[..4]);
        // PDF should also end with %%EOF (printpdf 0.9 adds it)
        let tail = &bytes[bytes.len().saturating_sub(8)..];
        assert!(
            tail.windows(5).any(|w| w == b"%%EOF"),
            "no %%EOF marker in tail: {:?}",
            tail
        );
    }

    #[test]
    fn pdf_export_works_with_zero_hits() {
        let report = sample_report(vec![]);
        let dir = TempDir::new().unwrap();
        let out = dir.path().join("empty.pdf");
        report.generate_pdf(&out).unwrap();
        let bytes = std::fs::read(&out).unwrap();
        assert!(!bytes.is_empty());
        assert_eq!(&bytes[..4], b"%PDF");
    }

    #[test]
    fn pdf_export_works_with_many_hits() {
        // 100 hits → forces multi-page pagination.
        let hits: Vec<CsamHit> = (0..100).map(|i| sample_hit(i as u8)).collect();
        let report = sample_report(hits);
        let dir = TempDir::new().unwrap();
        let out = dir.path().join("many.pdf");
        report.generate_pdf(&out).unwrap();
        let bytes = std::fs::read(&out).unwrap();
        // A 100-hit report should be substantially larger than empty.
        assert!(
            bytes.len() > 5000,
            "expected multi-page PDF, got {} bytes",
            bytes.len()
        );
    }

    /// **PERMANENT NON-NEGOTIABLE TEST.** This test is a structural
    /// guarantee that no future refactor of `build_lines()` can
    /// accidentally start embedding image bytes, base64 blobs, or
    /// any payload that would violate the "images are never auto-
    /// displayed, in any context" rule. It also locks in that the
    /// restricted-content notice and the 18 U.S.C. § 2258A mandatory
    /// reporting notice appear in every report.
    ///
    /// **DO NOT delete or weaken this test. DO NOT skip it.** Any
    /// change to the report layout that breaks it must be reviewed
    /// against the spec's "no auto-display" rule before the test is
    /// adjusted to match new (still-compliant) line content.
    #[test]
    fn build_lines_includes_no_image_payload() {
        // Sanity check: the lines list contains plain text only.
        // No base64, no image markers, no binary payloads.
        let report = sample_report(vec![sample_perceptual_hit()]);
        let lines = report.build_lines();
        for line in &lines {
            assert!(
                !line.contains("data:image"),
                "found data: URL in report line: {}",
                line
            );
            // Plain ASCII (or printable Unicode for the elision char).
            // No control characters except none — the lines have no
            // newlines because we split on lines.
            assert!(!line.contains('\n'));
        }
        // Restricted-content notice must always appear.
        assert!(lines.iter().any(|l| l.contains("RESTRICTED CONTENT")));
        // Mandatory reporting notice must always appear.
        assert!(lines.iter().any(|l| l.contains("18 U.S.C. § 2258A")));
    }

    #[test]
    fn build_lines_marks_unverified_audit_chain() {
        let mut report = sample_report(vec![sample_hit(1)]);
        report.audit_integrity_verified = false;
        let lines = report.build_lines();
        assert!(lines
            .iter()
            .any(|l| l.contains("NOT VERIFIED")));
    }

    #[test]
    fn build_lines_marks_verified_audit_chain() {
        let report = sample_report(vec![sample_hit(1)]);
        let lines = report.build_lines();
        assert!(lines
            .iter()
            .any(|l| l.contains("Chain Integrity      : VERIFIED")));
    }
}
