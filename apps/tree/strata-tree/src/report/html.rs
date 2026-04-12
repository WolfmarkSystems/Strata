// report/html.rs — Court-ready HTML case report generator.
// Self-contained single HTML file with inline CSS — no CDN dependency.
// All timestamps in UTC. Report is read-only from within Tree.

use anyhow::Result;
use std::path::Path;
use crate::state::AppState;

/// Generate the complete 8-section court-ready HTML report.
pub fn generate_html_report(state: &AppState, output_path: &Path) -> Result<()> {
    let case_name    = state.case_name().to_string();
    let examiner     = state.examiner_name().to_string();
    let generated    = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let version      = env!("CARGO_PKG_VERSION");

    // Section 3 stats.
    let total_files  = state.file_index.iter().filter(|f| !f.is_dir).count();
    let deleted      = state.file_index.iter().filter(|f| f.is_deleted).count();
    let known_bad    = state.file_index.iter()
                           .filter(|f| f.hash_flagged.as_deref() == Some("KnownBad"))
                           .count();

    // Section 2 — evidence sources.
    let evidence_rows: String = state.evidence_sources.iter().map(|s| {
        format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            escape_html(&s.path),
            escape_html(&s.format),
            s.sha256.as_deref().unwrap_or("—"),
            if s.hash_verified { "✓ VERIFIED" } else { "UNVERIFIED" },
            escape_html(&s.loaded_utc),
        )
    }).collect();

    // Section 4 — bookmarks, grouped by color.
    let bookmark_rows: String = {
        let mut rows = String::new();
        for color in &["Critical", "Notable", "Cleared", "Reference"] {
            for bm in state.bookmarks.iter().filter(|b| b.color.as_deref() == Some(color)) {
                let file = state.file_index.iter().find(|f| f.id == bm.file_id);
                let path = file.map(|f| f.path.as_str()).unwrap_or("—");
                let sha  = file.and_then(|f| f.sha256.as_deref()).unwrap_or("—");
                let sz   = file.and_then(|f| f.size).map(|s| format!("{}", s)).unwrap_or_else(|| "—".to_string());
                rows.push_str(&format!(
                    "<tr><td class=\"bm-{lc}\">{color}</td><td>{label}</td><td>{path}</td><td>{sz}</td><td>{sha}</td><td>{note}</td></tr>\n",
                    lc    = color.to_lowercase(),
                    color = color,
                    label = escape_html(bm.label.as_deref().unwrap_or("—")),
                    path  = escape_html(path),
                    sz    = sz,
                    sha   = sha,
                    note  = escape_html(bm.note.as_deref().unwrap_or("—")),
                ));
            }
        }
        rows
    };

    // Section 5 — search results.
    let search_rows: String = state.search_results.iter().take(50).map(|h| {
        let file_path = state.file_index.iter()
            .find(|f| f.id == h.file_id)
            .map(|f| f.path.as_str())
            .unwrap_or("—");
        format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            escape_html(&h.query),
            escape_html(h.context.as_deref().unwrap_or("—")),
            escape_html(file_path),
        )
    }).collect();

    // Appendix — Activity Log (Gap 14). Show first 200 rows; note overflow.
    let audit_rows: String = state.audit_log.iter().take(200).map(|e| {
        format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            escape_html(&e.timestamp_utc),
            escape_html(&e.examiner),
            escape_html(&e.action),
            escape_html(e.detail.as_deref().unwrap_or("—")),
        )
    }).collect();

    let audit_overflow = if state.audit_log.len() > 200 {
        format!(
            "<p class=\"notice\">[{} additional entries available in the .vtp case file]</p>",
            state.audit_log.len() - 200
        )
    } else {
        String::new()
    };

    let audit_section = if state.audit_log.is_empty() {
        "<p>No activity recorded during this examination.</p>".to_string()
    } else {
        format!(
            "<table><tr><th>Timestamp (UTC)</th><th>Examiner</th><th>Action</th><th>Detail</th></tr>{}</table>{}",
            audit_rows, audit_overflow,
        )
    };

    let html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width">
<title>Strata — Case Report: {case_name}</title>
<style>
* {{ box-sizing: border-box; }}
body {{ font-family: 'Courier New', monospace; margin: 2em auto; max-width: 1200px;
        background: #fff; color: #111; font-size: 13px; }}
h1 {{ font-size: 1.6em; border-bottom: 3px solid #111; padding-bottom: 0.3em; }}
h2 {{ font-size: 1.2em; border-bottom: 1px solid #999; margin-top: 2em; background: #f5f5f5;
      padding: 0.3em 0.5em; }}
table {{ border-collapse: collapse; width: 100%; margin: 0.5em 0; }}
th, td {{ border: 1px solid #ccc; padding: 5px 8px; text-align: left; vertical-align: top; }}
th {{ background: #e8e8e8; font-weight: bold; }}
tr:nth-child(even) {{ background: #fafafa; }}
.critical {{ color: #c00; font-weight: bold; }}
.notice   {{ color: #850; }}
.bm-critical {{ color: #c00; font-weight: bold; }}
.bm-notable  {{ color: #a60; font-weight: bold; }}
.bm-cleared  {{ color: #060; }}
.bm-reference {{ color: #06a; }}
.footer {{ margin-top: 3em; border-top: 1px solid #ccc; padding-top: 1em; color: #666; font-size: 11px; }}
.attest {{ border: 2px solid #111; padding: 1em; margin: 1em 0; }}
</style>
</head>
<body>
{trial_watermark}
<h1>Strata — Digital Forensic Examination Report</h1>

<h2>Section 1 — Case Header</h2>
<table>
<tr><th>Case Name</th><td>{case_name}</td></tr>
<tr><th>Examiner</th><td>{examiner}</td></tr>
<tr><th>Report Generated (UTC)</th><td>{generated}</td></tr>
<tr><th>Tool</th><td>Strata v{version}</td></tr>
</table>

{charges_section}

{summary_section}

<h2>Section 2 — Evidence Integrity</h2>
<table>
<tr><th>Source Path</th><th>Format</th><th>SHA-256</th><th>Verification</th><th>Loaded (UTC)</th></tr>
{evidence_rows}
</table>

<h2>Section 3 — Examination Summary</h2>
<table>
<tr><th>Total Files Indexed</th><td>{total_files}</td></tr>
<tr><th>Deleted Files Found</th><td>{deleted}</td></tr>
<tr><th>Known-Bad Hash Matches</th><td class="{bad_class}">{known_bad}</td></tr>
<tr><th>Search Queries Performed</th><td>{search_count}</td></tr>
<tr><th>Bookmarks Created</th><td>{bm_count}</td></tr>
</table>

<h2>Section 4 — Notable Files (Bookmarks)</h2>
{bm_section}

<h2>Section 5 — Search Results</h2>
{search_section}

<h2>Section 6 — Findings Summary</h2>
<table>
<tr><th>Finding</th><th>Detail</th></tr>
{findings_rows}
</table>
{findings_note}

<h2>Section 7 — Methodology</h2>
<table>
<tr><th>Tool Name</th><td>Strata</td></tr>
<tr><th>Tool Version</th><td>v{version}</td></tr>
<tr><th>Analysis Approach</th><td>Read-only examination of evidence container</td></tr>
<tr><th>Hash Algorithms Used</th><td>MD5, SHA-256</td></tr>
</table>

<div class="attest">
<strong>Examiner Attestation</strong><br><br>
I, <strong>{examiner}</strong>, attest that this report accurately reflects my examination
of the evidence described above. All analysis was conducted using read-only access to
the evidence. No evidence was modified during this examination.<br><br>
Signature: _____________________________ &nbsp;&nbsp; Date: _______________________
</div>

<h2>Section 8 — Chain of Custody</h2>
<table>
<tr><th>Item</th><th>Value</th></tr>
<tr><td>Audit Log Entries</td><td>{audit_count}</td></tr>
<tr><td>Chain Integrity</td><td>{chain_status}</td></tr>
<tr><td>First Action</td><td>{first_action}</td></tr>
<tr><td>Last Action</td><td>{last_action}</td></tr>
</table>
<p>The audit log uses SHA-256 hash chaining. Each entry's hash is computed from
the previous entry's hash concatenated with the current entry's content. Any
modification to any log entry will break the chain and be detectable.
The complete audit log is stored in the .vtp case file.</p>

<h2>Section 9 — Limitations</h2>
<ul>
<li>This tool does not modify evidence sources. All evidence access is read-only.</li>
<li>Some filesystem parsers are experimental and may return incomplete results. Verify all findings independently.</li>
<li>Hash values are provided for integrity verification. Algorithm is noted alongside every value.</li>
<li>AI-assisted analysis features, where used, are advisory only and must be reviewed by the examiner.</li>
</ul>

<h2>Section 10 — Glossary</h2>
<table>
<tr><th>Term</th><th>Definition</th></tr>
<tr><td>SHA-256</td><td>Secure Hash Algorithm (256-bit). Cryptographic hash function used to verify file integrity.</td></tr>
<tr><td>MD5</td><td>Message Digest Algorithm 5. Hash function used for file identification (not collision-resistant).</td></tr>
<tr><td>MFT</td><td>Master File Table. NTFS filesystem metadata structure containing file records.</td></tr>
<tr><td>EVTX</td><td>Windows Event Log format (XML-based binary log).</td></tr>
<tr><td>Known-Bad</td><td>A file whose hash matches a database of known malicious or contraband files.</td></tr>
<tr><td>Known-Good</td><td>A file whose hash matches the NIST NSRL database of legitimate software.</td></tr>
<tr><td>Carving</td><td>Recovery of files from raw disk data using file signature (magic byte) detection.</td></tr>
<tr><td>Chain of Custody</td><td>Documented sequence of custody, control, and handling of evidence.</td></tr>
<tr><td>Timestomping</td><td>Anti-forensic technique of modifying file timestamps to evade detection.</td></tr>
<tr><td>VTP</td><td>Strata Project file. SQLite database containing case metadata, file index, and audit log.</td></tr>
</table>

<h2>Appendix — Activity Log</h2>
<p>The complete examiner activity log is stored in the .vtp case file (append-only).
It cannot be deleted or modified from within Strata.</p>
{audit_section}

<div class="footer">
Generated by Strata v{version} &nbsp;|&nbsp; {generated} UTC &nbsp;|&nbsp;
Examiner: {examiner} &nbsp;|&nbsp; This report is self-contained. No external resources required.
</div>
</body>
</html>
"#,
        case_name    = escape_html(&case_name),
        examiner     = escape_html(&examiner),
        generated    = generated,
        version      = version,
        evidence_rows = evidence_rows,
        total_files  = total_files,
        deleted      = deleted,
        known_bad    = known_bad,
        bad_class    = if known_bad > 0 { "critical" } else { "" },
        search_count = state.search_results.len(),
        bm_count     = state.bookmarks.len(),
        bm_section   = if state.bookmarks.is_empty() {
            "<p>No bookmarks recorded during this examination.</p>".to_string()
        } else {
            format!("<table><tr><th>Category</th><th>Label</th><th>Path</th><th>Size</th><th>SHA-256</th><th>Note</th></tr>{}</table>", bookmark_rows)
        },
        audit_section  = audit_section,
        search_section = if state.search_results.is_empty() {
            "<p>No searches performed during this examination.</p>".to_string()
        } else {
            format!("<table><tr><th>Query</th><th>Match Context</th><th>File Path</th></tr>{}</table>", search_rows)
        },
        findings_rows = generate_findings_rows(state),
        findings_note = if known_bad > 0 {
            "<p class=\"critical\">⚠ Known-bad hash matches detected. See bookmarks for details.</p>".to_string()
        } else {
            String::new()
        },
        audit_count = state.audit_log.len(),
        chain_status = {
            let result = crate::state::verify_audit_chain(&state.audit_log);
            if result.valid { "✓ INTACT — All entries verified" } else { "✗ BROKEN — Chain integrity compromised" }
        },
        trial_watermark = if state.license_state.is_trial {
            "<div style=\"background:#c00;color:#fff;text-align:center;padding:12px;font-size:16px;font-weight:bold;margin-bottom:20px;\">⚠ TRIAL LICENSE — NOT FOR OFFICIAL USE ⚠</div>".to_string()
        } else {
            String::new()
        },
        charges_section = generate_charges_html(state),
        summary_section = crate::ui::summary_view::format_summary_html(state),
        first_action = state.audit_log.first()
            .map(|e| format!("{} — {}", e.timestamp_utc, e.action))
            .unwrap_or_else(|| "N/A".to_string()),
        last_action = state.audit_log.last()
            .map(|e| format!("{} — {}", e.timestamp_utc, e.action))
            .unwrap_or_else(|| "N/A".to_string()),
    );

    std::fs::write(output_path, html)?;
    Ok(())
}

fn generate_findings_rows(state: &AppState) -> String {
    let mut rows = String::new();

    // Known-bad files
    let known_bad_files: Vec<_> = state.file_index.iter()
        .filter(|f| f.hash_flag.as_deref() == Some("KnownBad"))
        .collect();
    if !known_bad_files.is_empty() {
        rows.push_str(&format!(
            "<tr><td class=\"critical\">Known-Bad Hash Matches</td><td>{} file(s) matched known malicious hashes</td></tr>\n",
            known_bad_files.len()
        ));
    }

    // Deleted files
    let deleted_count = state.file_index.iter().filter(|f| f.is_deleted).count();
    if deleted_count > 0 {
        rows.push_str(&format!(
            "<tr><td>Deleted Files Recovered</td><td>{} deleted file(s) identified in unallocated space</td></tr>\n",
            deleted_count
        ));
    }

    // Bookmarks by category
    for category in &["Critical", "Notable"] {
        let count = state.bookmarks.iter().filter(|b| b.color.as_deref() == Some(category)).count();
        if count > 0 {
            rows.push_str(&format!(
                "<tr><td>{} Bookmarks</td><td>{} item(s) marked as {}</td></tr>\n",
                category, count, category.to_lowercase()
            ));
        }
    }

    // Search hits
    if !state.search_results.is_empty() {
        rows.push_str(&format!(
            "<tr><td>Search Results</td><td>{} hit(s) from examiner queries</td></tr>\n",
            state.search_results.len()
        ));
    }

    // Carved files
    let carved_count = state.file_index.iter().filter(|f| f.is_carved).count();
    if carved_count > 0 {
        rows.push_str(&format!(
            "<tr><td>Carved Files</td><td>{} file(s) recovered via carving</td></tr>\n",
            carved_count
        ));
    }

    if rows.is_empty() {
        rows.push_str("<tr><td>No Findings</td><td>No notable items identified during this examination.</td></tr>\n");
    }

    rows
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
}

fn generate_charges_html(state: &AppState) -> String {
    if state.selected_charges.charges.is_empty() {
        return String::new();
    }

    let mut html = String::from(
        "<h2>CHARGES UNDER INVESTIGATION</h2>\n\
         <p>The following charges have been identified as relevant to this examination. \
         Digital evidence recovered during this examination should be evaluated in the \
         context of these statutes.</p>\n",
    );

    let usc: Vec<_> = state.selected_charges.charges.iter()
        .filter(|c| c.code_set == strata_charges::ChargeSet::USC)
        .collect();
    let ucmj: Vec<_> = state.selected_charges.charges.iter()
        .filter(|c| c.code_set == strata_charges::ChargeSet::UCMJ)
        .collect();

    if !usc.is_empty() {
        html.push_str("<h3>Federal Charges (USC)</h3>\n<table>\n\
            <tr><th>Citation</th><th>Offense</th><th>Penalty</th></tr>\n");
        for c in &usc {
            html.push_str(&format!(
                "<tr><td><strong>{}</strong></td><td>{}</td><td>{}</td></tr>\n",
                escape_html(&c.citation),
                escape_html(&c.short_title),
                escape_html(c.max_penalty.as_deref().unwrap_or("—")),
            ));
        }
        html.push_str("</table>\n");
    }

    if !ucmj.is_empty() {
        html.push_str("<h3>Military Charges (UCMJ)</h3>\n<table>\n\
            <tr><th>Citation</th><th>Offense</th><th>Penalty</th></tr>\n");
        for c in &ucmj {
            html.push_str(&format!(
                "<tr><td><strong>{}</strong></td><td>{}</td><td>{}</td></tr>\n",
                escape_html(&c.citation),
                escape_html(&c.short_title),
                escape_html(c.max_penalty.as_deref().unwrap_or("—")),
            ));
        }
        html.push_str("</table>\n");
    }

    if !state.selected_charges.examiner_notes.is_empty() {
        html.push_str(&format!(
            "<p><strong>Examiner Notes:</strong> {}</p>\n",
            escape_html(&state.selected_charges.examiner_notes)
        ));
    }

    html.push_str(
        "<p class=\"notice\">All findings should be reviewed by qualified legal counsel \
         before use in charging decisions.</p>\n",
    );

    html
}
