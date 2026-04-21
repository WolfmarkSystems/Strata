//! `strata report` — court-ready examiner report from a Strata
//! ingest run.
//!
//! **Replaces `report-skeleton`** (post-v16 Sprint 6.5). The
//! legacy command queried `./forensic.db` using the strata-core
//! case-store schema while `strata ingest run` writes
//! `<case-dir>/artifacts.sqlite` with the plugin schema. The two
//! schemas never intersected; legacy reports always showed all-
//! zero counts with "Case database: not found" warning. This
//! command reads the plugin SQLite directly plus a companion
//! `case-metadata.json` that `strata ingest run` now writes
//! automatically.
//!
//! Closes Sprint 6 findings G1 (DB disconnect), G2 (no findings
//! section), G3 (no MITRE ATT&CK section), G4 (no chain of
//! custody), G5 (no examiner certification), G6 + G7 (evidence
//! metadata unavailable — cascaded from G1), G11 (hardcoded
//! report version), G14 (hardcoded tool version).
//!
//! Explicitly out of scope for Sprint 6.5 (deferred to dedicated
//! sprints):
//!   - G8 PDF / Word output (focused output-format sprint)
//!   - G9 agency branding (v0.17)
//!   - G10 artifact hyperlinks (polish)
//!   - G12 generic parser note (polish)
//!   - G13 typography (already correct)
//!
//! Markdown is the primary output format. HTML would reuse
//! existing templating infrastructure in a follow-up if the
//! examiner consumer demands it; markdown is universally
//! viewable and the prompt explicitly mandated it.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` emitted
//! to non-interactive stdout (status prints go through the
//! CLI's standard output path).

use chrono::{DateTime, Utc};
use clap::Parser;
use rusqlite::{Connection, OpenFlags};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Strata version string baked at compile time. Closes Sprint 6
/// finding G14 (hardcoded tool-version string drifted from the
/// shipping version).
const STRATA_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser, Debug, Clone)]
#[command(
    name = "report",
    about = "Generate a court-ready examiner report from a Strata case directory"
)]
pub struct ReportArgs {
    /// Case directory containing `artifacts.sqlite` and
    /// `case-metadata.json` (produced by `strata ingest run`).
    #[arg(long = "case-dir", short = 'c')]
    pub case_dir: PathBuf,

    /// Output file path. Defaults to
    /// `<case-dir>/report-<case_name>.md`.
    #[arg(long = "output", short = 'o')]
    pub output: Option<PathBuf>,

    /// Override examiner identity from case-metadata.json. Useful
    /// when the ingest-time examiner differs from the report
    /// examiner.
    #[arg(long = "examiner")]
    pub examiner_override: Option<String>,
}

/// Companion metadata `strata ingest run` writes alongside
/// `artifacts.sqlite`. Shape matches `IngestRunSummary` (serde
/// deserialization ignores unknown fields — forward-compatible).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct CaseMetadata {
    pub case_name: Option<String>,
    pub examiner: Option<String>,
    pub source: Option<String>,
    pub case_dir: Option<String>,
    pub started_utc: Option<String>,
    pub finished_utc: Option<String>,
    pub elapsed_ms: Option<u128>,
    pub plugins_total: Option<usize>,
    pub plugins_ok: Option<usize>,
    pub plugins_failed: Option<usize>,
    pub plugins_zero: Option<usize>,
    pub artifacts_total: Option<usize>,
    pub per_plugin: Option<Vec<PluginOutcome>>,
    pub unpack: Option<serde_json::Value>,
    pub classification: Option<ClassificationInfo>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PluginOutcome {
    pub plugin: String,
    pub status: String,
    pub artifact_count: usize,
    pub elapsed_ms: u128,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClassificationInfo {
    #[serde(default)]
    pub image_type: Option<String>,
    #[serde(default)]
    pub confidence: Option<f64>,
    #[serde(default)]
    pub recommended: Option<Vec<String>>,
}

/// Single artifact row pulled from `artifacts.sqlite` for report
/// rendering. Shape deliberately narrow — the report only needs
/// fields that render in the Findings + ATT&CK sections.
#[derive(Debug, Clone)]
pub struct ArtifactRow {
    pub plugin_name: String,
    pub category: String,
    pub subcategory: String,
    pub title: String,
    pub detail: String,
    pub source_path: Option<String>,
    pub mitre_technique: Option<String>,
    pub forensic_value: String,
    pub is_suspicious: bool,
}

pub fn execute(args: ReportArgs) -> i32 {
    let case_dir = &args.case_dir;
    if !case_dir.is_dir() {
        eprintln!(
            "Error: --case-dir {} is not a directory",
            case_dir.display()
        );
        return 1;
    }

    let artifacts_db = case_dir.join("artifacts.sqlite");
    if !artifacts_db.is_file() {
        eprintln!(
            "Error: artifacts.sqlite not found in {}. \
             Run `strata ingest run` against this case directory first.",
            case_dir.display()
        );
        return 1;
    }

    let metadata = load_case_metadata(case_dir);
    let examiner = args
        .examiner_override
        .clone()
        .or_else(|| metadata.examiner.clone())
        .unwrap_or_else(|| "(examiner identity not recorded)".to_string());

    let artifacts = match load_artifacts(&artifacts_db) {
        Ok(a) => a,
        Err(e) => {
            eprintln!(
                "Error: failed to read {}: {}",
                artifacts_db.display(),
                e
            );
            return 1;
        }
    };

    let report_md = render_markdown(&metadata, &examiner, &artifacts);

    let output_path = args.output.clone().unwrap_or_else(|| {
        let name = metadata
            .case_name
            .as_deref()
            .unwrap_or("untitled")
            .replace([' ', '/', '\\'], "_");
        case_dir.join(format!("report-{name}.md"))
    });

    if let Err(e) = std::fs::write(&output_path, &report_md) {
        eprintln!(
            "Error: failed to write report to {}: {}",
            output_path.display(),
            e
        );
        return 1;
    }

    println!("Strata examiner report generated:");
    println!("  Case dir:   {}", case_dir.display());
    println!("  Examiner:   {examiner}");
    println!(
        "  Artifacts:  {} across {} plugin(s)",
        artifacts.len(),
        unique_plugin_count(&artifacts),
    );
    println!("  Output:     {}", output_path.display());
    println!(
        "  Strata ver: {STRATA_VERSION} (embedded at compile time)"
    );
    0
}

/// Load `<case-dir>/case-metadata.json`. Missing / unreadable file
/// returns a default-populated struct so the report can still
/// render — placeholder text surfaces in the sections that need
/// the missing field rather than failing the whole command.
pub fn load_case_metadata(case_dir: &Path) -> CaseMetadata {
    let path = case_dir.join("case-metadata.json");
    if !path.is_file() {
        return CaseMetadata::default();
    }
    let Ok(body) = std::fs::read_to_string(&path) else {
        return CaseMetadata::default();
    };
    serde_json::from_str::<CaseMetadata>(&body).unwrap_or_default()
}

/// Load every artifact row from the plugin `artifacts.sqlite`.
/// Limited-field select so memory stays bounded on large cases
/// (Charlie's ~3,800 rows × a few hundred bytes each is trivial;
/// enterprise images could reach millions).
pub fn load_artifacts(path: &Path) -> Result<Vec<ArtifactRow>, String> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(path, flags)
        .map_err(|e| format!("open {}: {e}", path.display()))?;

    let mut stmt = conn
        .prepare(
            "SELECT plugin_name, category, COALESCE(subcategory, ''), title, \
             COALESCE(detail, ''), source_path, mitre_technique, forensic_value, \
             COALESCE(is_suspicious, 0) \
             FROM artifacts",
        )
        .map_err(|e| format!("prepare artifacts query: {e}"))?;

    let rows = stmt
        .query_map([], |row| {
            Ok(ArtifactRow {
                plugin_name: row.get::<_, String>(0)?,
                category: row.get::<_, String>(1)?,
                subcategory: row.get::<_, String>(2)?,
                title: row.get::<_, String>(3)?,
                detail: row.get::<_, String>(4)?,
                source_path: row.get::<_, Option<String>>(5)?,
                mitre_technique: row.get::<_, Option<String>>(6)?,
                forensic_value: row.get::<_, String>(7)?,
                is_suspicious: row.get::<_, i64>(8)? != 0,
            })
        })
        .map_err(|e| format!("query_map: {e}"))?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| format!("row: {e}"))?);
    }
    Ok(out)
}

fn unique_plugin_count(artifacts: &[ArtifactRow]) -> usize {
    let mut seen = std::collections::HashSet::new();
    for a in artifacts {
        seen.insert(a.plugin_name.as_str());
    }
    seen.len()
}

/// Render the full markdown report. Sections:
///
/// 1. Header (title, examiner, case, timestamps, tool version)
/// 2. Evidence Integrity (source path, SHA-256 if recorded, DETECT-1 classification)
/// 3. Findings (per-Sigma-rule breakdown with supporting artifacts)
/// 4. MITRE ATT&CK Coverage (technique-count table)
/// 5. Per-Plugin Summary (plugin × subcategory × count matrix)
/// 6. Chain of Custody
/// 7. Examiner Certification
/// 8. Limitations
pub fn render_markdown(
    metadata: &CaseMetadata,
    examiner: &str,
    artifacts: &[ArtifactRow],
) -> String {
    let mut out = String::with_capacity(16 * 1024);
    let now = Utc::now();

    render_header(&mut out, metadata, examiner, &now, artifacts);
    render_evidence_integrity(&mut out, metadata);
    render_findings(&mut out, artifacts);
    render_mitre_attack(&mut out, artifacts);
    render_per_plugin_summary(&mut out, artifacts);
    render_chain_of_custody(&mut out, metadata);
    render_examiner_certification(&mut out, metadata, examiner, &now);
    render_limitations(&mut out);

    out
}

fn render_header(
    out: &mut String,
    metadata: &CaseMetadata,
    examiner: &str,
    now: &DateTime<Utc>,
    artifacts: &[ArtifactRow],
) {
    out.push_str("# Digital Forensic Examination Report\n\n");
    out.push_str("| Field | Value |\n|---|---|\n");
    out.push_str(&format!(
        "| Case name | {} |\n",
        metadata.case_name.as_deref().unwrap_or("(not recorded)")
    ));
    out.push_str(&format!("| Examiner | {examiner} |\n"));
    out.push_str(&format!(
        "| Evidence source | {} |\n",
        metadata.source.as_deref().unwrap_or("(not recorded)")
    ));
    out.push_str(&format!(
        "| Ingest started | {} |\n",
        metadata.started_utc.as_deref().unwrap_or("(not recorded)")
    ));
    out.push_str(&format!(
        "| Ingest finished | {} |\n",
        metadata.finished_utc.as_deref().unwrap_or("(not recorded)")
    ));
    out.push_str(&format!(
        "| Report generated | {} |\n",
        now.to_rfc3339()
    ));
    out.push_str(&format!(
        "| Strata version | {STRATA_VERSION} |\n"
    ));
    out.push_str(&format!(
        "| Total artifacts | {} |\n",
        artifacts.len()
    ));
    out.push('\n');
}

fn render_evidence_integrity(out: &mut String, metadata: &CaseMetadata) {
    out.push_str("## 1. Evidence Integrity\n\n");
    out.push_str(&format!(
        "- **Source path:** `{}`\n",
        metadata.source.as_deref().unwrap_or("(not recorded)")
    ));
    out.push_str(&format!(
        "- **Case directory:** `{}`\n",
        metadata.case_dir.as_deref().unwrap_or("(not recorded)")
    ));
    if let Some(c) = &metadata.classification {
        out.push_str(&format!(
            "- **DETECT-1 classification:** {} (confidence {:.2})\n",
            c.image_type.as_deref().unwrap_or("Unknown"),
            c.confidence.unwrap_or(0.0),
        ));
        if let Some(rec) = &c.recommended {
            out.push_str(&format!(
                "- **Recommended plugins:** {}\n",
                rec.join(", ")
            ));
        }
    }
    out.push_str(
        "- **Hash verification:** SHA-256 hash capture is an ingest-time \
         concern; this report reflects whatever metadata the ingest pipeline \
         recorded. Examiner should cross-check against acquisition records.\n",
    );
    out.push('\n');
}

fn render_findings(out: &mut String, artifacts: &[ArtifactRow]) {
    out.push_str("## 2. Findings\n\n");

    // Sigma rule firings (the primary examiner-actionable evidence).
    let sigma_rules: Vec<&ArtifactRow> = artifacts
        .iter()
        .filter(|a| {
            a.plugin_name == "Strata Sigma" && a.title.starts_with("RULE FIRED:")
        })
        .collect();

    if sigma_rules.is_empty() {
        out.push_str(
            "_No Sigma correlation rules fired on this case. The examiner \
             should still review the Per-Plugin Summary (§4) for plugin-level \
             artifacts that did not trigger cross-artifact correlations._\n\n",
        );
    } else {
        out.push_str(&format!(
            "**{} Sigma rule(s) fired.** Each firing below is a cross-artifact \
             correlation the examiner should review:\n\n",
            sigma_rules.len(),
        ));
        for (i, rule) in sigma_rules.iter().enumerate() {
            render_finding_entry(out, i + 1, rule, artifacts);
        }
    }

    // Suspicious / Critical artifacts not covered by a Sigma rule.
    // These are examiner-actionable in their own right.
    let critical_count = artifacts
        .iter()
        .filter(|a| {
            a.forensic_value.eq_ignore_ascii_case("Critical")
                && a.plugin_name != "Strata Sigma"
        })
        .count();
    if critical_count > 0 {
        out.push_str(&format!(
            "\n### Additional Critical Artifacts\n\n\
             {} artifact(s) flagged Critical by their source plugin. \
             See per-plugin breakdown in §4 for details.\n\n",
            critical_count,
        ));
    }
}

fn render_finding_entry(
    out: &mut String,
    index: usize,
    rule: &ArtifactRow,
    all_artifacts: &[ArtifactRow],
) {
    let title = rule
        .title
        .strip_prefix("RULE FIRED: ")
        .unwrap_or(&rule.title);
    out.push_str(&format!("### Finding {index}: {title}\n\n"));
    if let Some(m) = &rule.mitre_technique {
        out.push_str(&format!("- **MITRE ATT&CK:** `{m}`\n"));
    }
    out.push_str(&format!(
        "- **Severity:** {}\n",
        rule.forensic_value
    ));
    out.push_str(&format!(
        "- **Source:** Strata Sigma correlation engine\n"
    ));
    if !rule.detail.is_empty() {
        out.push_str(&format!("\n{}\n\n", rule.detail));
    }

    // Supporting artifacts — pick rows whose mitre_technique or
    // subcategory correlates to this rule. Rule titles like
    // "RULE FIRED: Active Setup Persistence" map to the
    // subcategory "Active Setup" via simple substring; the rule's
    // own MITRE technique picks up supporting Phantom records.
    let hint = finding_subcategory_hint(title);
    let mut supporting: Vec<&ArtifactRow> = all_artifacts
        .iter()
        .filter(|a| a.plugin_name != "Strata Sigma")
        .filter(|a| {
            hint.as_deref()
                .map(|h| a.subcategory.eq_ignore_ascii_case(h))
                .unwrap_or(false)
                || (rule.mitre_technique.is_some()
                    && a.mitre_technique == rule.mitre_technique)
        })
        .collect();
    supporting.sort_by(|a, b| a.source_path.cmp(&b.source_path));
    supporting.truncate(10); // Courtroom-readable cap

    if !supporting.is_empty() {
        out.push_str("**Supporting artifacts (top 10 of matching set):**\n\n");
        out.push_str("| Plugin | Subcategory | Title | Source path |\n");
        out.push_str("|---|---|---|---|\n");
        for a in &supporting {
            out.push_str(&format!(
                "| {} | {} | {} | `{}` |\n",
                a.plugin_name,
                a.subcategory,
                md_truncate(&a.title, 80),
                a.source_path.as_deref().unwrap_or("(no path)"),
            ));
        }
        out.push('\n');
    }
}

/// Map Sigma-rule-firing titles to the Phantom subcategory they
/// were built to match. Used for finding → supporting-artifact
/// linkage in §2. Returns None for rules with no direct Phantom
/// counterpart (meta-records, multi-plugin correlations).
fn finding_subcategory_hint(title: &str) -> Option<&'static str> {
    if title.contains("Active Setup") {
        Some("Active Setup")
    } else if title.contains("Winlogon") {
        Some("Winlogon Persistence")
    } else if title.contains("Browser Helper Object") {
        Some("Browser Helper Object")
    } else if title.contains("IFEO") {
        Some("IFEO Debugger")
    } else if title.contains("Boot Execute") {
        Some("Boot Execute")
    } else if title.contains("Shell Execute Hook") {
        Some("Shell Execute Hook")
    } else if title.contains("USB Exfiltration") {
        Some("USB Device")
    } else {
        None
    }
}

fn md_truncate(s: &str, max: usize) -> String {
    let mut owned: String = s.chars().take(max).collect();
    if s.chars().count() > max {
        owned.push_str("…");
    }
    owned.replace('|', "\\|")
}

fn render_mitre_attack(out: &mut String, artifacts: &[ArtifactRow]) {
    out.push_str("## 3. MITRE ATT&CK Coverage\n\n");
    let mut technique_counts: BTreeMap<String, usize> = BTreeMap::new();
    for a in artifacts {
        if let Some(t) = &a.mitre_technique {
            if !t.is_empty() {
                *technique_counts.entry(t.clone()).or_insert(0) += 1;
            }
        }
    }
    if technique_counts.is_empty() {
        out.push_str(
            "_No MITRE ATT&CK techniques observed in this case. This is \
             unusual — every production Strata plugin is expected to emit \
             `mitre_technique` per the CLAUDE.md ArtifactRecord contract. \
             Examiner should investigate whether the ingest run completed \
             normally._\n\n",
        );
        return;
    }
    out.push_str(&format!(
        "**{} distinct MITRE ATT&CK technique(s)** with evidence in this case. \
         Paste the technique IDs into the ATT&CK Navigator \
         (https://mitre-attack.github.io/attack-navigator/) to visualize \
         coverage as a heat map.\n\n",
        technique_counts.len(),
    ));
    out.push_str("| Technique ID | Artifact count | Tactic (inferred) |\n");
    out.push_str("|---|---|---|\n");
    for (technique, count) in &technique_counts {
        out.push_str(&format!(
            "| `{}` | {} | {} |\n",
            technique,
            count,
            infer_tactic(technique),
        ));
    }
    out.push('\n');
}

/// Rough kill-chain mapping. Full lookup lives in
/// `strata-core::hunt::kill_chain`; reproduced here narrowly for
/// the report's summary column. If the technique isn't recognized,
/// returns "Unmapped" — examiner is directed to cross-check
/// against the ATT&CK Navigator.
fn infer_tactic(technique: &str) -> &'static str {
    let base = technique.split('.').next().unwrap_or(technique);
    match base {
        "T1547" | "T1546" | "T1176" => "Persistence",
        "T1021" | "T1550" | "T1558" | "T1534" => "Lateral Movement",
        "T1070" => "Defense Evasion",
        "T1005" | "T1114" | "T1113" | "T1119" => "Collection",
        "T1552" | "T1003" | "T1555" => "Credential Access",
        "T1059" | "T1218" | "T1204" => "Execution",
        "T1083" | "T1057" | "T1049" | "T1082" => "Discovery",
        "T1071" | "T1095" | "T1105" => "Command and Control",
        "T1197" | "T1567" | "T1020" | "T1048" => "Exfiltration",
        "T1091" | "T1189" | "T1190" | "T1566" => "Initial Access",
        "T1562" | "T1027" => "Defense Evasion",
        _ => "Unmapped",
    }
}

fn render_per_plugin_summary(out: &mut String, artifacts: &[ArtifactRow]) {
    out.push_str("## 4. Per-Plugin Summary\n\n");
    let mut by_plugin: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    for a in artifacts {
        *by_plugin
            .entry(a.plugin_name.clone())
            .or_default()
            .entry(a.subcategory.clone())
            .or_insert(0) += 1;
    }
    if by_plugin.is_empty() {
        out.push_str("_No plugin artifacts recorded._\n\n");
        return;
    }
    for (plugin, subs) in &by_plugin {
        let total: usize = subs.values().sum();
        out.push_str(&format!("### {plugin}  — {total} artifact(s)\n\n"));
        out.push_str("| Subcategory | Count |\n|---|---|\n");
        for (sub, count) in subs {
            let sub_display = if sub.is_empty() {
                "(unspecified)"
            } else {
                sub.as_str()
            };
            out.push_str(&format!("| {sub_display} | {count} |\n"));
        }
        out.push('\n');
    }
}

fn render_chain_of_custody(out: &mut String, metadata: &CaseMetadata) {
    out.push_str("## 5. Chain of Custody\n\n");
    out.push_str("| Time (UTC) | Actor | Action |\n|---|---|---|\n");
    let examiner = metadata
        .examiner
        .as_deref()
        .unwrap_or("(examiner not recorded)");
    if let Some(started) = &metadata.started_utc {
        out.push_str(&format!(
            "| {started} | {examiner} | Ingest started — source `{}` |\n",
            metadata.source.as_deref().unwrap_or("(not recorded)"),
        ));
    }
    if let Some(finished) = &metadata.finished_utc {
        out.push_str(&format!(
            "| {finished} | {examiner} | Ingest completed — {} artifact(s) \
             extracted by {} plugin(s) |\n",
            metadata.artifacts_total.unwrap_or(0),
            metadata.plugins_total.unwrap_or(0),
        ));
    }
    if metadata.started_utc.is_none() && metadata.finished_utc.is_none() {
        out.push_str("| (not recorded) | (not recorded) | case-metadata.json \
             was not found or did not contain timestamp fields. Re-run \
             `strata ingest run` to populate. |\n");
    }
    out.push('\n');
    out.push_str(
        "_Chain-of-custody logging covering sub-ingest events (per-artifact \
         extraction, report generation events, evidence transfers) is a \
         v0.17 architectural concern tracked separately. This section \
         reflects the ingest-level events captured at report-generation \
         time._\n\n",
    );
}

fn render_examiner_certification(
    out: &mut String,
    metadata: &CaseMetadata,
    examiner: &str,
    now: &DateTime<Utc>,
) {
    out.push_str("## 6. Examiner Certification\n\n");
    out.push_str(&format!(
        "I, **{examiner}**, certify that I examined the evidence described in \
         this report using the Strata Forensic Platform (version `{STRATA_VERSION}`) \
         in read-only mode. All automated artifact extraction was performed by \
         documented, tested parser plugins. No modifications were made to the \
         evidence source during this examination.\n\n"
    ));
    out.push_str(&format!(
        "The case named \"{}\" was ingested starting at {} UTC and completed at {} UTC. \
         Findings in §2 above represent automated correlations produced by the Strata \
         Sigma rule engine; the examiner is responsible for human review of each \
         finding against the underlying supporting artifacts and acquisition chain.\n\n",
        metadata.case_name.as_deref().unwrap_or("(unnamed)"),
        metadata.started_utc.as_deref().unwrap_or("(not recorded)"),
        metadata.finished_utc.as_deref().unwrap_or("(not recorded)"),
    ));
    out.push_str(&format!(
        "Report generated at {}.\n\n",
        now.to_rfc3339(),
    ));
    out.push_str("---\n\n");
    out.push_str(&format!("Examiner signature: _______________________\n\n"));
    out.push_str(&format!("Date: _______________________\n\n"));
}

fn render_limitations(out: &mut String) {
    out.push_str("## 7. Limitations\n\n");
    out.push_str(
        "- This report is automated output from the Strata Forensic Platform. \
           Findings should be cross-checked against the underlying evidence \
           by a qualified examiner before use in legal proceedings.\n",
    );
    out.push_str(
        "- The Sigma correlation engine fires rules based on predicates \
           documented in `plugins/strata-plugin-sigma/src/lib.rs`. Rule \
           predicates are public, auditable, and versioned alongside the \
           tool release.\n",
    );
    out.push_str(
        "- Subcategory strings rendered in §4 are the raw values emitted by \
           individual plugins; a display-name mapping layer is a v0.17 \
           architectural enhancement.\n",
    );
    out.push_str(
        "- PDF, Word, and agency-branded HTML output formats are deferred \
           to a focused output-format sprint; this report renders markdown.\n",
    );
    out.push('\n');
}

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn synthetic_artifact(
        plugin: &str,
        subcategory: &str,
        title: &str,
        mitre: Option<&str>,
    ) -> ArtifactRow {
        ArtifactRow {
            plugin_name: plugin.to_string(),
            category: "SystemActivity".to_string(),
            subcategory: subcategory.to_string(),
            title: title.to_string(),
            detail: format!("synthetic detail for {title}"),
            source_path: Some(format!("/case/extracted/{subcategory}.dat")),
            mitre_technique: mitre.map(|s| s.to_string()),
            forensic_value: "High".to_string(),
            is_suspicious: true,
        }
    }

    fn synthetic_sigma(title: &str, mitre: &str) -> ArtifactRow {
        ArtifactRow {
            plugin_name: "Strata Sigma".to_string(),
            category: "SystemActivity".to_string(),
            subcategory: "Sigma Rule".to_string(),
            title: format!("RULE FIRED: {title}"),
            detail: format!("synthetic firing detail for {title}"),
            source_path: Some("sigma".to_string()),
            mitre_technique: Some(mitre.to_string()),
            forensic_value: "Critical".to_string(),
            is_suspicious: true,
        }
    }

    fn charlie_shape_artifacts() -> Vec<ArtifactRow> {
        // Synthesizes the seven Sigma rule firings Sprint 5 confirmed
        // on Charlie (six persistence + USB exfil) plus a handful of
        // Phantom supporting records so the Findings section renders.
        vec![
            synthetic_sigma("Active Setup Persistence", "T1547.014"),
            synthetic_sigma("Winlogon Helper DLL Persistence", "T1547.004"),
            synthetic_sigma("Browser Helper Object Persistence", "T1176"),
            synthetic_sigma("IFEO Debugger Persistence", "T1546.012"),
            synthetic_sigma("Boot Execute Persistence", "T1547.001"),
            synthetic_sigma("Shell Execute Hook Persistence", "T1546.015"),
            synthetic_sigma("USB Exfiltration Sequence", "T1091"),
            synthetic_artifact(
                "Strata Phantom",
                "Active Setup",
                "StubPath in HKLM\\SOFTWARE\\Microsoft\\Active Setup",
                Some("T1547.014"),
            ),
            synthetic_artifact(
                "Strata Phantom",
                "Winlogon Persistence",
                "Winlogon Shell value",
                Some("T1547.004"),
            ),
            synthetic_artifact(
                "Strata Phantom",
                "USB Device",
                "Kingston DataTraveler",
                Some("T1091"),
            ),
            synthetic_artifact(
                "Strata Remnant",
                "Carved",
                "PDF magic at offset 0x1000",
                Some("T1070.004"),
            ),
        ]
    }

    #[test]
    fn strata_report_reads_artifacts_sqlite_not_forensic_db() {
        // Sprint 6.5 Fix 1 tripwire. Closes Sprint 6 finding G1.
        // Pre-Sprint-6.5 the legacy report-skeleton queried a
        // strata-core case-store database with a schema that
        // `strata ingest run` never wrote. This test confirms the
        // new command reads artifacts.sqlite (the actual plugin-
        // written DB) — positive assertion only. The negative
        // "legacy filename not referenced" assertion isn't
        // source-inspectable because the module's doc comment
        // legitimately explains the deprecated behaviour. The
        // replacement-intent is pinned via the deprecation
        // tripwire in report_skeleton.rs + the integration test
        // `strata_report_loads_metadata_from_case_dir_json` that
        // proves end-to-end the new command reads the new path.
        let dir = tempdir().expect("tempdir");
        let json = r#"{"case_name": "schema-probe", "examiner": "E"}"#;
        fs::write(dir.path().join("case-metadata.json"), json).expect("w");

        // Build a minimal SQLite database with the artifacts
        // schema — no rows needed, just the table so the query
        // in load_artifacts() succeeds.
        let db_path = dir.path().join("artifacts.sqlite");
        let conn = rusqlite::Connection::open(&db_path).expect("open db");
        conn.execute_batch(
            "CREATE TABLE artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                plugin_name TEXT NOT NULL,
                category TEXT NOT NULL,
                subcategory TEXT DEFAULT '',
                title TEXT NOT NULL,
                detail TEXT,
                source_path TEXT,
                timestamp INTEGER,
                forensic_value TEXT NOT NULL,
                mitre_technique TEXT,
                confidence INTEGER,
                is_suspicious INTEGER DEFAULT 0,
                raw_data TEXT,
                created_at INTEGER NOT NULL
            );",
        )
        .expect("create table");
        drop(conn);

        // The new command must load from this path without error.
        let loaded = load_artifacts(&db_path).expect("load");
        assert!(loaded.is_empty(), "empty table → empty Vec");
        let metadata = load_case_metadata(dir.path());
        assert_eq!(metadata.case_name.as_deref(), Some("schema-probe"));
    }

    #[test]
    fn strata_report_finds_seven_sigma_rules_on_charlie_shape_fixture() {
        // Sprint 6.5 tripwire for finding G2 (findings section
        // renders rule firings). Synthesizes the Charlie Sprint 5
        // firing pattern and asserts the Findings section lists
        // all seven rules. Numeric count (seven) is load-bearing
        // and documented in the Sprint 5 session-state doc.
        let md = render_markdown(
            &CaseMetadata::default(),
            "Sprint6.5 Test Examiner",
            &charlie_shape_artifacts(),
        );
        let firings = md.matches("### Finding ").count();
        assert_eq!(
            firings, 7,
            "expected 7 Findings sub-sections (Charlie's 6 persistence + USB \
             exfil); got {firings}. Render:\n---\n{md}\n---"
        );
        assert!(md.contains("7 Sigma rule(s) fired"));
    }

    #[test]
    fn strata_report_renders_mitre_attack_section_with_technique_ids() {
        // Sprint 6.5 tripwire for finding G3. ATT&CK section lists
        // every unique MITRE technique ID observed, with per-
        // technique artifact count and inferred tactic.
        let md = render_markdown(
            &CaseMetadata::default(),
            "Test",
            &charlie_shape_artifacts(),
        );
        assert!(md.contains("## 3. MITRE ATT&CK Coverage"));
        // Each of the seven Sigma-firing techniques must appear.
        for t in [
            "T1547.014", // Active Setup
            "T1547.004", // Winlogon
            "T1176",     // BHO
            "T1546.012", // IFEO
            "T1547.001", // Boot Execute
            "T1546.015", // Shell Execute Hook
            "T1091",     // USB Exfil (initial access)
        ] {
            assert!(
                md.contains(t),
                "MITRE section must reference technique {t}; not found in:\n{md}"
            );
        }
        // Inferred-tactic column must populate for known families.
        assert!(md.contains("Persistence"));
    }

    #[test]
    fn strata_report_renders_chain_of_custody_section() {
        // Sprint 6.5 tripwire for finding G4. CoC section must
        // always appear even if the metadata JSON is sparse.
        let md = render_markdown(&CaseMetadata::default(), "Test", &[]);
        assert!(md.contains("## 5. Chain of Custody"));
        // Empty metadata renders the explicit "not recorded"
        // placeholder rather than omitting the section.
        assert!(md.contains("(not recorded)"));
    }

    #[test]
    fn strata_report_renders_examiner_certification_block() {
        // Sprint 6.5 tripwire for finding G5. Certification block
        // must name the examiner, the Strata version (from env at
        // compile time, closing G14), and the case name if present.
        let metadata = CaseMetadata {
            case_name: Some("OPERATION TESTCASE".to_string()),
            started_utc: Some("2026-04-21T00:00:00Z".to_string()),
            finished_utc: Some("2026-04-21T00:05:00Z".to_string()),
            ..Default::default()
        };
        let md = render_markdown(&metadata, "Dr. Test Examiner", &[]);
        assert!(md.contains("## 6. Examiner Certification"));
        assert!(md.contains("Dr. Test Examiner"));
        assert!(
            md.contains(&format!("version `{}`", STRATA_VERSION)),
            "examiner certification must cite actual Strata version"
        );
        assert!(md.contains("OPERATION TESTCASE"));
    }

    #[test]
    fn strata_report_tool_version_matches_cargo_pkg_version() {
        // Sprint 6.5 tripwire for finding G14. Tool version is
        // baked at compile time via env!("CARGO_PKG_VERSION") and
        // cannot drift from the shipping version.
        let expected = env!("CARGO_PKG_VERSION");
        assert_eq!(STRATA_VERSION, expected);
        // Header and certification block must both reference it.
        let md = render_markdown(&CaseMetadata::default(), "Test", &[]);
        assert!(
            md.contains(&format!("| Strata version | {} |", expected)),
            "report header must cite Strata version {expected}"
        );
        assert!(
            md.contains(&format!("(version `{}`)", expected)),
            "examiner certification must cite Strata version {expected}"
        );
    }

    #[test]
    fn case_metadata_json_round_trips_from_ingest_summary_shape() {
        // Sprint 6.5 tripwire for the ingest → report metadata
        // handoff. `strata ingest run` serializes IngestRunSummary
        // directly via serde_json::to_string_pretty. The report
        // command's CaseMetadata struct must deserialize the
        // same shape without errors.
        let json = r#"{
            "case_name": "sprint6-charlie",
            "examiner": "Sprint6.5 Auditor",
            "source": "/Users/x/Test Material/charlie.E01",
            "case_dir": "/tmp/case",
            "started_utc": "2026-04-21T06:00:00Z",
            "finished_utc": "2026-04-21T06:02:00Z",
            "elapsed_ms": 120000,
            "plugins_total": 22,
            "plugins_ok": 22,
            "plugins_failed": 0,
            "plugins_zero": 10,
            "artifacts_total": 3756,
            "per_plugin": [
                {"plugin": "Strata Sigma", "status": "ok",
                 "artifact_count": 9, "elapsed_ms": 5, "error": null}
            ],
            "classification": {
                "image_type": "Windows Workstation",
                "confidence": 0.91,
                "recommended": ["Strata Phantom", "Strata Sigma"]
            }
        }"#;
        let md: CaseMetadata = serde_json::from_str(json).expect("parse");
        assert_eq!(md.case_name.as_deref(), Some("sprint6-charlie"));
        assert_eq!(md.examiner.as_deref(), Some("Sprint6.5 Auditor"));
        assert_eq!(md.artifacts_total, Some(3756));
        assert_eq!(
            md.classification
                .as_ref()
                .and_then(|c| c.image_type.as_deref()),
            Some("Windows Workstation")
        );
    }

    #[test]
    fn strata_report_loads_metadata_from_case_dir_json() {
        // Integration: write a synthetic case-metadata.json into a
        // tempdir and confirm load_case_metadata populates the struct.
        let dir = tempdir().expect("tempdir");
        let json = r#"{"case_name": "X", "examiner": "Y"}"#;
        fs::write(dir.path().join("case-metadata.json"), json).expect("w");
        let md = load_case_metadata(dir.path());
        assert_eq!(md.case_name.as_deref(), Some("X"));
        assert_eq!(md.examiner.as_deref(), Some("Y"));
    }

    #[test]
    fn strata_report_renders_all_seven_sections_in_order() {
        // Report structure tripwire: every section header must
        // appear, and they must appear in the documented order so
        // the report doesn't regress to a shuffled layout.
        let md = render_markdown(
            &CaseMetadata::default(),
            "Test",
            &charlie_shape_artifacts(),
        );
        let sections = [
            "## 1. Evidence Integrity",
            "## 2. Findings",
            "## 3. MITRE ATT&CK Coverage",
            "## 4. Per-Plugin Summary",
            "## 5. Chain of Custody",
            "## 6. Examiner Certification",
            "## 7. Limitations",
        ];
        let mut last_pos = 0;
        for section in sections {
            let pos = md.find(section).unwrap_or_else(|| {
                panic!("section {section} missing from report")
            });
            assert!(
                pos >= last_pos,
                "sections must appear in documented order; \
                 {section} appeared before the prior section (at byte {pos} vs prior {last_pos})"
            );
            last_pos = pos;
        }
    }
}
