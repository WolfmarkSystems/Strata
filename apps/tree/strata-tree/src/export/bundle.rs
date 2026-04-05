// export/bundle.rs — Case export bundle (Gap 7).
// Produces a timestamped directory containing:
//   case.vtp          — the case database
//   report.html       — HTML report
//   bookmarks.csv     — CSV bookmark export
//   activity_log.jsonl— audit trail as JSONL
//   MANIFEST.json     — bundle metadata

use anyhow::{Context, Result};
use std::path::Path;

use crate::state::AppState;

#[derive(Debug)]
pub struct ExportStats {
    pub files_exported: u64,
    pub output_path: String,
}

/// Build and write a case export bundle.
pub fn export_case_bundle(
    case_path: &Path,
    output_dir: &Path,
    state: &AppState,
) -> Result<ExportStats> {
    let case_name = state.case_name().to_string();
    let examiner  = state.examiner_name().to_string();
    let ts = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let bundle_name = format!("{}_export_{}", sanitize_name(&case_name), ts);
    let bundle_dir = output_dir.join(&bundle_name);
    std::fs::create_dir_all(&bundle_dir)
        .context("Failed to create export bundle directory")?;

    let mut files_written: Vec<&str> = Vec::new();

    // ── 1. case.vtp ──────────────────────────────────────────────────────────
    let vtp_dest = bundle_dir.join("case.vtp");
    std::fs::copy(case_path, &vtp_dest)
        .context("Failed to copy .vtp case file")?;
    files_written.push("case.vtp");

    // ── 2. report.html ───────────────────────────────────────────────────────
    let report_path = bundle_dir.join("report.html");
    crate::report::html::generate_html_report(state, &report_path)
        .context("Failed to generate HTML report")?;
    files_written.push("report.html");

    // ── 3. bookmarks.csv ─────────────────────────────────────────────────────
    let bm_path = bundle_dir.join("bookmarks.csv");
    write_bookmarks_csv(state, &bm_path)
        .context("Failed to write bookmarks CSV")?;
    files_written.push("bookmarks.csv");

    // ── 4. activity_log.jsonl ────────────────────────────────────────────────
    let log_path = bundle_dir.join("activity_log.jsonl");
    write_activity_log(state, &log_path)
        .context("Failed to write activity log")?;
    files_written.push("activity_log.jsonl");

    // ── 5. MANIFEST.json ─────────────────────────────────────────────────────
    let tool_version = env!("CARGO_PKG_VERSION");
    let manifest = serde_json::json!({
        "export_utc": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "tool": "Strata",
        "tool_version": tool_version,
        "case_name": case_name,
        "exported_by": examiner,
        "files": files_written,
    });
    let manifest_path = bundle_dir.join("MANIFEST.json");
    std::fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)
        .context("Failed to write MANIFEST.json")?;
    files_written.push("MANIFEST.json");

    Ok(ExportStats {
        files_exported: files_written.len() as u64,
        output_path: bundle_dir.to_string_lossy().to_string(),
    })
}

fn write_bookmarks_csv(state: &AppState, path: &Path) -> Result<()> {
    let mut lines = vec![
        "file_path,size,modified,sha256,examiner,label,note,color".to_string(),
    ];
    for bm in &state.bookmarks {
        let file = state.file_index.iter().find(|f| f.id == bm.file_id);
        let file_path = file.map(|f| f.path.as_str()).unwrap_or("");
        let size      = file.and_then(|f| f.size).map(|s| s.to_string()).unwrap_or_default();
        let modified  = file.and_then(|f| f.modified_utc.as_deref()).unwrap_or("").to_string();
        let sha256    = file.and_then(|f| f.sha256.as_deref()).unwrap_or("").to_string();
        lines.push(format!(
            "{},{},{},{},{},{},{},{}",
            csv_escape(file_path),
            size,
            csv_escape(&modified),
            sha256,
            csv_escape(&bm.examiner),
            csv_escape(bm.label.as_deref().unwrap_or("")),
            csv_escape(bm.note.as_deref().unwrap_or("")),
            csv_escape(bm.color.as_deref().unwrap_or("")),
        ));
    }
    std::fs::write(path, lines.join("\n"))?;
    Ok(())
}

fn write_activity_log(state: &AppState, path: &Path) -> Result<()> {
    let mut lines = Vec::with_capacity(state.audit_log.len());
    for entry in &state.audit_log {
        let obj = serde_json::json!({
            "id":           entry.id,
            "timestamp_utc": entry.timestamp_utc,
            "examiner":     entry.examiner,
            "action":       entry.action,
            "detail":       entry.detail,
            "file_id":      entry.file_id,
        });
        lines.push(serde_json::to_string(&obj)?);
    }
    std::fs::write(path, lines.join("\n"))?;
    Ok(())
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn sanitize_name(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
        .collect()
}

/// Legacy stub kept for backwards compat.
pub fn export_case_bundle_stub(_case_path: &Path, _output_dir: &Path) -> Result<ExportStats> {
    Ok(ExportStats { files_exported: 0, output_path: String::new() })
}
