//! Export/report writers for toolbar actions.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;
use printpdf::*;

use crate::state::{verify_audit_chain, AppState, ChainVerifyResult, TimelineEventType};

pub fn export_bundle(state: &AppState, out_dir: &Path) -> Result<Vec<PathBuf>> {
    guard_output_path(state, out_dir)?;
    std::fs::create_dir_all(out_dir)?;
    let mut written = Vec::new();

    let files_csv = out_dir.join("files.csv");
    export_files_csv(state, &files_csv)?;
    written.push(files_csv);

    let bm_csv = out_dir.join("bookmarks.csv");
    export_bookmarks_csv(state, &bm_csv)?;
    written.push(bm_csv);

    let bm_html = out_dir.join("bookmarks.html");
    export_bookmarks_html(state, &bm_html)?;
    written.push(bm_html);

    let timeline_csv = out_dir.join("timeline.csv");
    export_timeline_csv(state, &timeline_csv)?;
    written.push(timeline_csv);

    let timeline_json = out_dir.join("timeline.json");
    export_timeline_json(state, &timeline_json)?;
    written.push(timeline_json);

    let timeline_pdf = out_dir.join("timeline.pdf");
    export_timeline_pdf(state, &timeline_pdf)?;
    written.push(timeline_pdf);

    let report_pdf = out_dir.join("case_report.pdf");
    export_case_pdf(state, &report_pdf)?;
    written.push(report_pdf);

    let report_html = out_dir.join("case_report.html");
    export_case_html(state, &report_html)?;
    written.push(report_html);

    let audit_csv = out_dir.join("audit_log.csv");
    export_audit_csv(state, &audit_csv)?;
    written.push(audit_csv);

    let audit_json = out_dir.join("audit_log.json");
    export_audit_json(state, &audit_json)?;
    written.push(audit_json);

    let audit_pdf = out_dir.join("audit_log.pdf");
    export_audit_pdf(state, &audit_pdf)?;
    written.push(audit_pdf);

    Ok(written)
}

pub fn export_files_csv(state: &AppState, out_path: &Path) -> Result<()> {
    guard_output_path(state, out_path)?;
    let mut f = std::fs::File::create(out_path)?;
    write_csv_metadata_header(&mut f, state)?;
    writeln!(
        f,
        "id,evidence_id,path,size,created,modified,accessed,is_deleted,is_carved,hash_md5,hash_sha256,category,examiner_notes"
    )?;
    for entry in &state.file_index {
        if entry.is_dir {
            continue;
        }
        writeln!(
            f,
            "{},{},{},{},{},{},{},{},{},{},{},{},{}",
            csv(&entry.id),
            csv(&entry.evidence_id),
            csv(&entry.path),
            entry.size.unwrap_or(0),
            csv(entry.created_utc.as_deref().unwrap_or("")),
            csv(entry.modified_utc.as_deref().unwrap_or("")),
            csv(entry.accessed_utc.as_deref().unwrap_or("")),
            entry.is_deleted as u8,
            entry.is_carved as u8,
            csv(entry.md5.as_deref().unwrap_or("")),
            csv(entry.sha256.as_deref().unwrap_or("")),
            csv(entry.category.as_deref().unwrap_or("")),
            csv(&state.examiner_note),
        )?;
    }
    Ok(())
}

pub fn export_bookmarks_csv(state: &AppState, out_path: &Path) -> Result<()> {
    guard_output_path(state, out_path)?;
    let mut f = std::fs::File::create(out_path)?;
    write_csv_metadata_header(&mut f, state)?;
    writeln!(f, "id,file_id,registry_path,tag,note,examiner,created_utc")?;
    let mut bookmarks = state.bookmarks.clone();
    bookmarks.sort_by_key(|bm| (bm.tag.clone(), bookmark_target(state, bm)));
    for bm in &bookmarks {
        writeln!(
            f,
            "{},{},{},{},{},{},{}",
            csv(&bm.id),
            csv(bm.file_id.as_deref().unwrap_or("")),
            csv(bm.registry_path.as_deref().unwrap_or("")),
            csv(&bm.tag),
            csv(&bm.note),
            csv(&bm.examiner),
            csv(&bm.created_utc),
        )?;
    }
    Ok(())
}

pub fn export_bookmarks_html(state: &AppState, out_path: &Path) -> Result<()> {
    guard_output_path(state, out_path)?;
    let mut rows = String::new();
    let mut bookmarks = state.bookmarks.clone();
    bookmarks.sort_by_key(|bm| (bm.tag.clone(), bookmark_target(state, bm)));
    for bm in &bookmarks {
        let target = bookmark_target(state, bm);
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&target),
            esc(&bm.tag),
            esc(&bm.note),
            esc(&bm.examiner),
            esc(&bm.created_utc),
        ));
    }
    let html = format!(
        "<html><head><meta charset=\"utf-8\"><style>body{{font-family:Consolas,monospace}}table{{border-collapse:collapse}}td,th{{border:1px solid #ccc;padding:6px}}</style></head><body><h1>Bookmarks</h1><table><tr><th>Target</th><th>Tag</th><th>Note</th><th>Examiner</th><th>UTC</th></tr>{}</table></body></html>",
        rows
    );
    std::fs::write(out_path, html)?;
    Ok(())
}

pub fn export_timeline_csv(state: &AppState, out_path: &Path) -> Result<()> {
    guard_output_path(state, out_path)?;
    let mut f = std::fs::File::create(out_path)?;
    write_csv_metadata_header(&mut f, state)?;
    writeln!(
        f,
        "timestamp,event_type,path,evidence_id,detail,file_id,suspicious"
    )?;
    for entry in &state.timeline_entries {
        writeln!(
            f,
            "{},{},{},{},{},{},{}",
            csv(&entry
                .timestamp
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
            csv(match entry.event_type {
                TimelineEventType::FileCreated => "FileCreated",
                TimelineEventType::FileModified => "FileModified",
                TimelineEventType::FileAccessed => "FileAccessed",
                TimelineEventType::FileMftModified => "FileMftModified",
                TimelineEventType::FileDeleted => "FileDeleted",
                TimelineEventType::RegistryKeyCreated => "RegistryKeyCreated",
                TimelineEventType::RegistryKeyModified => "RegistryKeyModified",
                TimelineEventType::RegistryValueSet => "RegistryValueSet",
                TimelineEventType::ProcessExecuted => "ProcessExecuted",
                TimelineEventType::UserLogin => "UserLogin",
                TimelineEventType::UserActivity => "UserActivity",
                TimelineEventType::WebVisit => "WebVisit",
            }),
            csv(&entry.path),
            csv(&entry.evidence_id),
            csv(&entry.detail),
            csv(entry.file_id.as_deref().unwrap_or("")),
            entry.suspicious as u8,
        )?;
    }
    Ok(())
}

pub fn export_timeline_json(state: &AppState, out_path: &Path) -> Result<()> {
    guard_output_path(state, out_path)?;
    let mut rows = Vec::with_capacity(state.timeline_entries.len());
    for entry in &state.timeline_entries {
        rows.push(serde_json::json!({
            "timestamp_utc": entry.timestamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "event_type": event_type_label(&entry.event_type),
            "path": entry.path,
            "evidence_id": entry.evidence_id,
            "detail": entry.detail,
            "file_id": entry.file_id,
            "suspicious": entry.suspicious,
        }));
    }
    std::fs::write(out_path, serde_json::to_string_pretty(&rows)?)?;
    Ok(())
}

pub fn export_timeline_pdf(state: &AppState, out_path: &Path) -> Result<()> {
    guard_output_path(state, out_path)?;
    let mut lines = Vec::new();
    lines.push("Strata Timeline Report".to_string());
    lines.push(format!(
        "Case: {}",
        state
            .case
            .as_ref()
            .map(|c| c.name.as_str())
            .unwrap_or("No Case")
    ));
    lines.push(format!("Examiner: {}", state.examiner_name));
    lines.push(format!("Events: {}", state.timeline_entries.len()));
    lines.push(format!("Suspicious: {}", state.suspicious_event_count));
    lines.push(String::new());

    for entry in &state.timeline_entries {
        lines.push(format!(
            "{} | {} | {} | suspicious={}",
            entry
                .timestamp
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            event_type_label(&entry.event_type),
            entry.path,
            entry.suspicious as u8
        ));
    }

    let generated = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut doc = PdfDocument::new("Timeline Report");
    let pages = paginate_pdf_lines(
        &lines,
        &state.examiner_name,
        state.case.as_ref().map(|c| c.id.as_str()).unwrap_or("-"),
        &generated,
        8.5,
        9.5,
        50,
    );
    let mut warnings = Vec::new();
    let bytes = doc
        .with_pages(pages)
        .save(&PdfSaveOptions::default(), &mut warnings);
    std::fs::write(out_path, bytes)?;
    Ok(())
}

pub fn export_case_pdf(state: &AppState, out_path: &Path) -> Result<()> {
    guard_output_path(state, out_path)?;
    let mut doc = PdfDocument::new("Strata Case Report");
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let chain_status = match verify_audit_chain(&state.audit_log) {
        ChainVerifyResult::Verified { count } => format!("VERIFIED ({} entries)", count),
        ChainVerifyResult::Broken { sequence, detail } => {
            format!("BROKEN at {} ({})", sequence, detail)
        }
    };

    let lines = vec![
        format!("Strata v{} - Case Report", env!("CARGO_PKG_VERSION")),
        format!(
            "Case: {}",
            state
                .case
                .as_ref()
                .map(|c| c.name.as_str())
                .unwrap_or("No Case")
        ),
        format!(
            "Case Number: {}",
            state.case.as_ref().map(|c| c.id.as_str()).unwrap_or("-")
        ),
        format!("Examiner: {}", state.examiner_name),
        format!("Generated (UTC): {}", now),
        format!("Evidence sources: {}", state.evidence_sources.len()),
        format!(
            "Indexed files: {}",
            state.file_index.iter().filter(|f| !f.is_dir).count()
        ),
        format!("Bookmarks: {}", state.bookmarks.len()),
        format!("Suspicious events: {}", state.suspicious_event_count),
        format!("Audit chain integrity: {}", chain_status),
        String::new(),
        "Evidence Summary:".to_string(),
    ];

    let mut lines = lines;
    for src in &state.evidence_sources {
        lines.push(format!(
            " - {} | format={} | sha256={} | verified={}",
            src.path,
            src.format,
            src.sha256.as_deref().unwrap_or("-"),
            if src.hash_verified { "YES" } else { "NO" }
        ));
    }
    lines.push(String::new());
    lines.push("Top 20 most recently modified files:".to_string());

    if let (Some(first), Some(last)) = (
        state.timeline_entries.first().map(|e| e.timestamp),
        state.timeline_entries.last().map(|e| e.timestamp),
    ) {
        lines.push(format!(
            "Timeline window: {} -> {}",
            first.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            last.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        ));
    }
    lines.push(format!(
        "Timeline events total: {}",
        state.timeline_entries.len()
    ));
    lines.push(format!(
        "Suspicious timeline events: {}",
        state.suspicious_event_count
    ));
    lines.push(String::new());
    lines.push("Top 50 suspicious events:".to_string());

    for event in state
        .timeline_entries
        .iter()
        .filter(|e| e.suspicious)
        .take(50)
    {
        lines.push(format!(
            "{} | {} | {}",
            event
                .timestamp
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            event_type_label(&event.event_type),
            event.path
        ));
    }
    lines.push(String::new());
    lines.push("Bookmarks (file + registry):".to_string());

    let mut bookmarks = state.bookmarks.clone();
    bookmarks.sort_by_key(|bm| (bm.tag.clone(), bookmark_target(state, bm)));
    for bm in bookmarks.iter().take(200) {
        if let Some(file_id) = &bm.file_id {
            if let Some(file) = state.file_index.iter().find(|f| &f.id == file_id) {
                lines.push(format!("[{}] Path: {}", bm.tag, file.path));
                lines.push(format!("  Size: {} bytes", file.size.unwrap_or(0)));
                lines.push(format!(
                    "  Created: {}",
                    file.created_utc.as_deref().unwrap_or("-")
                ));
                lines.push(format!(
                    "  Modified: {}",
                    file.modified_utc.as_deref().unwrap_or("-")
                ));
                lines.push(format!("  MD5: {}", file.md5.as_deref().unwrap_or("-")));
                lines.push(format!(
                    "  SHA-256: {}",
                    file.sha256.as_deref().unwrap_or("-")
                ));
                lines.push(format!(
                    "  Hash Match: {}",
                    file.hash_flag.as_deref().unwrap_or("None")
                ));
                lines.push(format!("  Examiner Note: {}", bm.note));
                continue;
            }
        }

        let target = bookmark_target(state, bm);
        lines.push(format!("[{}] {}", bm.tag, target));
        lines.push(format!("  Examiner Note: {}", bm.note));
    }
    lines.push(String::new());
    lines.push("Audit Log (latest 50):".to_string());
    for entry in state.audit_log.iter().rev().take(50) {
        lines.push(format!(
            "{} | {} | {}",
            entry.timestamp_utc, entry.action, entry.detail
        ));
    }
    lines.push(String::new());
    lines.push("Footer: Page 1 of 1".to_string());
    lines.push(format!(
        "Footer: Examiner {} | Case {}",
        state.examiner_name,
        state.case.as_ref().map(|c| c.id.as_str()).unwrap_or("-")
    ));

    let mut files: Vec<_> = state.file_index.iter().filter(|f| !f.is_dir).collect();
    files.sort_by(|a, b| b.modified_utc.cmp(&a.modified_utc));
    for file in files.into_iter().take(20) {
        let row = format!(
            "{}  {}",
            file.modified_utc.clone().unwrap_or_else(|| "-".to_string()),
            file.path
        );
        lines.push(row);
    }

    let pages = paginate_pdf_lines(
        &lines,
        &state.examiner_name,
        state.case.as_ref().map(|c| c.id.as_str()).unwrap_or("-"),
        &now,
        9.0,
        10.0,
        46,
    );
    let mut warnings = Vec::new();
    let bytes = doc
        .with_pages(pages)
        .save(&PdfSaveOptions::default(), &mut warnings);
    std::fs::write(out_path, bytes)?;
    Ok(())
}

pub fn export_case_html(state: &AppState, out_path: &Path) -> Result<()> {
    guard_output_path(state, out_path)?;
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let chain_status = match verify_audit_chain(&state.audit_log) {
        ChainVerifyResult::Verified { count } => format!("VERIFIED ({} entries)", count),
        ChainVerifyResult::Broken { sequence, detail } => {
            format!("BROKEN at {} ({})", sequence, detail)
        }
    };

    let case_name = state
        .case
        .as_ref()
        .map(|c| c.name.as_str())
        .unwrap_or("No Case");
    let case_id = state.case.as_ref().map(|c| c.id.as_str()).unwrap_or("-");
    let total_files = state.file_index.iter().filter(|f| !f.is_dir).count();
    let deleted_files = state.file_index.iter().filter(|f| f.is_deleted).count();
    let known_bad = state
        .file_index
        .iter()
        .filter(|f| f.hash_flag.as_deref() == Some("KnownBad"))
        .count();

    let mut evidence_rows = String::new();
    for src in &state.evidence_sources {
        let file_count = state
            .file_index
            .iter()
            .filter(|f| !f.is_dir && f.evidence_id == src.id)
            .count();
        evidence_rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&src.path),
            esc(&src.format),
            esc(src.sha256.as_deref().unwrap_or("-")),
            file_count,
            if src.hash_verified { "YES" } else { "NO" }
        ));
    }

    let mut bookmark_rows = String::new();
    let mut bookmarks = state.bookmarks.clone();
    bookmarks.sort_by_key(|bm| (bm.tag.clone(), bookmark_target(state, bm)));
    for bm in &bookmarks {
        bookmark_rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&bm.tag),
            esc(&bookmark_target(state, bm)),
            esc(&bm.note),
            esc(&bm.examiner),
        ));
    }

    let search_rows: String = state
        .search_results
        .iter()
        .take(100)
        .map(|hit| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&hit.query),
                esc(&hit.context),
                esc(&hit.hit_type),
            )
        })
        .collect();

    let mut suspicious_rows = String::new();
    for event in state
        .timeline_entries
        .iter()
        .filter(|e| e.suspicious)
        .take(50)
    {
        suspicious_rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&event
                .timestamp
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
            esc(event_type_label(&event.event_type)),
            esc(&event.path),
            esc(&event.detail),
        ));
    }

    let mut audit_rows = String::new();
    for entry in &state.audit_log {
        audit_rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td><td><code>{}</code></td></tr>",
            esc(&entry.timestamp_utc),
            esc(&entry.examiner),
            esc(&format!("{} | {}", entry.action, entry.detail)),
            esc(&entry.prev_hash),
            esc(&entry.entry_hash),
        ));
    }

    let obstruction_section = build_obstruction_html(state);

    let wolf_svg = wolf_head_svg_inline();

    let html = format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>Strata Case Report</title>
  <style>
    body {{ font-family: Consolas, "Courier New", monospace; margin: 18px; color: #111622; background: #ffffff; }}
    h1, h2 {{ margin: 0 0 10px 0; }}
    h1 {{ font-size: 20px; color: #1a2e44; }}
    h2 {{ font-size: 16px; margin-top: 20px; border-top: 2px solid #8fa8c0; padding-top: 8px; color: #1a2e44; }}
    .meta {{ margin-bottom: 14px; }}
    .meta div {{ margin: 3px 0; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 8px; }}
    th, td {{ border: 1px solid #8fa8c0; padding: 6px 8px; text-align: left; vertical-align: top; font-size: 12px; }}
    th {{ background: #eef2f7; color: #1a2e44; }}
    .appendix {{ border: 2px solid #1a2e44; padding: 10px; margin-top: 20px; }}
    .report-header {{ display: flex; align-items: center; gap: 12px; margin-bottom: 20px; padding-bottom: 16px; border-bottom: 2px solid #8fa8c0; }}
    .report-header svg {{ flex-shrink: 0; }}
    .report-header-text h1 {{ margin: 0; font-size: 20px; color: #1a2e44; }}
    .report-header-text p {{ margin: 2px 0 0; font-size: 12px; color: #4a6080; }}
    .badge-critical {{ color: #b85050; font-weight: bold; }}
    .badge-warning {{ color: #c8855a; font-weight: bold; }}
    .badge-clean {{ color: #5a9068; font-weight: bold; }}
  </style>
</head>
<body>
  <div class="report-header">
    {}
    <div class="report-header-text">
      <h1>STRATA</h1>
      <p>Wolfmark Systems &middot; Forensic Analysis Report</p>
    </div>
  </div>

  <h2>Section 1 - Case Header</h2>
  <div class="meta">
    <div><strong>Case Name:</strong> {}</div>
    <div><strong>Case Number:</strong> {}</div>
    <div><strong>Examiner:</strong> {}</div>
    <div><strong>Generated UTC:</strong> {}</div>
    <div><strong>Tool Version:</strong> Strata v{}</div>
    <div><strong>Audit Chain:</strong> {}</div>
  </div>

  <h2>Section 2 - Evidence Integrity</h2>
  <table>
    <tr><th>Path</th><th>Format</th><th>SHA-256</th><th>Files</th><th>Verified</th></tr>
    {}
  </table>

  <h2>Section 3 - Examination Summary</h2>
  <table>
    <tr><th>Total Indexed Files</th><td>{}</td></tr>
    <tr><th>Deleted Files</th><td>{}</td></tr>
    <tr><th>Known-Bad Hash Matches</th><td>{}</td></tr>
    <tr><th>Bookmarks</th><td>{}</td></tr>
    <tr><th>Search Hits</th><td>{}</td></tr>
    <tr><th>Timeline Events</th><td>{}</td></tr>
    <tr><th>Suspicious Events</th><td>{}</td></tr>
  </table>

  {}

  <h2>Section 4 - Bookmarked Items</h2>
  <table>
    <tr><th>Tag</th><th>Target</th><th>Note</th><th>Examiner</th></tr>
    {}
  </table>

  <h2>Section 5 - Search Results</h2>
  <table>
    <tr><th>Query</th><th>Context</th><th>Type</th></tr>
    {}
  </table>

  <h2>Section 6 - Timeline (Top 50 Suspicious)</h2>
  <table>
    <tr><th>Timestamp UTC</th><th>Type</th><th>Path</th><th>Detail</th></tr>
    {}
  </table>

  <h2>Section 7 - Methodology</h2>
  <ul>
    <li>Evidence processed in read-only mode.</li>
    <li>File metadata indexed from supported parsers.</li>
    <li>Hashes computed using MD5 and SHA-256 where requested.</li>
    <li>Timestamps displayed in UTC.</li>
  </ul>

  <h2>Section 8 - Limitations and Examiner Attestation</h2>
  <ul>
    <li>Parser coverage depends on source format and available metadata.</li>
    <li>Findings should be corroborated by examiner review.</li>
    <li>This report reflects current case state at export time.</li>
  </ul>
  <p><strong>Attestation:</strong> Examiner {}</p>

  <div class="appendix">
    <h2>Appendix A - Audit Log</h2>
    <p>Audit chain status: <strong>{}</strong></p>
    <table>
      <tr><th>Timestamp UTC</th><th>Examiner</th><th>Action</th><th>Prev Hash</th><th>Entry Hash</th></tr>
      {}
    </table>
  </div>
</body>
</html>"#,
        wolf_svg,
        esc(case_name),
        esc(case_id),
        esc(&state.examiner_name),
        esc(&now),
        env!("CARGO_PKG_VERSION"),
        esc(&chain_status),
        evidence_rows,
        total_files,
        deleted_files,
        known_bad,
        state.bookmarks.len(),
        state.search_results.len(),
        state.timeline_entries.len(),
        state.suspicious_event_count,
        obstruction_section,
        bookmark_rows,
        search_rows,
        suspicious_rows,
        esc(&state.examiner_name),
        esc(&chain_status),
        audit_rows,
    );

    std::fs::write(out_path, html)?;
    Ok(())
}

pub fn export_audit_csv(state: &AppState, out_path: &Path) -> Result<()> {
    guard_output_path(state, out_path)?;
    let mut f = std::fs::File::create(out_path)?;
    write_csv_metadata_header(&mut f, state)?;
    writeln!(
        f,
        "id,sequence,timestamp_utc,examiner,action,detail,evidence_id,file_path,prev_hash,entry_hash"
    )?;
    for entry in &state.audit_log {
        writeln!(
            f,
            "{},{},{},{},{},{},{},{},{},{}",
            csv(&entry.id),
            entry.sequence,
            csv(&entry.timestamp_utc),
            csv(&entry.examiner),
            csv(&entry.action),
            csv(&entry.detail),
            csv(entry.evidence_id.as_deref().unwrap_or("")),
            csv(entry.file_path.as_deref().unwrap_or("")),
            csv(&entry.prev_hash),
            csv(&entry.entry_hash),
        )?;
    }
    Ok(())
}

pub fn export_audit_json(state: &AppState, out_path: &Path) -> Result<()> {
    guard_output_path(state, out_path)?;
    let mut rows = Vec::with_capacity(state.audit_log.len());
    for entry in &state.audit_log {
        rows.push(serde_json::json!({
            "id": entry.id,
            "sequence": entry.sequence,
            "timestamp_utc": entry.timestamp_utc,
            "examiner": entry.examiner,
            "action": entry.action,
            "detail": entry.detail,
            "evidence_id": entry.evidence_id,
            "file_path": entry.file_path,
            "prev_hash": entry.prev_hash,
            "entry_hash": entry.entry_hash,
        }));
    }
    std::fs::write(out_path, serde_json::to_string_pretty(&rows)?)?;
    Ok(())
}

pub fn export_audit_pdf(state: &AppState, out_path: &Path) -> Result<()> {
    guard_output_path(state, out_path)?;
    let chain_status = match verify_audit_chain(&state.audit_log) {
        ChainVerifyResult::Verified { count } => format!("VERIFIED ({} entries)", count),
        ChainVerifyResult::Broken { sequence, detail } => {
            format!("BROKEN at {} ({})", sequence, detail)
        }
    };
    let mut lines = vec![
        "Strata Audit Log".to_string(),
        format!(
            "Case: {}",
            state.case.as_ref().map(|c| c.name.as_str()).unwrap_or("-")
        ),
        format!("Examiner: {}", state.examiner_name),
        format!("Chain integrity: {}", chain_status),
        String::new(),
    ];
    for entry in &state.audit_log {
        lines.push(format!(
            "{} | {} | {} | prev={} entry={}",
            entry.timestamp_utc,
            entry.action,
            entry.detail,
            &entry.prev_hash.chars().take(16).collect::<String>(),
            &entry.entry_hash.chars().take(16).collect::<String>(),
        ));
    }

    let generated = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut doc = PdfDocument::new("Audit Log");
    let pages = paginate_pdf_lines(
        &lines,
        &state.examiner_name,
        state.case.as_ref().map(|c| c.id.as_str()).unwrap_or("-"),
        &generated,
        8.5,
        9.5,
        50,
    );
    let mut warnings = Vec::new();
    let bytes = doc
        .with_pages(pages)
        .save(&PdfSaveOptions::default(), &mut warnings);
    std::fs::write(out_path, bytes)?;
    Ok(())
}

fn bookmark_target(state: &AppState, bm: &crate::state::Bookmark) -> String {
    if let Some(reg) = &bm.registry_path {
        return format!("[REG] {}", reg);
    }
    if let Some(fid) = &bm.file_id {
        if let Some(file) = state.file_index.iter().find(|f| &f.id == fid) {
            return file.path.clone();
        }
        return fid.clone();
    }
    "-".to_string()
}

fn event_type_label(event: &TimelineEventType) -> &'static str {
    match event {
        TimelineEventType::FileCreated => "FileCreated",
        TimelineEventType::FileModified => "FileModified",
        TimelineEventType::FileAccessed => "FileAccessed",
        TimelineEventType::FileMftModified => "FileMftModified",
        TimelineEventType::FileDeleted => "FileDeleted",
        TimelineEventType::RegistryKeyCreated => "RegistryKeyCreated",
        TimelineEventType::RegistryKeyModified => "RegistryKeyModified",
        TimelineEventType::RegistryValueSet => "RegistryValueSet",
        TimelineEventType::ProcessExecuted => "ProcessExecuted",
        TimelineEventType::UserLogin => "UserLogin",
        TimelineEventType::UserActivity => "UserActivity",
        TimelineEventType::WebVisit => "WebVisit",
    }
}

fn csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn write_csv_metadata_header(file: &mut std::fs::File, state: &AppState) -> Result<()> {
    let case_name = state
        .case
        .as_ref()
        .map(|c| c.name.as_str())
        .unwrap_or("No Case");
    let case_number = state.case.as_ref().map(|c| c.id.as_str()).unwrap_or("-");
    let generated = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    writeln!(file, "# examiner={}", csv(&state.examiner_name))?;
    writeln!(file, "# case_name={}", csv(case_name))?;
    writeln!(file, "# case_number={}", csv(case_number))?;
    writeln!(file, "# generated_utc={}", csv(&generated))?;
    Ok(())
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn guard_output_path(state: &AppState, out_path: &Path) -> Result<()> {
    state
        .ensure_output_path_safe(out_path)
        .map_err(anyhow::Error::msg)
}

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

        for line in &lines[start..end] {
            ops.push(Op::ShowText {
                items: vec![TextItem::Text(line.clone())],
            });
            ops.push(Op::AddLineBreak);
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

/// Inline SVG wolf head mark for HTML reports.
fn build_obstruction_html(state: &AppState) -> String {
    let assessment = match &state.obstruction_assessment {
        Some(a) if a.score > 0 => a,
        _ => return String::new(),
    };

    let severity_color = match assessment.score {
        0..=20 => "#888",
        21..=40 => "#5a9068",
        41..=60 => "#c8855a",
        61..=80 => "#e07030",
        _ => "#b85050",
    };

    let mut factor_rows = String::new();
    for f in &assessment.factors {
        let ts = f.timestamp.as_deref().unwrap_or("-");
        let mult = f
            .multiplier_applied
            .as_deref()
            .unwrap_or("none");
        factor_rows.push_str(&format!(
            "<tr><td>+{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            f.applied_weight,
            esc(&f.description),
            esc(&f.artifact_detail),
            esc(ts),
            esc(mult),
        ));
    }

    format!(
        r#"<h2>Section 3b - Anti-Forensic Activity Assessment</h2>
  <div style="border:2px solid {color}; padding:10px; margin:8px 0;">
    <p><strong>Obstruction Score:</strong> <span style="color:{color}; font-size:18px;">{score}/100</span>
       &nbsp;&mdash;&nbsp; <span style="color:{color}; font-weight:bold;">{severity}</span></p>
    <p>{interpretation}</p>
    <table>
      <tr><th>Weight</th><th>Factor</th><th>Detail</th><th>Timestamp</th><th>Multiplier</th></tr>
      {rows}
    </table>
    <p style="margin-top:10px; font-size:11px; color:#666; border-top:1px solid #ccc; padding-top:6px;">
      {advisory}
    </p>
  </div>"#,
        color = severity_color,
        score = assessment.score,
        severity = assessment.severity.label(),
        interpretation = esc(&assessment.interpretation),
        rows = factor_rows,
        advisory = esc(&assessment.advisory_notice),
    )
}

fn wolf_head_svg_inline() -> &'static str {
    r##"<svg width="40" height="40" viewBox="0 0 28 28" fill="none" xmlns="http://www.w3.org/2000/svg">
      <polygon points="4,14 7,3 11,11" fill="#8fa8c0" opacity="0.9"/>
      <polygon points="5,13 7,5 10,11" fill="#1a2e44"/>
      <polygon points="24,14 21,3 17,11" fill="#8fa8c0" opacity="0.9"/>
      <polygon points="23,13 21,5 18,11" fill="#1a2e44"/>
      <polygon points="14,2 22,8 24,15 20,22 14,26 8,22 4,15 6,8" fill="#1a2e44" stroke="#8fa8c0" stroke-width="0.8"/>
      <polygon points="14,4 18,8 14,11 10,8" fill="#2a3a55" stroke="#8fa8c0" stroke-width="0.4"/>
      <polygon points="8,11 10,10 12,12 10,14 7,13" fill="#111622"/>
      <polygon points="9,11 10,10 11,12 10,13 8,12" fill="#4a6080"/>
      <polygon points="20,11 18,10 16,12 18,14 21,13" fill="#111622"/>
      <polygon points="19,11 18,10 17,12 18,13 20,12" fill="#4a6080"/>
      <polygon points="13,16 14,14 15,16 14,18" fill="#8fa8c0" opacity="0.7"/>
      <polygon points="10,21 14,19 18,21 16,25 12,25" fill="#2a3a55" stroke="#8fa8c0" stroke-width="0.4"/>
      <line x1="14" y1="4" x2="14" y2="14" stroke="#8fa8c0" stroke-width="0.3" opacity="0.25"/>
    </svg>"##
}

#[cfg(test)]
mod tests {
    use super::export_case_html;
    use crate::state::{ActiveCase, AppState};

    #[test]
    fn html_report_contains_eight_sections_and_audit_appendix() {
        let root = std::env::temp_dir().join(format!(
            "strata_export_html_test_{}",
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::create_dir_all(&root);
        let out_path = root.join("case_report.html");

        let mut state = AppState {
            case: Some(ActiveCase {
                name: "HTML Export Test".to_string(),
                id: "CASE-001".to_string(),
                agency: String::new(),
                path: root.join("case.vtp").to_string_lossy().to_string(),
            }),
            examiner_name: "Examiner".to_string(),
            ..AppState::default()
        };
        state.log_action("TEST_ACTION", "verifying html report content");

        export_case_html(&state, &out_path).expect("export html");
        let html = std::fs::read_to_string(&out_path).expect("read html");

        assert!(html.contains("Section 1 - Case Header"));
        assert!(html.contains("Section 2 - Evidence Integrity"));
        assert!(html.contains("Section 3 - Examination Summary"));
        assert!(html.contains("Section 4 - Bookmarked Items"));
        assert!(html.contains("Section 5 - Search Results"));
        assert!(html.contains("Section 6 - Timeline (Top 50 Suspicious)"));
        assert!(html.contains("Section 7 - Methodology"));
        assert!(html.contains("Section 8 - Limitations and Examiner Attestation"));
        assert!(html.contains("Appendix A - Audit Log"));

        let _ = std::fs::remove_file(&out_path);
        let _ = std::fs::remove_dir_all(&root);
    }
}
