//! Compare view — multi-evidence diff and export.

use std::io::Write;
use std::path::Path;

use crate::state::{colors::*, diff_evidence, AppState, CompareFilter};
use printpdf::*;

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("COMPARE")
                .color(ACCENT)
                .size(11.0)
                .strong(),
        );
        ui.separator();
        ui.label(
            egui::RichText::new("Evidence A vs Evidence B")
                .color(TEXT_MUTED)
                .size(9.5),
        );
    });
    ui.add_space(4.0);

    ui.columns(2, |cols| {
        render_selector(&mut cols[0], state);
        render_results(&mut cols[1], state);
    });
}

fn render_selector(ui: &mut egui::Ui, state: &mut AppState) {
    ui.label(
        egui::RichText::new("Select Evidence A")
            .color(TEXT_MUTED)
            .size(8.5),
    );
    egui::ComboBox::from_id_source("compare_a")
        .selected_text(selected_label(&state.compare_a_id))
        .show_ui(ui, |ui| {
            for src in &state.evidence_sources {
                ui.selectable_value(
                    &mut state.compare_a_id,
                    Some(src.id.clone()),
                    src.id.clone(),
                );
            }
        });

    ui.add_space(4.0);
    ui.label(
        egui::RichText::new("Select Evidence B")
            .color(TEXT_MUTED)
            .size(8.5),
    );
    egui::ComboBox::from_id_source("compare_b")
        .selected_text(selected_label(&state.compare_b_id))
        .show_ui(ui, |ui| {
            for src in &state.evidence_sources {
                ui.selectable_value(
                    &mut state.compare_b_id,
                    Some(src.id.clone()),
                    src.id.clone(),
                );
            }
        });

    ui.add_space(8.0);
    if ui.button("RUN COMPARISON").clicked() {
        if let (Some(a), Some(b)) = (state.compare_a_id.clone(), state.compare_b_id.clone()) {
            let diff = diff_evidence(&state.file_index, &a, &b);
            for (left, right) in &diff.modified {
                if left.sha256.is_some()
                    && right.sha256.is_some()
                    && left.sha256 == right.sha256
                    && left.modified_utc != right.modified_utc
                {
                    state.log_action(
                        "TIMESTOMPING_INDICATOR",
                        &format!(
                            "path={} modified_a={:?} modified_b={:?}",
                            left.path, left.modified_utc, right.modified_utc
                        ),
                    );
                }
            }
            state.compare_result = Some(diff);
            state.mark_case_dirty();
            save_case_compare_result(state);
            state.log_action("COMPARE_RUN", &format!("evidence_a={} evidence_b={}", a, b));
        }
    }
}

fn render_results(ui: &mut egui::Ui, state: &mut AppState) {
    let Some(diff) = state.compare_result.clone() else {
        ui.label(egui::RichText::new("Run a comparison to view results.").color(TEXT_MUTED));
        return;
    };

    ui.horizontal_wrapped(|ui| {
        ui.label(egui::RichText::new(format!("{} added", diff.only_in_b.len())).color(GREEN_OK));
        ui.separator();
        ui.label(egui::RichText::new(format!("{} deleted", diff.only_in_a.len())).color(DANGER));
        ui.separator();
        ui.label(egui::RichText::new(format!("{} modified", diff.modified.len())).color(AMBER));
        ui.separator();
        ui.label(
            egui::RichText::new(format!("{} identical", diff.identical.len())).color(TEXT_MUTED),
        );
    });

    ui.horizontal(|ui| {
        ui.selectable_value(&mut state.compare_filter, CompareFilter::All, "SHOW ALL");
        ui.selectable_value(&mut state.compare_filter, CompareFilter::Added, "ADDED");
        ui.selectable_value(&mut state.compare_filter, CompareFilter::Deleted, "DELETED");
        ui.selectable_value(
            &mut state.compare_filter,
            CompareFilter::Modified,
            "MODIFIED",
        );
        ui.selectable_value(
            &mut state.compare_filter,
            CompareFilter::Identical,
            "IDENTICAL",
        );
    });

    ui.horizontal(|ui| {
        if ui.button("Export CSV").clicked() {
            if let Some(path) = rfd::FileDialog::new()
                .set_file_name("evidence_diff.csv")
                .save_file()
            {
                match export_diff_csv(state, &diff, &path) {
                    Ok(()) => {
                        state.status = format!("Diff CSV exported: {}", path.display());
                        state.log_action(
                            "COMPARE_EXPORT",
                            &format!("format=csv path={}", path.display()),
                        );
                    }
                    Err(err) => {
                        state.status = format!("Diff CSV export failed: {}", err);
                    }
                }
            }
        }
        if ui.button("Export PDF").clicked() {
            if let Some(path) = rfd::FileDialog::new()
                .set_file_name("evidence_diff.pdf")
                .save_file()
            {
                match export_diff_pdf(&diff, state, &path) {
                    Ok(()) => {
                        state.status = format!("Diff PDF exported: {}", path.display());
                        state.log_action(
                            "COMPARE_EXPORT",
                            &format!("format=pdf path={}", path.display()),
                        );
                    }
                    Err(err) => {
                        state.status = format!("Diff PDF export failed: {}", err);
                    }
                }
            }
        }
    });

    ui.separator();
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("STATUS")
                .color(TEXT_MUTED)
                .size(8.0)
                .strong(),
        );
        ui.add_space(40.0);
        ui.label(
            egui::RichText::new("PATH")
                .color(TEXT_MUTED)
                .size(8.0)
                .strong(),
        );
        ui.add_space(16.0);
        ui.label(
            egui::RichText::new("DETAIL")
                .color(TEXT_MUTED)
                .size(8.0)
                .strong(),
        );
    });
    ui.separator();
    egui::ScrollArea::vertical()
        .id_source("compare_rows")
        .show(ui, |ui| {
            if state.compare_filter == CompareFilter::All
                || state.compare_filter == CompareFilter::Added
            {
                for entry in &diff.only_in_b {
                    render_diff_row(ui, state, "ADDED", entry, GREEN_OK);
                }
            }
            if state.compare_filter == CompareFilter::All
                || state.compare_filter == CompareFilter::Deleted
            {
                for entry in &diff.only_in_a {
                    render_diff_row(ui, state, "DELETED", entry, DANGER);
                }
            }
            if state.compare_filter == CompareFilter::All
                || state.compare_filter == CompareFilter::Modified
            {
                for (a, b) in &diff.modified {
                    render_modified_row(ui, state, a, b);
                }
            }
            if state.compare_filter == CompareFilter::All
                || state.compare_filter == CompareFilter::Identical
            {
                for entry in &diff.identical {
                    render_diff_row(ui, state, "IDENTICAL", entry, TEXT_MUTED);
                }
            }
        });
}

fn selected_label(id: &Option<String>) -> String {
    id.clone().unwrap_or_else(|| "(select)".to_string())
}

fn render_diff_row(
    ui: &mut egui::Ui,
    state: &mut AppState,
    status: &str,
    file: &crate::state::FileEntry,
    color: egui::Color32,
) {
    let detail = format!(
        "size={} modified={}",
        file.size.unwrap_or(0),
        file.modified_utc.as_deref().unwrap_or("-")
    );
    let response = draw_bordered_row(ui, color, status, &file.path, &detail);
    response.context_menu(|ui| {
        if ui.button("Open in File Explorer").clicked() {
            navigate_to_file(state, file);
            ui.close_menu();
        }
        if ui.button("Copy Path").clicked() {
            ui.ctx().copy_text(file.path.clone());
            ui.close_menu();
        }
    });
    if response.clicked() {
        navigate_to_file(state, file);
    }
}

fn render_modified_row(
    ui: &mut egui::Ui,
    state: &mut AppState,
    a: &crate::state::FileEntry,
    b: &crate::state::FileEntry,
) {
    let hash_a = a.sha256.as_deref().unwrap_or("-");
    let hash_b = b.sha256.as_deref().unwrap_or("-");
    let mod_a = a.modified_utc.as_deref().unwrap_or("-");
    let mod_b = b.modified_utc.as_deref().unwrap_or("-");

    let detail = if a.sha256 == b.sha256 && a.modified_utc != b.modified_utc {
        format!(
            "size:{}->{} mtime:{}->{} hash:same (timestomping indicator)",
            a.size.unwrap_or(0),
            b.size.unwrap_or(0),
            mod_a,
            mod_b
        )
    } else {
        format!(
            "size:{}->{} mtime:{}->{} hash:{}->{}",
            a.size.unwrap_or(0),
            b.size.unwrap_or(0),
            mod_a,
            mod_b,
            hash_a,
            hash_b
        )
    };

    let response = draw_bordered_row(ui, AMBER, "MODIFIED", &a.path, &detail);
    response.context_menu(|ui| {
        if ui.button("Open in File Explorer").clicked() {
            navigate_to_file(state, a);
            ui.close_menu();
        }
        if ui.button("Copy Path").clicked() {
            ui.ctx().copy_text(a.path.clone());
            ui.close_menu();
        }
    });
    if response.clicked() {
        navigate_to_file(state, a);
    }
}

fn draw_bordered_row(
    ui: &mut egui::Ui,
    border_color: egui::Color32,
    status: &str,
    path: &str,
    detail: &str,
) -> egui::Response {
    let response = egui::Frame::none()
        .fill(egui::Color32::from_rgba_unmultiplied(5, 12, 21, 220))
        .stroke(egui::Stroke::new(1.0, BORDER_SUBTLE))
        .inner_margin(egui::Margin::symmetric(6.0, 4.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(status)
                        .color(border_color)
                        .size(8.2)
                        .strong(),
                );
                ui.add_space(10.0);
                ui.label(egui::RichText::new(path).color(TEXT_PRI).size(8.2));
                ui.add_space(10.0);
                ui.label(
                    egui::RichText::new(detail)
                        .color(TEXT_MUTED)
                        .size(7.8)
                        .monospace(),
                );
            });
        })
        .response
        .interact(egui::Sense::click());

    let rect = response.rect;
    ui.painter().line_segment(
        [rect.left_top(), rect.left_bottom()],
        egui::Stroke::new(2.5, border_color),
    );
    response
}

fn navigate_to_file(state: &mut AppState, file: &crate::state::FileEntry) {
    state.selected_file_id = Some(file.id.clone());
    state.selected_tree_path = Some(file.parent_path.clone());
    state.file_filter = file.parent_path.clone();
    state.mark_filter_dirty();
    state.view_mode = crate::state::ViewMode::FileExplorer;
}

fn export_diff_csv(
    state: &AppState,
    diff: &crate::state::EvidenceDiff,
    path: &Path,
) -> anyhow::Result<()> {
    state
        .ensure_output_path_safe(path)
        .map_err(anyhow::Error::msg)?;
    let mut f = std::fs::File::create(path)?;
    writeln!(
        f,
        "status,path,size_a,size_b,hash_a,hash_b,modified_a,modified_b,timestomp_indicator"
    )?;
    for a in &diff.only_in_a {
        writeln!(
            f,
            "deleted,{},{},,,{},,0",
            csv(&a.path),
            a.size.unwrap_or(0),
            csv(a.modified_utc.as_deref().unwrap_or(""))
        )?;
    }
    for b in &diff.only_in_b {
        writeln!(
            f,
            "added,{},,{},,,{},,0",
            csv(&b.path),
            b.size.unwrap_or(0),
            csv(b.modified_utc.as_deref().unwrap_or(""))
        )?;
    }
    for (a, b) in &diff.modified {
        let timestomp = a.sha256 == b.sha256 && a.modified_utc != b.modified_utc;
        writeln!(
            f,
            "modified,{},{},{},{},{},{},{},{}",
            csv(&a.path),
            a.size.unwrap_or(0),
            b.size.unwrap_or(0),
            csv(a.sha256.as_deref().unwrap_or("")),
            csv(b.sha256.as_deref().unwrap_or("")),
            csv(a.modified_utc.as_deref().unwrap_or("")),
            csv(b.modified_utc.as_deref().unwrap_or("")),
            timestomp as u8,
        )?;
    }
    Ok(())
}

fn export_diff_pdf(
    diff: &crate::state::EvidenceDiff,
    state: &AppState,
    path: &Path,
) -> anyhow::Result<()> {
    state
        .ensure_output_path_safe(path)
        .map_err(anyhow::Error::msg)?;
    let mut doc = PdfDocument::new("Evidence Comparison Report");
    let source_a = state
        .evidence_sources
        .iter()
        .find(|s| s.id == diff.evidence_a_id);
    let source_b = state
        .evidence_sources
        .iter()
        .find(|s| s.id == diff.evidence_b_id);
    let count_a = state
        .file_index
        .iter()
        .filter(|f| !f.is_dir && f.evidence_id == diff.evidence_a_id)
        .count();
    let count_b = state
        .file_index
        .iter()
        .filter(|f| !f.is_dir && f.evidence_id == diff.evidence_b_id)
        .count();
    let mut ops = vec![
        Op::StartTextSection,
        Op::SetFont {
            font: PdfFontHandle::Builtin(BuiltinFont::CourierBold),
            size: Pt(12.0),
        },
        Op::SetLineHeight { lh: Pt(12.0) },
        Op::SetTextCursor {
            pos: Point::new(Mm(15.0), Mm(280.0)),
        },
        Op::ShowText {
            items: vec![TextItem::Text("Evidence Comparison Report".to_string())],
        },
        Op::AddLineBreak,
        Op::SetFont {
            font: PdfFontHandle::Builtin(BuiltinFont::Courier),
            size: Pt(9.0),
        },
        Op::ShowText {
            items: vec![TextItem::Text(format!(
                "Generated UTC: {}",
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            ))],
        },
        Op::AddLineBreak,
        Op::ShowText {
            items: vec![TextItem::Text(format!(
                "Evidence A: {}",
                diff.evidence_a_id
            ))],
        },
        Op::AddLineBreak,
        Op::ShowText {
            items: vec![TextItem::Text(format!(
                "A Path: {}",
                source_a.map(|s| s.path.as_str()).unwrap_or("-")
            ))],
        },
        Op::AddLineBreak,
        Op::ShowText {
            items: vec![TextItem::Text(format!(
                "A SHA-256: {}",
                source_a.and_then(|s| s.sha256.as_deref()).unwrap_or("-")
            ))],
        },
        Op::AddLineBreak,
        Op::ShowText {
            items: vec![TextItem::Text(format!("A File Count: {}", count_a))],
        },
        Op::AddLineBreak,
        Op::ShowText {
            items: vec![TextItem::Text(format!(
                "Evidence B: {}",
                diff.evidence_b_id
            ))],
        },
        Op::AddLineBreak,
        Op::ShowText {
            items: vec![TextItem::Text(format!(
                "B Path: {}",
                source_b.map(|s| s.path.as_str()).unwrap_or("-")
            ))],
        },
        Op::AddLineBreak,
        Op::ShowText {
            items: vec![TextItem::Text(format!(
                "B SHA-256: {}",
                source_b.and_then(|s| s.sha256.as_deref()).unwrap_or("-")
            ))],
        },
        Op::AddLineBreak,
        Op::ShowText {
            items: vec![TextItem::Text(format!("B File Count: {}", count_b))],
        },
        Op::AddLineBreak,
        Op::ShowText {
            items: vec![TextItem::Text(format!(
                "Added={} Deleted={} Modified={} Identical={}",
                diff.only_in_b.len(),
                diff.only_in_a.len(),
                diff.modified.len(),
                diff.identical.len()
            ))],
        },
        Op::AddLineBreak,
        Op::AddLineBreak,
        Op::ShowText {
            items: vec![TextItem::Text(format!(
                "Examiner signature: {}",
                state.examiner_name
            ))],
        },
        Op::AddLineBreak,
    ];

    for a in diff.only_in_a.iter().take(200) {
        ops.push(Op::ShowText {
            items: vec![TextItem::Text(format!("DELETED {}", a.path))],
        });
        ops.push(Op::AddLineBreak);
    }
    for b in diff.only_in_b.iter().take(200) {
        ops.push(Op::ShowText {
            items: vec![TextItem::Text(format!("ADDED {}", b.path))],
        });
        ops.push(Op::AddLineBreak);
    }
    for (a, b) in diff.modified.iter().take(200) {
        ops.push(Op::ShowText {
            items: vec![TextItem::Text(format!(
                "MODIFIED {} size:{}->{} mtime:{:?}->{:?}",
                a.path,
                a.size.unwrap_or(0),
                b.size.unwrap_or(0),
                a.modified_utc,
                b.modified_utc
            ))],
        });
        ops.push(Op::AddLineBreak);
    }
    ops.push(Op::EndTextSection);

    let page = PdfPage::new(Mm(210.0), Mm(297.0), ops);
    let mut warnings = Vec::new();
    let bytes = doc
        .with_pages(vec![page])
        .save(&PdfSaveOptions::default(), &mut warnings);
    std::fs::write(path, bytes)?;
    Ok(())
}

fn csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn save_case_compare_result(state: &AppState) {
    let Some(case_path) = state.case.as_ref().map(|c| c.path.clone()) else {
        return;
    };
    if case_path.is_empty() {
        return;
    }
    let Some(diff) = state.compare_result.as_ref() else {
        return;
    };
    let Ok(project) = crate::case::project::VtpProject::open(&case_path) else {
        return;
    };
    let Ok(json) = serde_json::to_string(diff) else {
        return;
    };
    let _ = project.set_meta("compare_result_json", &json);
    if let Some(a) = &state.compare_a_id {
        let _ = project.set_meta("compare_a_id", a);
    }
    if let Some(b) = &state.compare_b_id {
        let _ = project.set_meta("compare_b_id", b);
    }
}
