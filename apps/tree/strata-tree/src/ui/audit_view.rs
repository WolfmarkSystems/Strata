//! Audit Log view — append-only examiner activity log.

use crate::state::{colors::*, verify_audit_chain, AppState, ChainVerifyResult};
use egui::ScrollArea;

#[derive(Default)]
struct AuditUiState {
    last_seen_signature: String,
}

thread_local! {
    static UI_STATE: std::cell::RefCell<AuditUiState> =
        std::cell::RefCell::new(AuditUiState::default());
}

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    log_chain_status_if_changed(state);

    // ── Header ────────────────────────────────────────────────────────────────
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("AUDIT LOG")
                .color(ACCENT)
                .size(11.0)
                .strong(),
        );
        ui.separator();
        ui.label(
            egui::RichText::new(format!("{} entries", state.audit_log.len()))
                .color(TEXT_MUTED)
                .size(9.5),
        );
        ui.separator();
        match verify_audit_chain(&state.audit_log) {
            ChainVerifyResult::Verified { count } => {
                ui.label(
                    egui::RichText::new(format!("Chain integrity: VERIFIED ({})", count))
                        .color(GREEN_OK)
                        .size(8.8)
                        .strong(),
                );
            }
            ChainVerifyResult::Broken { sequence, detail } => {
                ui.label(
                    egui::RichText::new(format!("CHAIN BROKEN at entry {} ({})", sequence, detail))
                        .color(DANGER)
                        .size(8.8)
                        .strong(),
                );
            }
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(
                egui::RichText::new("Read-only · Append-only")
                    .color(AMBER)
                    .size(8.5),
            );
        });
    });
    ui.horizontal(|ui| {
        if ui.button("Export CSV").clicked() {
            if let Some(path) = rfd::FileDialog::new()
                .set_file_name("audit_log.csv")
                .save_file()
            {
                match crate::ui::export::export_audit_csv(state, &path) {
                    Ok(()) => {
                        state.status = format!("Audit CSV exported: {}", path.display());
                        state.log_action("AUDIT_EXPORT", &format!("csv={}", path.display()));
                    }
                    Err(err) => {
                        state.status = format!("Audit CSV export failed: {}", err);
                    }
                }
            }
        }
        if ui.button("Export JSON").clicked() {
            if let Some(path) = rfd::FileDialog::new()
                .set_file_name("audit_log.json")
                .save_file()
            {
                match crate::ui::export::export_audit_json(state, &path) {
                    Ok(()) => {
                        state.status = format!("Audit JSON exported: {}", path.display());
                        state.log_action("AUDIT_EXPORT", &format!("json={}", path.display()));
                    }
                    Err(err) => {
                        state.status = format!("Audit JSON export failed: {}", err);
                    }
                }
            }
        }
        if ui.button("Export PDF").clicked() {
            if let Some(path) = rfd::FileDialog::new()
                .set_file_name("audit_log.pdf")
                .save_file()
            {
                match crate::ui::export::export_audit_pdf(state, &path) {
                    Ok(()) => {
                        state.status = format!("Audit PDF exported: {}", path.display());
                        state.log_action("AUDIT_EXPORT", &format!("pdf={}", path.display()));
                    }
                    Err(err) => {
                        state.status = format!("Audit PDF export failed: {}", err);
                    }
                }
            }
        }
    });
    ui.add_space(2.0);

    // Column headers.
    egui::Grid::new("audit_hdr")
        .num_columns(5)
        .spacing([8.0, 3.0])
        .min_col_width(60.0)
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new("TIMESTAMP (UTC)")
                    .color(TEXT_MUTED)
                    .size(8.5)
                    .strong(),
            );
            ui.label(
                egui::RichText::new("ACTION")
                    .color(TEXT_MUTED)
                    .size(8.5)
                    .strong(),
            );
            ui.label(
                egui::RichText::new("DETAIL")
                    .color(TEXT_MUTED)
                    .size(8.5)
                    .strong(),
            );
            ui.label(
                egui::RichText::new("PREV HASH")
                    .color(TEXT_MUTED)
                    .size(8.5)
                    .strong(),
            );
            ui.label(
                egui::RichText::new("ENTRY HASH")
                    .color(TEXT_MUTED)
                    .size(8.5)
                    .strong(),
            );
            ui.end_row();
        });
    ui.add(egui::Separator::default());

    if state.audit_log.is_empty() {
        ui.add_space(12.0);
        ui.label(
            egui::RichText::new(
                "No activity recorded yet. Actions taken during this session will appear here.",
            )
            .color(TEXT_MUTED)
            .size(10.0),
        );
        return;
    }

    // ── Log rows ──────────────────────────────────────────────────────────────
    ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::Grid::new("audit_log_grid")
                .num_columns(5)
                .spacing([8.0, 2.0])
                .striped(true)
                .min_col_width(60.0)
                .show(ui, |ui| {
                    // Most-recent first.
                    for entry in state.audit_log.iter().rev() {
                        // Timestamp — to-second precision only.
                        ui.label(
                            egui::RichText::new(&entry.timestamp_utc)
                                .monospace()
                                .color(TEXT_MUTED)
                                .size(8.5),
                        );

                        // Action — colour-coded by category.
                        let action_color = action_color(&entry.action);
                        ui.label(
                            egui::RichText::new(&entry.action)
                                .color(action_color)
                                .size(9.0)
                                .strong(),
                        );

                        // Detail — truncated with hover for full text.
                        let detail = &entry.detail;
                        let truncated = if detail.len() > 120 {
                            format!("{}…", &detail[..120])
                        } else {
                            detail.clone()
                        };
                        ui.label(egui::RichText::new(&truncated).color(TEXT_SEC).size(8.5))
                            .on_hover_text(detail.as_str());

                        let prev_short: String = entry.prev_hash.chars().take(16).collect();
                        let prev = ui
                            .label(
                                egui::RichText::new(prev_short)
                                    .monospace()
                                    .color(TEXT_MUTED)
                                    .size(8.0),
                            )
                            .on_hover_text("Click to copy full prev_hash");
                        if prev.clicked() {
                            ui.ctx().copy_text(entry.prev_hash.clone());
                        }

                        let entry_short: String = entry.entry_hash.chars().take(16).collect();
                        let hash = ui
                            .label(
                                egui::RichText::new(entry_short)
                                    .monospace()
                                    .color(TEXT_MUTED)
                                    .size(8.0),
                            )
                            .on_hover_text("Click to copy full entry_hash");
                        if hash.clicked() {
                            ui.ctx().copy_text(entry.entry_hash.clone());
                        }

                        ui.end_row();
                    }
                });
        });
}

fn log_chain_status_if_changed(state: &mut AppState) {
    let signature = format!(
        "{}:{}:{}",
        state.audit_log.len(),
        state
            .audit_log
            .last()
            .map(|e| e.entry_hash.as_str())
            .unwrap_or("-"),
        state
            .audit_log
            .last()
            .map(|e| e.sequence.to_string())
            .unwrap_or_else(|| "0".to_string()),
    );

    UI_STATE.with(|cell| {
        let mut ui_state = cell.borrow_mut();
        if ui_state.last_seen_signature == signature {
            return;
        }
        ui_state.last_seen_signature = signature;

        match verify_audit_chain(&state.audit_log) {
            ChainVerifyResult::Verified { count } => {
                state.log_action("AUDIT_CHAIN_VERIFIED", &format!("entries={}", count));
            }
            ChainVerifyResult::Broken { sequence, detail } => {
                state.log_action(
                    "AUDIT_CHAIN_BROKEN",
                    &format!("sequence={} detail={}", sequence, detail),
                );
            }
        }
    });
}

fn action_color(action: &str) -> egui::Color32 {
    if action.contains("FAILED") || action.contains("ERROR") {
        crate::state::colors::DANGER
    } else if action.contains("SEARCH") {
        crate::state::colors::ACCENT
    } else if action.contains("HASH") || action.contains("CARVE") {
        egui::Color32::from_rgb(0xa0, 0x78, 0xe0)
    } else if action.contains("CASE") || action.contains("EVIDENCE") {
        crate::state::colors::GREEN_OK
    } else if action.contains("BOOKMARK") {
        crate::state::colors::AMBER
    } else if action.contains("PLUGIN") || action.contains("REGISTRY") {
        egui::Color32::from_rgb(0x60, 0xb4, 0xe0)
    } else {
        crate::state::colors::TEXT_PRI
    }
}
