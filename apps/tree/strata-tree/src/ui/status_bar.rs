//! Status bar — 24px bottom bar with clickable stat pills.

use crate::state::{AppState, ViewMode};

pub fn render(ctx: &egui::Context, state: &mut AppState) {
    let t = *state.theme();

    egui::TopBottomPanel::bottom("status_bar")
        .exact_height(24.0)
        .frame(
            egui::Frame::none()
                .fill(t.panel)
                .stroke(egui::Stroke::NONE)
                .inner_margin(egui::Margin::symmetric(12.0, 4.0)),
        )
        .show(ctx, |ui| {
            ui.horizontal_centered(|ui| {
                ui.spacing_mut().item_spacing = egui::vec2(6.0, 0.0);

                // Court-mode indicator
                if state.court_mode {
                    ui.label(
                        egui::RichText::new("⚖ COURT MODE")
                            .color(egui::Color32::from_rgb(0x2a, 0x50, 0x68))
                            .size(11.0)
                            .strong(),
                    );
                    bar_div(ui, &t);
                }

                // Search mode indicator
                if state.global_search_active {
                    ui.label(
                        egui::RichText::new("SEARCH MODE")
                            .color(egui::Color32::from_rgb(0x7d, 0xd3, 0xfc))
                            .size(11.0)
                            .strong(),
                    );
                    bar_div(ui, &t);
                    pill_clickable(
                        ui, "RESULTS",
                        &state.global_search_results.len().to_string(),
                        egui::Color32::from_rgb(0x7d, 0xd3, 0xfc),
                        true, || {},
                    );
                    bar_div(ui, &t);
                }

                // FILES — muted
                let files_color = egui::Color32::from_rgb(0x88, 0x99, 0xaa);
                pill_clickable(
                    ui,
                    "FILES",
                    &state.total_files_count.to_string(),
                    files_color,
                    false,
                    || {},
                );
                bar_div(ui, &t);

                // SUSPICIOUS — amber, bold when > 0
                let sus_count = state.suspicious_event_count;
                let sus_color = egui::Color32::from_rgb(0xf5, 0x9e, 0x0b);
                let sus_bold = sus_count > 0;
                if pill_clickable(ui, "SUSPICIOUS", &sus_count.to_string(), sus_color, sus_bold, || {}) {
                    state.file_filter = "$suspicious".to_string();
                    state.mark_filter_dirty();
                    state.view_mode = ViewMode::FileExplorer;
                }
                bar_div(ui, &t);

                // FLAGGED — red, bold when > 0
                let flag_count = state.flagged_count();
                let flag_color = egui::Color32::from_rgb(0xef, 0x44, 0x44);
                let flag_bold = flag_count > 0;
                if pill_clickable(ui, "FLAGGED", &flag_count.to_string(), flag_color, flag_bold, || {}) {
                    state.file_filter = "knownbad".to_string();
                    state.mark_filter_dirty();
                    state.view_mode = ViewMode::FileExplorer;
                }
                bar_div(ui, &t);

                // CARVED — cyan
                let carved_count = state.carved_count();
                let carved_color = egui::Color32::from_rgb(0x7d, 0xd3, 0xfc);
                if pill_clickable(ui, "CARVED", &carved_count.to_string(), carved_color, false, || {}) {
                    state.file_filter = "$CARVED".to_string();
                    state.mark_filter_dirty();
                    state.view_mode = ViewMode::FileExplorer;
                }
                bar_div(ui, &t);

                // HASHED — green
                let hashed_count = state.hashed_count();
                let hashed_color = egui::Color32::from_rgb(0x22, 0xc5, 0x5e);
                pill_clickable(ui, "HASHED", &hashed_count.to_string(), hashed_color, false, || {});
                bar_div(ui, &t);

                // ARTIFACTS — purple
                let artifact_color = egui::Color32::from_rgb(0xa7, 0x8b, 0xfa);
                if pill_clickable(ui, "ARTIFACTS", &state.artifact_total.to_string(), artifact_color, state.artifact_total > 0, || {}) {
                    state.view_mode = ViewMode::Artifacts;
                }
            });
        });
}

/// Render a clickable stat label+value. Returns true if clicked.
fn pill_clickable(
    ui: &mut egui::Ui,
    label: &str,
    value: &str,
    value_color: egui::Color32,
    bold: bool,
    _on_click: impl FnOnce(),
) -> bool {
    let label_text = egui::RichText::new(label)
        .color(if bold { value_color } else { egui::Color32::from_rgb(0x88, 0x99, 0xaa) })
        .size(11.0)
        .strong();
    let value_text = if bold {
        egui::RichText::new(value)
            .color(value_color)
            .size(12.0)
            .strong()
    } else {
        egui::RichText::new(value)
            .color(value_color)
            .size(12.0)
    };

    let resp = ui.horizontal(|ui| {
        ui.label(label_text);
        ui.label(value_text);
    }).response;

    let click = ui.interact(resp.rect, resp.id.with(label), egui::Sense::click());
    click.clicked()
}

fn bar_div(ui: &mut egui::Ui, t: &crate::theme::StrataTheme) {
    let cursor = ui.cursor().min;
    ui.painter().line_segment(
        [
            egui::pos2(cursor.x, cursor.y + 2.0),
            egui::pos2(cursor.x, cursor.y + 18.0),
        ],
        egui::Stroke::new(1.0, t.border),
    );
    ui.add_space(6.0);
}
