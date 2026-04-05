// ui/bookmark_panel.rs — Examiner bookmark panel with multi-examiner filter (Gap 12).
// Bookmarks grouped by color. All actions logged in activity_log.

use crate::state::{AppState, Bookmark};

pub const COLOR_RED:    &str = "Critical";
pub const COLOR_YELLOW: &str = "Notable";
pub const COLOR_GREEN:  &str = "Cleared";
pub const COLOR_BLUE:   &str = "Reference";

fn color_to_egui(color: &str) -> egui::Color32 {
    match color {
        COLOR_RED    => egui::Color32::from_rgb(200, 60, 60),
        COLOR_YELLOW => egui::Color32::from_rgb(200, 170, 30),
        COLOR_GREEN  => egui::Color32::from_rgb(60, 160, 60),
        COLOR_BLUE   => egui::Color32::from_rgb(60, 120, 200),
        _            => egui::Color32::GRAY,
    }
}

pub fn render(ctx: &egui::Context, state: &mut AppState) {
    egui::SidePanel::left("bookmark_panel")
        .resizable(true)
        .min_width(200.0)
        .default_width(280.0)
        .show(ctx, |ui| {
            ui.heading("Bookmarks");
            ui.separator();

            // ── Examiner filter (Gap 12) ──────────────────────────────────────
            let distinct_examiners: Vec<String> = {
                let mut seen = std::collections::HashSet::new();
                state.bookmarks.iter()
                    .map(|b| b.examiner.clone())
                    .filter(|e| seen.insert(e.clone()))
                    .collect()
            };

            if distinct_examiners.len() > 1 {
                ui.horizontal(|ui| {
                    ui.label("Show bookmarks from:");
                    egui::ComboBox::from_id_source("examiner_filter")
                        .selected_text(
                            state.ui_state.bookmark_examiner_filter
                                .as_deref()
                                .unwrap_or("All Examiners"),
                        )
                        .show_ui(ui, |ui| {
                            if ui.selectable_value(
                                &mut state.ui_state.bookmark_examiner_filter,
                                None,
                                "All Examiners",
                            ).clicked() {}

                            for ex in &distinct_examiners {
                                let count = state.bookmarks.iter()
                                    .filter(|b| &b.examiner == ex)
                                    .count();
                                let label = format!("{} ({})", ex, count);
                                if ui.selectable_value(
                                    &mut state.ui_state.bookmark_examiner_filter,
                                    Some(ex.clone()),
                                    label,
                                ).clicked() {}
                            }
                        });
                });
                ui.separator();
            }

            // ── Bookmark list ─────────────────────────────────────────────────
            // Apply examiner filter.
            let active_filter = state.ui_state.bookmark_examiner_filter.clone();
            let visible: Vec<&Bookmark> = state.bookmarks.iter()
                .filter(|b| {
                    active_filter.as_ref().map_or(true, |f| &b.examiner == f)
                })
                .collect();

            if visible.is_empty() {
                ui.label("No bookmarks.");
                if active_filter.is_some() {
                    ui.label(egui::RichText::new("(filter active — change above to see all)")
                        .small().color(egui::Color32::from_rgb(150, 120, 60)));
                } else {
                    ui.label(egui::RichText::new("Right-click a file to add a bookmark.")
                        .small());
                }
            } else {
                for color in &[COLOR_RED, COLOR_YELLOW, COLOR_GREEN, COLOR_BLUE] {
                    let group: Vec<_> = visible.iter()
                        .filter(|b| b.color.as_deref() == Some(color))
                        .collect();
                    if group.is_empty() { continue; }

                    egui::CollapsingHeader::new(
                        egui::RichText::new(format!("● {} ({})", color, group.len()))
                            .color(color_to_egui(color))
                            .strong(),
                    )
                    .default_open(true)
                    .show(ui, |ui| {
                        for bm in group {
                            let label_text = bm.label.as_deref().unwrap_or(&bm.file_id);
                            let is_sel = state.selected_file.as_deref() == Some(bm.file_id.as_str());
                            if ui.selectable_label(
                                is_sel,
                                egui::RichText::new(label_text).color(color_to_egui(color)),
                            ).clicked() {
                                state.selected_file = Some(bm.file_id.clone());
                            }
                            // Show examiner attribution when multiple examiners present.
                            if distinct_examiners.len() > 1 {
                                ui.indent(bm.id.as_str(), |ui| {
                                    ui.label(egui::RichText::new(format!("by {}", bm.examiner))
                                        .small().color(egui::Color32::from_rgb(130, 130, 130)));
                                });
                            }
                            if let Some(note) = &bm.note {
                                ui.indent(bm.id.as_str(), |ui| {
                                    ui.label(egui::RichText::new(note).italics().small());
                                });
                            }
                        }
                    });
                }
            }

            ui.separator();

            // ── Add bookmark for selected file ────────────────────────────────
            if let Some(file_id) = &state.selected_file.clone() {
                ui.label("Add bookmark:");
                ui.horizontal(|ui| {
                    if ui.button("Critical").clicked() { add_bookmark(state, file_id, COLOR_RED); }
                    if ui.button("Notable").clicked()  { add_bookmark(state, file_id, COLOR_YELLOW); }
                    if ui.button("Cleared").clicked()  { add_bookmark(state, file_id, COLOR_GREEN); }
                    if ui.button("Ref").clicked()      { add_bookmark(state, file_id, COLOR_BLUE); }
                });
            }

            ui.separator();
            if ui.button("Close").clicked() {
                state.ui_state.show_bookmark_panel = false;
            }
        });
}

fn add_bookmark(state: &mut AppState, file_id: &str, color: &str) {
    let file_name = state.file_index.iter()
        .find(|f| f.id == file_id)
        .map(|f| f.name.clone())
        .unwrap_or_else(|| file_id.to_string());

    let bm = Bookmark {
        id: uuid::Uuid::new_v4().to_string(),
        file_id: file_id.to_string(),
        examiner: state.examiner_name().to_string(),
        label: Some(file_name.clone()),
        note: None,
        color: Some(color.to_string()),
        created_utc: chrono::Utc::now()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    };
    state.bookmarks.push(bm);
    state.log_action(
        "BOOKMARK_ADD",
        Some(&format!("file={} color={}", file_name, color)),
        Some(file_id),
    );
    state.status_message = format!("Bookmark added: {} ({})", file_name, color);
}
