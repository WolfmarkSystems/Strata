//! Tagged Evidence view — categorized evidence tagging with left/right pane.

use crate::state::{AppState, ViewMode};

const TAG_CATEGORIES: &[(&str, &str, egui::Color32)] = &[
    (
        "\u{1F534}",
        "Critical Evidence",
        egui::Color32::from_rgb(0xa8, 0x40, 0x40),
    ),
    (
        "\u{1F7E0}",
        "Suspicious",
        egui::Color32::from_rgb(0xb8, 0x78, 0x40),
    ),
    (
        "\u{1F7E1}",
        "Needs Review",
        egui::Color32::from_rgb(0xc8, 0xa0, 0x40),
    ),
    (
        "\u{1F7E2}",
        "Confirmed Clean",
        egui::Color32::from_rgb(0x48, 0x78, 0x58),
    ),
    (
        "\u{1F535}",
        "Key Artifact",
        egui::Color32::from_rgb(0x4a, 0x70, 0xc0),
    ),
    (
        "\u{26AB}",
        "Excluded",
        egui::Color32::from_rgb(0x3a, 0x48, 0x58),
    ),
];

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    let t = *state.theme();

    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("TAGGED EVIDENCE")
                .color(t.active)
                .size(11.0)
                .strong(),
        );
        ui.separator();
        ui.label(
            egui::RichText::new(format!("{} entries", state.bookmarks.len()))
                .color(t.muted)
                .size(9.5),
        );
    });
    ui.add_space(6.0);

    if state.bookmarks.is_empty() {
        ui.vertical_centered(|ui| {
            ui.add_space(ui.available_height() / 3.0);
            ui.label(
                egui::RichText::new("No tagged files yet.\nRight-click any file to add a tag.")
                    .color(t.muted)
                    .size(12.0),
            );
        });
        return;
    }

    let total_w = ui.available_width();
    let left_w = total_w * 0.35;
    let right_w = total_w * 0.63;

    ui.horizontal(|ui| {
        // ── Left: Tag category list ──────────────────────────────────────
        ui.vertical(|ui| {
            ui.set_width(left_w);
            egui::ScrollArea::vertical()
                .id_source("tag_list")
                .show(ui, |ui| {
                    // "All" entry
                    let all_selected = state.active_tag.is_empty();
                    let all_count = state.bookmarks.len();
                    let resp = ui.selectable_label(
                        all_selected,
                        egui::RichText::new(format!("All  ({})", all_count))
                            .color(if all_selected { t.text } else { t.secondary })
                            .size(11.0),
                    );
                    if resp.clicked() {
                        state.active_tag.clear();
                    }
                    ui.add_space(4.0);

                    for &(dot, tag_name, color) in TAG_CATEGORIES {
                        let count = state.bookmarks.iter().filter(|b| b.tag == tag_name).count();
                        let selected = state.active_tag == tag_name;
                        let label = format!("{} {}  ({})", dot, tag_name, count);
                        let resp = ui.selectable_label(
                            selected,
                            egui::RichText::new(label)
                                .color(if selected { color } else { t.secondary })
                                .size(11.0),
                        );
                        if resp.clicked() {
                            state.active_tag = tag_name.to_string();
                        }
                    }

                    // Custom tags
                    let custom_tags: Vec<String> = state
                        .bookmarks
                        .iter()
                        .filter(|b| TAG_CATEGORIES.iter().all(|&(_, n, _)| b.tag != n))
                        .map(|b| b.tag.clone())
                        .collect::<std::collections::HashSet<_>>()
                        .into_iter()
                        .collect();
                    for tag in &custom_tags {
                        let count = state.bookmarks.iter().filter(|b| &b.tag == tag).count();
                        let selected = state.active_tag == *tag;
                        let resp = ui.selectable_label(
                            selected,
                            egui::RichText::new(format!("\u{1F3F7} {}  ({})", tag, count))
                                .color(if selected { t.text } else { t.secondary })
                                .size(11.0),
                        );
                        if resp.clicked() {
                            state.active_tag = tag.clone();
                        }
                    }
                });
        });

        ui.add_space(8.0);

        // ── Right: Files with selected tag ───────────────────────────────
        ui.vertical(|ui| {
            ui.set_width(right_w);

            let filtered: Vec<_> = if state.active_tag.is_empty() {
                state.bookmarks.clone()
            } else {
                state
                    .bookmarks
                    .iter()
                    .filter(|b| b.tag == state.active_tag)
                    .cloned()
                    .collect()
            };

            egui::ScrollArea::vertical()
                .id_source("tagged_files")
                .show(ui, |ui| {
                    for bm in &filtered {
                        let label = if let Some(reg) = &bm.registry_path {
                            format!("[REG] {}", reg)
                        } else if let Some(fid) = &bm.file_id {
                            if let Some(file) = state.file_index.iter().find(|f| &f.id == fid) {
                                file.name.clone()
                            } else {
                                fid.clone()
                            }
                        } else {
                            "[UNKNOWN]".to_string()
                        };

                        // Find tag color
                        let tag_color = TAG_CATEGORIES
                            .iter()
                            .find(|&&(_, n, _)| n == bm.tag.as_str())
                            .map(|&(_, _, c)| c)
                            .unwrap_or(t.muted);

                        ui.horizontal(|ui| {
                            // Tag color dot
                            let (dot_rect, _) =
                                ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
                            ui.painter()
                                .circle_filled(dot_rect.center(), 4.0, tag_color);

                            let resp = ui.selectable_label(
                                false,
                                egui::RichText::new(&label).color(t.text).size(10.0),
                            );
                            if resp.double_clicked() {
                                if let Some(reg) = &bm.registry_path {
                                    state.pending_registry_nav = Some(reg.clone());
                                    state.view_mode = ViewMode::Registry;
                                } else if let Some(fid) = &bm.file_id {
                                    state.selected_file_id = Some(fid.clone());
                                    if let Some(file) =
                                        state.file_index.iter().find(|f| &f.id == fid)
                                    {
                                        state.selected_tree_path = Some(file.parent_path.clone());
                                        state.file_filter = file.parent_path.clone();
                                        state.mark_filter_dirty();
                                    }
                                    state.view_mode = ViewMode::FileExplorer;
                                }
                            }
                            resp.context_menu(|ui| {
                                if ui.button("Remove Tag").clicked() {
                                    state.bookmarks.retain(|x| x.id != bm.id);
                                    state.mark_case_dirty();
                                    state.log_action(
                                        "TAG_REMOVE",
                                        &format!("bookmark_id={}", bm.id),
                                    );
                                    ui.close_menu();
                                }
                            });
                        });

                        ui.label(
                            egui::RichText::new(format!(
                                "{} | {} | {}",
                                bm.tag, bm.note, bm.examiner
                            ))
                            .size(8.0)
                            .color(t.muted),
                        );
                        ui.add_space(2.0);
                    }
                });
        });
    });
}
