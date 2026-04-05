//! Bookmarks view — unified file and registry bookmark list with navigation.

use crate::state::{colors::*, AppState, ViewMode};

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("BOOKMARKS")
                .color(ACCENT)
                .size(11.0)
                .strong(),
        );
        ui.separator();
        ui.label(
            egui::RichText::new(format!("{} entries", state.bookmarks.len()))
                .color(TEXT_MUTED)
                .size(9.5),
        );
    });
    ui.add_space(6.0);

    if state.bookmarks.is_empty() {
        ui.label(egui::RichText::new("No bookmarks yet.").color(TEXT_MUTED));
        return;
    }

    let mut marks = state.bookmarks.clone();
    marks.sort_by_key(|bm| {
        (
            bm.tag.clone(),
            bm.registry_path
                .clone()
                .or_else(|| bm.file_id.clone())
                .unwrap_or_default(),
            bm.created_utc.clone(),
        )
    });

    egui::ScrollArea::vertical()
        .id_source("bookmarks_list")
        .show(ui, |ui| {
            for bm in marks {
                let line = if let Some(reg) = &bm.registry_path {
                    format!("[REG] {}", reg)
                } else if let Some(fid) = &bm.file_id {
                    if let Some(file) = state.file_index.iter().find(|f| &f.id == fid) {
                        format!("[FILE] {}", file.path)
                    } else {
                        format!("[FILE] {}", fid)
                    }
                } else {
                    "[UNKNOWN]".to_string()
                };

                let resp = ui.selectable_label(false, egui::RichText::new(line).color(TEXT_PRI));
                if resp.double_clicked() {
                    if let Some(reg) = &bm.registry_path {
                        state.pending_registry_nav = Some(reg.clone());
                        state.view_mode = ViewMode::Registry;
                    } else if let Some(fid) = &bm.file_id {
                        state.selected_file_id = Some(fid.clone());
                        if let Some(file) = state.file_index.iter().find(|f| &f.id == fid) {
                            state.selected_tree_path = Some(file.parent_path.clone());
                            state.file_filter = file.parent_path.clone();
                            state.mark_filter_dirty();
                        }
                        state.view_mode = ViewMode::FileExplorer;
                    }
                }
                resp.context_menu(|ui| {
                    if ui.button("Copy Bookmark Path").clicked() {
                        if let Some(reg) = &bm.registry_path {
                            ui.ctx().copy_text(reg.clone());
                        } else if let Some(fid) = &bm.file_id {
                            if let Some(file) = state.file_index.iter().find(|f| &f.id == fid) {
                                ui.ctx().copy_text(file.path.clone());
                            }
                        }
                        ui.close_menu();
                    }
                    if ui.button("Remove Bookmark").clicked() {
                        state.bookmarks.retain(|x| x.id != bm.id);
                        state.mark_case_dirty();
                        state.log_action("BOOKMARK_REMOVE", &format!("bookmark_id={}", bm.id));
                        ui.close_menu();
                    }
                });

                ui.label(
                    egui::RichText::new(format!("Tag: {} | Note: {}", bm.tag, bm.note))
                        .size(8.5)
                        .color(TEXT_MUTED),
                );
                ui.label(
                    egui::RichText::new(format!("Examiner: {} | {}", bm.examiner, bm.created_utc))
                        .size(8.0)
                        .color(TEXT_MUTED),
                );
                ui.separator();
            }
        });
}
