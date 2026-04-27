// ui/dialogs/search.rs — Advanced search dialog with multi-field query builder.
use crate::state::{colors::*, AppState, SearchMode};

pub fn render(ctx: &egui::Context, state: &mut AppState) {
    if !state.show_advanced_search {
        return;
    }

    egui::Window::new("Advanced Search")
        .collapsible(false)
        .resizable(true)
        .default_width(520.0)
        .default_height(380.0)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            ui.label(
                egui::RichText::new("SEARCH QUERY BUILDER")
                    .color(ACCENT)
                    .size(11.0)
                    .strong(),
            );
            ui.add_space(8.0);

            // Filename / path filter
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Filename:").color(TEXT_SEC).size(9.5));
                ui.text_edit_singleline(&mut state.adv_search_filename);
            });

            // Extension filter
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Extension:").color(TEXT_SEC).size(9.5));
                ui.text_edit_singleline(&mut state.adv_search_extension);
            });

            // Size range
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("Min size (bytes):")
                        .color(TEXT_SEC)
                        .size(9.5),
                );
                ui.text_edit_singleline(&mut state.adv_search_min_size);
                ui.label(egui::RichText::new("Max:").color(TEXT_SEC).size(9.5));
                ui.text_edit_singleline(&mut state.adv_search_max_size);
            });

            // Date range
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("Modified after:")
                        .color(TEXT_SEC)
                        .size(9.5),
                );
                ui.text_edit_singleline(&mut state.adv_search_date_after);
                ui.label(egui::RichText::new("Before:").color(TEXT_SEC).size(9.5));
                ui.text_edit_singleline(&mut state.adv_search_date_before);
            });

            // Category filter
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Category:").color(TEXT_SEC).size(9.5));
                ui.text_edit_singleline(&mut state.adv_search_category);
            });

            // Flags
            ui.horizontal(|ui| {
                ui.checkbox(&mut state.adv_search_deleted_only, "Deleted files only");
                ui.checkbox(&mut state.adv_search_hashed_only, "Hashed files only");
                ui.checkbox(&mut state.adv_search_flagged_only, "Flagged files only");
            });

            // Hash search
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("Hash (MD5/SHA256):")
                        .color(TEXT_SEC)
                        .size(9.5),
                );
                ui.text_edit_singleline(&mut state.adv_search_hash);
            });

            // Full-text content search
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("Content contains:")
                        .color(TEXT_SEC)
                        .size(9.5),
                );
                ui.text_edit_singleline(&mut state.adv_search_content);
            });

            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if ui
                    .button(egui::RichText::new("SEARCH").color(ACCENT).strong())
                    .clicked()
                {
                    run_advanced_search(state);
                    state.show_advanced_search = false;
                    state.view_mode = crate::state::ViewMode::Search;
                }
                if ui.button("Cancel").clicked() {
                    state.show_advanced_search = false;
                }
                if ui.button("Clear").clicked() {
                    state.adv_search_filename.clear();
                    state.adv_search_extension.clear();
                    state.adv_search_min_size.clear();
                    state.adv_search_max_size.clear();
                    state.adv_search_date_after.clear();
                    state.adv_search_date_before.clear();
                    state.adv_search_category.clear();
                    state.adv_search_hash.clear();
                    state.adv_search_content.clear();
                    state.adv_search_deleted_only = false;
                    state.adv_search_hashed_only = false;
                    state.adv_search_flagged_only = false;
                }
            });
        });
}

fn run_advanced_search(state: &mut AppState) {
    let mut results = Vec::new();
    let filename_lower = state.adv_search_filename.to_lowercase();
    let ext_lower = state.adv_search_extension.to_lowercase().replace('.', "");
    let min_size: Option<u64> = state.adv_search_min_size.parse().ok();
    let max_size: Option<u64> = state.adv_search_max_size.parse().ok();
    let hash_lower = state.adv_search_hash.to_lowercase();
    let category_lower = state.adv_search_category.to_lowercase();

    for file in &state.file_index {
        if file.is_dir {
            continue;
        }

        // Filename filter
        if !filename_lower.is_empty() && !file.name.to_lowercase().contains(&filename_lower) {
            continue;
        }

        // Extension filter
        if !ext_lower.is_empty() {
            let file_ext = file
                .extension
                .as_deref()
                .unwrap_or("")
                .to_lowercase()
                .replace('.', "");
            if file_ext != ext_lower {
                continue;
            }
        }

        // Size filter
        if let Some(min) = min_size {
            if file.size.unwrap_or(0) < min {
                continue;
            }
        }
        if let Some(max) = max_size {
            if file.size.unwrap_or(0) > max {
                continue;
            }
        }

        // Date filter
        if !state.adv_search_date_after.is_empty() {
            if let Some(ref modified) = file.modified_utc {
                if modified.as_str() < state.adv_search_date_after.as_str() {
                    continue;
                }
            }
        }
        if !state.adv_search_date_before.is_empty() {
            if let Some(ref modified) = file.modified_utc {
                if modified.as_str() > state.adv_search_date_before.as_str() {
                    continue;
                }
            }
        }

        // Category filter
        if !category_lower.is_empty() {
            let cat = file.category.as_deref().unwrap_or("").to_lowercase();
            if !cat.contains(&category_lower) {
                continue;
            }
        }

        // Flag filters
        if state.adv_search_deleted_only && !file.is_deleted {
            continue;
        }
        if state.adv_search_hashed_only && file.sha256.is_none() {
            continue;
        }
        if state.adv_search_flagged_only && file.hash_flag.is_none() {
            continue;
        }

        // Hash filter
        if !hash_lower.is_empty() {
            let md5_match = file
                .md5
                .as_deref()
                .map(|h| h.to_lowercase() == hash_lower)
                .unwrap_or(false);
            let sha_match = file
                .sha256
                .as_deref()
                .map(|h| h.to_lowercase() == hash_lower)
                .unwrap_or(false);
            if !md5_match && !sha_match {
                continue;
            }
        }

        results.push(crate::state::SearchHit {
            file_id: file.id.clone(),
            query: state.adv_search_filename.clone(),
            context: format!(
                "size={} cat={} ext={}",
                file.size.unwrap_or(0),
                file.category.as_deref().unwrap_or("-"),
                file.extension.as_deref().unwrap_or("-"),
            ),
            hit_type: "advanced_search".to_string(),
        });

        if results.len() >= 10000 {
            break;
        }
    }

    state.search_results = results;
    state.search_mode = SearchMode::Metadata;
    state.status = format!("Advanced search: {} results", state.search_results.len());
    state.log_action(
        "ADVANCED_SEARCH",
        &format!(
            "filename={} ext={} results={}",
            state.adv_search_filename,
            state.adv_search_extension,
            state.search_results.len()
        ),
    );
}
