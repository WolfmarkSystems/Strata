// ui/search_panel.rs — Filename + content search panel (Gap 4).
// Two modes: Filename (instant, no index) | Content (tantivy index required).

use crate::search::filename::{search_filenames, SearchOptions};
use crate::search::content::ContentIndexer;
use crate::state::{AppState, ContentIndexStatus, SearchHit};

pub fn render(ctx: &egui::Context, state: &mut AppState) {
    egui::SidePanel::right("search_panel")
        .resizable(true)
        .min_width(280.0)
        .default_width(340.0)
        .show(ctx, |ui| {
            ui.heading("Search");
            ui.separator();

            // ── Mode toggle ───────────────────────────────────────────────────
            ui.horizontal(|ui| {
                if ui.radio(!state.ui_state.search_content_mode, "Filename").clicked() {
                    state.ui_state.search_content_mode = false;
                }
                if ui.radio(state.ui_state.search_content_mode, "Content").clicked() {
                    state.ui_state.search_content_mode = true;
                }
            });
            ui.separator();

            if state.ui_state.search_content_mode {
                render_content_mode(ui, state);
            } else {
                render_filename_mode(ui, state);
            }

            ui.separator();
            if ui.button("Close").clicked() {
                state.ui_state.show_search_panel = false;
            }
        });
}

// ─── Filename search ──────────────────────────────────────────────────────────

fn render_filename_mode(ui: &mut egui::Ui, state: &mut AppState) {
    ui.label("Search file names and paths:");
    ui.horizontal(|ui| {
        let response = ui.text_edit_singleline(&mut state.search_query);
        if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            run_filename_search(state);
        }
        if ui.button("Search").clicked() {
            run_filename_search(state);
        }
    });

    ui.separator();
    ui.label(format!("Results: {}", state.search_results.len()));

    egui::ScrollArea::vertical()
        .max_height(400.0)
        .show(ui, |ui| {
            for hit in &state.search_results {
                let label = hit.context.as_deref().unwrap_or(&hit.file_id);
                let is_sel = state.selected_file.as_deref() == Some(hit.file_id.as_str());
                if ui.selectable_label(is_sel, label).clicked() {
                    state.selected_file = Some(hit.file_id.clone());
                }
            }
        });
}

fn run_filename_search(state: &mut AppState) {
    let query = state.search_query.clone();
    if query.trim().is_empty() {
        state.search_results.clear();
        return;
    }

    let options = SearchOptions {
        case_sensitive: false,
        regex: false,
        include_paths: true,
        include_deleted: true,
        extension_filter: Vec::new(),
    };

    match search_filenames(&query, &state.file_index, &options) {
        Ok(hits) => {
            let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            state.search_results = hits.iter().map(|h| SearchHit {
                id: uuid::Uuid::new_v4().to_string(),
                file_id: h.file_id.clone(),
                query: query.clone(),
                hit_type: "filename".to_string(),
                offset: None,
                context: Some(h.file_name.clone()),
                found_utc: now.clone(),
            }).collect();
            state.status_message =
                format!("Search '{}': {} results", query, state.search_results.len());
            state.log_action(
                "SEARCH",
                Some(&format!("type=filename query={} results={}", query, state.search_results.len())),
                None,
            );
        }
        Err(e) => {
            state.error_message = Some(format!("Search failed: {}", e));
        }
    }
}

// ─── Content search ───────────────────────────────────────────────────────────

fn render_content_mode(ui: &mut egui::Ui, state: &mut AppState) {
    // Index status + build control.
    let (status_text, status_color, index_ready, building) = match &state.content_index_status {
        ContentIndexStatus::NotBuilt => (
            "Index not built".to_string(),
            egui::Color32::from_rgb(150, 120, 60),
            false, false,
        ),
        ContentIndexStatus::Building { progress, indexed, total } => (
            format!("Building index: {}/{} files ({:.0}%)", indexed, total, progress * 100.0),
            egui::Color32::from_rgb(60, 120, 200),
            false, true,
        ),
        ContentIndexStatus::Ready { file_count } => (
            format!("Index ready: {} files", file_count),
            egui::Color32::from_rgb(60, 160, 60),
            true, false,
        ),
        ContentIndexStatus::Failed(e) => (
            format!("Index failed: {}", e),
            egui::Color32::from_rgb(200, 60, 60),
            false, false,
        ),
    };

    ui.horizontal(|ui| {
        ui.colored_label(status_color, &status_text);
        if building {
            ui.spinner();
        }
    });

    let can_build = !building && !state.file_index.is_empty();
    ui.add_enabled_ui(can_build, |ui| {
        if ui.button("Build Index").clicked() {
            state.pending_content_index = true;
        }
    });
    if state.file_index.is_empty() {
        ui.label(
            egui::RichText::new("Load evidence first to build the index.")
                .small()
                .color(egui::Color32::from_rgb(150, 120, 60)),
        );
    }

    ui.separator();
    ui.label("Boolean operators: AND  OR  NOT  NEAR");
    ui.add_space(4.0);

    // Search input — only enabled when index is ready.
    ui.add_enabled_ui(index_ready, |ui| {
        let response = ui.text_edit_singleline(&mut state.search_query);
        if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            run_content_search(state);
        }
        if ui.button("Search").clicked() {
            run_content_search(state);
        }
    });

    if !index_ready && !building {
        ui.label(
            egui::RichText::new("Build the content index to enable full-text search.")
                .small()
                .color(egui::Color32::from_rgb(150, 120, 60)),
        );
    }

    ui.separator();
    ui.label(format!("Results: {}", state.search_results.len()));

    egui::ScrollArea::vertical()
        .max_height(350.0)
        .show(ui, |ui| {
            for hit in &state.search_results {
                let is_sel = state.selected_file.as_deref() == Some(hit.file_id.as_str());
                egui::CollapsingHeader::new(
                    egui::RichText::new(hit.context.as_deref().unwrap_or(&hit.file_id))
                        .small()
                )
                .id_source(&hit.id)
                .show(ui, |ui| {
                    if let Some(ctx) = &hit.context {
                        ui.label(egui::RichText::new(ctx).small().color(egui::Color32::from_rgb(140, 140, 140)));
                    }
                    if ui.selectable_label(is_sel, "Jump to file").clicked() {
                        state.selected_file = Some(hit.file_id.clone());
                    }
                });
            }
        });
}

fn run_content_search(state: &mut AppState) {
    let query = state.search_query.clone();
    if query.trim().is_empty() {
        state.search_results.clear();
        return;
    }

    let index_dir = if let Some(case) = &state.case {
        let vtp = std::path::PathBuf::from(&case.path);
        ContentIndexer::index_dir_for_case(&vtp)
    } else {
        std::env::temp_dir().join("strata_content_index")
    };

    let indexer = ContentIndexer::new(&index_dir);
    match indexer.search(&query, 200) {
        Ok(hits) => {
            let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            state.search_results = hits.iter().map(|h| SearchHit {
                id: uuid::Uuid::new_v4().to_string(),
                file_id: h.file_id.clone(),
                query: query.clone(),
                hit_type: "content".to_string(),
                offset: None,
                context: Some(h.file_path.clone()),
                found_utc: now.clone(),
            }).collect();
            state.status_message =
                format!("Content search '{}': {} results", query, state.search_results.len());
            state.log_action(
                "SEARCH",
                Some(&format!(
                    "type=content query={} results={}",
                    query,
                    state.search_results.len()
                )),
                None,
            );
        }
        Err(e) => {
            state.error_message = Some(format!("Content search failed: {}", e));
        }
    }
}
