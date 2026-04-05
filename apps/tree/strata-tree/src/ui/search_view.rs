//! Search view — filename/path search over the file index.

use crate::state::{colors::*, AppState, SearchHit, SearchMode};

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    // ── Header ────────────────────────────────────────────────────────────────
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("SEARCH")
                .color(ACCENT)
                .size(11.0)
                .strong(),
        );
        ui.separator();
        ui.label(
            egui::RichText::new(format!("{} results", state.search_results.len()))
                .color(TEXT_MUTED)
                .size(9.5),
        );
    });
    ui.add_space(4.0);

    if state.file_index.is_empty() {
        ui.add_space(24.0);
        ui.centered_and_justified(|ui| {
            ui.label(
                egui::RichText::new("No files indexed. Load evidence first.")
                    .color(TEXT_MUTED)
                    .size(11.0),
            );
        });
        return;
    }

    // ── Search bar ────────────────────────────────────────────────────────────
    let can_content_index = state.has_feature("content_search");
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Query:").color(TEXT_MUTED).size(9.5));
        let resp = ui.add(
            egui::TextEdit::singleline(&mut state.search_query)
                .hint_text(match state.search_mode {
                    SearchMode::Metadata => "filename, extension, path…",
                    SearchMode::FullText => "content query…",
                })
                .desired_width(280.0),
        );
        ui.separator();
        ui.selectable_value(&mut state.search_mode, SearchMode::Metadata, "Metadata");
        ui.selectable_value(&mut state.search_mode, SearchMode::FullText, "Full-text");
        if matches!(state.search_mode, SearchMode::FullText) {
            let idx_resp = ui.add_enabled(can_content_index, egui::Button::new("INDEX CONTENT"));
            if idx_resp.clicked() {
                match state.start_content_indexing() {
                    Ok(()) => {}
                    Err(err) => {
                        state.status = format!("Content indexing unavailable: {}", err);
                    }
                }
            }
            if !can_content_index {
                idx_resp.on_hover_text("Content search requires Pro license");
            }
        }
        let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if enter
            || ui
                .button(egui::RichText::new("Search").color(TEXT_PRI).size(9.5))
                .clicked()
        {
            match state.search_mode {
                SearchMode::Metadata => run_metadata_search(state),
                SearchMode::FullText => {
                    if !can_content_index {
                        state.status = "Content search requires Pro license".to_string();
                    } else if !state.content_index_ready {
                        state.status =
                            "Content index is not ready. Click INDEX CONTENT first.".to_string();
                    } else if let Err(err) = state.run_content_search() {
                        state.status = err;
                    }
                }
            }
        }
        if ui
            .button(egui::RichText::new("Clear").color(TEXT_MUTED).size(9.0))
            .clicked()
        {
            state.search_query.clear();
            state.search_results.clear();
            state.content_search_hits.clear();
            state.search_active = false;
        }
    });

    // ── Filter options ────────────────────────────────────────────────────────
    ui.add_space(2.0);
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Tip:").color(TEXT_MUTED).size(8.5));
        let tip = if matches!(state.search_mode, SearchMode::FullText) {
            if state.content_indexing_active {
                let (done, total) = state.content_index_progress;
                format!(
                    "Building content index: {} / {} files (indexed {}).",
                    done, total, state.content_indexed_files
                )
            } else if state.content_index_ready {
                format!(
                    "Full-text index ready. Last indexed files: {}.",
                    state.content_indexed_files
                )
            } else {
                "Build index first, then search inside file contents.".to_string()
            }
        } else {
            "Matches against name, path, and extension. Case-insensitive.".to_string()
        };
        ui.label(egui::RichText::new(tip).color(TEXT_MUTED).size(8.5));
    });

    ui.separator();

    if !state.search_active {
        return;
    }

    if state.search_results.is_empty() {
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new("No matches.")
                .color(TEXT_MUTED)
                .size(10.0),
        );
        return;
    }

    // ── Results ───────────────────────────────────────────────────────────────
    // Snapshot results to avoid borrow issues.
    let results: Vec<SearchHit> = state.search_results.clone();

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for (idx, hit) in results.iter().enumerate() {
                let entry = state
                    .file_index
                    .iter()
                    .find(|f| f.id == hit.file_id)
                    .cloned();
                let Some(f) = entry else {
                    continue;
                };

                let is_sel = state.selected_file_id.as_deref() == Some(hit.file_id.as_str());
                let bg = if is_sel {
                    egui::Color32::from_rgb(0x0f, 0x25, 0x40)
                } else {
                    SURFACE_EL
                };
                let name_c = if f.is_deleted {
                    DANGER
                } else if is_sel {
                    ACCENT
                } else {
                    TEXT_PRI
                };
                let size_s = f.size.map(fmt_size).unwrap_or_else(|| "—".into());

                let (rect, resp) = ui.allocate_exact_size(
                    egui::Vec2::new(ui.available_width(), 28.0),
                    egui::Sense::click(),
                );

                if ui.is_rect_visible(rect) {
                    ui.painter().rect_filled(rect, 0.0, bg);
                    if idx > 0 {
                        ui.painter().line_segment(
                            [rect.left_top(), rect.right_top()],
                            egui::Stroke::new(1.0, BORDER_SUBTLE),
                        );
                    }

                    // Row number.
                    ui.painter().text(
                        egui::pos2(rect.left() + 6.0, rect.center().y),
                        egui::Align2::LEFT_CENTER,
                        format!("{}", idx + 1),
                        egui::FontId::monospace(8.0),
                        TEXT_MUTED,
                    );

                    // Name.
                    ui.painter().text(
                        egui::pos2(rect.left() + 36.0, rect.center().y - 4.0),
                        egui::Align2::LEFT_CENTER,
                        &f.name,
                        egui::FontId::proportional(9.5),
                        name_c,
                    );

                    // Path.
                    let path_max = (rect.width() - 160.0).max(80.0);
                    let context_line = if matches!(state.search_mode, SearchMode::FullText) {
                        hit.context.clone()
                    } else {
                        f.path.clone()
                    };
                    let path_str = truncate_path(&context_line, path_max as usize / 6);
                    ui.painter().text(
                        egui::pos2(rect.left() + 36.0, rect.center().y + 5.0),
                        egui::Align2::LEFT_CENTER,
                        path_str,
                        egui::FontId::monospace(7.5),
                        TEXT_MUTED,
                    );

                    // Size.
                    ui.painter().text(
                        egui::pos2(rect.right() - 8.0, rect.center().y),
                        egui::Align2::RIGHT_CENTER,
                        size_s,
                        egui::FontId::monospace(8.5),
                        TEXT_MUTED,
                    );

                    let hit_type = hit.hit_type.to_uppercase();
                    ui.painter().text(
                        egui::pos2(rect.right() - 72.0, rect.center().y),
                        egui::Align2::RIGHT_CENTER,
                        hit_type,
                        egui::FontId::monospace(8.0),
                        ACCENT,
                    );
                }

                let fid = hit.file_id.clone();
                let query_text = hit.query.clone();
                let resp = resp.on_hover_text(format!("Query: {}", query_text));
                if resp.clicked() {
                    state.selected_file_id = Some(fid.clone());
                    state.load_hex_for_file(&fid);
                    state.view_mode = crate::state::ViewMode::FileExplorer;
                }
            }
        });
}

fn run_metadata_search(state: &mut AppState) {
    let q = state.search_query.to_lowercase();
    if q.trim().is_empty() {
        state.search_results.clear();
        state.search_active = false;
        return;
    }

    // Search filters: prefix with "ext:", "deleted:", "hash:", "cat:", "size>" or "size<"
    let (filter_type, filter_val) = if q.starts_with("ext:") {
        ("ext", q.trim_start_matches("ext:").trim())
    } else if q.starts_with("deleted:") || q == "deleted" {
        ("deleted", "true")
    } else if q.starts_with("carved:") || q == "carved" {
        ("carved", "true")
    } else if q.starts_with("hash:") {
        ("hash", q.trim_start_matches("hash:").trim())
    } else if q.starts_with("cat:") {
        ("cat", q.trim_start_matches("cat:").trim())
    } else if q.starts_with("size>") {
        ("size_gt", q.trim_start_matches("size>").trim())
    } else if q.starts_with("size<") {
        ("size_lt", q.trim_start_matches("size<").trim())
    } else {
        ("text", q.as_str())
    };

    let hits: Vec<SearchHit> = state
        .file_index
        .iter()
        .filter(|f| !f.is_dir)
        .filter(|f| match filter_type {
            "ext" => f
                .extension
                .as_deref()
                .map(|e| e.to_lowercase() == filter_val)
                .unwrap_or(false),
            "deleted" => f.is_deleted,
            "carved" => f.is_carved,
            "hash" => {
                f.md5
                    .as_deref()
                    .map(|h| h.to_lowercase().starts_with(filter_val))
                    .unwrap_or(false)
                    || f.sha256
                        .as_deref()
                        .map(|h| h.to_lowercase().starts_with(filter_val))
                        .unwrap_or(false)
            }
            "cat" => f
                .category
                .as_deref()
                .map(|c| c.to_lowercase().contains(filter_val))
                .unwrap_or(false),
            "size_gt" => filter_val
                .parse::<u64>()
                .ok()
                .map(|threshold| f.size.unwrap_or(0) > threshold)
                .unwrap_or(false),
            "size_lt" => filter_val
                .parse::<u64>()
                .ok()
                .map(|threshold| f.size.unwrap_or(0) < threshold)
                .unwrap_or(false),
            _ => {
                // "text" — search name, path, extension
                f.name.to_lowercase().contains(filter_val)
                    || f.path.to_lowercase().contains(filter_val)
                    || f.extension
                        .as_deref()
                        .map(|e| e.to_lowercase().contains(filter_val))
                        .unwrap_or(false)
            }
        })
        .map(|f| SearchHit {
            file_id: f.id.clone(),
            query: state.search_query.clone(),
            context: f.path.clone(),
            hit_type: "filename".to_string(),
        })
        .collect();

    let count = hits.len();
    state.search_results = hits;
    state.search_active = true;
    state.log_action(
        "SEARCH",
        &format!("query='{}' results={}", state.search_query, count),
    );
    state.persist_search_results();
}

fn fmt_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.0} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn truncate_path(path: &str, max_chars: usize) -> String {
    if path.len() <= max_chars {
        return path.to_string();
    }
    let keep = max_chars.saturating_sub(3);
    let start = path.len() - keep;
    format!("…{}", &path[start..])
}
