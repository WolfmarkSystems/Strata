//! Toolbar — 2-row top bar, Strata design language.
//! Row 1: Logo + navigation + case info + trial badge
//! Row 2: Global search bar + action buttons

use crate::state::AppState;
use strata_license::LicenseTier;

pub fn render(ctx: &egui::Context, state: &mut AppState) {
    let t = *state.theme();

    egui::TopBottomPanel::top("toolbar")
        .frame(
            egui::Frame::none()
                .fill(t.panel)
                .inner_margin(egui::Margin::symmetric(10.0, 4.0))
                .stroke(egui::Stroke::NONE),
        )
        .show(ctx, |ui| {
            // ═══ ROW 1: STRATA wordmark + nav + case info + badges ═══
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing = egui::vec2(6.0, 0.0);

                // TODO: embed wolf_mark.png here
                // use include_bytes! when PNG ready
                // icon_data: load_image_bytes(...)
                let (_wolf_slot, _) = ui.allocate_exact_size(egui::vec2(32.0, 32.0), egui::Sense::hover());

                // STRATA wordmark — 18px bold, letter spacing via spaces
                ui.label(
                    egui::RichText::new("S T R A T A")
                        .color(egui::Color32::from_rgb(0xd8, 0xe2, 0xec))
                        .size(18.0)
                        .strong(),
                );

                ui.add_space(16.0);

                // + Open Evidence (primary accent button)
                let ev_btn = ui.add(
                    egui::Button::new(
                        egui::RichText::new("+ Open Evidence")
                            .color(t.bg)
                            .size(11.0)
                            .strong(),
                    )
                    .fill(t.active)
                    .rounding(6.0),
                );
                if ev_btn.clicked() {
                    state.open_ev_dlg.open = true;
                }

                // New Case / Open Case (secondary)
                if sec_btn(ui, &t, "New Case").clicked() {
                    state.new_case_dlg.open = true;
                }
                if sec_btn(ui, &t, "Open Case").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("Strata Case", &["vtp"])
                        .pick_file()
                    {
                        open_case_file(state, &path);
                    }
                }

                // Right-aligned: case info + badges
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // DEV badge (only in dev-bypass builds)
                    #[cfg(feature = "dev-bypass")]
                    {
                        ui.add(
                            egui::Button::new(
                                egui::RichText::new("DEV")
                                    .color(egui::Color32::from_rgb(0xc8, 0x85, 0x5a))
                                    .size(9.0)
                                    .strong()
                                    .monospace(),
                            )
                            .fill(egui::Color32::from_rgb(0x2a, 0x1a, 0x00))
                            .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(0xc8, 0x85, 0x5a)))
                            .rounding(3.0),
                        );
                        ui.add_space(4.0);
                    }

                    // License badge
                    let (license_color, license_label) = license_indicator(state);
                    let badge = ui.add(
                        egui::Button::new(
                            egui::RichText::new(license_label)
                                .color(license_color)
                                .size(9.0)
                                .strong(),
                        )
                        .fill(t.card)
                        .stroke(egui::Stroke::new(1.0, t.border))
                        .rounding(4.0),
                    );
                    if badge.clicked() {
                        state.show_license_panel = true;
                    }

                    ui.add_space(6.0);

                    // Case name
                    let case_name = state
                        .case
                        .as_ref()
                        .map(|c| c.name.as_str())
                        .unwrap_or("Unsaved Session");
                    ui.label(
                        egui::RichText::new(case_name)
                            .color(t.text)
                            .size(10.0)
                            .strong(),
                    );
                    ui.label(
                        egui::RichText::new("CASE")
                            .color(egui::Color32::from_rgb(0x1c, 0x26, 0x38))
                            .size(8.0),
                    );
                });
            });

            ui.add_space(2.0);

            // ═══ ROW 2: Search + stats + action buttons ═══
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing = egui::vec2(4.0, 0.0);

                // Search bar — max 480px
                let search_border = if state.global_search_active || !state.global_search_query.is_empty() {
                    t.active
                } else {
                    t.border
                };

                egui::Frame::none()
                    .fill(t.card)
                    .stroke(egui::Stroke::new(1.0, search_border))
                    .rounding(6.0)
                    .inner_margin(egui::Margin::symmetric(8.0, 3.0))
                    .show(ui, |ui| {
                        ui.set_width(480.0_f32.min(ui.available_width() * 0.35));
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("\u{E30C}").color(t.muted).size(12.0));
                            let resp = ui.add(
                                egui::TextEdit::singleline(&mut state.global_search_query)
                                    .desired_width(ui.available_width() - 20.0)
                                    .hint_text("Search files, paths...")
                                    .frame(false),
                            );
                            if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                                activate_search_mode(state);
                            }
                            if state.global_search_active
                                && ui.button(egui::RichText::new("\u{2715}").color(t.muted).size(10.0)).clicked()
                            {
                                exit_search_mode(state);
                            }
                        });
                    });

                ui.add_space(8.0);

                // ── Inline stats ────────────────────────────────────────
                let label_c = egui::Color32::from_rgb(0x1c, 0x26, 0x38);
                let sep_c = label_c;
                let total_files = state.total_files_count;
                let suspicious = state.suspicious_event_count;
                let flagged = state.file_index.iter().filter(|f| f.hash_flag.as_deref() == Some("KnownBad")).count();
                let carved = state.file_index.iter().filter(|f| f.is_carved).count();
                let hashed = state.file_index.iter().filter(|f| f.sha256.is_some()).count();
                let artifacts = state.artifact_total;

                let stat = |ui: &mut egui::Ui, name: &str, val: usize, val_color: egui::Color32| {
                    ui.label(egui::RichText::new(name).color(label_c).size(8.0));
                    ui.label(egui::RichText::new(format_count(val)).color(val_color).size(8.5).strong());
                };
                let sep = |ui: &mut egui::Ui| {
                    ui.label(egui::RichText::new("|").color(sep_c).size(8.0));
                };

                stat(ui, "FILES", total_files, egui::Color32::from_rgb(0x4a, 0x60, 0x80));
                sep(ui);
                stat(ui, "SUSPICIOUS", suspicious, egui::Color32::from_rgb(0xb8, 0x78, 0x40));
                sep(ui);
                stat(ui, "FLAGGED", flagged, egui::Color32::from_rgb(0xa8, 0x40, 0x40));
                sep(ui);
                stat(ui, "CARVED", carved, egui::Color32::from_rgb(0x4a, 0x78, 0x90));
                sep(ui);
                stat(ui, "HASHED", hashed, egui::Color32::from_rgb(0x48, 0x78, 0x58));
                sep(ui);
                stat(ui, "ARTIFACTS", artifacts, egui::Color32::from_rgb(0x60, 0x58, 0x78));

                // ── Action buttons (right-aligned) ─────────────────────
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.spacing_mut().item_spacing = egui::vec2(4.0, 0.0);

                    let has_files = !state.file_index.is_empty();
                    let has_case = state.case.is_some();
                    let can_file_carve = state.has_feature("file_carving");
                    let can_report_export = state.has_feature("report_export");
                    let can_html_report = !matches!(state.license_state.tier, LicenseTier::Free)
                        && !state.license_state.is_trial_expired();

                    // Export
                    ui.add_enabled_ui(has_case, |ui| {
                        let resp = action_btn(ui, "EXPORT",
                            egui::Color32::from_rgb(0xb8, 0x78, 0x40),
                            egui::Color32::from_rgb(0x38, 0x20, 0x10),
                            egui::Color32::from_rgb(0x0f, 0x10, 0x14));
                        if resp.clicked() {
                            if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                                match crate::ui::export::export_bundle(state, &dir) {
                                    Ok(files) => {
                                        state.status = format!("Export: {} files → {}", files.len(), dir.display());
                                        state.log_action("EXPORT", &format!("dir={} files={}", dir.display(), files.len()));
                                    }
                                    Err(e) => state.status = format!("Export failed: {}", e),
                                }
                            }
                        }
                    });

                    // Report
                    ui.add_enabled_ui(has_case && can_report_export, |ui| {
                        let resp = action_btn(ui, "REPORT",
                            egui::Color32::from_rgb(0x48, 0x78, 0x58),
                            egui::Color32::from_rgb(0x14, 0x20, 0x18),
                            egui::Color32::from_rgb(0x0f, 0x10, 0x14));
                        if resp.clicked() {
                            if let Some(path) = rfd::FileDialog::new()
                                .add_filter("HTML", &["html"])
                                .add_filter("PDF", &["pdf"])
                                .save_file()
                            {
                                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
                                let result = if ext == "html" && can_html_report {
                                    crate::ui::export::export_case_html(state, &path).map(|_| "html")
                                } else {
                                    crate::ui::export::export_case_pdf(state, &path).map(|_| "pdf")
                                };
                                match result {
                                    Ok(k) => { state.status = format!("Report: {}", path.display()); state.log_action("REPORT", &format!("{}={}", k, path.display())); }
                                    Err(e) => state.status = format!("Report failed: {}", e),
                                }
                            }
                        }
                    });

                    // Carve
                    ui.add_enabled_ui(has_files && can_file_carve, |ui| {
                        let resp = action_btn(ui, "CARVE",
                            egui::Color32::from_rgb(0x3a, 0x48, 0x58),
                            egui::Color32::from_rgb(0x18, 0x1c, 0x24),
                            egui::Color32::from_rgb(0x0f, 0x10, 0x14));
                        if resp.clicked() && !state.carve_active {
                            if state.carve_target_evidence_id.is_none() {
                                if let Some(first) = state.evidence_sources.first() {
                                    state.carve_target_evidence_id = Some(first.id.clone());
                                }
                            }
                            state.show_carve_dialog = true;
                        }
                    });

                    // Hash All
                    ui.add_enabled_ui(has_files, |ui| {
                        let resp = action_btn(ui, "HASH ALL",
                            egui::Color32::from_rgb(0x8a, 0x9a, 0xaa),
                            egui::Color32::from_rgb(0x1a, 0x28, 0x40),
                            egui::Color32::from_rgb(0x0f, 0x10, 0x14));
                        if resp.clicked() && !state.hashing_active {
                            let files: Vec<crate::state::FileEntry> = state.file_index.iter()
                                .filter(|f| !f.is_dir && f.sha256.is_none()).cloned().collect();
                            if !files.is_empty() {
                                let (tx, rx) = std::sync::mpsc::channel();
                                crate::evidence::hasher::spawn_hash_worker(files, state.vfs_context.clone(), tx);
                                state.hashing_rx = Some(rx);
                                state.hashing_active = true;
                                state.status = "Hashing started...".to_string();
                            }
                        }
                    });
                });
            });
        });

    // Handle Escape to exit search mode
    if state.global_search_active {
        ctx.input(|i| {
            if i.key_pressed(egui::Key::Escape) {
                // Will be handled next frame
            }
        });
        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            exit_search_mode(state);
        }
    }

    render_license_panel(ctx, state);
}

fn activate_search_mode(state: &mut AppState) {
    let query = state.global_search_query.to_lowercase();
    if query.is_empty() {
        return;
    }
    state.global_search_active = true;
    state.global_search_results.clear();

    // Search file index for matches
    for (idx, f) in state.file_index.iter().enumerate() {
        if f.is_dir {
            continue;
        }
        let name_lower = f.name.to_lowercase();
        let path_lower = f.path.to_lowercase();
        let ext_lower = f.extension.as_deref().unwrap_or("").to_lowercase();

        if name_lower.contains(&query)
            || path_lower.contains(&query)
            || ext_lower.contains(&query)
        {
            state.global_search_results.push(idx);
        }
    }

    // Apply search results as file filter
    state.file_filter = format!("$search:{}", state.global_search_query);
    state.mark_filter_dirty();
    state.view_mode = crate::state::ViewMode::FileExplorer;
    state.status = format!(
        "Search: {} results for \"{}\"",
        state.global_search_results.len(),
        state.global_search_query
    );
    state.log_action("SEARCH", &format!("query={} results={}", state.global_search_query, state.global_search_results.len()));
}

fn exit_search_mode(state: &mut AppState) {
    state.global_search_active = false;
    state.global_search_query.clear();
    state.global_search_results.clear();
    state.file_filter.clear();
    state.mark_filter_dirty();
    state.status = "Search mode exited.".to_string();
}

fn format_count(n: usize) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{},{:03}", n / 1000, n % 1000)
    } else {
        n.to_string()
    }
}

fn action_btn(
    ui: &mut egui::Ui,
    label: &str,
    text_color: egui::Color32,
    border_color: egui::Color32,
    bg_color: egui::Color32,
) -> egui::Response {
    ui.add(
        egui::Button::new(
            egui::RichText::new(label)
                .color(text_color)
                .size(10.0)
                .strong(),
        )
        .fill(bg_color)
        .stroke(egui::Stroke::new(1.0, border_color))
        .rounding(6.0),
    )
}

#[allow(dead_code)]
fn primary_btn(ui: &mut egui::Ui, t: &crate::theme::StrataTheme, label: &str) -> egui::Response {
    ui.add(
        egui::Button::new(egui::RichText::new(label).color(t.bg).size(10.0).strong())
            .fill(t.active)
            .stroke(egui::Stroke::new(1.0, t.active))
            .rounding(crate::theme::RADIUS_MD),
    )
}

fn sec_btn(ui: &mut egui::Ui, t: &crate::theme::StrataTheme, label: &str) -> egui::Response {
    ui.add(
        egui::Button::new(egui::RichText::new(label).color(t.secondary).size(10.0))
            .fill(egui::Color32::TRANSPARENT)
            .stroke(egui::Stroke::new(1.0, t.border))
            .rounding(crate::theme::RADIUS_MD),
    )
}

#[allow(dead_code)]
fn sec_btn_enabled(
    ui: &mut egui::Ui,
    t: &crate::theme::StrataTheme,
    label: &str,
    enabled: bool,
) -> egui::Response {
    ui.add_enabled(
        enabled,
        egui::Button::new(egui::RichText::new(label).color(t.secondary).size(10.0))
            .fill(egui::Color32::TRANSPARENT)
            .stroke(egui::Stroke::new(1.0, t.border))
            .rounding(crate::theme::RADIUS_MD),
    )
}

#[allow(dead_code)]
fn meta_item(ui: &mut egui::Ui, t: &crate::theme::StrataTheme, label: &str, value: &str) {
    ui.label(
        egui::RichText::new(format!("{}:", label))
            .color(t.secondary)
            .size(10.0),
    );
    ui.label(egui::RichText::new(value).color(t.text).size(10.0).strong());
}

#[allow(dead_code)]
fn meta_div(ui: &mut egui::Ui, t: &crate::theme::StrataTheme) {
    let cursor = ui.cursor().min;
    ui.painter().line_segment(
        [
            egui::pos2(cursor.x, cursor.y + 2.0),
            egui::pos2(cursor.x, cursor.y + 14.0),
        ],
        egui::Stroke::new(1.0, t.border),
    );
    ui.add_space(8.0);
}

#[allow(dead_code)]
fn truncate_path(p: &str, max: usize) -> String {
    if p.len() <= max {
        return p.to_string();
    }
    format!("\u{2026}{}", &p[p.len().saturating_sub(max)..])
}

fn open_case_file(state: &mut AppState, path: &std::path::Path) {
    let Ok(project) = crate::case::project::VtpProject::open(path) else {
        state.status = format!("Failed to open case: {}", path.display());
        return;
    };

    let case_name = project
        .get_meta("case_name")
        .unwrap_or_else(|| "Opened Case".to_string());
    let examiner = project
        .get_meta("examiner")
        .unwrap_or_else(|| state.examiner_name.clone());

    state.case = Some(crate::state::ActiveCase {
        name: case_name.clone(),
        id: project
            .get_meta("case_id")
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        agency: project.get_meta("agency").unwrap_or_default(),
        path: path.to_string_lossy().to_string(),
    });

    state.examiner_name = examiner;
    if let Ok(sources) = project.load_evidence_sources() {
        state.evidence_sources = sources;
        state.rebuild_vfs_context();
    }
    if let Ok(files) = project.load_file_index() {
        state.file_index = files;
        state.mark_counters_dirty();
        state.mark_filter_dirty();
    }
    if project.get_meta("database_path").is_none() {
        let default_db = std::path::PathBuf::from(path)
            .parent()
            .map(|p| p.join("strata_index.db"))
            .unwrap_or_else(|| std::path::PathBuf::from("strata_index.db"));
        let _ = project.set_meta("database_path", &default_db.to_string_lossy());
    }
    if let Ok(bookmarks) = project.load_bookmarks() {
        state.bookmarks = bookmarks;
    }
    if let Ok(search_results) = project.load_search_results() {
        state.search_results = search_results;
        state.search_active = !state.search_results.is_empty();
    }
    if let Ok(audit) = project.load_audit_log() {
        state.audit_log = audit;
    }
    let get_pref = |key: &str| project.get_ui_pref(key).or_else(|| project.get_meta(key));

    if let Ok(Some((diff, compare_a, compare_b))) = project.load_latest_compare_result() {
        state.compare_result = Some(diff);
        state.compare_a_id = compare_a;
        state.compare_b_id = compare_b;
    } else if let Some(compare_json) = project.get_meta("compare_result_json") {
        if let Ok(diff) = serde_json::from_str::<crate::state::EvidenceDiff>(&compare_json) {
            state.compare_result = Some(diff);
        }
        if let Some(compare_a_id) = get_pref("compare_a_id") {
            state.compare_a_id = Some(compare_a_id);
        }
        if let Some(compare_b_id) = get_pref("compare_b_id") {
            state.compare_b_id = Some(compare_b_id);
        }
    }
    if let Some(timeline_json) = get_pref("timeline_entries_json") {
        if let Ok(entries) =
            serde_json::from_str::<Vec<crate::state::TimelineEntry>>(&timeline_json)
        {
            state.suspicious_event_count = entries.iter().filter(|e| e.suspicious).count();
            state.timeline_entries = entries;
        }
    } else if let Ok(entries) = project.load_timeline_entries() {
        state.suspicious_event_count = entries.iter().filter(|e| e.suspicious).count();
        state.timeline_entries = entries;
    }
    if let Some(timeline_filter_json) = get_pref("timeline_filter_json") {
        if let Ok(filter) =
            serde_json::from_str::<crate::state::TimelineFilterState>(&timeline_filter_json)
        {
            state.timeline_filter = filter;
        }
    }
    if let Some(timeline_query) = get_pref("timeline_query") {
        state.timeline_query = timeline_query;
    }
    if let Some(timeline_from_utc) = get_pref("timeline_from_utc") {
        state.timeline_from_utc = timeline_from_utc;
    }
    if let Some(timeline_to_utc) = get_pref("timeline_to_utc") {
        state.timeline_to_utc = timeline_to_utc;
    }
    let mut loaded_hash_ref_rows = false;
    if let Ok(mut list) = project.load_hash_set_refs() {
        if !list.is_empty() {
            loaded_hash_ref_rows = true;
            for item in &mut list {
                let path = std::path::PathBuf::from(&item.source);
                if !path.exists() {
                    continue;
                }
                let loaded = if item.name.to_lowercase().contains("nsrl")
                    || item.category.eq_ignore_ascii_case("KnownGood")
                {
                    state.hash_set_manager.load_nsrl(&path)
                } else {
                    state.hash_set_manager.load_custom(&path, &item.category)
                };
                if let Ok(count) = loaded {
                    item.entry_count = count;
                }
            }
            state.hash_sets = list;
            state.recompute_hash_flags();
        }
    }
    if !loaded_hash_ref_rows {
        if let Ok(mut list) = project.load_hash_sets() {
            if !list.is_empty() {
                for item in &mut list {
                    let path = std::path::PathBuf::from(&item.source);
                    if !path.exists() {
                        continue;
                    }
                    let loaded = if item.name.to_lowercase().contains("nsrl")
                        || item.category.eq_ignore_ascii_case("KnownGood")
                    {
                        state.hash_set_manager.load_nsrl(&path)
                    } else {
                        state.hash_set_manager.load_custom(&path, &item.category)
                    };
                    if let Ok(count) = loaded {
                        item.entry_count = count;
                    }
                }
                state.hash_sets = list;
                state.recompute_hash_flags();
            }
        } else if let Some(hash_sets_json) = get_pref("hash_sets_json") {
            if let Ok(list) =
                serde_json::from_str::<Vec<crate::state::HashSetListItem>>(&hash_sets_json)
            {
                state.hash_sets = list;
            }
        }
    }
    if let Some(table_state_json) = get_pref("file_table_state_json") {
        if let Ok(table_state) =
            serde_json::from_str::<crate::state::FileTableState>(&table_state_json)
        {
            state.file_table_state = table_state;
        }
    }
    if let Some(selected_file_id) = get_pref("last_selected_file_id") {
        state.selected_file_id = Some(selected_file_id);
    }
    if let Some(selected_tree_path) = get_pref("last_selected_tree_path") {
        state.selected_tree_path = Some(selected_tree_path.clone());
        state.file_filter = selected_tree_path;
        state.mark_filter_dirty();
    } else if let Some(file_filter) = get_pref("file_filter") {
        state.file_filter = file_filter;
        state.mark_filter_dirty();
    }
    if let Some(view_mode) = get_pref("view_mode") {
        state.view_mode = match view_mode.as_str() {
            "bookmarks" => crate::state::ViewMode::Bookmarks,
            "gallery" => crate::state::ViewMode::Gallery,
            "compare" => crate::state::ViewMode::Compare,
            "timeline" => crate::state::ViewMode::Timeline,
            "registry" => crate::state::ViewMode::Registry,
            "event_logs" => crate::state::ViewMode::EventLogs,
            "browser_history" => crate::state::ViewMode::BrowserHistory,
            "search" => crate::state::ViewMode::Search,
            "hash_sets" => crate::state::ViewMode::HashSets,
            "audit_log" => crate::state::ViewMode::AuditLog,
            "plugins" => crate::state::ViewMode::Plugins,
            _ => crate::state::ViewMode::FileExplorer,
        };
    }
    if let Some(active_tag) = get_pref("active_tag") {
        state.active_tag = active_tag;
    }
    if let Some(examiner_note) = get_pref("examiner_note") {
        state.examiner_note = examiner_note;
    }
    if let Some(preview_tab) = get_pref("preview_tab") {
        state.preview_tab = preview_tab.parse::<u8>().ok().unwrap_or(0);
    }
    if let Some(selected_plugin) = get_pref("selected_plugin") {
        state.selected_plugin = Some(selected_plugin);
    }
    if let Some(plugin_enabled_json) = project.get_meta("plugin_enabled_json") {
        if let Ok(enabled) =
            serde_json::from_str::<std::collections::HashMap<String, bool>>(&plugin_enabled_json)
        {
            state.plugin_enabled = enabled;
        }
    }
    if !state.hash_sets.is_empty() {
        state.recompute_hash_flags();
    }
    state.refresh_running_counters();
    state.content_index_ready = state
        .content_index_dir()
        .map(|p| p.exists())
        .unwrap_or(false);
    state.content_indexing_active = false;
    state.content_index_rx = None;
    state.content_index_progress = (0, 0);
    state.content_search_hits.clear();
    state.content_index_error = None;
    state.case_dirty = false;
    state.last_auto_save_at = Some(std::time::Instant::now());
    state.last_auto_save_utc =
        Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));

    let mut status = format!("Case opened: {}", case_name);
    match project.integrity_check() {
        Ok(result) if result.eq_ignore_ascii_case("ok") => {}
        Ok(result) => {
            status = format!("Case opened with warning: DB integrity check={}", result);
            state.log_action(
                "CASE_INTEGRITY_FAILED",
                &format!("sqlite_integrity={}", result),
            );
        }
        Err(err) => {
            status = format!(
                "Case opened with warning: DB integrity check failed ({})",
                err
            );
            state.log_action(
                "CASE_INTEGRITY_FAILED",
                &format!("sqlite_integrity_error={}", err),
            );
        }
    }
    if let Some(stored_hash) = project.get_meta("case_integrity_hash") {
        let current_hash = project.compute_integrity_hash().ok();
        if let Some(current_hash) = current_hash {
            if !stored_hash.eq_ignore_ascii_case(&current_hash) {
                status = "Case opened with warning: case integrity hash mismatch".to_string();
                state.log_action("CASE_INTEGRITY_WARNING", "case_integrity_hash mismatch");
            }
        } else {
            status = "Case opened with warning: case integrity hash mismatch".to_string();
            state.log_action(
                "CASE_INTEGRITY_WARNING",
                "case_integrity_hash verification failed",
            );
        }
    }
    match crate::state::verify_audit_chain(&state.audit_log) {
        crate::state::ChainVerifyResult::Verified { .. } => {}
        crate::state::ChainVerifyResult::Broken { sequence, detail } => {
            status = format!(
                "Case opened with warning: audit chain broken at {} ({})",
                sequence, detail
            );
            state.log_action(
                "CASE_INTEGRITY_FAILED",
                &format!("audit_chain_break sequence={} detail={}", sequence, detail),
            );
        }
    }

    state.status = status;
    state.log_action("CASE_OPENED", &format!("path={}", path.display()));
}

/// Wolf head mark — retained for future use when real PNG logo is embedded.
#[allow(dead_code)]
fn draw_wolf_head(painter: &egui::Painter, rect: egui::Rect) {
    let ox = rect.left();
    let oy = rect.top();
    let sx = rect.width() / 28.0;
    let sy = rect.height() / 28.0;

    let p = |x: f32, y: f32| egui::pos2(ox + x * sx, oy + y * sy);

    let poly = |points: &[(f32, f32)], fill: egui::Color32| {
        let pts: Vec<egui::Pos2> = points.iter().map(|&(x, y)| p(x, y)).collect();
        painter.add(egui::Shape::convex_polygon(
            pts,
            fill,
            egui::Stroke::NONE,
        ));
    };

    let poly_stroke = |points: &[(f32, f32)], fill: egui::Color32, stroke: egui::Stroke| {
        let pts: Vec<egui::Pos2> = points.iter().map(|&(x, y)| p(x, y)).collect();
        painter.add(egui::Shape::convex_polygon(pts, fill, stroke));
    };

    let bg = egui::Color32::from_rgb(0x08, 0x09, 0x0d);

    // Left ear outer
    poly(
        &[(4.0, 14.0), (7.0, 3.0), (11.0, 11.0)],
        egui::Color32::from_rgba_unmultiplied(0xb8, 0xc8, 0xd8, 230),
    );
    // Left ear inner
    poly(&[(5.0, 13.0), (7.0, 5.0), (10.0, 11.0)], bg);

    // Right ear outer
    poly(
        &[(24.0, 14.0), (21.0, 3.0), (17.0, 11.0)],
        egui::Color32::from_rgba_unmultiplied(0xb8, 0xc8, 0xd8, 230),
    );
    // Right ear inner
    poly(&[(23.0, 13.0), (21.0, 5.0), (18.0, 11.0)], bg);

    // Main head octagon
    poly_stroke(
        &[
            (14.0, 2.0),
            (22.0, 8.0),
            (24.0, 15.0),
            (20.0, 22.0),
            (14.0, 26.0),
            (8.0, 22.0),
            (4.0, 15.0),
            (6.0, 8.0),
        ],
        egui::Color32::from_rgb(0x11, 0x1e, 0x2e),
        egui::Stroke::new(0.8 * sx.min(sy), egui::Color32::from_rgb(0x8f, 0xa8, 0xc0)),
    );

    // Forehead center plate
    poly_stroke(
        &[(14.0, 4.0), (18.0, 8.0), (14.0, 11.0), (10.0, 8.0)],
        egui::Color32::from_rgb(0x1a, 0x2e, 0x44),
        egui::Stroke::new(0.4 * sx.min(sy), egui::Color32::from_rgb(0x8f, 0xa8, 0xc0)),
    );

    // Left face plate
    poly(
        &[(6.0, 8.0), (10.0, 8.0), (9.0, 15.0), (5.0, 14.0)],
        egui::Color32::from_rgba_unmultiplied(0x16, 0x20, 0x30, 204),
    );
    // Right face plate
    poly(
        &[(22.0, 8.0), (18.0, 8.0), (19.0, 15.0), (23.0, 14.0)],
        egui::Color32::from_rgba_unmultiplied(0x16, 0x20, 0x30, 204),
    );

    // Left eye socket
    poly(
        &[(8.0, 11.0), (10.0, 10.0), (12.0, 12.0), (10.0, 14.0), (7.0, 13.0)],
        egui::Color32::from_rgb(0x08, 0x0c, 0x10),
    );
    // Left eye glow
    poly(
        &[(8.0, 11.0), (10.0, 10.0), (12.0, 12.0), (10.0, 13.0), (8.0, 12.0)],
        egui::Color32::from_rgba_unmultiplied(0x4a, 0x7f, 0xc1, 128),
    );
    // Left eye bright
    poly(
        &[(9.0, 11.0), (10.0, 10.0), (11.0, 12.0), (10.0, 13.0), (8.0, 12.0)],
        egui::Color32::from_rgba_unmultiplied(0xff, 0xff, 0xff, 230),
    );

    // Right eye socket
    poly(
        &[(20.0, 11.0), (18.0, 10.0), (16.0, 12.0), (18.0, 14.0), (21.0, 13.0)],
        egui::Color32::from_rgb(0x08, 0x0c, 0x10),
    );
    // Right eye glow
    poly(
        &[(20.0, 11.0), (18.0, 10.0), (16.0, 12.0), (18.0, 13.0), (20.0, 12.0)],
        egui::Color32::from_rgba_unmultiplied(0x4a, 0x7f, 0xc1, 128),
    );
    // Right eye bright
    poly(
        &[(19.0, 11.0), (18.0, 10.0), (17.0, 12.0), (18.0, 13.0), (20.0, 12.0)],
        egui::Color32::from_rgba_unmultiplied(0xff, 0xff, 0xff, 230),
    );

    // Nose
    poly(
        &[(13.0, 16.0), (14.0, 14.0), (15.0, 16.0), (14.0, 18.0)],
        egui::Color32::from_rgba_unmultiplied(0x8f, 0xa8, 0xc0, 179),
    );

    // Chin plate
    poly_stroke(
        &[(10.0, 21.0), (14.0, 19.0), (18.0, 21.0), (16.0, 25.0), (12.0, 25.0)],
        egui::Color32::from_rgb(0x1a, 0x2e, 0x44),
        egui::Stroke::new(0.4 * sx.min(sy), egui::Color32::from_rgb(0x8f, 0xa8, 0xc0)),
    );

    // Center line
    painter.line_segment(
        [p(14.0, 4.0), p(14.0, 14.0)],
        egui::Stroke::new(
            0.3 * sx.min(sy),
            egui::Color32::from_rgba_unmultiplied(0x8f, 0xa8, 0xc0, 64),
        ),
    );
}

fn license_indicator(state: &AppState) -> (egui::Color32, String) {
    if state.license_state.is_trial_expired() {
        return (
            egui::Color32::from_rgb(0xe2, 0x4b, 0x4a),
            "Expired".to_string(),
        );
    }
    if state.license_state.is_trial {
        let days = state.license_state.trial_days_remaining.unwrap_or(0);
        return (
            egui::Color32::from_rgb(0xef, 0x9f, 0x27),
            format!("Trial ({})", days),
        );
    }
    match state.license_state.tier {
        LicenseTier::Professional | LicenseTier::Enterprise => {
            (egui::Color32::from_rgb(0x4a, 0xde, 0x80), "Pro".to_string())
        }
        LicenseTier::Trial => {
            let days = state.license_state.days_remaining.unwrap_or(0);
            (
                egui::Color32::from_rgb(0xef, 0x9f, 0x27),
                format!("Trial ({})", days),
            )
        }
        LicenseTier::Free => (
            egui::Color32::from_rgb(0x60, 0xa5, 0xfa),
            "Free".to_string(),
        ),
    }
}

fn render_license_panel(ctx: &egui::Context, state: &mut AppState) {
    if !state.show_license_panel {
        return;
    }

    let mut open = state.show_license_panel;
    egui::Window::new("License")
        .collapsible(false)
        .resizable(true)
        .default_width(520.0)
        .default_height(380.0)
        .open(&mut open)
        .show(ctx, |ui| {
            ui.label(
                egui::RichText::new(state.license_state.display_status())
                    .size(11.0)
                    .strong(),
            );
            ui.add_space(4.0);
            ui.label(format!("Tier: {}", state.license_state.tier_short_label()));
            ui.label(format!(
                "Licensee: {}",
                state.license_state.licensee_display()
            ));
            ui.label(format!("Expiry: {}", state.license_state.expiry_display()));
            if let Some(path) = &state.license_state.license_path {
                ui.label(format!("License file: {}", path.to_string_lossy()));
            } else {
                ui.label("License file: (none)");
            }
            if let Some(err) = state.license_state.validation_error() {
                ui.colored_label(
                    egui::Color32::from_rgb(0xef, 0x9f, 0x27),
                    format!("Last validation warning: {}", err),
                );
            }

            ui.separator();
            ui.label(egui::RichText::new("License Features").strong().size(9.5));
            egui::ScrollArea::vertical()
                .max_height(120.0)
                .show(ui, |ui| {
                    for feature in &state.license_state.features {
                        ui.label(format!("- {}", feature));
                    }
                });

            ui.separator();
            ui.label(egui::RichText::new("Machine ID").strong().size(9.5));
            let machine_id = state.license_state.machine_id_display();
            ui.horizontal(|ui| {
                ui.monospace(&machine_id);
                if ui.small_button("Copy").clicked() {
                    ui.ctx().copy_text(machine_id.clone());
                }
            });
            ui.label(
                "Send this to wolfmarksystems@proton.me to request a trial or purchase a license.",
            );

            ui.add_space(8.0);
            if ui.button("Load License File...").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("Strata License", &["vlic"])
                    .pick_file()
                {
                    match crate::license_state::AppLicenseState::install_license_file(&path) {
                        Ok(_) => {
                            state.refresh_license_state();
                            state.status = "License loaded successfully.".to_string();
                            state.log_action("LICENSE_LOAD", &format!("path={}", path.display()));
                        }
                        Err(err) => {
                            state.status = format!("License load failed: {}", err);
                            state.log_action("LICENSE_LOAD_FAILED", &err);
                        }
                    }
                }
            }
        });
    state.show_license_panel = open;
}
