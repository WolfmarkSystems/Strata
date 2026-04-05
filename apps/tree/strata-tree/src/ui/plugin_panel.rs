// ui/plugin_panel.rs — Plugin management panel (Gap 9).

use crate::state::AppState;

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading(format!("Plugins ({})", state.plugin_manager.plugins.len()));
    ui.separator();

    ui.horizontal(|ui| {
        if ui.button("Load Plugin…").clicked() {
            let filters: &[&str] = if cfg!(target_os = "windows") {
                &["dll"]
            } else if cfg!(target_os = "macos") {
                &["dylib"]
            } else {
                &["so"]
            };

            if let Some(path) = rfd::FileDialog::new()
                .set_title("Load Strata Plugin")
                .add_filter("Plugin Library", filters)
                .pick_file()
            {
                let path_display = path.display().to_string();
                match state.plugin_manager.load_plugin(&path) {
                    Ok(_) => {
                        state.log_action(
                            "PLUGIN_LOADED",
                            Some(&format!("path={}", path_display)),
                            None,
                        );
                        state.status_message =
                            format!("Plugin loaded from: {}", path_display);
                    }
                    Err(e) => {
                        state.error_message =
                            Some(format!("Plugin load failed: {}", e));
                    }
                }
            }
        }
        ui.label(
            egui::RichText::new(
                "Plugins receive file bytes read-only. All invocations are logged."
            )
            .small()
            .color(egui::Color32::from_rgb(130, 130, 130)),
        );
    });

    ui.separator();

    if state.plugin_manager.plugins.is_empty() {
        ui.label("No plugins loaded.");
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new(
                "Use 'Load Plugin…' to load a .dll/.so/.dylib built with the Strata SDK.",
            )
            .small(),
        );
        return;
    }

    // ── Plugin table ─────────────────────────────────────────────────────────
    let plugin_count = state.plugin_manager.plugins.len();
    let has_evidence = !state.evidence_sources.is_empty();

    // Collect info before the loop (avoid borrow conflicts).
    let plugin_info: Vec<(String, String, String)> = state
        .plugin_manager
        .plugins
        .iter()
        .map(|p| (
            p.meta.name.clone(),
            p.meta.version.clone(),
            p.meta.description.clone(),
        ))
        .collect();

    let mut unload_idx: Option<usize> = None;
    let mut invoke_idx: Option<usize> = None;

    egui::ScrollArea::vertical().show(ui, |ui| {
        egui::Grid::new("plugin_table")
            .num_columns(5)
            .spacing([8.0, 4.0])
            .striped(true)
            .min_col_width(80.0)
            .show(ui, |ui| {
                ui.strong("Name");
                ui.strong("Version");
                ui.strong("Description");
                ui.strong("Status");
                ui.strong("Actions");
                ui.end_row();

                for (i, (name, version, desc)) in plugin_info.iter().enumerate() {
                    ui.label(name);
                    ui.label(version);
                    ui.label(
                        egui::RichText::new(desc)
                            .small()
                            .color(egui::Color32::from_rgb(140, 140, 140)),
                    );
                    ui.label(
                        egui::RichText::new("Ready")
                            .color(egui::Color32::from_rgb(60, 160, 60)),
                    );
                    ui.horizontal(|ui| {
                        ui.add_enabled_ui(has_evidence, |ui| {
                            if ui.button("Invoke").clicked() {
                                invoke_idx = Some(i);
                            }
                        });
                        if ui.small_button("Unload").clicked() {
                            unload_idx = Some(i);
                        }
                    });
                    ui.end_row();
                }
            });
    });

    // ── Handle deferred actions ───────────────────────────────────────────────
    if let Some(i) = invoke_idx {
        if i < plugin_count {
            let source_path = state
                .evidence_sources
                .first()
                .map(|s| s.path.clone())
                .unwrap_or_default();
            let name = state.plugin_manager.plugins[i].meta.name.clone();
            let result = state.plugin_manager.plugins[i]
                .invoke_with_timeout(std::time::Duration::from_secs(30));
            state.log_action(
                "PLUGIN_INVOKE",
                Some(&format!("plugin={} source={} ok={}", name, source_path, result.success)),
                None,
            );
            state.status_message = format!("Plugin '{}': {}", name, result.message);
        }
    }

    if let Some(i) = unload_idx {
        if i < plugin_count {
            let name = state.plugin_manager.plugins[i].meta.name.clone();
            state.plugin_manager.plugins.remove(i);
            state.log_action("PLUGIN_UNLOAD", Some(&format!("plugin={}", name)), None);
            state.status_message = format!("Plugin '{}' unloaded.", name);
        }
    }

    if !has_evidence {
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new("Load evidence before invoking plugins.")
                .small()
                .color(egui::Color32::from_rgb(150, 120, 60)),
        );
    }
}
