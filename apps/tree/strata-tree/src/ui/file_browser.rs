// ui/file_browser.rs — Left pane: evidence source tree and directory navigation.

use crate::state::AppState;

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading("Evidence");
    ui.separator();

    if state.evidence_sources.is_empty() {
        ui.label("No evidence loaded.");
        ui.label("Use 'Open Evidence' to add a source.");
        return;
    }

    egui::ScrollArea::vertical().show(ui, |ui| {
        for source in &state.evidence_sources {
            let label = source.label.as_deref().unwrap_or(
                std::path::Path::new(&source.path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(&source.path),
            );
            let header = format!("📁 {} [{}]", label, source.format);
            egui::CollapsingHeader::new(header)
                .default_open(true)
                .show(ui, |ui| {
                    // Gather unique top-level directories for this evidence source.
                    let dirs: std::collections::BTreeSet<String> = state
                        .file_index
                        .iter()
                        .filter(|f| f.evidence_id == source.id && f.is_dir)
                        .map(|f| f.name.clone())
                        .collect();

                    for dir in &dirs {
                        if ui.selectable_label(false, format!("📂 {}", dir)).clicked() {
                            state.ui_state.current_dir_filter = Some(dir.clone());
                        }
                    }
                });
        }
    });

    ui.separator();
    if ui.button("+ Add Evidence Source").clicked() {
        state.ui_state.show_open_evidence_dialog = true;
    }
}
