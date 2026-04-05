// ui/statusbar.rs — Bottom status bar.
// Shows: file count | deleted count | indexing status | examiner name.

use crate::state::{AppState, IndexingStatus};

pub fn render(ctx: &egui::Context, state: &AppState) {
    egui::TopBottomPanel::bottom("statusbar").show(ctx, |ui| {
        ui.horizontal(|ui| {
            // File counts — show dash when data not loaded.
            let file_count = if state.file_index.is_empty() && !state.has_open_case() {
                "—".to_string()
            } else {
                state.file_index.len().to_string()
            };
            ui.label(format!("Files: {}", file_count));
            ui.separator();

            let deleted_count: usize = state.file_index.iter().filter(|f| f.is_deleted).count();
            let deleted_str = if state.file_index.is_empty() && !state.has_open_case() {
                "—".to_string()
            } else {
                deleted_count.to_string()
            };
            ui.label(format!("Deleted: {}", deleted_str));
            ui.separator();

            // Indexing status
            match &state.indexing_status {
                IndexingStatus::Idle => {}
                IndexingStatus::Running { files_found } => {
                    ui.spinner();
                    ui.label(format!("Indexing: {} files…", files_found));
                    ui.separator();
                }
                IndexingStatus::Complete { file_count } => {
                    ui.label(format!("Indexed: {}", file_count));
                    ui.separator();
                }
                IndexingStatus::Failed(err) => {
                    ui.colored_label(egui::Color32::RED, format!("Index failed: {}", err));
                    ui.separator();
                }
            }

            // Status / error message
            if let Some(err) = &state.error_message {
                ui.colored_label(egui::Color32::RED, err);
            } else if !state.status_message.is_empty() {
                ui.label(&state.status_message);
            }

            // Examiner always visible — chain of custody requirement.
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let name = state.examiner_name().to_string();
                if state.examiner.show_warning() {
                    ui.colored_label(
                        egui::Color32::from_rgb(220, 120, 0),
                        format!("⚠ {}", name),
                    );
                } else {
                    ui.label(egui::RichText::new(name).strong());
                }
            });
        });
    });
}
