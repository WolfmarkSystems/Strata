// ui/dialogs/export.rs — Export options dialog.
use crate::state::{colors::*, AppState};

pub fn render(ctx: &egui::Context, state: &mut AppState) {
    if !state.show_export_dialog {
        return;
    }

    egui::Window::new("Export Case Data")
        .collapsible(false)
        .resizable(false)
        .default_width(400.0)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            ui.label(
                egui::RichText::new("EXPORT OPTIONS")
                    .color(ACCENT)
                    .size(11.0)
                    .strong(),
            );
            ui.add_space(8.0);

            ui.checkbox(&mut state.export_files_csv, "File listing (CSV)");
            ui.checkbox(&mut state.export_bookmarks, "Bookmarks (CSV + HTML)");
            ui.checkbox(&mut state.export_timeline, "Timeline (CSV)");
            ui.checkbox(&mut state.export_audit_log, "Audit log (CSV)");
            ui.checkbox(&mut state.export_hashes, "Hash results (CSV)");
            ui.checkbox(&mut state.export_pdf_report, "Court-ready PDF report");

            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if ui
                    .button(egui::RichText::new("EXPORT").color(ACCENT).strong())
                    .clicked()
                {
                    if let Some(dir) = rfd::FileDialog::new()
                        .set_title("Select export directory")
                        .pick_folder()
                    {
                        match crate::ui::export::export_bundle(state, &dir) {
                            Ok(files) => {
                                state.status = format!("Exported {} files to {}", files.len(), dir.display());
                                state.log_action(
                                    "EXPORT_BUNDLE",
                                    &format!("dir={} files={}", dir.display(), files.len()),
                                );
                            }
                            Err(e) => {
                                state.status = format!("Export failed: {}", e);
                            }
                        }
                        state.show_export_dialog = false;
                    }
                }
                if ui.button("Cancel").clicked() {
                    state.show_export_dialog = false;
                }
            });
        });
}
