// ui/audit_log.rs — Examiner Audit Log viewer (Phase 3, Task 3.1).
//
// Displays the activity_log in a read-only, chronological table.
// Entries cannot be deleted, edited, or exported from this panel —
// the log is append-only and stored in the .vtp case file.
// Examiner can copy a single entry's detail to clipboard.

use egui::ScrollArea;
use crate::state::AppState;

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading("Examiner Audit Log");
    ui.horizontal(|ui| {
        ui.label(format!("{} entries", state.audit_log.len()));
        ui.separator();
        ui.label(egui::RichText::new("Read-only. Cannot be modified or deleted.").color(egui::Color32::from_rgb(180, 130, 50)));
    });
    ui.separator();

    if state.audit_log.is_empty() {
        ui.label("No activity recorded yet. Actions taken during this examination will appear here.");
        return;
    }

    // Column headers.
    egui::Grid::new("audit_header")
        .num_columns(4)
        .striped(false)
        .min_col_width(60.0)
        .show(ui, |ui| {
            ui.strong("Timestamp (UTC)");
            ui.strong("Examiner");
            ui.strong("Action");
            ui.strong("Detail");
            ui.end_row();
        });

    ui.separator();

    ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::Grid::new("audit_log_grid")
                .num_columns(4)
                .striped(true)
                .min_col_width(60.0)
                .show(ui, |ui| {
                    // Show most-recent first.
                    for entry in state.audit_log.iter().rev() {
                        // Timestamp — show only to-the-second part.
                        let ts = entry.timestamp_utc.as_str();
                        ui.label(egui::RichText::new(ts).monospace().small());

                        // Examiner.
                        ui.label(egui::RichText::new(&entry.examiner).small());

                        // Action — colour-coded by severity.
                        let action_text = egui::RichText::new(&entry.action).small();
                        let action_text = match entry.action.as_str() {
                            s if s.contains("FAILED") || s.contains("ERROR") =>
                                action_text.color(egui::Color32::from_rgb(200, 80, 80)),
                            s if s.contains("BOOKMARK") || s.contains("SEARCH") =>
                                action_text.color(egui::Color32::from_rgb(100, 160, 220)),
                            s if s.contains("HASH") || s.contains("CARVE") =>
                                action_text.color(egui::Color32::from_rgb(160, 120, 220)),
                            s if s.contains("CASE") || s.contains("EVIDENCE") =>
                                action_text.color(egui::Color32::from_rgb(80, 180, 100)),
                            _ => action_text,
                        };
                        ui.label(action_text);

                        // Detail (truncated).
                        let detail = entry.detail.as_deref().unwrap_or("—");
                        let truncated = if detail.len() > 120 {
                            format!("{}…", &detail[..120])
                        } else {
                            detail.to_string()
                        };
                        ui.label(egui::RichText::new(&truncated).small())
                            .on_hover_text(detail);

                        ui.end_row();
                    }
                });
        });
}
