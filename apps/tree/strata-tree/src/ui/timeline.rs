// ui/timeline.rs — File System Timestamp View (Phase 2, Task 2.3).
//
// Groups files by their modified_utc date (YYYY-MM-DD) and presents them
// in a collapsible per-day list sorted chronologically.
// Also draws a simple calendar heatmap (activity density by date).
//
// NOTE: This shows filesystem metadata timestamps extracted from the evidence.
// It is NOT the Chronicle artifact timeline (that is a separate product feature).

use egui::ScrollArea;
use crate::state::AppState;

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading("File System Timeline");
    ui.separator();

    if state.file_index.is_empty() {
        ui.label("No files indexed. Load evidence to populate the timeline.");
        return;
    }

    // Build date → file list mapping.
    let mut by_date: std::collections::BTreeMap<String, Vec<usize>> = std::collections::BTreeMap::new();
    for (idx, f) in state.file_index.iter().enumerate() {
        if f.is_dir { continue; }
        let date = f.modified_utc.as_deref()
            .and_then(|s| s.get(..10))
            .unwrap_or("Unknown Date");
        by_date.entry(date.to_string()).or_default().push(idx);
    }

    let total_days = by_date.len();
    let total_files = state.file_index.iter().filter(|f| !f.is_dir).count();

    ui.label(format!("{} files across {} distinct dates", total_files, total_days));
    ui.separator();

    // ─── Heatmap ───────────────────────────────────────────────────────────
    let max_per_day = by_date.values().map(|v| v.len()).max().unwrap_or(1).max(1);

    ui.label("Activity heatmap (daily file-modification density):");
    ui.add_space(4.0);

    let cell_size = 14.0f32;
    let weeks_to_show = 52usize;
    let desired_width = weeks_to_show as f32 * (cell_size + 1.0);

    // Get ordered dates for last N weeks.
    let all_dates: Vec<_> = by_date.keys().cloned().collect();
    let display_dates: Vec<_> = all_dates.iter().rev().take(weeks_to_show * 7).collect();

    let (rect, _) = ui.allocate_exact_size(
        egui::Vec2::new(desired_width, 7.0 * (cell_size + 1.0) + 20.0),
        egui::Sense::hover(),
    );

    if ui.is_rect_visible(rect) {
        let mut col = 0;
        let mut row = 0;
        for date_str in display_dates.iter().rev() {
            let count = by_date.get(*date_str).map(|v| v.len()).unwrap_or(0);
            let intensity = (count as f32 / max_per_day as f32).sqrt(); // sqrt for perceptual scale
            let color = heat_color(intensity);

            let cell_rect = egui::Rect::from_min_size(
                rect.min + egui::Vec2::new(col as f32 * (cell_size + 1.0), row as f32 * (cell_size + 1.0)),
                egui::Vec2::splat(cell_size),
            );
            ui.painter().rect_filled(cell_rect, 2.0, color);

            row += 1;
            if row >= 7 {
                row = 0;
                col += 1;
            }
        }
    }

    ui.add_space(8.0);
    ui.separator();

    // ─── Per-Day Collapsible List ───────────────────────────────────────────
    ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            // Show most-recent first.
            for (date, indices) in by_date.iter().rev() {
                let header = format!("{} — {} file{}", date, indices.len(), if indices.len() == 1 { "" } else { "s" });
                egui::CollapsingHeader::new(&header)
                    .default_open(false)
                    .show(ui, |ui| {
                        for &idx in indices.iter().take(200) {
                            let f = &state.file_index[idx];
                            let time = f.modified_utc.as_deref()
                                .and_then(|s| s.get(11..19))
                                .unwrap_or("??:??:??");
                            let size_str = f.size
                                .map(|s| format_size(s as u64))
                                .unwrap_or_else(|| "—".to_string());
                            let label = format!(
                                "{} │ {} │ {}",
                                time,
                                size_str,
                                f.path,
                            );
                            let is_selected = state.selected_file.as_deref() == Some(&f.id);
                            let text = if is_selected {
                                egui::RichText::new(&label).strong().color(egui::Color32::from_rgb(120, 180, 255))
                            } else if f.is_deleted {
                                egui::RichText::new(&label).color(egui::Color32::from_rgb(180, 100, 100))
                            } else {
                                egui::RichText::new(&label)
                            };
                            if ui.selectable_label(is_selected, text).clicked() {
                                state.selected_file = Some(f.id.clone());
                            }
                        }
                        if indices.len() > 200 {
                            ui.label(format!("… {} more files not shown", indices.len() - 200));
                        }
                    });
            }
        });
}

fn heat_color(intensity: f32) -> egui::Color32 {
    let i = intensity.clamp(0.0, 1.0);
    if i < 0.001 {
        egui::Color32::from_rgb(30, 30, 30)
    } else if i < 0.25 {
        egui::Color32::from_rgb(0, 68, 27)
    } else if i < 0.50 {
        egui::Color32::from_rgb(0, 109, 44)
    } else if i < 0.75 {
        egui::Color32::from_rgb(49, 163, 84)
    } else {
        egui::Color32::from_rgb(173, 221, 142)
    }
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes >= GB { format!("{:.1} GB", bytes as f64 / GB as f64) }
    else if bytes >= MB { format!("{:.1} MB", bytes as f64 / MB as f64) }
    else if bytes >= KB { format!("{:.0} KB", bytes as f64 / KB as f64) }
    else { format!("{} B", bytes) }
}
