//! Timeline view — chronological event timeline with filters and suspicious flags.

use chrono::{DateTime, Utc};

use crate::state::{colors::*, AppState, TimelineEventType, ViewMode};

#[derive(Default)]
struct TimelineUiState {
    show_file: bool,
    show_registry: bool,
    show_process: bool,
    show_user: bool,
    show_web: bool,
}

thread_local! {
    static UI_STATE: std::cell::RefCell<TimelineUiState> = const { std::cell::RefCell::new(TimelineUiState {
        show_file: true,
        show_registry: true,
        show_process: true,
        show_user: true,
        show_web: true,
    }) };
}

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("TIMELINE")
                .color(ACCENT)
                .size(11.0)
                .strong(),
        );
        ui.separator();
        ui.label(
            egui::RichText::new(format!("{} events", state.timeline_entries.len()))
                .color(TEXT_MUTED)
                .size(9.5),
        );
        ui.separator();
        ui.label(
            egui::RichText::new(format!("Suspicious: {}", state.suspicious_event_count))
                .color(if state.suspicious_event_count > 0 {
                    AMBER
                } else {
                    GREEN_OK
                })
                .size(9.0)
                .strong(),
        );
    });
    ui.add_space(4.0);

    ui.horizontal(|ui| {
        if ui.button("Export CSV").clicked() {
            if let Some(path) = rfd::FileDialog::new()
                .set_file_name("timeline.csv")
                .save_file()
            {
                match crate::ui::export::export_timeline_csv(state, &path) {
                    Ok(()) => state.status = format!("Timeline CSV exported: {}", path.display()),
                    Err(err) => state.status = format!("Timeline CSV export failed: {}", err),
                }
            }
        }
        if ui.button("Export JSON").clicked() {
            if let Some(path) = rfd::FileDialog::new()
                .set_file_name("timeline.json")
                .save_file()
            {
                match crate::ui::export::export_timeline_json(state, &path) {
                    Ok(()) => state.status = format!("Timeline JSON exported: {}", path.display()),
                    Err(err) => state.status = format!("Timeline JSON export failed: {}", err),
                }
            }
        }
        if ui.button("Export PDF").clicked() {
            if let Some(path) = rfd::FileDialog::new()
                .set_file_name("timeline.pdf")
                .save_file()
            {
                match crate::ui::export::export_timeline_pdf(state, &path) {
                    Ok(()) => state.status = format!("Timeline PDF exported: {}", path.display()),
                    Err(err) => state.status = format!("Timeline PDF export failed: {}", err),
                }
            }
        }
    });

    if state.timeline_entries.is_empty() {
        ui.label(
            egui::RichText::new("Timeline is empty. It is generated after indexing completes.")
                .color(TEXT_MUTED),
        );
        return;
    }

    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("From UTC:").color(TEXT_MUTED).size(8.5));
        if ui
            .text_edit_singleline(&mut state.timeline_from_utc)
            .changed()
        {
            state.mark_case_dirty();
        }
        ui.label(egui::RichText::new("To UTC:").color(TEXT_MUTED).size(8.5));
        if ui
            .text_edit_singleline(&mut state.timeline_to_utc)
            .changed()
        {
            state.mark_case_dirty();
        }
    });

    ui.horizontal(|ui| {
        if ui
            .checkbox(&mut state.timeline_filter.show_created, "Created")
            .changed()
        {
            state.mark_case_dirty();
        }
        if ui
            .checkbox(&mut state.timeline_filter.show_modified, "Modified")
            .changed()
        {
            state.mark_case_dirty();
        }
        if ui
            .checkbox(&mut state.timeline_filter.show_accessed, "Accessed")
            .changed()
        {
            state.mark_case_dirty();
        }
        if ui
            .checkbox(&mut state.timeline_filter.show_deleted, "Deleted")
            .changed()
        {
            state.mark_case_dirty();
        }
        ui.separator();
        ui.label(
            egui::RichText::new("Path search:")
                .color(TEXT_MUTED)
                .size(8.5),
        );
        if ui.text_edit_singleline(&mut state.timeline_query).changed() {
            state.mark_case_dirty();
        }
    });

    ui.horizontal_wrapped(|ui| {
        ui.label(egui::RichText::new("Sources:").color(TEXT_MUTED).size(8.5));
        UI_STATE.with(|cell| {
            let mut s = cell.borrow_mut();
            if ui.checkbox(&mut s.show_file, "File").changed() {
                state.mark_case_dirty();
            }
            if ui.checkbox(&mut s.show_registry, "Registry").changed() {
                state.mark_case_dirty();
            }
            if ui.checkbox(&mut s.show_process, "Process").changed() {
                state.mark_case_dirty();
            }
            if ui.checkbox(&mut s.show_user, "User").changed() {
                state.mark_case_dirty();
            }
            if ui.checkbox(&mut s.show_web, "Web").changed() {
                state.mark_case_dirty();
            }
        });
    });

    // ── Burst detection ────────────────────────────────────────────────────
    let bursts = detect_activity_bursts(&state.timeline_entries);
    if !bursts.is_empty() {
        ui.add_space(2.0);
        egui::Frame::none()
            .fill(egui::Color32::from_rgba_unmultiplied(20, 10, 5, 200))
            .stroke(egui::Stroke::new(1.0, AMBER))
            .inner_margin(egui::Margin::symmetric(8.0, 4.0))
            .show(ui, |ui| {
                ui.label(
                    egui::RichText::new(format!("⚠ {} activity burst(s) detected", bursts.len()))
                        .color(AMBER)
                        .size(9.0)
                        .strong(),
                );
                for burst in bursts.iter().take(5) {
                    ui.label(
                        egui::RichText::new(format!(
                            "  {} events in {} sec at {} (avg {:.1} events/sec)",
                            burst.event_count,
                            burst.duration_secs,
                            burst.start_time,
                            burst.events_per_sec,
                        ))
                        .color(TEXT_SEC)
                        .size(8.5)
                        .monospace(),
                    );
                }
            });
    }

    ui.add_space(4.0);
    render_timeline_heatmap(ui, state);

    ui.separator();
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("TIMESTAMP")
                .color(TEXT_MUTED)
                .strong()
                .size(8.5),
        );
        ui.separator();
        ui.label(
            egui::RichText::new("EVENT")
                .color(TEXT_MUTED)
                .strong()
                .size(8.5),
        );
        ui.separator();
        ui.label(
            egui::RichText::new("PATH")
                .color(TEXT_MUTED)
                .strong()
                .size(8.5),
        );
    });
    ui.separator();

    let filtered = UI_STATE.with(|cell| {
        let source = cell.borrow();
        filtered_entry_indices(
            state,
            &state.timeline_from_utc,
            &state.timeline_to_utc,
            &source,
        )
    });
    let row_h = 20.0;
    egui::ScrollArea::vertical().show_rows(ui, row_h, filtered.len(), |ui, range| {
        for idx in &filtered[range] {
            let Some(entry) = state.timeline_entries.get(*idx).cloned() else {
                continue;
            };
            let color = event_color(&entry.event_type);
            ui.horizontal(|ui| {
                if entry.suspicious {
                    ui.label(egui::RichText::new("!").color(AMBER).strong());
                } else {
                    ui.label(" ");
                }
                ui.label(
                    egui::RichText::new(
                        entry
                            .timestamp
                            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    )
                    .monospace()
                    .size(8.5)
                    .color(TEXT_SEC),
                );
                ui.separator();
                ui.label(
                    egui::RichText::new(event_label(&entry.event_type))
                        .color(color)
                        .size(8.5),
                );
                ui.separator();

                let selectable =
                    ui.selectable_label(false, egui::RichText::new(&entry.path).size(8.5));
                selectable.context_menu(|ui| {
                    if ui.button("Navigate to File").clicked() {
                        if let Some(fid) = &entry.file_id {
                            state.selected_file_id = Some(fid.clone());
                            if let Some(file) = state.file_index.iter().find(|f| f.id == *fid) {
                                state.selected_tree_path = Some(file.parent_path.clone());
                                state.file_filter = file.parent_path.clone();
                                state.mark_filter_dirty();
                            }
                        }
                        state.view_mode = ViewMode::FileExplorer;
                        ui.close_menu();
                    }
                    if ui.button("Copy Path").clicked() {
                        ui.ctx().copy_text(entry.path.clone());
                        ui.close_menu();
                    }
                    if ui.button("Copy Detail").clicked() {
                        ui.ctx().copy_text(entry.detail.clone());
                        ui.close_menu();
                    }
                });
                if selectable.clicked() {
                    if let Some(fid) = &entry.file_id {
                        state.selected_file_id = Some(fid.clone());
                        if let Some(file) = state.file_index.iter().find(|f| f.id == *fid) {
                            state.selected_tree_path = Some(file.parent_path.clone());
                            state.file_filter = file.parent_path.clone();
                            state.mark_filter_dirty();
                        }
                    }
                    state.view_mode = ViewMode::FileExplorer;
                }
            });
        }
    });
}

fn filtered_entry_indices(
    state: &AppState,
    from_utc: &str,
    to_utc: &str,
    source_filters: &TimelineUiState,
) -> Vec<usize> {
    let from_dt = parse_filter_datetime(from_utc);
    let to_dt = parse_filter_datetime(to_utc);
    let q = state.timeline_query.to_lowercase();

    state
        .timeline_entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| match entry.event_type {
            TimelineEventType::FileCreated => state.timeline_filter.show_created,
            TimelineEventType::FileModified | TimelineEventType::FileMftModified => {
                state.timeline_filter.show_modified
            }
            TimelineEventType::FileAccessed => state.timeline_filter.show_accessed,
            TimelineEventType::FileDeleted => state.timeline_filter.show_deleted,
            _ => true,
        })
        .filter(|(_, entry)| source_enabled(&entry.event_type, source_filters))
        .filter(|(_, entry)| {
            if let Some(from) = from_dt {
                if entry.timestamp < from {
                    return false;
                }
            }
            if let Some(to) = to_dt {
                if entry.timestamp > to {
                    return false;
                }
            }
            true
        })
        .filter(|(_, entry)| q.is_empty() || entry.path.to_lowercase().contains(&q))
        .map(|(idx, _)| idx)
        .collect()
}

fn source_enabled(event_type: &TimelineEventType, source_filters: &TimelineUiState) -> bool {
    match event_type {
        TimelineEventType::FileCreated
        | TimelineEventType::FileModified
        | TimelineEventType::FileAccessed
        | TimelineEventType::FileMftModified
        | TimelineEventType::FileDeleted => source_filters.show_file,
        TimelineEventType::RegistryKeyCreated
        | TimelineEventType::RegistryKeyModified
        | TimelineEventType::RegistryValueSet => source_filters.show_registry,
        TimelineEventType::ProcessExecuted => source_filters.show_process,
        TimelineEventType::UserLogin | TimelineEventType::UserActivity => source_filters.show_user,
        TimelineEventType::WebVisit => source_filters.show_web,
    }
}

fn render_timeline_heatmap(ui: &mut egui::Ui, state: &AppState) {
    use chrono::Timelike;
    use std::collections::BTreeMap;

    let mut dates: BTreeMap<String, [u16; 24]> = BTreeMap::new();
    for event in &state.timeline_entries {
        let day = event.timestamp.format("%Y-%m-%d").to_string();
        let hour = event.timestamp.hour() as usize;
        let row = dates.entry(day).or_insert([0u16; 24]);
        row[hour] = row[hour].saturating_add(1);
    }

    if dates.is_empty() {
        return;
    }

    let max_count = dates
        .values()
        .flat_map(|r| r.iter())
        .copied()
        .max()
        .unwrap_or(1) as f32;

    ui.label(
        egui::RichText::new("Activity Heatmap (UTC)")
            .color(TEXT_MUTED)
            .size(8.5)
            .strong(),
    );
    egui::ScrollArea::horizontal().show(ui, |ui| {
        egui::Grid::new("timeline_heatmap")
            .num_columns(25)
            .spacing([2.0, 2.0])
            .striped(false)
            .show(ui, |ui| {
                ui.label(egui::RichText::new("DATE").color(TEXT_MUTED).size(7.8));
                for h in 0..24usize {
                    ui.label(
                        egui::RichText::new(format!("{:02}", h))
                            .color(TEXT_MUTED)
                            .size(7.2),
                    );
                }
                ui.end_row();

                for (day, counts) in dates.iter().rev().take(14) {
                    ui.label(
                        egui::RichText::new(day)
                            .color(TEXT_SEC)
                            .size(7.8)
                            .monospace(),
                    );
                    for (hour, count) in counts.iter().enumerate() {
                        let ratio = (*count as f32 / max_count).clamp(0.0, 1.0);
                        let alpha = (40.0 + ratio * 180.0) as u8;
                        let fill = egui::Color32::from_rgba_unmultiplied(125, 211, 252, alpha);
                        let (rect, resp) =
                            ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                        ui.painter().rect_filled(rect, 1.0, fill);
                        if resp.hovered() {
                            resp.on_hover_text(format!(
                                "{} {:02}:00 UTC = {} events",
                                day, hour, count
                            ));
                        }
                    }
                    ui.end_row();
                }
            });
    });
}

fn parse_filter_datetime(text: &str) -> Option<DateTime<Utc>> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(t) {
        return Some(dt.with_timezone(&Utc));
    }
    if let Ok(date) = chrono::NaiveDate::parse_from_str(t, "%Y-%m-%d") {
        let dt = date.and_hms_opt(0, 0, 0)?;
        return Some(chrono::DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc));
    }
    None
}

fn event_label(event_type: &TimelineEventType) -> &'static str {
    match event_type {
        TimelineEventType::FileCreated => "FileCreated",
        TimelineEventType::FileModified => "FileModified",
        TimelineEventType::FileAccessed => "FileAccessed",
        TimelineEventType::FileMftModified => "FileMftModified",
        TimelineEventType::FileDeleted => "FileDeleted",
        TimelineEventType::RegistryKeyCreated => "RegistryKeyCreated",
        TimelineEventType::RegistryKeyModified => "RegistryKeyModified",
        TimelineEventType::RegistryValueSet => "RegistryValueSet",
        TimelineEventType::ProcessExecuted => "ProcessExecuted",
        TimelineEventType::UserLogin => "UserLogin",
        TimelineEventType::UserActivity => "UserActivity",
        TimelineEventType::WebVisit => "WebVisit",
    }
}

fn event_color(event_type: &TimelineEventType) -> egui::Color32 {
    match event_type {
        TimelineEventType::FileCreated => GREEN_OK,
        TimelineEventType::FileModified | TimelineEventType::FileMftModified => AMBER,
        TimelineEventType::FileAccessed => ACCENT,
        TimelineEventType::FileDeleted => DANGER,
        _ => TEXT_SEC,
    }
}

// ─── Burst detection ─────────────────────────────────────────────────────────
// Detects clusters of rapid activity that may indicate automated tools,
// data staging, mass file operations, or anti-forensic activity.

struct ActivityBurst {
    start_time: String,
    event_count: usize,
    duration_secs: i64,
    events_per_sec: f64,
}

fn detect_activity_bursts(entries: &[crate::state::TimelineEntry]) -> Vec<ActivityBurst> {
    if entries.len() < 20 {
        return Vec::new();
    }

    let mut bursts = Vec::new();

    // Sliding window: look for 60-second windows with > 50 events
    const WINDOW_SECS: i64 = 60;
    const BURST_THRESHOLD: usize = 50;

    let mut window_start = 0;
    let mut i = 0;

    while i < entries.len() {
        // Find end of window
        let start_ts = entries[window_start].timestamp;
        let current_ts = entries[i].timestamp;
        let delta = (current_ts - start_ts).num_seconds().abs();

        if delta > WINDOW_SECS {
            let count = i - window_start;
            if count >= BURST_THRESHOLD {
                bursts.push(ActivityBurst {
                    start_time: start_ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    event_count: count,
                    duration_secs: delta,
                    events_per_sec: if delta > 0 {
                        count as f64 / delta as f64
                    } else {
                        count as f64
                    },
                });
            }
            window_start = i;
        }
        i += 1;
    }

    // Check final window
    let remaining = entries.len() - window_start;
    if remaining >= BURST_THRESHOLD && window_start < entries.len() {
        let start_ts = entries[window_start].timestamp;
        let end_ts = entries[entries.len() - 1].timestamp;
        let delta = (end_ts - start_ts).num_seconds().abs();
        bursts.push(ActivityBurst {
            start_time: start_ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            event_count: remaining,
            duration_secs: delta,
            events_per_sec: if delta > 0 {
                remaining as f64 / delta as f64
            } else {
                remaining as f64
            },
        });
    }

    // Sort by event density (events per second) descending
    bursts.sort_by(|a, b| {
        b.events_per_sec
            .partial_cmp(&a.events_per_sec)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    bursts.truncate(10);
    bursts
}
