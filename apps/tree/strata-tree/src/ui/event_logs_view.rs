//! Event Logs tab view.

use crate::artifacts::evtx::{is_high_value_event_id, is_suspicious_event, EvtxEvent};
use crate::state::{colors::*, AppState, TimelineEntry, TimelineEventType};

#[derive(Default)]
struct EventLogsUiState {
    query: String,
    events: Vec<EvtxEvent>,
    status: String,
    loaded_sources: usize,
    only_high_value: bool,
}

thread_local! {
    static UI_STATE: std::cell::RefCell<EventLogsUiState> =
        std::cell::RefCell::new(EventLogsUiState::default());
}

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    UI_STATE.with(|cell| {
        let mut ui_state = cell.borrow_mut();

        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("EVENT LOGS")
                    .color(ACCENT)
                    .size(11.0)
                    .strong(),
            );
            ui.separator();
            ui.label(
                egui::RichText::new("TIME | EVENT ID | CHANNEL | PROVIDER | COMPUTER | SUMMARY")
                    .color(TEXT_MUTED)
                    .size(8.6),
            );
        });
        ui.add_space(4.0);

        ui.horizontal(|ui| {
            if ui.button("LOAD SELECTED EVTX").clicked() {
                load_selected_log(state, &mut ui_state);
            }
            if ui.button("LOAD INDEXED EVTX").clicked() {
                load_indexed_logs(state, &mut ui_state);
            }
            if ui.button("EXPORT CSV").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .set_file_name("event_logs.csv")
                    .save_file()
                {
                    if let Err(err) = state.ensure_output_path_safe(path.as_path()) {
                        ui_state.status = err;
                        return;
                    }
                    match export_event_csv(
                        &path,
                        &ui_state.events,
                        &ui_state.query,
                        ui_state.only_high_value,
                    ) {
                        Ok(()) => {
                            ui_state.status = format!("Exported event log CSV: {}", path.display());
                            state.log_action(
                                "EVENT_LOG_EXPORT",
                                &format!("path={}", path.display()),
                            );
                        }
                        Err(err) => {
                            ui_state.status = format!("CSV export failed: {}", err);
                        }
                    }
                }
            }
            ui.checkbox(&mut ui_state.only_high_value, "High value only");
            ui.label(egui::RichText::new("Filter").color(TEXT_MUTED).size(8.5));
            ui.text_edit_singleline(&mut ui_state.query);
        });

        if !ui_state.status.is_empty() {
            ui.label(
                egui::RichText::new(&ui_state.status)
                    .color(TEXT_SEC)
                    .size(8.5),
            );
        }

        let query = ui_state.query.to_lowercase();
        let filtered: Vec<&EvtxEvent> = ui_state
            .events
            .iter()
            .filter(|event| {
                if ui_state.only_high_value && !is_high_value_event_id(event.event_id) {
                    return false;
                }
                if query.is_empty() {
                    return true;
                }
                let ts = event
                    .timestamp
                    .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                    .unwrap_or_default();
                ts.to_lowercase().contains(&query)
                    || event.event_id.to_string().contains(&query)
                    || event.channel.to_lowercase().contains(&query)
                    || event.provider.to_lowercase().contains(&query)
                    || event.computer.to_lowercase().contains(&query)
                    || event.summary.to_lowercase().contains(&query)
            })
            .collect();

        let suspicious_count = filtered
            .iter()
            .filter(|event| is_suspicious_event(event))
            .count();
        let high_value_count = filtered
            .iter()
            .filter(|event| is_high_value_event_id(event.event_id))
            .count();

        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new(format!(
                    "Sources: {} | Events: {} | High value: {} | Suspicious: {}",
                    ui_state.loaded_sources,
                    filtered.len(),
                    high_value_count,
                    suspicious_count
                ))
                .color(TEXT_MUTED)
                .size(8.2),
            );
        });
        ui.separator();

        egui::ScrollArea::vertical().show(ui, |ui| {
            for event in filtered {
                let ts = event
                    .timestamp
                    .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                    .unwrap_or_else(|| "-".to_string());
                let high_value = is_high_value_event_id(event.event_id);
                let suspicious = is_suspicious_event(event);
                let color = if suspicious {
                    DANGER
                } else if high_value {
                    AMBER
                } else {
                    TEXT_SEC
                };
                let rec = event
                    .record_id
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".to_string());
                ui.label(
                    egui::RichText::new(format!(
                        "{} | {} | {} | {} | {} | rec={} | lvl={} | {}",
                        ts,
                        event.event_id,
                        event.channel,
                        event.provider,
                        event.computer,
                        rec,
                        event.level,
                        event.summary
                    ))
                    .size(8.0)
                    .monospace()
                    .color(color),
                );
            }
        });
    });
}

fn load_selected_log(state: &mut AppState, ui_state: &mut EventLogsUiState) {
    let Some(file) = state.selected_file().cloned() else {
        ui_state.status = "Select an EVTX file first.".to_string();
        return;
    };
    if !is_event_log_file(&file) {
        ui_state.status = "Selected file is not categorized as Event Log.".to_string();
        return;
    }

    let bytes = match read_file_bytes(state, &file) {
        Ok(b) => b,
        Err(err) => {
            ui_state.status = format!("Read failed: {}", err);
            return;
        }
    };

    match crate::artifacts::evtx::parse_evtx_bytes(&file.path, &bytes, 10_000) {
        Ok(events) => {
            let added = append_event_timeline(state, &events, &file.path);
            ui_state.events = events;
            ui_state.loaded_sources = 1;
            ui_state.status = format!(
                "Loaded {} events from {} (timeline +{})",
                ui_state.events.len(),
                file.name,
                added
            );
            state.log_action(
                "EVENT_LOG_LOAD",
                &format!("path={} events={}", file.path, ui_state.events.len()),
            );
        }
        Err(err) => {
            ui_state.status = format!("Parse failed: {}", err);
        }
    }
}

fn load_indexed_logs(state: &mut AppState, ui_state: &mut EventLogsUiState) {
    let mut combined = Vec::<EvtxEvent>::new();
    let mut loaded = 0usize;
    let mut timeline_added = 0usize;

    let targets: Vec<_> = state
        .file_index
        .iter()
        .filter(|f| !f.is_dir && is_event_log_file(f))
        .take(8)
        .cloned()
        .collect();

    for file in targets {
        let Ok(bytes) = read_file_bytes(state, &file) else {
            continue;
        };
        let Ok(events) = crate::artifacts::evtx::parse_evtx_bytes(&file.path, &bytes, 3_000) else {
            continue;
        };
        timeline_added += append_event_timeline(state, &events, &file.path);
        combined.extend(events);
        loaded += 1;
    }

    ui_state.events = combined;
    ui_state.loaded_sources = loaded;
    ui_state.status = format!(
        "Loaded {} EVTX logs with {} events (timeline +{})",
        loaded,
        ui_state.events.len(),
        timeline_added
    );
    if loaded > 0 {
        state.log_action(
            "EVENT_LOG_LOAD",
            &format!("source_count={} events={}", loaded, ui_state.events.len()),
        );
    }
}

fn append_event_timeline(state: &mut AppState, events: &[EvtxEvent], source_path: &str) -> usize {
    let mut added = 0usize;

    for event in events {
        let Some(ts) = event.timestamp else {
            continue;
        };
        let event_type = map_event_type(event.event_id);
        let suspicious = is_suspicious_event(event);
        let detail = format!(
            "EVTX {} {} {}",
            event.event_id, event.provider, event.summary
        );
        let path = format!("{}#{}", source_path.replace('\\', "/"), event.event_id);

        let exists = state.timeline_entries.iter().any(|entry| {
            timeline_event_label(&entry.event_type) == timeline_event_label(&event_type)
                && entry.timestamp.timestamp() == ts.timestamp()
                && entry.path == path
                && entry.detail == detail
        });
        if exists {
            continue;
        }

        state.timeline_entries.push(TimelineEntry {
            timestamp: ts,
            event_type,
            path,
            evidence_id: String::new(),
            detail,
            file_id: None,
            suspicious,
        });
        added += 1;
    }

    if added > 0 {
        state.timeline_entries.sort_by_key(|e| e.timestamp);
        state.suspicious_event_count = state
            .timeline_entries
            .iter()
            .filter(|e| e.suspicious)
            .count();
    }

    added
}

fn map_event_type(event_id: u32) -> TimelineEventType {
    match event_id {
        4624 | 4625 | 4634 => TimelineEventType::UserLogin,
        4688 => TimelineEventType::ProcessExecuted,
        _ => TimelineEventType::UserActivity,
    }
}

fn timeline_event_label(event: &TimelineEventType) -> &'static str {
    match event {
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

fn is_event_log_file(file: &crate::state::FileEntry) -> bool {
    if matches!(file.category.as_deref(), Some("Event Log")) {
        return true;
    }
    if file
        .extension
        .as_deref()
        .map(|ext| ext.eq_ignore_ascii_case("evtx"))
        .unwrap_or(false)
    {
        return true;
    }
    let path = file.path.replace('\\', "/").to_lowercase();
    path.contains("/windows/system32/winevt/logs/")
}

fn read_file_bytes(state: &AppState, file: &crate::state::FileEntry) -> Result<Vec<u8>, String> {
    if let Some(ctx) = state.vfs_context.as_deref() {
        return ctx.read_file(file).map_err(|e| e.to_string());
    }
    std::fs::read(&file.path).map_err(|e| e.to_string())
}

fn export_event_csv(
    path: &std::path::Path,
    events: &[EvtxEvent],
    query: &str,
    high_only: bool,
) -> Result<(), String> {
    use std::io::Write;
    let q = query.to_lowercase();
    let mut file = std::fs::File::create(path).map_err(|e| e.to_string())?;
    writeln!(
        file,
        "timestamp_utc,event_id,channel,provider,computer,level,record_id,high_value,suspicious,summary"
    )
    .map_err(|e| e.to_string())?;

    for event in events {
        if high_only && !is_high_value_event_id(event.event_id) {
            continue;
        }
        if !q.is_empty() {
            let ts = event
                .timestamp
                .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                .unwrap_or_default()
                .to_lowercase();
            let matches = ts.contains(&q)
                || event.event_id.to_string().contains(&q)
                || event.channel.to_lowercase().contains(&q)
                || event.provider.to_lowercase().contains(&q)
                || event.computer.to_lowercase().contains(&q)
                || event.summary.to_lowercase().contains(&q);
            if !matches {
                continue;
            }
        }

        let ts = event
            .timestamp
            .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
            .unwrap_or_default();
        let record_id = event.record_id.map(|v| v.to_string()).unwrap_or_default();
        writeln!(
            file,
            "{},{},{},{},{},{},{},{},{},{}",
            csv(&ts),
            event.event_id,
            csv(&event.channel),
            csv(&event.provider),
            csv(&event.computer),
            csv(&event.level),
            csv(&record_id),
            is_high_value_event_id(event.event_id) as u8,
            is_suspicious_event(event) as u8,
            csv(&event.summary)
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}
