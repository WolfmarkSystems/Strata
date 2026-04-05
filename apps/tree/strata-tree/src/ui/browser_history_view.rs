//! Browser history tab view.

use crate::state::{colors::*, AppState};

#[derive(Default)]
struct BrowserHistoryUiState {
    query: String,
    history: Vec<crate::artifacts::browser::BrowserHistoryEntry>,
    downloads: Vec<crate::artifacts::browser::BrowserDownload>,
    status: String,
}

thread_local! {
    static UI_STATE: std::cell::RefCell<BrowserHistoryUiState> =
        std::cell::RefCell::new(BrowserHistoryUiState::default());
}

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    UI_STATE.with(|cell| {
        let mut ui_state = cell.borrow_mut();

        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("BROWSER HISTORY")
                    .color(ACCENT)
                    .size(11.0)
                    .strong(),
            );
            ui.separator();
            ui.label(
                egui::RichText::new("TIME | URL | TITLE | VISITS | SOURCE")
                    .color(TEXT_MUTED)
                    .size(8.8),
            );
        });
        ui.add_space(4.0);

        ui.horizontal(|ui| {
            if ui.button("LOAD SELECTED DB").clicked() {
                load_selected_db(state, &mut ui_state);
            }
            if ui.button("LOAD INDEXED DBS").clicked() {
                load_indexed_dbs(state, &mut ui_state);
            }
            if ui.button("EXPORT CSV").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .set_file_name("browser_history.csv")
                    .save_file()
                {
                    if let Err(err) = state.ensure_output_path_safe(path.as_path()) {
                        ui_state.status = err;
                        return;
                    }
                    match export_browser_csv(
                        &path,
                        &ui_state.history,
                        &ui_state.downloads,
                        &ui_state.query,
                    ) {
                        Ok(()) => {
                            ui_state.status =
                                format!("Exported browser history CSV: {}", path.display());
                            state.log_action(
                                "BROWSER_HISTORY_EXPORT",
                                &format!("path={}", path.display()),
                            );
                        }
                        Err(e) => {
                            ui_state.status = format!("CSV export failed: {}", e);
                        }
                    }
                }
            }
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

        ui.separator();
        ui.label(
            egui::RichText::new("Visits")
                .color(ACCENT)
                .size(9.0)
                .strong(),
        );

        let query = ui_state.query.to_lowercase();
        let visits: Vec<_> = ui_state
            .history
            .iter()
            .filter(|v| {
                if query.is_empty() {
                    return true;
                }
                let title = v.title.as_deref().unwrap_or("");
                v.url.to_lowercase().contains(&query)
                    || title.to_lowercase().contains(&query)
                    || v.browser.to_lowercase().contains(&query)
            })
            .collect();
        let suspicious_visits = visits
            .iter()
            .filter(|v| is_suspicious_visit(v.url.as_str(), v.title.as_deref().unwrap_or("")))
            .count();
        ui.label(
            egui::RichText::new(format!("Suspicious visits: {}", suspicious_visits))
                .size(8.2)
                .color(if suspicious_visits > 0 {
                    AMBER
                } else {
                    TEXT_MUTED
                }),
        );

        egui::ScrollArea::vertical()
            .max_height(220.0)
            .show(ui, |ui| {
                for v in visits {
                    let ts = v
                        .visit_time
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                    let title = v.title.as_deref().unwrap_or("(no title)");
                    let profile = v.profile.as_deref().unwrap_or("-");
                    let suspicious = is_suspicious_visit(v.url.as_str(), title);
                    let marker = if suspicious { " [!]" } else { "" };
                    ui.label(
                        egui::RichText::new(format!(
                            "{} | {}{} | {} | visits={} | {} | profile={}",
                            ts, v.url, marker, title, v.visit_count, v.browser, profile
                        ))
                        .monospace()
                        .size(8.0)
                        .color(if suspicious { AMBER } else { TEXT_SEC }),
                    );
                }
            });

        ui.separator();
        ui.label(
            egui::RichText::new("Downloads")
                .color(ACCENT)
                .size(9.0)
                .strong(),
        );
        let downloads: Vec<_> = ui_state
            .downloads
            .iter()
            .filter(|d| {
                if query.is_empty() {
                    return true;
                }
                d.url.to_lowercase().contains(&query)
                    || d.target_path.to_lowercase().contains(&query)
            })
            .collect();
        egui::ScrollArea::vertical()
            .max_height(220.0)
            .show(ui, |ui| {
                for d in downloads {
                    let ts = d
                        .start_time
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                    ui.label(
                        egui::RichText::new(format!(
                            "{} | {} | {} | {} bytes | {}",
                            ts, d.url, d.target_path, d.total_bytes, d.state
                        ))
                        .monospace()
                        .size(8.0)
                        .color(TEXT_SEC),
                    );
                }
            });
    });
}

fn is_suspicious_visit(url: &str, title: &str) -> bool {
    let u = url.to_lowercase();
    let t = title.to_lowercase();
    let has = |needle: &str| u.contains(needle) || t.contains(needle);
    has(".onion")
        || has("pastebin.com")
        || has("paste.ee")
        || has("mega.nz")
        || has("wetransfer.com")
        || has("protonvpn")
        || has("nordvpn")
        || has("hide.me")
        || has("how to delete")
        || has("cover tracks")
        || has("clear history")
}

fn export_browser_csv(
    path: &std::path::Path,
    history: &[crate::artifacts::browser::BrowserHistoryEntry],
    downloads: &[crate::artifacts::browser::BrowserDownload],
    query: &str,
) -> Result<(), String> {
    use std::io::Write;
    let q = query.to_lowercase();
    let mut f = std::fs::File::create(path).map_err(|e| e.to_string())?;
    writeln!(
        f,
        "kind,time,url,title,target_path,visits,source,status,size,end_time,suspicious"
    )
    .map_err(|e| e.to_string())?;

    for v in history {
        let title = v.title.as_deref().unwrap_or("");
        if !q.is_empty()
            && !v.url.to_lowercase().contains(&q)
            && !title.to_lowercase().contains(&q)
            && !v.browser.to_lowercase().contains(&q)
        {
            continue;
        }
        let suspicious = is_suspicious_visit(v.url.as_str(), title);
        writeln!(
            f,
            "visit,{},{},{},,{},{},,,,{}",
            csv(&v
                .visit_time
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
            csv(v.url.as_str()),
            csv(title),
            v.visit_count,
            csv(v.browser.as_str()),
            suspicious as u8
        )
        .map_err(|e| e.to_string())?;
    }

    for d in downloads {
        if !q.is_empty()
            && !d.url.to_lowercase().contains(&q)
            && !d.target_path.to_lowercase().contains(&q)
        {
            continue;
        }
        let end_time = d
            .end_time
            .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
            .unwrap_or_default();
        writeln!(
            f,
            "download,{},{},,{},,,{},{},{},0",
            csv(&d
                .start_time
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
            csv(d.url.as_str()),
            csv(d.target_path.as_str()),
            csv(d.state.as_str()),
            d.total_bytes,
            csv(&end_time),
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

fn load_selected_db(state: &mut AppState, ui_state: &mut BrowserHistoryUiState) {
    let Some(file) = state.selected_file().cloned() else {
        ui_state.status = "Select a browser DB file first.".to_string();
        return;
    };
    if !matches!(file.category.as_deref(), Some("Browser History")) {
        ui_state.status = "Selected file is not categorized as Browser History.".to_string();
        return;
    }

    match read_file_bytes(state, &file) {
        Ok(bytes) => match crate::artifacts::browser::parse_browser_db_bytes(&file.path, &bytes) {
            Ok(parsed) => {
                ui_state.history = parsed.history;
                ui_state.downloads = parsed.downloads;
                let added = append_browser_timeline(state, &ui_state.history);
                ui_state.status = format!(
                    "Loaded {} visits and {} downloads from {} (timeline +{})",
                    ui_state.history.len(),
                    ui_state.downloads.len(),
                    file.name,
                    added
                );
                state.log_action("BROWSER_HISTORY_LOAD", &format!("path={}", file.path));
            }
            Err(e) => {
                ui_state.status = format!("Parse failed: {}", e);
            }
        },
        Err(e) => {
            ui_state.status = format!("Read failed: {}", e);
        }
    }
}

fn load_indexed_dbs(state: &mut AppState, ui_state: &mut BrowserHistoryUiState) {
    let mut all_history = Vec::new();
    let mut all_downloads = Vec::new();
    let mut loaded = 0usize;

    for file in state
        .file_index
        .iter()
        .filter(|f| matches!(f.category.as_deref(), Some("Browser History")) && !f.is_dir)
        .take(12)
        .cloned()
    {
        let Ok(bytes) = read_file_bytes(state, &file) else {
            continue;
        };
        let Ok(parsed) = crate::artifacts::browser::parse_browser_db_bytes(&file.path, &bytes)
        else {
            continue;
        };
        all_history.extend(parsed.history);
        all_downloads.extend(parsed.downloads);
        loaded += 1;
    }

    ui_state.history = all_history;
    ui_state.downloads = all_downloads;
    let added = append_browser_timeline(state, &ui_state.history);
    ui_state.status = format!(
        "Loaded {} DBs: {} visits, {} downloads (timeline +{})",
        loaded,
        ui_state.history.len(),
        ui_state.downloads.len(),
        added
    );
    if loaded > 0 {
        state.log_action("BROWSER_HISTORY_LOAD", &format!("db_count={}", loaded));
    }
}

fn read_file_bytes(state: &AppState, file: &crate::state::FileEntry) -> Result<Vec<u8>, String> {
    if let Some(ctx) = state.vfs_context.as_deref() {
        return ctx.read_file(file).map_err(|e| e.to_string());
    }
    std::fs::read(&file.path).map_err(|e| e.to_string())
}

fn append_browser_timeline(
    state: &mut AppState,
    history: &[crate::artifacts::browser::BrowserHistoryEntry],
) -> usize {
    use crate::state::{TimelineEntry, TimelineEventType};

    let mut added = 0usize;
    for visit in history {
        let title = visit.title.as_deref().unwrap_or("");
        let suspicious = is_suspicious_visit(&visit.url, title);
        let detail = format!("{}: {}", visit.browser, title);

        let already_exists = state.timeline_entries.iter().any(|entry| {
            matches!(entry.event_type, TimelineEventType::WebVisit)
                && entry.path.eq_ignore_ascii_case(&visit.url)
                && entry.timestamp.timestamp() == visit.visit_time.timestamp()
        });
        if already_exists {
            continue;
        }

        state.timeline_entries.push(TimelineEntry {
            timestamp: visit.visit_time,
            event_type: TimelineEventType::WebVisit,
            path: visit.url.clone(),
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
