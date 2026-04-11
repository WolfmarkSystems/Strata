//! Registry view — parser-backed Windows hive browser using `nt-hive`.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::artifacts::shellbags::ShellbagEntry;
use crate::state::{colors::*, AppState};
use nt_hive::{Hive, KeyNode, KeyValueData, KeyValueDataType};

#[derive(Debug, Clone)]
struct RegistryValueRow {
    name: String,
    reg_type: String,
    data: String,
}

#[derive(Debug, Clone)]
struct RegistryKeyNode {
    path: String,
    name: String,
    children: Vec<String>,
    values: Vec<RegistryValueRow>,
}

#[derive(Debug, Clone)]
struct LoadedHive {
    alias: String,
    source_path: String,
    nodes: HashMap<String, RegistryKeyNode>,
}

#[derive(Debug, Clone)]
struct RegistrySearchHit {
    full_path: String,
    value_name: String,
    value_data: String,
}

#[derive(Default)]
struct RegistryPanelState {
    hive_path_input: String,
    selected_key_path: String,
    loaded_hives: Vec<LoadedHive>,
    search_query: String,
    search_hits: Vec<RegistrySearchHit>,
    selected_value_name: Option<String>,
    detected_hive_candidates: Vec<String>,
    shellbag_entries: Vec<ShellbagEntry>,
    shellbag_status: String,
    last_indexed_file_count: usize,
    error: Option<String>,
}

thread_local! {
    static PANEL_STATE: std::cell::RefCell<RegistryPanelState> =
        std::cell::RefCell::new(RegistryPanelState::default());
}

const QUICK_KEYS: &[(&str, &str)] = &[
    ("Services", "SYSTEM\\CurrentControlSet\\Services"),
    ("Run (HKLM)", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
    ("RunOnce (HKLM)", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
    ("Run (NTUSER)", "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
    ("AppCompatCache", "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache"),
    ("UserAssist", "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"),
    ("AppCompatFlags", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility"),
    ("BAM UserSettings", "SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings"),
    ("RecentDocs", "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"),
    ("OpenSavePidlMRU", "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU"),
    ("TypedURLs", "NTUSER.DAT\\Software\\Microsoft\\Internet Explorer\\TypedURLs"),
    ("OS Version", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"),
    ("ComputerName", "SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName"),
    ("TimeZone", "SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation"),
    ("Network Profiles", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles"),
    ("TCP/IP Interfaces", "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces"),
];

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    PANEL_STATE.with(|panel| {
        let mut panel = panel.borrow_mut();

        if let Some(target) = state.pending_registry_nav.take() {
            ensure_hive_loaded_for_target(&mut panel, &target, state);
            if let Some((key, value)) = target.rsplit_once("\\@") {
                panel.selected_key_path = key.to_string();
                panel.selected_value_name = Some(value.to_string());
            } else {
                panel.selected_key_path = target;
                panel.selected_value_name = None;
            }
        }

        if panel.last_indexed_file_count != state.file_index.len() {
            panel.detected_hive_candidates = detect_hive_candidates(state);
            panel.last_indexed_file_count = state.file_index.len();
        }

        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("REGISTRY").color(ACCENT).size(11.0).strong());
            ui.separator();
            ui.label(egui::RichText::new("Hive parser and forensic key explorer").color(TEXT_MUTED).size(9.5));
        });
        ui.add_space(4.0);

        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Hive file:").color(TEXT_MUTED).size(9.0));
            ui.text_edit_singleline(&mut panel.hive_path_input);

            if ui.button("Open…").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .set_title("Open Registry Hive")
                    .add_filter("Registry Hive", &["dat", "DAT", "hiv", "HIV"])
                    .add_filter("All Files", &["*"])
                    .pick_file()
                {
                    panel.hive_path_input = path.to_string_lossy().to_string();
                    let chosen = panel.hive_path_input.clone();
                    load_hive_from_path(&mut panel, &chosen, state);
                }
            }

            if !panel.hive_path_input.is_empty() && ui.button("Load").clicked() {
                let chosen = panel.hive_path_input.clone();
                load_hive_from_path(&mut panel, &chosen, state);
            }
        });

        if !panel.detected_hive_candidates.is_empty() {
            ui.add_space(3.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(egui::RichText::new("Detected:").color(TEXT_MUTED).size(8.5));
                let candidates = panel.detected_hive_candidates.clone();
                for candidate in &candidates {
                    let label = Path::new(candidate)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| candidate.clone());
                    if ui.small_button(label).on_hover_text(candidate).clicked() {
                        panel.hive_path_input = candidate.clone();
                        load_hive_from_path(&mut panel, candidate, state);
                    }
                }
            });
        }

        if let Some(err) = &panel.error {
            ui.colored_label(DANGER, err);
        }

        ui.separator();
        render_shellbag_actions(ui, state, &mut panel);
        if !panel.shellbag_status.is_empty() {
            ui.label(egui::RichText::new(&panel.shellbag_status).color(TEXT_MUTED).size(8.5));
        }
        ui.separator();

        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Quick Keys").color(ACCENT).size(9.0).strong());
            for (label, target_path) in QUICK_KEYS {
                let quick = ui.small_button(*label);
                quick.context_menu(|ui| {
                    if ui.button("Copy Registry Path").clicked() {
                        ui.ctx().copy_text((*target_path).to_string());
                        ui.close_menu();
                    }
                });
                if quick.clicked() {
                    if resolve_path_exists(&panel.loaded_hives, target_path) {
                        panel.selected_key_path = target_path.to_string();
                    } else {
                        panel.error = Some(format!("Quick key not found in loaded hives: {}", target_path));
                    }
                }
            }
        });
        ui.separator();

        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Search").color(TEXT_MUTED).size(9.0));
            let resp = ui.text_edit_singleline(&mut panel.search_query);
            let should_search = resp.lost_focus() || ui.button("Find").clicked();
            if should_search {
                panel.search_hits = search_registry(&panel.loaded_hives, &panel.search_query);
            }
        });

        if !panel.search_hits.is_empty() {
            ui.label(egui::RichText::new(format!("{} search results", panel.search_hits.len())).color(TEXT_MUTED).size(8.5));
            egui::ScrollArea::vertical().max_height(120.0).show(ui, |ui| {
                for hit in panel.search_hits.clone() {
                    let text = format!(
                        "{}  |  {}  |  {}",
                        hit.full_path,
                        if hit.value_name.is_empty() { "(key)" } else { &hit.value_name },
                        hit.value_data
                    );
                    let hit_resp = ui.selectable_label(false, text);
                    hit_resp.context_menu(|ui| {
                        if ui.button("Copy Full Path").clicked() {
                            ui.ctx().copy_text(hit.full_path.clone());
                            ui.close_menu();
                        }
                        if !hit.value_name.is_empty() && ui.button("Copy Value Name").clicked() {
                            ui.ctx().copy_text(hit.value_name.clone());
                            ui.close_menu();
                        }
                    });
                    if hit_resp.clicked() {
                        panel.selected_key_path = hit.full_path;
                    }
                }
            });
            ui.separator();
        }

        if panel.loaded_hives.is_empty() {
            ui.label(egui::RichText::new("No hive loaded. Load SYSTEM/SOFTWARE/SAM/SECURITY/DEFAULT/NTUSER.DAT/UsrClass.dat.").color(TEXT_MUTED));
            return;
        }

        ui.columns(2, |cols| {
            egui::ScrollArea::vertical().id_source("reg_tree").show(&mut cols[0], |ui| {
                let hives = panel.loaded_hives.clone();
                render_registry_tree(ui, &hives, &mut panel.selected_key_path);
            });

            egui::ScrollArea::vertical().id_source("reg_values").show(&mut cols[1], |ui| {
                let hives = panel.loaded_hives.clone();
                let shellbags = panel.shellbag_entries.clone();
                let mut selected_key_path = panel.selected_key_path.clone();
                let mut selected_value_name = panel.selected_value_name.clone();
                render_values_table(
                    ui,
                    state,
                    &hives,
                    &mut selected_key_path,
                    &mut selected_value_name,
                    &shellbags,
                );
                panel.selected_key_path = selected_key_path;
                panel.selected_value_name = selected_value_name;
            });
        });
    });
}

fn render_registry_tree(ui: &mut egui::Ui, hives: &[LoadedHive], selected: &mut String) {
    let hklm_roots = ["SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"];
    let hkcu_roots = ["NTUSER.DAT"];
    let hku_roots = ["NTUSER.DAT", "USRCLASS.DAT"];

    egui::CollapsingHeader::new("HKEY_LOCAL_MACHINE")
        .default_open(true)
        .show(ui, |ui| {
            for alias in hklm_roots {
                if let Some(hive) = hives.iter().find(|h| h.alias.eq_ignore_ascii_case(alias)) {
                    render_hive_node(ui, hive, &hive.alias, selected);
                }
            }
        });

    egui::CollapsingHeader::new("HKEY_CURRENT_USER")
        .default_open(true)
        .show(ui, |ui| {
            for alias in hkcu_roots {
                if let Some(hive) = hives.iter().find(|h| h.alias.eq_ignore_ascii_case(alias)) {
                    render_hive_node(ui, hive, &hive.alias, selected);
                }
            }
        });

    egui::CollapsingHeader::new("HKEY_USERS")
        .default_open(true)
        .show(ui, |ui| {
            for alias in hku_roots {
                if let Some(hive) = hives.iter().find(|h| h.alias.eq_ignore_ascii_case(alias)) {
                    render_hive_node(ui, hive, &hive.alias, selected);
                }
            }
        });
}

fn render_hive_node(ui: &mut egui::Ui, hive: &LoadedHive, path: &str, selected: &mut String) {
    let Some(node) = hive.nodes.get(path) else {
        return;
    };
    let is_selected = *selected == node.path;

    if node.children.is_empty() {
        if ui.selectable_label(is_selected, &node.name).clicked() {
            *selected = node.path.clone();
        }
        return;
    }

    egui::CollapsingHeader::new(egui::RichText::new(&node.name).color(if is_selected {
        ACCENT
    } else {
        TEXT_PRI
    }))
    .id_source(format!("tree_{}_{}", hive.alias, node.path))
    .show(ui, |ui| {
        if ui.selectable_label(is_selected, "(values)").clicked() {
            *selected = node.path.clone();
        }
        for child_path in &node.children {
            render_hive_node(ui, hive, child_path, selected);
        }
    });
}

fn render_values_table(
    ui: &mut egui::Ui,
    state: &mut AppState,
    hives: &[LoadedHive],
    selected_key_path: &mut String,
    selected_value_name: &mut Option<String>,
    shellbags: &[ShellbagEntry],
) {
    if selected_key_path.is_empty() {
        ui.label(egui::RichText::new("Select a registry key to view values.").color(TEXT_MUTED));
        return;
    }

    let key_opt = hives
        .iter()
        .find_map(|h| h.nodes.get(selected_key_path.as_str()));

    let Some(key) = key_opt else {
        ui.label(
            egui::RichText::new("Selected key is not available in loaded hives.").color(TEXT_MUTED),
        );
        return;
    };

    ui.label(
        egui::RichText::new(format!("Key: {}", key.path))
            .strong()
            .color(ACCENT),
    );
    ui.add_space(2.0);
    render_registry_bookmark_controls(ui, state, &key.path, selected_value_name.as_deref());
    ui.separator();

    egui::Grid::new("registry_values_grid")
        .num_columns(3)
        .striped(true)
        .spacing([8.0, 4.0])
        .show(ui, |ui| {
            ui.label(egui::RichText::new("NAME").color(TEXT_MUTED).strong());
            ui.label(egui::RichText::new("TYPE").color(TEXT_MUTED).strong());
            ui.label(egui::RichText::new("DATA").color(TEXT_MUTED).strong());
            ui.end_row();

            if key.values.is_empty() {
                ui.label(
                    egui::RichText::new("(no values)")
                        .italics()
                        .color(TEXT_MUTED),
                );
                ui.label("");
                ui.label("");
                ui.end_row();
                return;
            }

            for value in &key.values {
                let selected = selected_value_name.as_deref() == Some(value.name.as_str());
                let name_resp =
                    ui.selectable_label(selected, egui::RichText::new(&value.name).color(TEXT_PRI));
                if name_resp.clicked() {
                    *selected_value_name = Some(value.name.clone());
                }
                ui.label(egui::RichText::new(&value.reg_type).color(ACCENT));
                ui.label(egui::RichText::new(&value.data).monospace());
                ui.end_row();
            }
        });

    if !shellbags.is_empty() {
        ui.add_space(8.0);
        render_shellbags_section(ui, shellbags, selected_key_path);
    }
}

fn render_shellbag_actions(
    ui: &mut egui::Ui,
    state: &mut AppState,
    panel: &mut RegistryPanelState,
) {
    let shellbag_hives: Vec<LoadedHive> = panel
        .loaded_hives
        .iter()
        .filter(|h| {
            h.alias.eq_ignore_ascii_case("NTUSER.DAT")
                || h.alias.eq_ignore_ascii_case("USRCLASS.DAT")
        })
        .cloned()
        .collect();

    if shellbag_hives.is_empty() {
        return;
    }

    ui.horizontal_wrapped(|ui| {
        ui.label(
            egui::RichText::new("SHELLBAGS")
                .color(ACCENT)
                .size(9.0)
                .strong(),
        );
        ui.label(
            egui::RichText::new("Detected in NTUSER.DAT / UsrClass.dat")
                .color(TEXT_MUTED)
                .size(8.5),
        );
        if ui.small_button("Parse shellbags").clicked() {
            panel.shellbag_entries.clear();
            let mut total = 0usize;
            let mut timeline_added = 0usize;

            for hive in &shellbag_hives {
                match parse_shellbags_from_path(&hive.source_path, &hive.alias) {
                    Ok(mut entries) => {
                        timeline_added += append_shellbag_timeline(state, &entries);
                        total += entries.len();
                        panel.shellbag_entries.append(&mut entries);
                    }
                    Err(err) => {
                        panel.error =
                            Some(format!("Shellbag parse failed ({}): {}", hive.alias, err));
                    }
                }
            }

            panel.shellbag_status = format!(
                "Parsed {} shellbag entries | Timeline +{} user-activity events",
                total, timeline_added
            );
            state.log_action("SHELLBAGS_PARSED", &panel.shellbag_status);
        }
    });
}

fn render_shellbags_section(
    ui: &mut egui::Ui,
    shellbags: &[ShellbagEntry],
    selected_key_path: &mut String,
) {
    ui.separator();
    ui.label(
        egui::RichText::new("SHELLBAGS")
            .color(ACCENT)
            .size(9.0)
            .strong(),
    );
    ui.label(
        egui::RichText::new(format!("{} reconstructed folder visits", shellbags.len()))
            .color(TEXT_MUTED)
            .size(8.5),
    );

    egui::ScrollArea::vertical()
        .id_source("shellbags_view")
        .max_height(180.0)
        .show(ui, |ui| {
            for entry in shellbags {
                let ts = entry
                    .last_interacted
                    .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                    .unwrap_or_else(|| "-".to_string());
                let suspicious = is_shellbag_path_suspicious(&entry.path);
                ui.horizontal(|ui| {
                    if suspicious {
                        ui.label(egui::RichText::new("!").color(AMBER).strong());
                    } else {
                        ui.label(" ");
                    }
                    let path_resp = ui.selectable_label(false, &entry.path);
                    if path_resp.double_clicked() {
                        *selected_key_path = entry.bag_key.clone();
                    }
                    ui.label(
                        egui::RichText::new(format!("accessed: {}", ts))
                            .color(TEXT_MUTED)
                            .size(8.0),
                    );
                });
            }
        });
}

fn parse_shellbags_from_path(path: &str, alias: &str) -> Result<Vec<ShellbagEntry>, String> {
    const MAX_HIVE_BYTES: u64 = 512 * 1024 * 1024;
    let pb = PathBuf::from(path);
    if !pb.exists() {
        return Err(format!("Hive not found: {}", path));
    }
    let file_size = pb.metadata().map(|m| m.len()).unwrap_or(0);
    if file_size > MAX_HIVE_BYTES {
        return Err(format!(
            "Hive too large ({} bytes, max {})",
            file_size, MAX_HIVE_BYTES
        ));
    }

    let mut data = Vec::new();
    let mut f = std::fs::File::open(&pb).map_err(|e| format!("Open failed: {}", e))?;
    f.read_to_end(&mut data)
        .map_err(|e| format!("Read failed: {}", e))?;

    let fallback_time = std::fs::metadata(&pb)
        .ok()
        .and_then(|m| m.modified().ok())
        .map(chrono::DateTime::<chrono::Utc>::from);

    crate::artifacts::shellbags::parse_shellbags(&data, alias, fallback_time)
}

fn append_shellbag_timeline(state: &mut AppState, shellbags: &[ShellbagEntry]) -> usize {
    use crate::state::{TimelineEntry, TimelineEventType};

    let mut added = 0usize;
    for entry in shellbags {
        let Some(ts) = entry.last_interacted else {
            continue;
        };
        let detail = format!("User browsed: {}", entry.path);

        let already_exists = state.timeline_entries.iter().any(|e| {
            matches!(e.event_type, TimelineEventType::UserActivity)
                && e.path.eq_ignore_ascii_case(&entry.path)
                && e.timestamp.timestamp() == ts.timestamp()
        });
        if already_exists {
            continue;
        }

        state.timeline_entries.push(TimelineEntry {
            timestamp: ts,
            event_type: TimelineEventType::UserActivity,
            path: entry.path.clone(),
            evidence_id: String::new(),
            detail,
            file_id: None,
            suspicious: is_shellbag_path_suspicious(&entry.path),
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

fn is_shellbag_path_suspicious(path: &str) -> bool {
    let p = path.to_lowercase();
    p.contains("desktop")
        || p.contains("downloads")
        || p.contains("temp")
        || p.contains("evidence")
        || p.contains("deleted")
        || p.contains("wiped")
        || p.contains("usb")
        || p.contains("removable")
}

fn render_registry_bookmark_controls(
    ui: &mut egui::Ui,
    state: &mut AppState,
    key_path: &str,
    selected_value_name: Option<&str>,
) {
    ui.horizontal_wrapped(|ui| {
        ui.label(egui::RichText::new("Tag").color(TEXT_MUTED).size(8.5));
        for tag in &[
            "NOTABLE",
            "RELEVANT",
            "REVIEWED",
            "IRRELEVANT",
            "SUSPICIOUS",
            "EXCULPATORY",
        ] {
            let active = state.active_tag == *tag;
            let color = if active { ACCENT } else { TEXT_MUTED };
            if ui
                .selectable_label(active, egui::RichText::new(*tag).color(color).size(8.0))
                .clicked()
            {
                state.active_tag = tag.to_string();
            }
        }
    });

    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Note").color(TEXT_MUTED).size(8.5));
        ui.text_edit_singleline(&mut state.examiner_note);
    });

    let bookmark_target = match selected_value_name {
        Some(v) if !v.is_empty() && v != "(Default)" => format!("{}\\@{}", key_path, v),
        _ => key_path.to_string(),
    };
    let examiner = state.examiner_name.clone();

    if ui
        .small_button(egui::RichText::new("+ BOOKMARK").color(ACCENT).size(8.5))
        .clicked()
    {
        let new_tag = state.active_tag.clone();
        let new_note = state.examiner_note.clone();
        if let Some(existing) = state.bookmark_for_registry_mut(&bookmark_target, &examiner) {
            existing.tag = new_tag.clone();
            existing.note = new_note.clone();
        } else {
            state.bookmarks.push(crate::state::Bookmark {
                id: uuid::Uuid::new_v4().to_string(),
                file_id: None,
                registry_path: Some(bookmark_target.clone()),
                tag: new_tag,
                examiner: examiner.clone(),
                note: new_note,
                created_utc: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            });
        }
        state.mark_case_dirty();
        persist_bookmarks(state);
        state.log_action(
            "BOOKMARK_SET",
            &format!("registry={} tag={}", bookmark_target, state.active_tag),
        );
    }
}

fn persist_bookmarks(state: &mut AppState) {
    let Some(case_path) = state.case.as_ref().map(|c| c.path.clone()) else {
        return;
    };
    if case_path.is_empty() {
        return;
    }
    if let Ok(project) = crate::case::project::VtpProject::open(&case_path) {
        let _ = project.save_bookmarks(&state.bookmarks);
    }
}

fn ensure_hive_loaded_for_target(
    panel: &mut RegistryPanelState,
    target: &str,
    state: &mut AppState,
) {
    let key_path = target.split("\\@").next().unwrap_or(target);
    let alias = key_path.split('\\').next().unwrap_or("").to_uppercase();
    if alias.is_empty() {
        return;
    }
    if panel
        .loaded_hives
        .iter()
        .any(|h| h.alias.eq_ignore_ascii_case(&alias))
    {
        return;
    }

    let candidates = if panel.detected_hive_candidates.is_empty() {
        detect_hive_candidates(state)
    } else {
        panel.detected_hive_candidates.clone()
    };
    for candidate in candidates {
        if infer_hive_alias(&candidate).eq_ignore_ascii_case(&alias) {
            load_hive_from_path(panel, &candidate, state);
            break;
        }
    }
}

fn resolve_path_exists(hives: &[LoadedHive], target: &str) -> bool {
    hives.iter().any(|h| h.nodes.contains_key(target))
}

fn detect_hive_candidates(state: &AppState) -> Vec<String> {
    let mut out = Vec::new();
    for file in &state.file_index {
        let name_lc = file.name.to_lowercase();
        if (file.category.as_deref() == Some("Registry Hive")
            || matches!(
                name_lc.as_str(),
                "system"
                    | "software"
                    | "sam"
                    | "security"
                    | "default"
                    | "ntuser.dat"
                    | "usrclass.dat"
            ))
            && !file.path.starts_with('[')
        {
            out.push(file.path.clone());
        }
    }

    for source in &state.evidence_sources {
        let source_path = PathBuf::from(&source.path);
        let rels = [
            "Windows/System32/config/SYSTEM",
            "Windows/System32/config/SOFTWARE",
            "Windows/System32/config/SAM",
            "Windows/System32/config/SECURITY",
            "Windows/System32/config/DEFAULT",
            "Users/Default/NTUSER.DAT",
        ];
        for rel in rels {
            let candidate = source_path.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));
            if candidate.exists() {
                out.push(candidate.to_string_lossy().to_string());
            }
        }
    }

    out.sort();
    out.dedup();
    out
}

fn load_hive_from_path(panel: &mut RegistryPanelState, path: &str, state: &mut AppState) {
    panel.error = None;
    let alias = infer_hive_alias(path);

    let parsed = parse_hive(path, &alias);
    let loaded = match parsed {
        Ok(v) => v,
        Err(e) => {
            panel.error = Some(e);
            return;
        }
    };

    if let Some(existing_idx) = panel
        .loaded_hives
        .iter()
        .position(|h| h.alias.eq_ignore_ascii_case(&loaded.alias))
    {
        panel.loaded_hives[existing_idx] = loaded;
    } else {
        panel.loaded_hives.push(loaded);
    }

    panel.selected_key_path = alias.clone();
    panel.search_hits.clear();
    state.log_action("REGISTRY_LOAD", &format!("{} ({})", alias, path));
    let added = append_registry_timeline_events(state, &panel.loaded_hives, &alias);
    if added > 0 {
        state.log_action(
            "REGISTRY_TIMELINE_ENRICH",
            &format!("hive={} events_added={}", alias, added),
        );
    }
}

fn parse_hive(path: &str, alias: &str) -> Result<LoadedHive, String> {
    const MAX_HIVE_BYTES: u64 = 512 * 1024 * 1024;
    let pb = PathBuf::from(path);
    if !pb.exists() {
        return Err(format!("Hive file not found: {}", path));
    }
    let file_size = pb.metadata().map(|m| m.len()).unwrap_or(0);
    if file_size > MAX_HIVE_BYTES {
        return Err(format!(
            "Hive too large ({} bytes, max {})",
            file_size, MAX_HIVE_BYTES
        ));
    }

    let mut data = Vec::new();
    let mut f = std::fs::File::open(&pb).map_err(|e| format!("Cannot open hive: {}", e))?;
    f.read_to_end(&mut data)
        .map_err(|e| format!("Cannot read hive: {}", e))?;
    if data.len() < 4 || &data[0..4] != b"regf" {
        return Err("Invalid registry hive magic (expected regf)".to_string());
    }

    let hive = Hive::new(data.as_slice()).map_err(|e| format!("Hive parse error: {}", e))?;
    let root = hive
        .root_key_node()
        .map_err(|e| format!("Root key error: {}", e))?;

    let mut nodes: HashMap<String, RegistryKeyNode> = HashMap::new();
    walk_key_tree(alias, root, &mut nodes);

    Ok(LoadedHive {
        alias: alias.to_string(),
        source_path: path.to_string(),
        nodes,
    })
}

fn walk_key_tree(
    alias: &str,
    root: KeyNode<'_, &[u8]>,
    nodes: &mut HashMap<String, RegistryKeyNode>,
) {
    let mut stack: Vec<(String, KeyNode<'_, &[u8]>)> = vec![(alias.to_string(), root)];

    while let Some((path, key_node)) = stack.pop() {
        let mut child_paths: Vec<String> = Vec::new();

        if let Some(Ok(subkeys)) = key_node.subkeys() {
            for child in subkeys.flatten() {
                if let Ok(child_name) = child.name() {
                    let child_name = child_name.to_string();
                    if !child_name.is_empty() {
                        let child_path = format!("{}\\{}", path, child_name);
                        child_paths.push(child_path.clone());
                        stack.push((child_path, child));
                    }
                }
            }
        }

        child_paths.sort();
        let values = read_values(&key_node);
        let name = path
            .rsplit('\\')
            .next()
            .map(|s| s.to_string())
            .unwrap_or_else(|| alias.to_string());

        nodes.insert(
            path.clone(),
            RegistryKeyNode {
                path,
                name,
                children: child_paths,
                values,
            },
        );
    }
}

fn read_values(key_node: &KeyNode<'_, &[u8]>) -> Vec<RegistryValueRow> {
    let mut out = Vec::new();

    let Some(values_res) = key_node.values() else {
        return out;
    };
    let Ok(values) = values_res else {
        return out;
    };

    for value_res in values {
        let Ok(value) = value_res else {
            continue;
        };

        let raw_name = value.name().map(|n| n.to_string()).unwrap_or_default();
        let display_name = if raw_name.is_empty() {
            "(Default)".to_string()
        } else {
            raw_name
        };

        let row = decode_registry_value(display_name, value);
        out.push(row);
    }

    out
}

fn decode_registry_value(name: String, value: nt_hive::KeyValue<'_, &[u8]>) -> RegistryValueRow {
    let data_type = value.data_type();
    let (reg_type, data) = match data_type {
        Ok(KeyValueDataType::RegSZ) => (
            "REG_SZ".to_string(),
            value
                .string_data()
                .unwrap_or_else(|_| "<decode error>".to_string()),
        ),
        Ok(KeyValueDataType::RegExpandSZ) => (
            "REG_EXPAND_SZ".to_string(),
            highlight_expand_vars(
                &value
                    .string_data()
                    .unwrap_or_else(|_| "<decode error>".to_string()),
            ),
        ),
        Ok(KeyValueDataType::RegDWord) | Ok(KeyValueDataType::RegDWordBigEndian) => {
            match value.dword_data() {
                Ok(v) => ("REG_DWORD".to_string(), format!("{} (0x{:08X})", v, v)),
                Err(_) => ("REG_DWORD".to_string(), "<decode error>".to_string()),
            }
        }
        Ok(KeyValueDataType::RegQWord) => match value.qword_data() {
            Ok(v) => ("REG_QWORD".to_string(), format!("{} (0x{:016X})", v, v)),
            Err(_) => ("REG_QWORD".to_string(), "<decode error>".to_string()),
        },
        Ok(KeyValueDataType::RegMultiSZ) => {
            let joined = match value.multi_string_data() {
                Ok(iter) => {
                    let lines: Vec<String> = iter.filter_map(|s| s.ok()).collect();
                    if lines.is_empty() {
                        "<empty>".to_string()
                    } else {
                        lines.join("\n")
                    }
                }
                Err(_) => "<decode error>".to_string(),
            };
            ("REG_MULTI_SZ".to_string(), joined)
        }
        Ok(KeyValueDataType::RegBinary) => {
            let hex = match value.data() {
                Ok(KeyValueData::Small(bytes)) => format_binary_preview(bytes),
                Ok(KeyValueData::Big(iter)) => {
                    let mut all = Vec::new();
                    for slice in iter.flatten() {
                        all.extend_from_slice(slice);
                        if all.len() >= 32 {
                            break;
                        }
                    }
                    format_binary_preview(all.as_slice())
                }
                Err(_) => "<decode error>".to_string(),
            };
            ("REG_BINARY".to_string(), hex)
        }
        Ok(other) => (
            format!("{:?}", other).to_uppercase(),
            "<not displayed>".to_string(),
        ),
        Err(_) => ("UNKNOWN".to_string(), "<type error>".to_string()),
    };

    RegistryValueRow {
        name,
        reg_type,
        data,
    }
}

fn format_binary_preview(bytes: &[u8]) -> String {
    let preview: Vec<String> = bytes
        .iter()
        .take(32)
        .map(|b| format!("{:02X}", b))
        .collect();
    if bytes.len() > 32 {
        format!("{} ...", preview.join(" "))
    } else {
        preview.join(" ")
    }
}

fn highlight_expand_vars(input: &str) -> String {
    let mut out = String::new();
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '%' {
            out.push(ch);
            continue;
        }

        let mut token = String::from("%");
        let mut found_end = false;
        for next in chars.by_ref() {
            token.push(next);
            if next == '%' {
                found_end = true;
                break;
            }
        }

        if found_end {
            out.push_str("[[");
            out.push_str(&token);
            out.push_str("]]");
        } else {
            out.push_str(&token);
        }
    }
    out
}

fn infer_hive_alias(path: &str) -> String {
    let file_name = Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let upper = file_name.to_uppercase();
    if upper.is_empty() {
        return "HIVE".to_string();
    }
    upper
}

fn search_registry(hives: &[LoadedHive], query: &str) -> Vec<RegistrySearchHit> {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    for hive in hives {
        for (path, node) in &hive.nodes {
            if path.to_lowercase().contains(&q) || node.name.to_lowercase().contains(&q) {
                out.push(RegistrySearchHit {
                    full_path: path.clone(),
                    value_name: String::new(),
                    value_data: "key match".to_string(),
                });
            }

            for value in &node.values {
                if value.name.to_lowercase().contains(&q) || value.data.to_lowercase().contains(&q)
                {
                    out.push(RegistrySearchHit {
                        full_path: path.clone(),
                        value_name: value.name.clone(),
                        value_data: value.data.clone(),
                    });
                }
            }
        }
    }
    out
}

fn append_registry_timeline_events(
    state: &mut AppState,
    hives: &[LoadedHive],
    alias: &str,
) -> usize {
    use crate::state::{TimelineEntry, TimelineEventType};

    let Some(hive) = hives.iter().find(|h| h.alias.eq_ignore_ascii_case(alias)) else {
        return 0;
    };

    let ts = std::fs::metadata(&hive.source_path)
        .ok()
        .and_then(|m| m.modified().ok())
        .map(chrono::DateTime::<chrono::Utc>::from)
        .unwrap_or_else(chrono::Utc::now);
    let ts_sec = ts.timestamp();

    let high_value_markers = [
        "\\currentcontrolset\\services",
        "\\currentversion\\run",
        "\\currentversion\\runonce",
        "\\appcompatcache",
        "\\userassist",
        "\\recentdocs",
        "\\opensavepidlmru",
        "\\typedurls",
        "\\networklist\\profiles",
        "\\tcpip\\parameters\\interfaces",
    ];

    let mut added = 0usize;
    for node in hive.nodes.values() {
        let path_lc = node.path.to_lowercase();
        let relevant = high_value_markers.iter().any(|m| path_lc.contains(m));
        if !relevant {
            continue;
        }

        if !state.timeline_entries.iter().any(|e| {
            e.timestamp.timestamp() == ts_sec
                && e.path == node.path
                && matches!(e.event_type, TimelineEventType::RegistryKeyModified)
        }) {
            state.timeline_entries.push(TimelineEntry {
                timestamp: ts,
                event_type: TimelineEventType::RegistryKeyModified,
                path: node.path.clone(),
                evidence_id: String::new(),
                detail: format!("Registry key present in {}", hive.alias),
                file_id: None,
                suspicious: is_registry_key_suspicious(&node.path),
            });
            added = added.saturating_add(1);
        }

        for value in node.values.iter().take(6) {
            let path = format!("{}\\@{}", node.path, value.name);
            if state.timeline_entries.iter().any(|e| {
                e.timestamp.timestamp() == ts_sec
                    && e.path == path
                    && matches!(e.event_type, TimelineEventType::RegistryValueSet)
            }) {
                continue;
            }

            let detail = format!(
                "{} = {}",
                value.reg_type,
                truncate_registry_timeline_data(&value.data)
            );
            state.timeline_entries.push(TimelineEntry {
                timestamp: ts,
                event_type: TimelineEventType::RegistryValueSet,
                path,
                evidence_id: String::new(),
                detail,
                file_id: None,
                suspicious: is_registry_key_suspicious(&node.path),
            });
            added = added.saturating_add(1);
        }
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

fn is_registry_key_suspicious(path: &str) -> bool {
    let p = path.to_lowercase();
    p.contains("\\currentversion\\run")
        || p.contains("\\currentversion\\runonce")
        || p.contains("\\currentcontrolset\\services")
        || p.contains("\\appcompatcache")
        || p.contains("\\userassist")
}

fn truncate_registry_timeline_data(input: &str) -> String {
    const MAX: usize = 96;
    if input.len() <= MAX {
        return input.to_string();
    }
    format!("{}...", &input[..MAX])
}
