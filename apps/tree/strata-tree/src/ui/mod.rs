pub mod dialogs;
pub mod evidence_drive;
pub mod export;
pub mod file_table;
pub mod hash_sets_view;
pub mod hex_panel;
pub mod layout;
pub mod preview_panel;
pub mod splash;
pub mod status_bar;
pub mod tabbar;
pub mod titlebar;
pub mod toolbar;
pub mod tree_panel;

// Phase 2 tab views.
pub mod artifacts_view;
pub mod audit_view;
pub mod bookmarks_view;
pub mod browser_history_view;
pub mod compare_view;
pub mod event_logs_view;
pub mod gallery_view;
pub mod plugins_view;
pub mod registry_view;
pub mod search_view;
pub mod settings_view;
pub mod timeline_view;

use crate::state::{AppState, ViewMode};

thread_local! {
    static LAST_VIEW_MODE: std::cell::RefCell<Option<crate::state::ViewMode>> =
        const { std::cell::RefCell::new(None) };
}

pub fn render(ctx: &egui::Context, state: &mut AppState) {
    // Activation flow takes priority over main UI
    if state.show_splash {
        splash::render(ctx, state);
        return;
    }

    // Evidence drive selection overlay
    evidence_drive::render(ctx, state);

    handle_keyboard_navigation(ctx, state);
    toolbar::render(ctx, state);
    layout::render(ctx, state);
    log_view_mode_transition(state);
}

fn log_view_mode_transition(state: &mut AppState) {
    let changed = LAST_VIEW_MODE.with(|last| {
        let mut last = last.borrow_mut();
        let changed = last.as_ref() != Some(&state.view_mode);
        if changed {
            *last = Some(state.view_mode.clone());
        }
        changed
    });
    if changed {
        state.log_action("VIEW_MODE", view_mode_label(&state.view_mode));
    }
}

fn view_mode_label(mode: &crate::state::ViewMode) -> &'static str {
    match mode {
        crate::state::ViewMode::FileExplorer => "FileExplorer",
        crate::state::ViewMode::Artifacts => "Artifacts",
        crate::state::ViewMode::Bookmarks => "Bookmarks",
        crate::state::ViewMode::Gallery => "Gallery",
        crate::state::ViewMode::Compare => "Compare",
        crate::state::ViewMode::Timeline => "Timeline",
        crate::state::ViewMode::Registry => "Registry",
        crate::state::ViewMode::EventLogs => "EventLogs",
        crate::state::ViewMode::BrowserHistory => "BrowserHistory",
        crate::state::ViewMode::Search => "Search",
        crate::state::ViewMode::HashSets => "HashSets",
        crate::state::ViewMode::AuditLog => "AuditLog",
        crate::state::ViewMode::Plugins => "Plugins",
        crate::state::ViewMode::Settings => "Settings",
    }
}

fn handle_keyboard_navigation(ctx: &egui::Context, state: &mut AppState) {
    use crate::state::ViewMode;

    let mut cycle_tabs: i32 = 0;
    let mut row_move: i32 = 0;
    let mut jump_top = false;
    let mut jump_bottom = false;
    let mut open_evidence = false;
    let mut new_case = false;
    let mut save_case = false;
    let mut hash_all = false;
    let mut go_search = false;
    let mut preview_tab: Option<u8> = None;
    let mut direct_tab: Option<ViewMode> = None;
    let mut open_explorer = false;

    ctx.input(|i| {
        if i.modifiers.ctrl && i.key_pressed(egui::Key::Tab) {
            cycle_tabs = if i.modifiers.shift { -1 } else { 1 };
        }
        if i.key_pressed(egui::Key::F6) {
            cycle_tabs = 1;
        }
        if i.modifiers.ctrl && i.key_pressed(egui::Key::Num1) {
            direct_tab = Some(ViewMode::FileExplorer);
        } else if i.modifiers.ctrl && i.key_pressed(egui::Key::Num2) {
            direct_tab = Some(ViewMode::Bookmarks);
        } else if i.modifiers.ctrl && i.key_pressed(egui::Key::Num3) {
            direct_tab = Some(ViewMode::Gallery);
        } else if i.modifiers.ctrl && i.key_pressed(egui::Key::Num4) {
            direct_tab = Some(ViewMode::Compare);
        } else if i.modifiers.ctrl && i.key_pressed(egui::Key::Num5) {
            direct_tab = Some(ViewMode::Timeline);
        } else if i.modifiers.ctrl && i.key_pressed(egui::Key::Num6) {
            direct_tab = Some(ViewMode::Registry);
        } else if i.modifiers.ctrl && i.key_pressed(egui::Key::Num7) {
            direct_tab = Some(ViewMode::EventLogs);
        } else if i.modifiers.ctrl && i.key_pressed(egui::Key::Num8) {
            direct_tab = Some(ViewMode::BrowserHistory);
        } else if i.modifiers.ctrl && i.key_pressed(egui::Key::Num9) {
            direct_tab = Some(ViewMode::Search);
        } else if i.modifiers.ctrl && i.key_pressed(egui::Key::Num0) {
            direct_tab = Some(ViewMode::HashSets);
        } else if i.modifiers.ctrl && i.key_pressed(egui::Key::F1) {
            direct_tab = Some(ViewMode::AuditLog);
        } else if i.modifiers.ctrl && i.key_pressed(egui::Key::F2) {
            direct_tab = Some(ViewMode::Plugins);
        }
        if i.modifiers.ctrl && i.key_pressed(egui::Key::O) {
            open_evidence = true;
        }
        if i.modifiers.ctrl && i.key_pressed(egui::Key::N) {
            new_case = true;
        }
        if i.modifiers.ctrl && i.key_pressed(egui::Key::S) {
            save_case = true;
        }
        if i.modifiers.ctrl && i.key_pressed(egui::Key::H) {
            hash_all = true;
        }
        if i.modifiers.ctrl && i.key_pressed(egui::Key::F) {
            go_search = true;
        }
        if i.key_pressed(egui::Key::Escape) {
            open_explorer = true;
        }
        if i.modifiers.alt && i.key_pressed(egui::Key::Num1) {
            preview_tab = Some(0);
        } else if i.modifiers.alt && i.key_pressed(egui::Key::Num2) {
            preview_tab = Some(1);
        } else if i.modifiers.alt && i.key_pressed(egui::Key::Num3) {
            preview_tab = Some(2);
        } else if i.modifiers.alt && i.key_pressed(egui::Key::Num4) {
            preview_tab = Some(3);
        }
        if i.key_pressed(egui::Key::ArrowDown) {
            row_move = 1;
        } else if i.key_pressed(egui::Key::ArrowUp) {
            row_move = -1;
        } else if i.key_pressed(egui::Key::PageDown) {
            row_move = 10;
        } else if i.key_pressed(egui::Key::PageUp) {
            row_move = -10;
        } else if i.key_pressed(egui::Key::Home) {
            jump_top = true;
        } else if i.key_pressed(egui::Key::End) {
            jump_bottom = true;
        }
    });

    if open_evidence {
        state.open_ev_dlg.open = true;
        state.status = "Shortcut: Open Evidence dialog".to_string();
    }
    if new_case {
        state.new_case_dlg.open = true;
        state.status = "Shortcut: New Case dialog".to_string();
    }
    if save_case {
        match state.persist_case_snapshot() {
            Ok(()) => {
                state.status = "Case saved.".to_string();
                state.log_action("CASE_SAVE", "manual save (Ctrl+S)");
            }
            Err(err) => {
                state.status = format!("Case save failed: {}", err);
            }
        }
    }
    if hash_all {
        start_hash_all_shortcut(state);
    }
    if go_search {
        state.view_mode = ViewMode::Search;
    }
    if open_explorer {
        state.view_mode = ViewMode::FileExplorer;
    }
    if let Some(tab) = preview_tab {
        state.preview_tab = tab;
    }
    if let Some(mode) = direct_tab {
        if can_access_view_mode(state, &mode) {
            state.view_mode = mode;
        } else {
            state.status = locked_view_message(&mode).to_string();
        }
    }

    if cycle_tabs != 0 {
        let modes = [
            ViewMode::FileExplorer,
            ViewMode::Bookmarks,
            ViewMode::Gallery,
            ViewMode::Compare,
            ViewMode::Timeline,
            ViewMode::Registry,
            ViewMode::EventLogs,
            ViewMode::BrowserHistory,
            ViewMode::Search,
            ViewMode::HashSets,
            ViewMode::AuditLog,
            ViewMode::Plugins,
        ];
        let current = modes
            .iter()
            .position(|m| *m == state.view_mode)
            .unwrap_or(0);
        let len = modes.len() as i32;
        let mut next = current as i32;
        for _ in 0..modes.len() {
            next = (next + cycle_tabs).rem_euclid(len);
            let candidate = modes[next as usize].clone();
            if can_access_view_mode(state, &candidate) {
                state.view_mode = candidate;
                break;
            }
        }
    }

    if state.view_mode == ViewMode::FileExplorer && (row_move != 0 || jump_top || jump_bottom) {
        state.refresh_filtered_files();
        if state.filtered_file_indices.is_empty() {
            return;
        }

        let mut current_pos = state
            .selected_file_id
            .as_ref()
            .and_then(|id| {
                state
                    .filtered_file_indices
                    .iter()
                    .position(|idx| state.file_index.get(*idx).map(|f| &f.id) == Some(id))
            })
            .unwrap_or(0);
        if jump_top {
            current_pos = 0;
        }
        if jump_bottom {
            current_pos = state.filtered_file_indices.len().saturating_sub(1);
        }
        let max = state.filtered_file_indices.len().saturating_sub(1) as i32;
        let next_pos = (current_pos as i32 + row_move).clamp(0, max) as usize;

        if let Some(file_idx) = state.filtered_file_indices.get(next_pos).copied() {
            if let Some(entry) = state.file_index.get(file_idx) {
                state.selected_file_id = Some(entry.id.clone());
                state.file_table_state.selected_id = Some(entry.id.clone());
                let id = entry.id.clone();
                state.load_hex_for_file(&id);
            }
        }
    }
}

fn can_access_view_mode(state: &AppState, mode: &ViewMode) -> bool {
    match mode {
        ViewMode::Registry => state.has_feature("registry_viewer"),
        ViewMode::HashSets => state.has_feature("hash_sets"),
        ViewMode::Plugins => state.has_feature("plugins"),
        _ => true,
    }
}

fn locked_view_message(mode: &ViewMode) -> &'static str {
    match mode {
        ViewMode::Registry => "Registry viewer requires Pro license",
        ViewMode::HashSets => "Hash Sets requires Pro license",
        ViewMode::Plugins => "Plugins require Enterprise license",
        _ => "Feature locked",
    }
}

fn start_hash_all_shortcut(state: &mut AppState) {
    if state.hashing_active {
        state.status = "Hashing already in progress.".to_string();
        return;
    }
    let files: Vec<crate::state::FileEntry> = state
        .file_index
        .iter()
        .filter(|f| !f.is_dir && f.sha256.is_none())
        .cloned()
        .collect();
    if files.is_empty() {
        state.status = "All files already hashed.".to_string();
        return;
    }

    let (tx, rx) = std::sync::mpsc::channel();
    crate::evidence::hasher::spawn_hash_worker(files, state.vfs_context.clone(), tx);
    state.hashing_rx = Some(rx);
    state.hashing_active = true;
    state.status = "Hashing started...".to_string();
    state.log_action("HASH_SHORTCUT", "Ctrl+H");
}
