//! Open Evidence dialog.

use crate::evidence::loader::start_indexing;
use crate::state::{colors::*, AppState, EvidenceSource};

#[derive(Default)]
struct ShadowPickerState {
    open: bool,
    copies: Vec<crate::evidence::shadowcopy::ShadowCopy>,
    selected: Option<String>,
}

thread_local! {
    static SHADOW_PICKER: std::cell::RefCell<ShadowPickerState> =
        std::cell::RefCell::new(ShadowPickerState::default());
}

pub fn render(ctx: &egui::Context, state: &mut AppState) {
    // Evidence drive must be selected before opening evidence
    if state.evidence_drive_path.is_none() && state.open_ev_dlg.open {
        state.show_drive_selection = true;
        state.open_ev_dlg.open = false;
        return;
    }

    egui::Window::new("Open Evidence Source")
        .collapsible(false)
        .resizable(false)
        .default_width(420.0)
        .min_width(380.0)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            ui.set_max_width(420.0);

            ui.label(
                egui::RichText::new("Select an evidence file or directory to load.")
                    .color(TEXT_SEC)
                    .size(10.0),
            );
            ui.add_space(8.0);

            // ── Path field (vertical stack) ──
            ui.label(egui::RichText::new("Evidence Path").color(TEXT_MUTED).size(9.5));
            ui.add_space(2.0);
            ui.add(
                egui::TextEdit::singleline(&mut state.open_ev_dlg.path)
                    .desired_width(f32::INFINITY)
                    .hint_text("/path/to/evidence.E01"),
            );
            ui.add_space(6.0);

            // ── Browse buttons (centered row) ──
            ui.horizontal(|ui| {
                if ui
                    .button(egui::RichText::new("Browse File\u{2026}").color(ACCENT))
                    .clicked()
                {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter(
                            "Evidence",
                            &["e01", "E01", "dd", "raw", "img", "vhd", "vmdk", "vhdx", "iso", "dmg", "qcow2", "vdi"],
                        )
                        .add_filter("All Files", &["*"])
                        .pick_file()
                    {
                        let fmt = detect_fmt(&p);
                        state.open_ev_dlg.path = p.to_string_lossy().to_string();
                        state.open_ev_dlg.format = Some(fmt);
                    }
                }
                if ui
                    .button(egui::RichText::new("Browse Directory\u{2026}").color(ACCENT))
                    .clicked()
                {
                    if let Some(p) = rfd::FileDialog::new().pick_folder() {
                        state.open_ev_dlg.path = p.to_string_lossy().to_string();
                        state.open_ev_dlg.format = Some("Directory".to_string());
                    }
                }
            });

            // ── Format + error feedback ──
            if let Some(fmt) = &state.open_ev_dlg.format.clone() {
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(format!("Format: {}", fmt))
                        .color(GREEN_OK)
                        .size(9.0),
                );
            }
            if let Some(err) = &state.open_ev_dlg.error.clone() {
                ui.add_space(2.0);
                ui.label(egui::RichText::new(err.as_str()).color(DANGER).size(9.0));
            }

            ui.add_space(8.0);
            ui.separator();
            ui.add_space(4.0);

            // ── Recent Evidence ──
            let recent: Vec<String> = state
                .evidence_sources
                .iter()
                .rev()
                .take(3)
                .map(|s| s.path.clone())
                .collect();
            if !recent.is_empty() {
                ui.label(egui::RichText::new("Recent Evidence").color(TEXT_MUTED).size(9.0));
                ui.add_space(2.0);
                for path in &recent {
                    let display = std::path::Path::new(path)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| path.clone());
                    if ui
                        .selectable_label(
                            false,
                            egui::RichText::new(format!("  {} {}", "\u{1F4C4}", display))
                                .color(TEXT_SEC)
                                .size(9.5),
                        )
                        .on_hover_text(path)
                        .clicked()
                    {
                        state.open_ev_dlg.path = path.clone();
                        state.open_ev_dlg.format = Some(detect_fmt(std::path::Path::new(path)));
                    }
                }
                ui.add_space(4.0);
                ui.separator();
                ui.add_space(4.0);
            }

            // ── Action buttons ──
            ui.horizontal(|ui| {
                let can_load = !state.open_ev_dlg.path.trim().is_empty();
                ui.add_enabled_ui(can_load, |ui| {
                    if ui
                        .button(
                            egui::RichText::new("Load Evidence")
                                .color(TEXT_PRI)
                                .strong(),
                        )
                        .clicked()
                    {
                        let path = state.open_ev_dlg.path.trim().to_string();
                        if !crate::evidence::loader::is_evidence_file(std::path::Path::new(&path)) {
                            state.open_ev_dlg.error = Some(
                                "Cannot load .vtp as evidence — this is a case file.".to_string(),
                            );
                            return;
                        }
                        let fmt = state
                            .open_ev_dlg
                            .format
                            .clone()
                            .unwrap_or_else(|| detect_fmt(std::path::Path::new(&path)));
                        if let Err(err) = load_evidence_path(state, path, fmt) {
                            state.open_ev_dlg.error = Some(err);
                        }
                    }
                });
                if ui.button("VSS Snapshot\u{2026}").clicked() {
                    match crate::evidence::shadowcopy::detect_shadow_copies() {
                        Ok(copies) => {
                            SHADOW_PICKER.with(|picker| {
                                let mut picker = picker.borrow_mut();
                                picker.open = true;
                                picker.copies = copies;
                                if picker.selected.is_none() {
                                    picker.selected = picker.copies.first().map(|c| c.id.clone());
                                }
                            });
                        }
                        Err(err) => {
                            state.open_ev_dlg.error =
                                Some(format!("VSS enumeration failed: {}", err));
                        }
                    }
                }
                if ui.button("Cancel").clicked() {
                    state.open_ev_dlg.open = false;
                    state.open_ev_dlg = Default::default();
                }
            });
        });

    render_shadow_picker_window(ctx, state);
}

fn detect_fmt(p: impl AsRef<std::path::Path>) -> String {
    let p = p.as_ref();
    if p.is_dir() {
        return "Directory".to_string();
    }
    match p
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase()
        .as_str()
    {
        "e01" | "ewf" => "E01",
        "dd" | "raw" | "img" => "RAW",
        "vhd" | "vhdx" => "VHD",
        "vmdk" => "VMDK",
        "aff" | "aff4" => "AFF",
        "iso" => "ISO",
        "dmg" => "DMG",
        "qcow2" => "QCOW2",
        "vdi" => "VDI",
        _ => "RAW",
    }
    .to_string()
}

fn load_evidence_path(state: &mut AppState, path: String, format: String) -> Result<(), String> {
    let ev_id = uuid::Uuid::new_v4().to_string();
    let size = std::fs::metadata(&path).ok().map(|m| m.len());
    state.evidence_sources.push(EvidenceSource {
        id: ev_id.clone(),
        path: path.clone(),
        format: format.clone(),
        sha256: None,
        hash_verified: false,
        loaded_utc: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        size_bytes: size,
    });
    state.rebuild_vfs_context();

    match start_indexing(&path, &ev_id) {
        Ok(rx) => {
            if state.case.is_none() {
                state.case = Some(crate::state::ActiveCase {
                    name: "Unsaved Session".to_string(),
                    ..Default::default()
                });
            }
            state.log_action("EVIDENCE_LOADED", &format!("path={} fmt={}", path, format));
            state.indexing_rx = Some(rx);
            state.indexing_state = crate::state::IndexingState::Running { files_found: 0 };
            state.status = "INDEXING: 0 files\u{2026}".to_string();
            state.open_ev_dlg.open = false;
            state.open_ev_dlg = Default::default();
            Ok(())
        }
        Err(e) => {
            let _ = state.evidence_sources.pop();
            state.rebuild_vfs_context();
            Err(format!("Failed to start indexing: {}", e))
        }
    }
}

fn render_shadow_picker_window(ctx: &egui::Context, state: &mut AppState) {
    SHADOW_PICKER.with(|picker| {
        let mut picker = picker.borrow_mut();
        if !picker.open {
            return;
        }

        let mut should_close = false;
        egui::Window::new("Volume Shadow Copies")
            .collapsible(false)
            .resizable(true)
            .default_width(640.0)
            .default_height(420.0)
            .show(ctx, |ui| {
                let copies = picker.copies.clone();
                let mut selected = picker.selected.clone();
                if let Some(chosen) =
                    crate::evidence::shadowcopy::render_shadow_picker(ui, &copies, &mut selected)
                {
                    picker.selected = selected;
                    let path = chosen.to_string_lossy().to_string();
                    let fmt = "VSS Snapshot".to_string();
                    match load_evidence_path(state, path.clone(), fmt.clone()) {
                        Ok(()) => {
                            state.log_action("VSS_LOADED", &format!("path={} fmt={}", path, fmt));
                            should_close = true;
                        }
                        Err(err) => {
                            state.open_ev_dlg.error = Some(err);
                        }
                    }
                } else {
                    picker.selected = selected;
                }
                ui.separator();
                if ui.button("Close").clicked() {
                    should_close = true;
                }
            });

        if should_close {
            picker.open = false;
        }
    });
}
