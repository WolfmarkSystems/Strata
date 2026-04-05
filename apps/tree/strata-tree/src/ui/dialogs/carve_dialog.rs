//! Carve dialog — configure and launch background file carving.

use crate::state::{colors::*, AppState};
use std::path::{Component, Path, Prefix};

pub fn render(ctx: &egui::Context, state: &mut AppState) {
    if !state.show_carve_dialog {
        return;
    }

    egui::Window::new("File Carving")
        .collapsible(false)
        .resizable(false)
        .default_width(560.0)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            ui.label(
                egui::RichText::new("CARVE UNALLOCATED / RAW CONTAINER BY SIGNATURE")
                    .color(ACCENT)
                    .size(9.5)
                    .strong(),
            );
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(
                    "Evidence remains read-only. Carved output is written to an examiner-selected directory.",
                )
                .color(TEXT_MUTED)
                .size(8.5),
            );
            ui.separator();

            if state.evidence_sources.is_empty() {
                ui.colored_label(DANGER, "No evidence sources loaded.");
                if ui.button("Close").clicked() {
                    state.show_carve_dialog = false;
                }
                return;
            }

            if state.carve_target_evidence_id.is_none() {
                if let Some(first) = state.evidence_sources.first() {
                    state.carve_target_evidence_id = Some(first.id.clone());
                }
            }
            if state.carve_selected_signatures.is_empty() {
                for sig in crate::carve::engine::SIGNATURES {
                    state
                        .carve_selected_signatures
                        .insert(sig.name.to_string());
                }
            }
            if state.carve_output_dir.trim().is_empty() {
                // Default to evidence drive root only (X:/strata-carved), never temp.
                if let Some(ev_id) = &state.carve_target_evidence_id {
                    if let Some(src) = state.evidence_sources.iter().find(|s| &s.id == ev_id) {
                        if let Some(default_dir) = default_carve_output_dir(&src.path) {
                            state.carve_output_dir = default_dir;
                        }
                    }
                }
            }

            ui.label(egui::RichText::new("Evidence Source").color(TEXT_MUTED).size(8.5));
            egui::ComboBox::from_id_source("carve_evidence_source")
                .selected_text(selected_label(state))
                .show_ui(ui, |ui| {
                    for src in &state.evidence_sources {
                        let label = format!(
                            "{} ({})",
                            src.path.replace('\\', "/"),
                            src.format
                        );
                        ui.selectable_value(
                            &mut state.carve_target_evidence_id,
                            Some(src.id.clone()),
                            label,
                        );
                    }
                });

            ui.add_space(4.0);
            ui.label(egui::RichText::new("Signatures").color(TEXT_MUTED).size(8.5));
            egui::ScrollArea::vertical()
                .max_height(130.0)
                .show(ui, |ui| {
                    for sig in crate::carve::engine::SIGNATURES {
                        let mut selected = state.carve_selected_signatures.contains(sig.name);
                        let label = format!("{} (.{})", sig.name, sig.extension);
                        if ui.checkbox(&mut selected, label).changed() {
                            if selected {
                                state.carve_selected_signatures.insert(sig.name.to_string());
                            } else {
                                state.carve_selected_signatures.remove(sig.name);
                            }
                        }
                    }
                });

            ui.add_space(4.0);
            ui.label(egui::RichText::new("Output Directory").color(TEXT_MUTED).size(8.5));
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut state.carve_output_dir);
                if ui.button("Browse...").clicked() {
                    if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                        state.carve_output_dir = dir.to_string_lossy().replace('\\', "/");
                    }
                }
            });
            let output_hint = state.carve_output_dir.replace('\\', "/");
            ui.add_space(2.0);
            ui.label(
                egui::RichText::new(format!("Output root: {}", output_hint))
                .size(8.0)
                .color(TEXT_MUTED),
            );
            if state.carve_output_dir.trim().is_empty() {
                ui.label(
                    egui::RichText::new("Please select an output directory")
                        .color(AMBER)
                        .size(8.5),
                );
            }
            if state.carve_active {
                ui.colored_label(AMBER, "Carving is already running.");
                let (done, total) = state.carve_progress_bytes;
                let pct = if total > 0 {
                    (done as f32 / total as f32).clamp(0.0, 1.0)
                } else {
                    0.0
                };
                ui.add(
                    egui::ProgressBar::new(pct)
                        .show_percentage()
                        .text(format!("{} / {} bytes", done, total.max(done))),
                );
                ui.label(
                    egui::RichText::new(format!("Files found: {}", state.carve_files_found))
                        .size(8.5)
                        .color(TEXT_SEC),
                );
            }

            ui.separator();
            ui.horizontal(|ui| {
                let has_output = !state.carve_output_dir.trim().is_empty();
                let can_start = !state.carve_active
                    && state.carve_target_evidence_id.is_some()
                    && !state.carve_selected_signatures.is_empty()
                    && has_output;
                if !has_output {
                    ui.label(egui::RichText::new("Please select an output directory").color(AMBER).size(9.0));
                }
                ui.add_enabled_ui(can_start, |ui| {
                    if ui.button("Start Carving").clicked() {
                        start_carving(state);
                    }
                });
                if state.carve_active {
                    if ui.button("Cancel").clicked() {
                        if let Some(flag) = &state.carve_cancel_flag {
                            flag.store(true, std::sync::atomic::Ordering::Relaxed);
                            state.status = "Carving cancel requested...".to_string();
                            state.log_action("CARVE_CANCEL", "cancel requested by examiner");
                        }
                    }
                } else if ui.button("Close").clicked() {
                    state.show_carve_dialog = false;
                }
            });
        });
}

fn selected_label(state: &AppState) -> String {
    if let Some(selected) = &state.carve_target_evidence_id {
        if let Some(src) = state.evidence_sources.iter().find(|s| &s.id == selected) {
            return src.path.replace('\\', "/");
        }
    }
    "Select source".to_string()
}

fn start_carving(state: &mut AppState) {
    let Some(selected) = state.carve_target_evidence_id.clone() else {
        state.status = "Carving unavailable: no evidence selected".to_string();
        return;
    };
    let Some(source) = state
        .evidence_sources
        .iter()
        .find(|s| s.id == selected)
        .cloned()
    else {
        state.status = "Carving unavailable: selected evidence missing".to_string();
        return;
    };

    let selected_signatures: Vec<crate::carve::engine::FileSignature> =
        crate::carve::engine::SIGNATURES
            .iter()
            .filter(|sig| state.carve_selected_signatures.contains(sig.name))
            .cloned()
            .collect();
    if selected_signatures.is_empty() {
        state.status = "Carving unavailable: select at least one signature".to_string();
        return;
    }
    let output_root = std::path::PathBuf::from(state.carve_output_dir.trim());
    if state.carve_output_dir.trim().is_empty() {
        state.status = "Output directory required".to_string();
        return;
    }
    if let Err(err) = state.ensure_output_path_safe(output_root.as_path()) {
        state.status = err;
        return;
    }

    let (tx, rx) = std::sync::mpsc::channel();
    let cancel_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    crate::carve::engine::carve_unallocated_with_options(
        &source,
        selected_signatures,
        output_root.clone(),
        Some(cancel_flag.clone()),
        tx,
    );
    state.carve_rx = Some(rx);
    state.carve_active = true;
    state.carve_cancel_flag = Some(cancel_flag);
    state.carve_progress_bytes = (0, source.size_bytes.unwrap_or(0));
    state.carve_files_found = 0;
    state.carve_source_evidence_id = Some(source.id.clone());
    state.status = format!("Carving started: {}", source.path.replace('\\', "/"));
    state.log_action(
        "CARVE_START",
        &format!(
            "evidence={} output={}",
            source.path.replace('\\', "/"),
            output_root.to_string_lossy().replace('\\', "/")
        ),
    );
}

fn default_carve_output_dir(evidence_path: &str) -> Option<String> {
    let windows_like = evidence_path.replace('/', "\\");
    let path = Path::new(&windows_like);
    let mut components = path.components();
    let prefix = components.next()?;
    match prefix {
        Component::Prefix(prefix_component) => match prefix_component.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
                let drive = char::from(letter).to_ascii_uppercase();
                if drive == 'C' {
                    return None;
                }
                Some(format!("{drive}:/strata-carved"))
            }
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::default_carve_output_dir;

    #[test]
    fn carve_default_output_uses_non_c_evidence_drive() {
        let derived = default_carve_output_dir(r"F:\cases\sample.E01");
        assert_eq!(derived.as_deref(), Some("F:/strata-carved"));

        let blocked_c = default_carve_output_dir(r"C:\cases\sample.E01");
        assert!(blocked_c.is_none());
    }
}
