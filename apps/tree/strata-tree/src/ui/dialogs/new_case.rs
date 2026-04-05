//! New Case dialog.

use crate::case::project::VtpProject;
use crate::state::{colors::*, ActiveCase, AppState};

pub fn render(ctx: &egui::Context, state: &mut AppState) {
    egui::Window::new("Create New Case")
        .collapsible(false)
        .resizable(false)
        .default_width(440.0)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            egui::Grid::new("new_case_grid")
                .num_columns(2)
                .spacing([8.0, 6.0])
                .show(ui, |ui| {
                    field(ui, "Case Name *", &mut state.new_case_dlg.name);
                    field(ui, "Case ID", &mut state.new_case_dlg.id);
                    field(ui, "Examiner *", &mut state.new_case_dlg.examiner);
                    field(ui, "Agency", &mut state.new_case_dlg.agency);

                    ui.label(
                        egui::RichText::new("Save Path *")
                            .color(TEXT_MUTED)
                            .size(9.5),
                    );
                    ui.horizontal(|ui| {
                        ui.text_edit_singleline(&mut state.new_case_dlg.save_path);
                        if ui.small_button("Browse\u{2026}").clicked() {
                            if let Some(p) = rfd::FileDialog::new()
                                .add_filter("Strata Case", &["vtp"])
                                .save_file()
                            {
                                state.new_case_dlg.save_path = p.to_string_lossy().to_string();
                            }
                        }
                    });
                    ui.end_row();
                });

            if let Some(err) = &state.new_case_dlg.error.clone() {
                ui.label(egui::RichText::new(err.as_str()).color(DANGER).size(9.0));
            }

            ui.separator();
            ui.horizontal(|ui| {
                let can = !state.new_case_dlg.name.trim().is_empty()
                    && !state.new_case_dlg.examiner.trim().is_empty()
                    && !state.new_case_dlg.save_path.trim().is_empty();

                ui.add_enabled_ui(can, |ui| {
                    if ui
                        .button(egui::RichText::new("Create Case").color(TEXT_PRI).strong())
                        .clicked()
                    {
                        create_case(state);
                    }
                });
                if ui.button("Cancel").clicked() {
                    state.new_case_dlg.open = false;
                    state.new_case_dlg = Default::default();
                }
            });
        });
}

fn field(ui: &mut egui::Ui, label: &str, val: &mut String) {
    ui.label(egui::RichText::new(label).color(TEXT_MUTED).size(9.5));
    ui.text_edit_singleline(val);
    ui.end_row();
}

fn create_case(state: &mut AppState) {
    let name = state.new_case_dlg.name.trim().to_string();
    let examiner = state.new_case_dlg.examiner.trim().to_string();
    let mut path = state.new_case_dlg.save_path.trim().to_string();
    if !path.to_lowercase().ends_with(".vtp") {
        path.push_str(".vtp");
    }

    let case_id = if state.new_case_dlg.id.trim().is_empty() {
        uuid::Uuid::new_v4().to_string()
    } else {
        state.new_case_dlg.id.trim().to_string()
    };

    match VtpProject::create(&path, &name, &examiner) {
        Ok(project) => {
            let _ = project.set_meta("case_id", &case_id);
            let _ = project.set_meta("agency", state.new_case_dlg.agency.trim());
            let _ = project.set_meta("tool_version", env!("CARGO_PKG_VERSION"));
            let db_path = std::path::PathBuf::from(&path)
                .parent()
                .map(|p| p.join("strata_index.db"))
                .unwrap_or_else(|| std::path::PathBuf::from("strata_index.db"));
            let _ = project.set_meta("database_path", &db_path.to_string_lossy());

            state.case = Some(ActiveCase {
                name: name.clone(),
                id: case_id.clone(),
                agency: state.new_case_dlg.agency.trim().to_string(),
                path,
            });
            state.examiner_name = examiner.clone();
            state.case_dirty = false;
            state.last_auto_save_at = Some(std::time::Instant::now());
            state.last_auto_save_utc =
                Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
            state.log_action("CASE_CREATED", &format!("name='{}' id={}", name, case_id));
            state.status = format!("Case '{}' created.", name);
            let integrity_hash = state.compute_case_integrity_hash();
            let _ = project.set_meta("case_integrity_hash", &integrity_hash);
            state.new_case_dlg.open = false;
            state.new_case_dlg = Default::default();
        }
        Err(e) => {
            state.new_case_dlg.error = Some(format!("Failed: {}", e));
        }
    }
}
