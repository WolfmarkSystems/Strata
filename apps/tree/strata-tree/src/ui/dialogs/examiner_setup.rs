//! Examiner Setup dialog — shown on first launch when no examiner is configured.
//! Cannot be dismissed without entering a name (min 2 chars).

use crate::state::{colors::*, AppState};

#[derive(Debug, Clone, Default)]
pub struct ExaminerSetupDialog {
    pub name: String,
    pub agency: String,
    pub badge: String,
    pub email: String,
    pub timezone: String,
    pub is_open: bool,
}

pub fn render(ctx: &egui::Context, state: &mut AppState) {
    if !state.examiner_setup_dlg.is_open {
        return;
    }

    egui::Window::new("Examiner Setup")
        .collapsible(false)
        .resizable(false)
        .default_width(400.0)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            ui.add_space(4.0);
            ui.label(egui::RichText::new(
                "Identify yourself before beginning examination.\nAll actions will be attributed to this identity."
            ).color(TEXT_SEC).size(10.0));
            ui.add_space(8.0);

            egui::Grid::new("examiner_setup_grid")
                .num_columns(2)
                .spacing([8.0, 6.0])
                .show(ui, |ui| {
                    ui.label(egui::RichText::new("Name *").color(TEXT_MUTED).size(9.5));
                    ui.text_edit_singleline(&mut state.examiner_setup_dlg.name);
                    ui.end_row();

                    ui.label(egui::RichText::new("Agency").color(TEXT_MUTED).size(9.5));
                    ui.text_edit_singleline(&mut state.examiner_setup_dlg.agency);
                    ui.end_row();

                    ui.label(egui::RichText::new("Badge / ID").color(TEXT_MUTED).size(9.5));
                    ui.text_edit_singleline(&mut state.examiner_setup_dlg.badge);
                    ui.end_row();

                    ui.label(egui::RichText::new("Email").color(TEXT_MUTED).size(9.5));
                    ui.text_edit_singleline(&mut state.examiner_setup_dlg.email);
                    ui.end_row();

                    ui.label(egui::RichText::new("Timezone").color(TEXT_MUTED).size(9.5));
                    ui.text_edit_singleline(&mut state.examiner_setup_dlg.timezone);
                    ui.end_row();
                });

            if state.examiner_setup_dlg.name.trim().len() < 2 {
                ui.add_space(4.0);
                ui.label(egui::RichText::new("Enter at least 2 characters for examiner name.")
                    .color(AMBER).size(8.5));
            }

            ui.add_space(8.0);
            ui.separator();

            let can_submit = state.examiner_setup_dlg.name.trim().len() >= 2;
            ui.add_enabled_ui(can_submit, |ui| {
                if ui.button(egui::RichText::new("Begin Examination").color(TEXT_PRI).strong()).clicked() {
                    let name = state.examiner_setup_dlg.name.trim().to_string();
                    let agency = state.examiner_setup_dlg.agency.trim().to_string();
                    let badge = state.examiner_setup_dlg.badge.trim().to_string();
                    let email = state.examiner_setup_dlg.email.trim().to_string();
                    let timezone = state.examiner_setup_dlg.timezone.trim().to_string();
                    state.examiner_name = name.clone();
                    match crate::case::profile::save_examiner_profile_full(
                        &name,
                        &agency,
                        &badge,
                        if email.is_empty() { None } else { Some(email.as_str()) },
                        if timezone.is_empty() { Some("UTC") } else { Some(timezone.as_str()) },
                    ) {
                        Ok(()) => {
                            state.status = "Examiner profile saved.".to_string();
                        }
                        Err(err) => {
                            state.status = format!("Examiner profile save failed: {}", err);
                        }
                    }
                    state.log_action("SESSION_START", &format!("examiner={}", name));
                    state.examiner_setup_dlg.is_open = false;
                    // Auto-open evidence dialog after examiner setup
                    state.open_ev_dlg.open = true;
                }

                // DEV SKIP button (only in dev-bypass builds)
                #[cfg(feature = "dev-bypass")]
                {
                    ui.add_space(8.0);
                    let btn = ui.add(
                        egui::Button::new(
                            egui::RichText::new("DEV SKIP \u{2192}")
                                .color(egui::Color32::from_rgb(0xc8, 0x85, 0x5a))
                                .size(9.0)
                                .monospace(),
                        )
                        .fill(egui::Color32::TRANSPARENT)
                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(0xc8, 0x85, 0x5a)))
                        .rounding(3.0),
                    );
                    if btn.clicked() {
                        state.examiner_name = "Dev Examiner".to_string();
                        state.examiner_setup_dlg.name = "Dev Examiner".to_string();
                        state.examiner_setup_dlg.agency = "Wolfmark Systems".to_string();
                        state.examiner_setup_dlg.badge = "DEV-001".to_string();
                        state.examiner_setup_dlg.email = "dev@wolfmark.local".to_string();
                        let _ = crate::case::profile::save_examiner_profile_full(
                            "Dev Examiner", "Wolfmark Systems", "DEV-001",
                            Some("dev@wolfmark.local"), Some("UTC"),
                        );
                        state.log_action("DEV_SKIP", "Examiner setup bypassed");
                        state.examiner_setup_dlg.is_open = false;
                        state.open_ev_dlg.open = true;
                    }
                }
            });
        });
}
