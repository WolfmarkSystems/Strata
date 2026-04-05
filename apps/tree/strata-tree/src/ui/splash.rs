//! Splash / License activation screen.
//! Shown on launch when no valid license is present.

use crate::state::{colors::*, AppState};

pub fn render(ctx: &egui::Context, state: &mut AppState) {
    if !state.show_splash {
        return;
    }

    egui::CentralPanel::default()
        .frame(
            egui::Frame::default()
                .fill(egui::Color32::from_rgb(0x04, 0x08, 0x12))
                .inner_margin(egui::Margin::same(40.0)),
        )
        .show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(80.0);

                // Strata wordmark
                ui.label(
                    egui::RichText::new("STRATA")
                        .color(ACCENT)
                        .size(42.0)
                        .strong(),
                );
                ui.add_space(8.0);

                // Tagline
                ui.label(
                    egui::RichText::new("Every layer. Every artifact. Every platform.")
                        .color(TEXT_SEC)
                        .size(13.0),
                );
                ui.add_space(4.0);

                // Company + version
                ui.label(
                    egui::RichText::new(format!(
                        "Wolfmark Systems — v{}",
                        env!("CARGO_PKG_VERSION")
                    ))
                    .color(TEXT_MUTED)
                    .size(10.0),
                );

                ui.add_space(40.0);

                // License input card
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(0x08, 0x0f, 0x1e))
                    .stroke(egui::Stroke::new(1.0, BORDER_SUBTLE))
                    .inner_margin(egui::Margin::symmetric(24.0, 20.0))
                    .rounding(egui::Rounding::same(8.0))
                    .show(ui, |ui| {
                        ui.set_width(400.0);

                        ui.label(
                            egui::RichText::new("License Key")
                                .color(TEXT_MUTED)
                                .size(9.5),
                        );
                        ui.add_space(4.0);
                        ui.add(
                            egui::TextEdit::singleline(&mut state.splash_license_key)
                                .desired_width(360.0)
                                .hint_text("STRATA-XXXX-XXXX-XXXX-XXXX"),
                        );
                        ui.add_space(12.0);

                        ui.horizontal(|ui| {
                            // Activate License button
                            let activate_btn = ui.add_sized(
                                [170.0, 32.0],
                                egui::Button::new(
                                    egui::RichText::new("Activate License")
                                        .color(egui::Color32::WHITE)
                                        .strong()
                                        .size(11.0),
                                )
                                .fill(egui::Color32::from_rgb(0x1d, 0x4e, 0x89)),
                            );
                            if activate_btn.clicked() {
                                // Try to load license file from the entered path/key
                                let key = state.splash_license_key.trim().to_string();
                                if !key.is_empty() {
                                    let path = std::path::Path::new(&key);
                                    if path.exists() && path.extension().map(|e| e == "vlic").unwrap_or(false) {
                                        match crate::license_state::AppLicenseState::install_license_file(path) {
                                            Ok(new_license) => {
                                                state.license_state = new_license;
                                                state.show_splash = false;
                                                state.splash_error.clear();
                                                state.log_action("LICENSE_ACTIVATED", "License file installed");
                                                advance_after_splash(state);
                                            }
                                            Err(e) => {
                                                state.splash_error = format!("License invalid: {}", e);
                                            }
                                        }
                                    } else {
                                        state.splash_error = "Enter path to .vlic license file or click Start Trial".to_string();
                                    }
                                }
                            }

                            ui.add_space(12.0);

                            // Start Trial button
                            let trial_btn = ui.add_sized(
                                [170.0, 32.0],
                                egui::Button::new(
                                    egui::RichText::new("Start Trial")
                                        .color(TEXT_PRI)
                                        .size(11.0),
                                )
                                .fill(egui::Color32::from_rgb(0x10, 0x1a, 0x2a)),
                            );
                            if trial_btn.clicked() {
                                match strata_license::start_trial("strata", 30) {
                                    Ok(_) => {
                                        state.license_state = crate::license_state::AppLicenseState::load();
                                        state.show_splash = false;
                                        state.splash_error.clear();
                                        state.log_action("TRIAL_STARTED", "30-day trial activated");
                                        advance_after_splash(state);
                                    }
                                    Err(e) => {
                                        state.splash_error = format!("Trial activation failed: {}", e);
                                    }
                                }
                            }
                        });

                        // Error message
                        if !state.splash_error.is_empty() {
                            ui.add_space(8.0);
                            ui.label(
                                egui::RichText::new(&state.splash_error)
                                    .color(DANGER)
                                    .size(9.0),
                            );
                        }
                    });

                ui.add_space(16.0);

                // Info text
                ui.label(
                    egui::RichText::new("Trial: 30 days · Full feature set · Reports watermarked")
                        .color(TEXT_MUTED)
                        .size(9.0),
                );
                ui.label(
                    egui::RichText::new("Pro: Permanent license · Court-ready reports · No watermark")
                        .color(TEXT_MUTED)
                        .size(9.0),
                );

                ui.add_space(20.0);

                // Machine ID for licensing
                ui.label(
                    egui::RichText::new(format!(
                        "Machine ID: {}",
                        state.license_state.machine_id_display()
                    ))
                    .color(TEXT_MUTED)
                    .size(8.0)
                    .monospace(),
                );
            });
        });
}

/// After license is activated, advance to the next step in the flow:
/// - If no examiner profile → examiner setup dialog opens (already handled by app.rs)
/// - If examiner exists → open evidence dialog immediately
fn advance_after_splash(state: &mut AppState) {
    if let Some(profile) = crate::case::profile::load_examiner_profile() {
        if profile.name.trim().len() >= 2 {
            // Examiner exists — go straight to open evidence
            state.examiner_name = profile.name.clone();
            state.examiner_setup_dlg.name = profile.name;
            state.examiner_setup_dlg.agency = profile.agency;
            state.examiner_setup_dlg.badge = profile.badge_number;
            state.examiner_setup_dlg.email = profile.email.unwrap_or_default();
            state.examiner_setup_dlg.timezone = profile.timezone;
            state.examiner_setup_dlg.is_open = false;
            state.open_ev_dlg.open = true;
            return;
        }
    }
    // No profile — examiner setup will open (it's already set in app.rs defaults)
    state.examiner_setup_dlg.is_open = true;
}
