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
                .fill(egui::Color32::from_rgb(0x08, 0x09, 0x0d))
                .inner_margin(egui::Margin::same(40.0)),
        )
        .show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(60.0);

                // Chevron stack mark — 80x70
                let (chevron_rect, _) =
                    ui.allocate_exact_size(egui::vec2(80.0, 70.0), egui::Sense::hover());
                draw_chevron_stack(ui.painter(), chevron_rect);
                ui.add_space(12.0);

                // STRATA wordmark — 44px, letter-spacing via spaces
                ui.label(
                    egui::RichText::new("S T R A T A")
                        .color(egui::Color32::from_rgb(0xdc, 0xe6, 0xf0))
                        .size(44.0)
                        .strong(),
                );
                ui.add_space(8.0);

                // Subtitle
                ui.label(
                    egui::RichText::new("Forensic Intelligence Platform")
                        .color(egui::Color32::from_rgb(0x3d, 0x50, 0x66))
                        .size(10.0),
                );
                ui.add_space(4.0);

                // Version + company
                ui.label(
                    egui::RichText::new(format!(
                        "v{}  ·  Wolfmark Systems",
                        env!("CARGO_PKG_VERSION")
                    ))
                    .color(egui::Color32::from_rgb(0x1c, 0x26, 0x38))
                    .size(9.0),
                );

                ui.add_space(24.0);

                // Thin divider
                let divider_rect = ui.available_rect_before_wrap();
                let center_x = divider_rect.center().x;
                ui.painter().line_segment(
                    [
                        egui::pos2(center_x - 200.0, divider_rect.top()),
                        egui::pos2(center_x + 200.0, divider_rect.top()),
                    ],
                    egui::Stroke::new(1.0, egui::Color32::from_rgb(0x14, 0x1c, 0x28)),
                );
                ui.add_space(16.0);

                // License input card
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(0x0c, 0x0f, 0x16))
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(0x14, 0x1c, 0x28)))
                    .inner_margin(egui::Margin::symmetric(24.0, 20.0))
                    .rounding(egui::Rounding::same(8.0))
                    .show(ui, |ui| {
                        ui.set_width(400.0);

                        ui.label(
                            egui::RichText::new("License Key")
                                .color(egui::Color32::from_rgb(0x3d, 0x50, 0x66))
                                .size(9.5),
                        );
                        ui.add_space(4.0);
                        ui.add(
                            egui::TextEdit::singleline(&mut state.splash_license_key)
                                .desired_width(360.0)
                                .hint_text("STRATA-XXXX-XXXX-XXXX-XXXX"),
                        );
                        ui.add_space(10.0);

                        // Start Trial button (primary)
                        let trial_btn = ui.add_sized(
                            [360.0, 34.0],
                            egui::Button::new(
                                egui::RichText::new("Start Trial")
                                    .color(egui::Color32::from_rgb(0x08, 0x09, 0x0d))
                                    .size(11.0)
                                    .strong(),
                            )
                            .fill(egui::Color32::from_rgb(0xdc, 0xe6, 0xf0)),
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

                        ui.add_space(8.0);

                        // Activate License button (secondary)
                        let activate_btn = ui.add_sized(
                            [360.0, 34.0],
                            egui::Button::new(
                                egui::RichText::new("Activate License")
                                    .color(egui::Color32::from_rgb(0x8f, 0xa8, 0xc0))
                                    .size(11.0),
                            )
                            .fill(egui::Color32::from_rgb(0x11, 0x16, 0x22))
                            .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(0x1c, 0x22, 0x35))),
                        );
                        if activate_btn.clicked() {
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

                // Copyright
                ui.label(
                    egui::RichText::new("\u{00A9} 2026 Wolfmark Systems")
                        .color(egui::Color32::from_rgb(0x14, 0x1c, 0x28))
                        .size(8.0),
                );
            });
        });
}

/// Draw the 3D chevron stack mark.
pub fn draw_chevron_stack(painter: &egui::Painter, rect: egui::Rect) {
    let ox = rect.left();
    let oy = rect.top();
    let sx = rect.width() / 80.0;
    let sy = rect.height() / 70.0;

    let p = |x: f32, y: f32| egui::pos2(ox + x * sx, oy + y * sy);

    let poly = |points: &[(f32, f32)], fill: egui::Color32| {
        let pts: Vec<egui::Pos2> = points.iter().map(|&(x, y)| p(x, y)).collect();
        painter.add(egui::Shape::convex_polygon(pts, fill, egui::Stroke::NONE));
    };

    // Top face (diamond)
    poly(
        &[(40.0, 4.0), (68.0, 20.0), (40.0, 36.0), (12.0, 20.0)],
        egui::Color32::from_rgba_unmultiplied(0xdc, 0xe6, 0xf0, 247),
    );
    // Right face
    poly(
        &[(68.0, 20.0), (68.0, 28.0), (40.0, 44.0), (40.0, 36.0)],
        egui::Color32::from_rgb(0x3d, 0x58, 0x78),
    );
    // Left face
    poly(
        &[(12.0, 20.0), (12.0, 28.0), (40.0, 44.0), (40.0, 36.0)],
        egui::Color32::from_rgb(0x8f, 0xa8, 0xc0),
    );

    // Layer 1
    poly(&[(68.0, 28.0), (72.0, 30.0), (72.0, 38.0), (68.0, 36.0)], egui::Color32::from_rgb(0x2a, 0x3a, 0x55));
    poly(&[(12.0, 28.0), (8.0, 30.0), (8.0, 38.0), (12.0, 36.0)], egui::Color32::from_rgb(0x4a, 0x68, 0x80));
    painter.line_segment([p(12.0, 36.0), p(68.0, 36.0)], egui::Stroke::new(1.0 * sx.min(sy), egui::Color32::from_rgba_unmultiplied(0xdc, 0xe6, 0xf0, 128)));

    // Layer 2
    poly(&[(68.0, 36.0), (72.0, 38.0), (72.0, 46.0), (68.0, 44.0)], egui::Color32::from_rgb(0x1a, 0x28, 0x40));
    poly(&[(12.0, 36.0), (8.0, 38.0), (8.0, 46.0), (12.0, 44.0)], egui::Color32::from_rgb(0x3a, 0x52, 0x68));
    painter.line_segment([p(12.0, 44.0), p(68.0, 44.0)], egui::Stroke::new(1.0 * sx.min(sy), egui::Color32::from_rgba_unmultiplied(0xb8, 0xc8, 0xd8, 102)));

    // Layer 3
    poly(&[(68.0, 44.0), (72.0, 46.0), (72.0, 54.0), (68.0, 52.0)], egui::Color32::from_rgb(0x0f, 0x1c, 0x2e));
    poly(&[(12.0, 44.0), (8.0, 46.0), (8.0, 54.0), (12.0, 52.0)], egui::Color32::from_rgb(0x28, 0x38, 0x48));
    painter.line_segment([p(12.0, 52.0), p(68.0, 52.0)], egui::Stroke::new(1.0 * sx.min(sy), egui::Color32::from_rgba_unmultiplied(0x8f, 0xa8, 0xc0, 77)));

    // Bottom faces
    poly(
        &[(12.0, 52.0), (8.0, 54.0), (36.0, 66.0), (40.0, 64.0), (40.0, 56.0)],
        egui::Color32::from_rgba_unmultiplied(0x0f, 0x1c, 0x2e, 230),
    );
    poly(
        &[(68.0, 52.0), (72.0, 54.0), (44.0, 66.0), (40.0, 64.0), (40.0, 56.0)],
        egui::Color32::from_rgba_unmultiplied(0x08, 0x0e, 0x18, 230),
    );

    // Top highlight edge
    painter.add(egui::Shape::line(
        vec![p(12.0, 20.0), p(40.0, 4.0), p(68.0, 20.0)],
        egui::Stroke::new(0.8 * sx.min(sy), egui::Color32::from_rgba_unmultiplied(0xff, 0xff, 0xff, 128)),
    ));
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
