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

                // Version + copyright
                ui.label(
                    egui::RichText::new(format!(
                        "v{} \u{00B7} \u{00A9} 2026 Wolfmark Systems",
                        env!("CARGO_PKG_VERSION")
                    ))
                    .color(egui::Color32::from_rgb(0x1c, 0x26, 0x38))
                    .size(8.0),
                );
            });
        });
}

/// Draw the 3D chevron stack mark — metallic isometric layered block.
pub fn draw_chevron_stack(painter: &egui::Painter, rect: egui::Rect) {
    let ox = rect.left();
    let oy = rect.top();
    let sx = rect.width() / 80.0;
    let sy = rect.height() / 80.0;

    let p = |x: f32, y: f32| egui::pos2(ox + x * sx, oy + y * sy);

    let poly = |points: &[(f32, f32)], fill: egui::Color32| {
        let pts: Vec<egui::Pos2> = points.iter().map(|&(x, y)| p(x, y)).collect();
        painter.add(egui::Shape::convex_polygon(pts, fill, egui::Stroke::NONE));
    };

    // The block is a 3D isometric shape with a bright top and darker sides,
    // separated by dark gap lines into 4 visible layers.

    let bg = egui::Color32::from_rgb(0x08, 0x09, 0x0d);

    // ── Top face (bright platinum diamond) ─────────────────────────────
    // Upper half of top face (brighter)
    poly(
        &[(40.0, 2.0), (70.0, 18.0), (40.0, 34.0), (10.0, 18.0)],
        egui::Color32::from_rgb(0xe8, 0xef, 0xf5),
    );
    // Subtle center highlight on top face
    poly(
        &[(40.0, 8.0), (58.0, 18.0), (40.0, 28.0), (22.0, 18.0)],
        egui::Color32::from_rgba_unmultiplied(0xff, 0xff, 0xff, 40),
    );

    // ── Layer 0 sides (directly below top face) ────────────────────────
    // Left side
    poly(
        &[(10.0, 18.0), (10.0, 26.0), (40.0, 42.0), (40.0, 34.0)],
        egui::Color32::from_rgb(0x7a, 0x90, 0xa8),
    );
    // Right side
    poly(
        &[(70.0, 18.0), (70.0, 26.0), (40.0, 42.0), (40.0, 34.0)],
        egui::Color32::from_rgb(0x30, 0x44, 0x5e),
    );

    // ── Gap 1 (dark line) ──────────────────────────────────────────────
    poly(&[(10.0, 26.0), (10.0, 29.0), (40.0, 45.0), (40.0, 42.0)], bg);
    poly(&[(70.0, 26.0), (70.0, 29.0), (40.0, 45.0), (40.0, 42.0)], bg);

    // ── Layer 1 ────────────────────────────────────────────────────────
    poly(
        &[(10.0, 29.0), (10.0, 37.0), (40.0, 53.0), (40.0, 45.0)],
        egui::Color32::from_rgb(0x60, 0x78, 0x90),
    );
    poly(
        &[(70.0, 29.0), (70.0, 37.0), (40.0, 53.0), (40.0, 45.0)],
        egui::Color32::from_rgb(0x22, 0x34, 0x4c),
    );

    // ── Gap 2 ──────────────────────────────────────────────────────────
    poly(&[(10.0, 37.0), (10.0, 40.0), (40.0, 56.0), (40.0, 53.0)], bg);
    poly(&[(70.0, 37.0), (70.0, 40.0), (40.0, 56.0), (40.0, 53.0)], bg);

    // ── Layer 2 ────────────────────────────────────────────────────────
    poly(
        &[(10.0, 40.0), (10.0, 48.0), (40.0, 64.0), (40.0, 56.0)],
        egui::Color32::from_rgb(0x48, 0x60, 0x78),
    );
    poly(
        &[(70.0, 40.0), (70.0, 48.0), (40.0, 64.0), (40.0, 56.0)],
        egui::Color32::from_rgb(0x18, 0x28, 0x3e),
    );

    // ── Gap 3 ──────────────────────────────────────────────────────────
    poly(&[(10.0, 48.0), (10.0, 51.0), (40.0, 67.0), (40.0, 64.0)], bg);
    poly(&[(70.0, 48.0), (70.0, 51.0), (40.0, 67.0), (40.0, 64.0)], bg);

    // ── Layer 3 (bottom) ───────────────────────────────────────────────
    poly(
        &[(10.0, 51.0), (10.0, 59.0), (40.0, 75.0), (40.0, 67.0)],
        egui::Color32::from_rgb(0x30, 0x48, 0x60),
    );
    poly(
        &[(70.0, 51.0), (70.0, 59.0), (40.0, 75.0), (40.0, 67.0)],
        egui::Color32::from_rgb(0x10, 0x1e, 0x30),
    );

    // ── Top edge highlight (bright line along top diamond edges) ───────
    painter.add(egui::Shape::line(
        vec![p(10.0, 18.0), p(40.0, 2.0), p(70.0, 18.0)],
        egui::Stroke::new(1.2 * sx.min(sy), egui::Color32::from_rgba_unmultiplied(0xff, 0xff, 0xff, 140)),
    ));

    // Subtle front edge highlights on each layer
    for &y in &[34.0, 45.0, 56.0, 67.0] {
        painter.line_segment(
            [p(10.0, y - 8.0), p(10.0, y)],
            egui::Stroke::new(0.5 * sx.min(sy), egui::Color32::from_rgba_unmultiplied(0xb8, 0xc8, 0xd8, 50)),
        );
    }
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
