//! Settings panel — tabbed: Appearance, Examiner, Hash Sets, License, About.

use crate::state::{colors::*, AppState};

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    let has_charges = state.charges_available();

    // Tab bar
    ui.horizontal(|ui| {
        let mut tabs: Vec<&str> = vec!["Appearance", "Examiner", "Hash Sets", "License", "About"];
        if has_charges {
            tabs.push("Charges");
        }
        for (i, label) in tabs.iter().enumerate() {
            let selected = state.settings_tab == i as u8;
            let resp = ui.selectable_label(
                selected,
                egui::RichText::new(*label)
                    .color(if selected { ACCENT } else { TEXT_MUTED })
                    .size(11.0)
                    .strong(),
            );
            if resp.clicked() {
                state.settings_tab = i as u8;
            }
        }
    });
    ui.separator();
    ui.add_space(8.0);

    egui::ScrollArea::vertical().show(ui, |ui| match state.settings_tab {
        0 => render_appearance_tab(ui, state),
        1 => render_examiner_tab(ui, state),
        2 => render_hashsets_tab(ui, state),
        3 => render_license_tab(ui, state),
        4 => render_about_tab(ui, state),
        5 if has_charges => super::charges_view::render(ui, state),
        _ => {}
    });
}

fn render_appearance_tab(ui: &mut egui::Ui, state: &mut AppState) {
    ui.label(
        egui::RichText::new("THEME")
            .color(ACCENT)
            .size(11.0)
            .strong(),
    );
    ui.add_space(4.0);
    ui.label(egui::RichText::new("Theme").color(TEXT_MUTED).size(9.5));
    ui.add_space(4.0);

    ui.horizontal_wrapped(|ui| {
        for (idx, theme) in crate::theme::THEMES.iter().enumerate() {
            let selected = state.theme_index == idx;
            let border_color = if selected { theme.active } else { theme.border };
            let border_width = if selected { 2.5 } else { 1.0 };

            let resp = egui::Frame::none()
                .fill(theme.bg)
                .stroke(egui::Stroke::new(border_width, border_color))
                .rounding(crate::theme::RADIUS_MD)
                .inner_margin(egui::Margin::symmetric(14.0, 12.0))
                .show(ui, |ui| {
                    ui.set_min_size(egui::vec2(120.0, 46.0));
                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new(theme.name)
                                .color(theme.text)
                                .size(14.0)
                                .strong(),
                        );
                        ui.label(
                            egui::RichText::new(theme.subtitle)
                                .color(theme.secondary)
                                .size(11.0),
                        );
                    });
                })
                .response;
            let click = ui.interact(resp.rect, resp.id.with("theme_click"), egui::Sense::click());
            if click.clicked() {
                state.set_theme(idx);
            }
        }
    });
}

fn render_examiner_tab(ui: &mut egui::Ui, state: &mut AppState) {
    ui.label(
        egui::RichText::new("EXAMINER PROFILE")
            .color(ACCENT)
            .size(11.0)
            .strong(),
    );
    ui.add_space(4.0);

    egui::Grid::new("settings_examiner_grid")
        .num_columns(2)
        .spacing([8.0, 6.0])
        .show(ui, |ui| {
            ui.label(egui::RichText::new("Name").color(TEXT_MUTED).size(9.5));
            ui.label(
                egui::RichText::new(&state.examiner_name)
                    .color(TEXT_PRI)
                    .size(10.0),
            );
            ui.end_row();
            ui.label(egui::RichText::new("Agency").color(TEXT_MUTED).size(9.5));
            ui.label(
                egui::RichText::new(&state.examiner_setup_dlg.agency)
                    .color(TEXT_PRI)
                    .size(10.0),
            );
            ui.end_row();
            ui.label(
                egui::RichText::new("Badge / ID")
                    .color(TEXT_MUTED)
                    .size(9.5),
            );
            ui.label(
                egui::RichText::new(&state.examiner_setup_dlg.badge)
                    .color(TEXT_PRI)
                    .size(10.0),
            );
            ui.end_row();
            ui.label(egui::RichText::new("Email").color(TEXT_MUTED).size(9.5));
            ui.label(
                egui::RichText::new(&state.examiner_setup_dlg.email)
                    .color(TEXT_PRI)
                    .size(10.0),
            );
            ui.end_row();
        });

    ui.add_space(4.0);
    if ui.button("Edit Profile").clicked() {
        state.examiner_setup_dlg.is_open = true;
    }
}

fn render_hashsets_tab(ui: &mut egui::Ui, state: &mut AppState) {
    // Delegate to the existing hash sets view
    super::hash_sets_view::render(ui, state);
}

fn render_license_tab(ui: &mut egui::Ui, state: &mut AppState) {
    ui.label(
        egui::RichText::new("LICENSE")
            .color(ACCENT)
            .size(11.0)
            .strong(),
    );
    ui.add_space(4.0);
    ui.label(
        egui::RichText::new(state.license_state.display_status())
            .color(TEXT_PRI)
            .size(10.0),
    );
    ui.label(
        egui::RichText::new(format!("Expires: {}", state.license_state.expiry_display()))
            .color(TEXT_MUTED)
            .size(9.0),
    );
    ui.label(
        egui::RichText::new(format!(
            "Machine ID: {}",
            state.license_state.machine_id_display()
        ))
        .color(TEXT_MUTED)
        .size(8.5)
        .monospace(),
    );
}

fn render_about_tab(ui: &mut egui::Ui, _state: &mut AppState) {
    ui.vertical_centered(|ui| {
        // Chevron stack mark — 60x52
        let (chevron_rect, _) =
            ui.allocate_exact_size(egui::vec2(60.0, 52.0), egui::Sense::hover());
        crate::ui::splash::draw_chevron_stack(ui.painter(), chevron_rect);
        ui.add_space(8.0);

        ui.label(
            egui::RichText::new("S T R A T A")
                .color(egui::Color32::from_rgb(0xdc, 0xe6, 0xf0))
                .size(28.0)
                .strong(),
        );
        ui.add_space(6.0);
        ui.label(
            egui::RichText::new("Every layer. Every artifact. Every platform.")
                .color(egui::Color32::from_rgb(0x3d, 0x50, 0x66))
                .size(12.0)
                .italics(),
        );
        ui.add_space(16.0);

        // Thin divider
        let rect = ui.available_rect_before_wrap();
        let cx = rect.center().x;
        ui.painter().line_segment(
            [
                egui::pos2(cx - 120.0, rect.top()),
                egui::pos2(cx + 120.0, rect.top()),
            ],
            egui::Stroke::new(1.0, egui::Color32::from_rgb(0x14, 0x1c, 0x28)),
        );
        ui.add_space(12.0);

        ui.label(
            egui::RichText::new(format!("Version  {}", env!("CARGO_PKG_VERSION")))
                .color(egui::Color32::from_rgb(0x8f, 0xa8, 0xc0))
                .size(11.0),
        );
        ui.label(
            egui::RichText::new(format!(
                "Platform  {} {}",
                std::env::consts::OS,
                std::env::consts::ARCH
            ))
            .color(egui::Color32::from_rgb(0x8f, 0xa8, 0xc0))
            .size(11.0),
        );
        ui.add_space(16.0);

        ui.label(
            egui::RichText::new("Wolfmark Systems")
                .color(egui::Color32::from_rgb(0xdc, 0xe6, 0xf0))
                .size(12.0),
        );
        ui.label(
            egui::RichText::new("wolfmarksystems@proton.me")
                .color(egui::Color32::from_rgb(0x3d, 0x50, 0x66))
                .size(10.0),
        );
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new("\u{00A9} 2026 Wolfmark Systems \u{00B7} All Rights Reserved")
                .color(egui::Color32::from_rgb(0x1c, 0x26, 0x38))
                .size(9.0),
        );
    });
}
