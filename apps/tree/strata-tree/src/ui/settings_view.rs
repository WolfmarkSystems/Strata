//! Settings panel — tabbed: Appearance, Examiner, Hash Sets, License, About.

use crate::state::{colors::*, AppState};

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    // Tab bar
    ui.horizontal(|ui| {
        let tabs = ["Appearance", "Examiner", "Hash Sets", "License", "About"];
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

    egui::ScrollArea::vertical().show(ui, |ui| {
        match state.settings_tab {
            0 => render_appearance_tab(ui, state),
            1 => render_examiner_tab(ui, state),
            2 => render_hashsets_tab(ui, state),
            3 => render_license_tab(ui, state),
            4 => render_about_tab(ui, state),
            _ => {}
        }
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
                let click =
                    ui.interact(resp.rect, resp.id.with("theme_click"), egui::Sense::click());
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
            ui.label(egui::RichText::new(&state.examiner_name).color(TEXT_PRI).size(10.0));
            ui.end_row();
            ui.label(egui::RichText::new("Agency").color(TEXT_MUTED).size(9.5));
            ui.label(egui::RichText::new(&state.examiner_setup_dlg.agency).color(TEXT_PRI).size(10.0));
            ui.end_row();
            ui.label(egui::RichText::new("Badge / ID").color(TEXT_MUTED).size(9.5));
            ui.label(egui::RichText::new(&state.examiner_setup_dlg.badge).color(TEXT_PRI).size(10.0));
            ui.end_row();
            ui.label(egui::RichText::new("Email").color(TEXT_MUTED).size(9.5));
            ui.label(egui::RichText::new(&state.examiner_setup_dlg.email).color(TEXT_PRI).size(10.0));
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
    ui.label(egui::RichText::new(state.license_state.display_status()).color(TEXT_PRI).size(10.0));
    ui.label(egui::RichText::new(format!("Expires: {}", state.license_state.expiry_display())).color(TEXT_MUTED).size(9.0));
    ui.label(egui::RichText::new(format!("Machine ID: {}", state.license_state.machine_id_display())).color(TEXT_MUTED).size(8.5).monospace());
}

fn render_about_tab(ui: &mut egui::Ui, _state: &mut AppState) {
    ui.label(egui::RichText::new("Strata").color(TEXT_PRI).size(16.0).strong());
    ui.label(egui::RichText::new("Every layer. Every artifact. Every platform.").color(TEXT_SEC).size(10.0));
    ui.label(egui::RichText::new(format!("Version {}", env!("CARGO_PKG_VERSION"))).color(TEXT_MUTED).size(9.5));
    ui.add_space(4.0);
    ui.label(egui::RichText::new("Wolfmark Systems LLC").color(TEXT_MUTED).size(9.0));
    ui.label(egui::RichText::new("Court-defensible digital forensic examination platform.").color(TEXT_MUTED).size(9.0));
}
