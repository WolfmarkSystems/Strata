//! Layout — 4-column: icon sidebar | evidence tree | file table | detail panel.
//! Uses painter-drawn card backgrounds for reliable rounded corners.

use super::{
    artifacts_view, audit_view, bookmarks_view, browser_history_view, compare_view,
    csam_review_view, dialogs, event_logs_view, file_table, gallery_view, hash_sets_view,
    plugins_view, preview_panel, registry_view, search_view, settings_view, summary_view, tabbar,
    timeline_view, tree_panel,
};
use crate::state::{AppState, ViewMode};

/// Paint a card background on the full available rect and clip content to it.
fn paint_card(ui: &mut egui::Ui, t: &crate::theme::StrataTheme) {
    let rect = ui.max_rect();
    ui.painter().rect(
        rect,
        crate::theme::RADIUS_LG,
        t.card,
        egui::Stroke::new(1.0, t.border),
    );
    ui.set_clip_rect(rect);
}

/// Paint a panel background (for sidebar) and clip content to it.
fn paint_panel(ui: &mut egui::Ui, t: &crate::theme::StrataTheme) {
    let rect = ui.max_rect();
    ui.painter().rect(
        rect,
        crate::theme::RADIUS_LG,
        t.panel,
        egui::Stroke::NONE,
    );
    ui.set_clip_rect(rect);
}

pub fn render(ctx: &egui::Context, state: &mut AppState) {
    dialogs::render(ctx, state);

    // Ctrl+B: toggle navigator panel
    if ctx.input(|i| i.modifiers.command && i.key_pressed(egui::Key::B)) {
        state.navigator_collapsed = !state.navigator_collapsed;
    }

    let t = *state.theme();

    // ── Status bar (24px bottom) ─────────────────────────────────────────
    super::status_bar::render(ctx, state);

    // ── Left icon sidebar (40px — tightened) ─────────────────────────────
    egui::SidePanel::left("icon_sidebar")
        .exact_width(40.0)
        .resizable(false)
        .frame(egui::Frame::none().fill(t.bg).inner_margin(egui::Margin {
            left: 8.0,
            top: 8.0,
            bottom: 8.0,
            right: 4.0,
        }))
        .show(ctx, |ui| {
            paint_panel(ui, &t);
            egui::Frame::none()
                .inner_margin(egui::Margin::symmetric(2.0, 4.0))
                .show(ui, |ui| {
                    tabbar::render(ui, state);
                });
        });

    // Show ingestion progress screen while indexing is active
    if matches!(state.indexing_state, crate::state::IndexingState::Running { .. }) {
        render_ingestion_progress(ctx, state, &t);
        return;
    }

    match state.view_mode {
        ViewMode::FileExplorer => render_explorer(ctx, state, &t),
        _ => render_tab_content(ctx, state, &t),
    }
}

fn render_ingestion_progress(ctx: &egui::Context, state: &mut AppState, t: &crate::theme::StrataTheme) {
    use crate::state::colors::*;

    let files_found = match &state.indexing_state {
        crate::state::IndexingState::Running { files_found } => *files_found,
        _ => 0,
    };

    let evidence_name = state
        .evidence_sources
        .last()
        .map(|s| {
            std::path::Path::new(&s.path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| s.path.clone())
        })
        .unwrap_or_else(|| "evidence".to_string());

    let evidence_format = state
        .evidence_sources
        .last()
        .map(|s| s.format.clone())
        .unwrap_or_default();

    egui::CentralPanel::default()
        .frame(egui::Frame::default().fill(t.bg).inner_margin(egui::Margin::same(40.0)))
        .show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(100.0);

                ui.label(
                    egui::RichText::new("INGESTING EVIDENCE")
                        .color(ACCENT)
                        .size(18.0)
                        .strong(),
                );
                ui.add_space(16.0);

                // Evidence info
                ui.label(
                    egui::RichText::new(&evidence_name)
                        .color(TEXT_PRI)
                        .size(14.0),
                );
                ui.label(
                    egui::RichText::new(format!("Format: {}", evidence_format))
                        .color(TEXT_MUTED)
                        .size(10.0),
                );

                ui.add_space(24.0);

                // Spinning progress indicator
                ui.add(egui::Spinner::new().size(32.0).color(ACCENT));

                ui.add_space(16.0);

                // File count
                ui.label(
                    egui::RichText::new(format!("{} files indexed", files_found))
                        .color(TEXT_PRI)
                        .size(16.0)
                        .monospace(),
                );

                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new("Parsing filesystem and building file index…")
                        .color(TEXT_MUTED)
                        .size(10.0),
                );

                ui.add_space(40.0);

                // Status bar info
                ui.label(
                    egui::RichText::new("Evidence is read-only. No data is modified during indexing.")
                        .color(TEXT_MUTED)
                        .size(8.5),
                );
            });
        });

    // Keep polling for new batches
    ctx.request_repaint();
}

fn render_explorer(ctx: &egui::Context, state: &mut AppState, t: &crate::theme::StrataTheme) {
    // ── Navigator panel (collapsible, 200px default, Ctrl+B toggle) ──
    if !state.navigator_collapsed {
        egui::SidePanel::left("navigator_panel")
            .resizable(true)
            .default_width(200.0)
            .min_width(140.0)
            .max_width(360.0)
            .frame(egui::Frame::none().fill(t.bg).inner_margin(egui::Margin {
                left: 4.0,
                top: 8.0,
                bottom: 8.0,
                right: 4.0,
            }))
            .show(ctx, |ui| {
                paint_card(ui, t);
                egui::Frame::none()
                    .inner_margin(egui::Margin::same(0.0))
                    .show(ui, |ui| {
                        tree_panel::render(ui, state);
                    });
            });
    }

    // ── Detail panel (280px, right) ──────────────────────────────────
    egui::SidePanel::right("detail_panel")
        .resizable(true)
        .default_width(280.0)
        .min_width(220.0)
        .max_width(440.0)
        .frame(egui::Frame::none().fill(t.bg).inner_margin(egui::Margin {
            left: 4.0,
            top: 8.0,
            bottom: 8.0,
            right: 8.0,
        }))
        .show(ctx, |ui| {
            paint_card(ui, t);
            egui::Frame::none()
                .inner_margin(egui::Margin::same(0.0))
                .show(ui, |ui| {
                    preview_panel::render(ui, state);
                });
        });

    // ── File table (fills remaining center) ──────────────────────────
    egui::CentralPanel::default()
        .frame(egui::Frame::none().fill(t.bg).inner_margin(egui::Margin {
            left: 4.0,
            top: 8.0,
            bottom: 8.0,
            right: 4.0,
        }))
        .show(ctx, |ui| {
            paint_card(ui, t);
            egui::Frame::none()
                .inner_margin(egui::Margin::same(0.0))
                .show(ui, |ui| {
                    file_table::render(ui, state);
                });
        });
}

fn render_tab_content(ctx: &egui::Context, state: &mut AppState, t: &crate::theme::StrataTheme) {
    egui::CentralPanel::default()
        .frame(
            egui::Frame::none()
                .fill(t.bg)
                .inner_margin(egui::Margin::same(8.0)),
        )
        .show(ctx, |ui| {
            paint_card(ui, t);
            egui::Frame::none()
                .inner_margin(egui::Margin::same(12.0))
                .show(ui, |ui| match state.view_mode {
                    ViewMode::Artifacts => artifacts_view::render(ui, state),
                    ViewMode::Bookmarks => bookmarks_view::render(ui, state),
                    ViewMode::Gallery => gallery_view::render(ui, state),
                    ViewMode::Compare => compare_view::render(ui, state),
                    ViewMode::Timeline => timeline_view::render(ui, state),
                    ViewMode::Registry => registry_view::render(ui, state),
                    ViewMode::EventLogs => event_logs_view::render(ui, state),
                    ViewMode::BrowserHistory => browser_history_view::render(ui, state),
                    ViewMode::Search => search_view::render(ui, state),
                    ViewMode::HashSets => hash_sets_view::render(ui, state),
                    ViewMode::AuditLog => audit_view::render(ui, state),
                    ViewMode::Plugins => plugins_view::render(ui, state),
                    ViewMode::Settings => settings_view::render(ui, state),
                    ViewMode::Summary => summary_view::render(ui, state),
                    ViewMode::CsamReview => csam_review_view::render(ui, state),
                    ViewMode::FileExplorer => {}
                });
        });
}
