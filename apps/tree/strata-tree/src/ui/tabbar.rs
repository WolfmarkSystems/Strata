//! Left icon sidebar — 48px wide. Phosphor icons via egui-phosphor font.
//! Active: accent + 2px left border. Settings pinned bottom.

use crate::state::{AppState, ViewMode};
use egui::Color32;

// Phosphor Regular icon codepoints (loaded via font in app.rs)
#[allow(dead_code)]
mod ph {
    pub const FOLDER_OPEN: &str = "\u{E256}";       // File Explorer
    pub const STACK: &str = "\u{E68A}";              // Artifacts (stacked layers)
    pub const BOOKMARK_SIMPLE: &str = "\u{E0EA}";    // Bookmarks
    pub const IMAGE: &str = "\u{E2CA}";              // Gallery
    pub const CLOCK: &str = "\u{E19A}";              // Timeline
    pub const TREE_STRUCTURE: &str = "\u{E6EE}";     // Registry (branching tree)
    pub const WARNING: &str = "\u{E752}";            // Event Logs (warning triangle)
    pub const GLOBE: &str = "\u{E288}";              // Browser History
    pub const MAGNIFYING_GLASS: &str = "\u{E30C}";   // Search
    pub const HASH: &str = "\u{E2A2}";              // Hash Sets
    pub const SHIELD_CHECK: &str = "\u{E622}";       // Audit Log (shield + check)
    pub const PUZZLE_PIECE: &str = "\u{E596}";       // Plugins
    pub const GEAR: &str = "\u{E270}";              // Settings
}

struct SidebarEntry {
    icon: &'static str,
    tooltip: &'static str,
    mode: ViewMode,
    color: Color32,
}

const fn c(r: u8, g: u8, b: u8) -> Color32 {
    Color32::from_rgb(r, g, b)
}

fn entries() -> Vec<SidebarEntry> {
    vec![
        // ── 4 core panels ──
        SidebarEntry {
            icon: ph::FOLDER_OPEN,
            tooltip: "File Explorer",
            mode: ViewMode::FileExplorer,
            color: c(0x7d, 0xd3, 0xfc),
        },
        SidebarEntry {
            icon: ph::STACK,
            tooltip: "Artifacts",
            mode: ViewMode::Artifacts,
            color: c(0xa7, 0x8b, 0xfa),
        },
        SidebarEntry {
            icon: ph::BOOKMARK_SIMPLE,
            tooltip: "Tagged Evidence",
            mode: ViewMode::Bookmarks,
            color: c(0xfb, 0xbf, 0x24),
        },
        SidebarEntry {
            icon: ph::PUZZLE_PIECE,
            tooltip: "Plugins",
            mode: ViewMode::Plugins,
            color: c(0x22, 0xc5, 0x5e),
        },
    ]
}

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    let t = *state.theme();

    ui.vertical_centered(|ui| {
        ui.add_space(4.0);
        for entry in &entries() {
            let active = state.view_mode == entry.mode;
            let icon_color = if active {
                t.active
            } else if t.is_light() {
                // Light theme: use dark muted icons
                Color32::from_rgba_unmultiplied(0x2a, 0x28, 0x26, 180)
            } else {
                Color32::from_rgba_unmultiplied(
                    entry.color.r(),
                    entry.color.g(),
                    entry.color.b(),
                    160,
                )
            };

            let desired = egui::vec2(36.0, 32.0);
            let (rect, resp) = ui.allocate_exact_size(desired, egui::Sense::click());

            // Hover highlight
            if resp.hovered() && !active {
                ui.painter()
                    .rect_filled(rect, crate::theme::RADIUS_MD, t.card);
            }

            // Active: card bg + 2px left accent border
            if active {
                ui.painter()
                    .rect_filled(rect, crate::theme::RADIUS_MD, t.card);
                let bar =
                    egui::Rect::from_min_size(rect.left_top(), egui::vec2(2.0, rect.height()));
                ui.painter().rect_filled(bar, 0.0, t.active);
            }

            // Phosphor icon
            ui.painter().text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                entry.icon,
                egui::FontId::proportional(20.0),
                icon_color,
            );

            if resp.clicked() {
                state.view_mode = entry.mode.clone();
            }
            resp.on_hover_text(entry.tooltip);
        }

        // Spacer to push pinned items to bottom
        let remaining = ui.available_height() - 72.0; // room for audit + gear
        if remaining > 0.0 {
            ui.add_space(remaining);
        }

        // ── Pinned: Audit Log ──
        {
            let active = state.view_mode == ViewMode::AuditLog;
            let icon_color = if active {
                t.active
            } else if t.is_light() {
                Color32::from_rgba_unmultiplied(0x2a, 0x28, 0x26, 180)
            } else {
                Color32::from_rgba_unmultiplied(0x94, 0xa3, 0xb8, 160)
            };
            let (rect, resp) = ui.allocate_exact_size(egui::vec2(36.0, 32.0), egui::Sense::click());
            if resp.hovered() && !active {
                ui.painter().rect_filled(rect, crate::theme::RADIUS_MD, t.card);
            }
            if active {
                ui.painter().rect_filled(rect, crate::theme::RADIUS_MD, t.card);
                let bar = egui::Rect::from_min_size(rect.left_top(), egui::vec2(2.0, rect.height()));
                ui.painter().rect_filled(bar, 0.0, t.active);
            }
            ui.painter().text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                ph::SHIELD_CHECK,
                egui::FontId::proportional(20.0),
                icon_color,
            );
            if resp.clicked() {
                state.view_mode = ViewMode::AuditLog;
            }
            resp.on_hover_text("Audit Log");
        }

        // ── Pinned: Settings gear ──
        let (rect, resp) = ui.allocate_exact_size(egui::vec2(36.0, 32.0), egui::Sense::click());
        if resp.hovered() {
            ui.painter()
                .rect_filled(rect, crate::theme::RADIUS_MD, t.card);
        }
        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            ph::GEAR,
            egui::FontId::proportional(20.0),
            t.muted,
        );
        if resp.clicked() {
            state.view_mode = ViewMode::Settings;
        }
        resp.on_hover_text("Settings");
    });
}
