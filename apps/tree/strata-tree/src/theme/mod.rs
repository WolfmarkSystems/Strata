//! Strata Theme System — 6 locked themes, hot-swappable.
//!
//! Status colors are constant across all themes (except High Contrast).

use egui::Color32;

/// Complete color palette for a Strata theme.
#[derive(Debug, Clone, Copy)]
pub struct StrataTheme {
    pub name: &'static str,
    pub subtitle: &'static str,
    // Layout surfaces (lightest → darkest depth)
    pub bg: Color32,
    pub panel: Color32,
    pub card: Color32,
    pub elevated: Color32,
    pub border: Color32,
    // Accent (per-tool, but overridden by theme selection)
    pub active: Color32,
    // Text
    pub text: Color32,
    pub secondary: Color32,
    pub muted: Color32,
    // Status colors
    pub suspicious: Color32,
    pub flagged: Color32,
    pub clean: Color32,
}

impl StrataTheme {
    /// Returns true for light themes (Ash) where UI must render dark-on-light.
    pub fn is_light(&self) -> bool {
        self.bg.r() > 128
    }
}

// ── Default status colors ────────────────────────────────────────────────────
const SUSPICIOUS: Color32 = Color32::from_rgb(0xf5, 0x9e, 0x0b);
const FLAGGED: Color32 = Color32::from_rgb(0xef, 0x44, 0x44);
const CLEAN: Color32 = Color32::from_rgb(0x22, 0xc5, 0x5e);

// ── Theme 0: Iron Wolf (DEFAULT) ─────────────────────────────────────────────
pub const THEME_IRON_WOLF: StrataTheme = StrataTheme {
    name: "Iron Wolf",
    subtitle: "DEFAULT",
    bg:       Color32::from_rgb(0x07, 0x08, 0x09),
    panel:    Color32::from_rgb(0x0d, 0x0e, 0x12),
    card:     Color32::from_rgb(0x0f, 0x10, 0x14),
    elevated: Color32::from_rgb(0x0f, 0x10, 0x14),
    border:   Color32::from_rgb(0x18, 0x1c, 0x24),
    active:   Color32::from_rgb(0xd8, 0xe2, 0xec),
    text:     Color32::from_rgb(0xd8, 0xe2, 0xec),
    secondary:Color32::from_rgb(0x8a, 0x9a, 0xaa),
    muted:    Color32::from_rgb(0x3a, 0x48, 0x58),
    suspicious: Color32::from_rgb(0xb8, 0x78, 0x40),
    flagged:    Color32::from_rgb(0xa8, 0x40, 0x40),
    clean:      Color32::from_rgb(0x48, 0x78, 0x58),
};

// ── Theme 1: Midnight ───────────────────────────────────────────────────────
pub const THEME_MIDNIGHT: StrataTheme = StrataTheme {
    name: "Midnight",
    subtitle: "DEEP BLUE",
    bg: Color32::from_rgb(0x0f, 0x11, 0x17),
    panel: Color32::from_rgb(0x16, 0x1b, 0x27),
    card: Color32::from_rgb(0x1e, 0x25, 0x35),
    elevated: Color32::from_rgb(0x25, 0x2d, 0x3d),
    border: Color32::from_rgb(0x2a, 0x33, 0x47),
    active: Color32::from_rgb(0x7d, 0xd3, 0xfc),
    text: Color32::from_rgb(0xe2, 0xe8, 0xf0),
    secondary: Color32::from_rgb(0x88, 0x99, 0xaa),
    muted: Color32::from_rgb(0x4a, 0x55, 0x68),
    suspicious: SUSPICIOUS,
    flagged: FLAGGED,
    clean: CLEAN,
};

// ── Theme 2: Void ────────────────────────────────────────────────────────────
pub const THEME_VOID: StrataTheme = StrataTheme {
    name: "Void",
    subtitle: "DEEP PURPLE",
    bg: Color32::from_rgb(0x0a, 0x0a, 0x0f),
    panel: Color32::from_rgb(0x10, 0x10, 0x18),
    card: Color32::from_rgb(0x18, 0x18, 0x1f),
    elevated: Color32::from_rgb(0x22, 0x22, 0x2c),
    border: Color32::from_rgb(0x2a, 0x2a, 0x38),
    active: Color32::from_rgb(0xa7, 0x8b, 0xfa),
    text: Color32::from_rgb(0xed, 0xe9, 0xfe),
    secondary: Color32::from_rgb(0x7c, 0x6f, 0xaa),
    muted: Color32::from_rgb(0x3f, 0x3a, 0x58),
    suspicious: SUSPICIOUS,
    flagged: FLAGGED,
    clean: CLEAN,
};

// ── Theme 3: Tactical ────────────────────────────────────────────────────────
pub const THEME_TACTICAL: StrataTheme = StrataTheme {
    name: "Tactical",
    subtitle: "TACTICAL GREEN",
    bg: Color32::from_rgb(0x0f, 0x12, 0x14),
    panel: Color32::from_rgb(0x16, 0x1c, 0x20),
    card: Color32::from_rgb(0x1e, 0x25, 0x2a),
    elevated: Color32::from_rgb(0x25, 0x2e, 0x34),
    border: Color32::from_rgb(0x2a, 0x38, 0x40),
    active: Color32::from_rgb(0x4a, 0xde, 0x80),
    text: Color32::from_rgb(0xe2, 0xed, 0xe8),
    secondary: Color32::from_rgb(0x6a, 0x88, 0x78),
    muted: Color32::from_rgb(0x3a, 0x4e, 0x44),
    suspicious: SUSPICIOUS,
    flagged: FLAGGED,
    clean: CLEAN,
};

// ── Theme 4: Ash ─────────────────────────────────────────────────────────────
pub const THEME_ASH: StrataTheme = StrataTheme {
    name: "Ash",
    subtitle: "WARM LIGHT",
    bg: Color32::from_rgb(0xe4, 0xe0, 0xda),
    panel: Color32::from_rgb(0xd8, 0xd4, 0xce),
    card: Color32::from_rgb(0xcc, 0xc8, 0xc2),
    elevated: Color32::from_rgb(0xc4, 0xbf, 0xb8),
    border: Color32::from_rgb(0x90, 0x8a, 0x82),
    active: Color32::from_rgb(0x2a, 0x50, 0x68),
    text: Color32::from_rgb(0x1a, 0x18, 0x15),
    secondary: Color32::from_rgb(0x2a, 0x28, 0x26),
    muted: Color32::from_rgb(0x5a, 0x55, 0x50),
    suspicious: SUSPICIOUS,
    flagged: FLAGGED,
    clean: CLEAN,
};

// ── Theme 5: Graphite ────────────────────────────────────────────────────────
pub const THEME_GRAPHITE: StrataTheme = StrataTheme {
    name: "Graphite",
    subtitle: "NEUTRAL",
    bg: Color32::from_rgb(0x1a, 0x1a, 0x1a),
    panel: Color32::from_rgb(0x22, 0x22, 0x22),
    card: Color32::from_rgb(0x2e, 0x2e, 0x2e),
    elevated: Color32::from_rgb(0x33, 0x33, 0x33),
    border: Color32::from_rgb(0x40, 0x40, 0x40),
    active: Color32::from_rgb(0xaa, 0xaa, 0xaa),
    text: Color32::from_rgb(0xee, 0xee, 0xee),
    secondary: Color32::from_rgb(0x88, 0x88, 0x88),
    muted: Color32::from_rgb(0x55, 0x55, 0x55),
    suspicious: SUSPICIOUS,
    flagged: FLAGGED,
    clean: CLEAN,
};

// ── Theme 6: High Contrast (accessibility) ───────────────────────────────────
pub const THEME_HIGH_CONTRAST: StrataTheme = StrataTheme {
    name: "High Contrast",
    subtitle: "ACCESSIBILITY",
    bg: Color32::from_rgb(0x00, 0x00, 0x00),
    panel: Color32::from_rgb(0x00, 0x00, 0x00),
    card: Color32::from_rgb(0x1a, 0x1a, 0x1a),
    elevated: Color32::from_rgb(0x22, 0x22, 0x22),
    border: Color32::from_rgb(0xff, 0xff, 0xff),
    active: Color32::from_rgb(0xff, 0xff, 0x00),
    text: Color32::from_rgb(0xff, 0xff, 0xff),
    secondary: Color32::from_rgb(0xaa, 0xaa, 0xaa),
    muted: Color32::from_rgb(0x55, 0x55, 0x55),
    suspicious: Color32::from_rgb(0xff, 0xff, 0x00),
    flagged: Color32::from_rgb(0xff, 0x44, 0x44),
    clean: Color32::from_rgb(0x00, 0xff, 0x00),
};

/// All available themes, indexed 0..6.
pub const THEMES: &[StrataTheme] = &[
    THEME_IRON_WOLF,
    THEME_MIDNIGHT,
    THEME_VOID,
    THEME_TACTICAL,
    THEME_ASH,
    THEME_GRAPHITE,
    THEME_HIGH_CONTRAST,
];

/// Border radius constants from design language.
pub const RADIUS_LG: f32 = 10.0;
pub const RADIUS_MD: f32 = 6.0;
pub const RADIUS_PILL: f32 = 20.0;

/// Load saved theme index from settings, default 0 (Dark).
pub fn load_theme_index() -> usize {
    let path = theme_settings_path();
    match std::fs::read_to_string(&path) {
        Ok(content) => {
            // Simple JSON: { "theme": N }
            content
                .split("\"theme\"")
                .nth(1)
                .and_then(|s| {
                    s.trim_start_matches(|c: char| c == ':' || c.is_whitespace())
                        .chars()
                        .take_while(|c| c.is_ascii_digit())
                        .collect::<String>()
                        .parse::<usize>()
                        .ok()
                })
                .unwrap_or(0)
                .min(THEMES.len().saturating_sub(1))
        }
        Err(_) => 0,
    }
}

/// Save theme index to settings.
pub fn save_theme_index(index: usize) {
    let path = theme_settings_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let json = format!("{{ \"theme\": {} }}\n", index);
    let _ = std::fs::write(&path, json);
}

fn theme_settings_path() -> std::path::PathBuf {
    if let Some(appdata) = std::env::var_os("APPDATA") {
        std::path::PathBuf::from(appdata)
            .join("Strata")
            .join("theme.json")
    } else {
        std::path::PathBuf::from("theme.json")
    }
}

/// Apply a StrataTheme to egui visuals and style.
pub fn apply_theme(ctx: &egui::Context, theme: &StrataTheme) {
    // Use light visuals base for light themes (Ash), dark for all others
    let is_light = theme.bg.r() > 128;
    let mut visuals = if is_light {
        egui::Visuals::light()
    } else {
        egui::Visuals::dark()
    };

    visuals.panel_fill = theme.bg;
    visuals.warn_fg_color = theme.suspicious;
    visuals.error_fg_color = theme.flagged;
    visuals.hyperlink_color = theme.active;

    if is_light {
        // Light theme: dialogs brighter than bg, inputs white
        visuals.window_fill = Color32::from_rgb(0xe8, 0xe4, 0xde);
        visuals.extreme_bg_color = Color32::from_rgb(0xff, 0xff, 0xff);
        visuals.faint_bg_color = Color32::from_rgb(0xf0, 0xec, 0xe6);
        visuals.code_bg_color = Color32::from_rgb(0xf5, 0xf2, 0xed);
        visuals.selection.bg_fill = Color32::from_rgb(0xd0, 0xcc, 0xc6);
        visuals.selection.stroke = egui::Stroke::new(1.5, theme.active);
    } else {
        visuals.window_fill = theme.card;
        visuals.extreme_bg_color = theme.bg;
        visuals.faint_bg_color = theme.panel;
        visuals.code_bg_color = theme.panel;
        visuals.selection.bg_fill = theme.elevated;
        visuals.selection.stroke = egui::Stroke::new(1.0, theme.active);
    }

    let bdr = egui::Stroke::new(1.0, theme.border);
    let bdr2 = egui::Stroke::new(1.0, theme.border);

    if is_light {
        // Light: buttons and widgets with visible dark borders
        visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(0xdc, 0xd8, 0xd2);
        visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, theme.border);
        visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, theme.secondary);
        visuals.widgets.noninteractive.rounding = egui::Rounding::same(RADIUS_MD);

        visuals.widgets.inactive.bg_fill = Color32::from_rgb(0xdc, 0xd8, 0xd2);
        visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, theme.border);
        visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, theme.text);
        visuals.widgets.inactive.rounding = egui::Rounding::same(RADIUS_MD);

        visuals.widgets.hovered.bg_fill = Color32::from_rgb(0xd0, 0xcc, 0xc6);
        visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.5, theme.active);
        visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, theme.active);
        visuals.widgets.hovered.rounding = egui::Rounding::same(RADIUS_MD);

        visuals.widgets.active.bg_fill = Color32::from_rgb(0xc8, 0xc4, 0xbe);
        visuals.widgets.active.bg_stroke = egui::Stroke::new(1.5, theme.active);
        visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, theme.active);
        visuals.widgets.active.rounding = egui::Rounding::same(RADIUS_MD);

        visuals.widgets.open.bg_fill = Color32::from_rgb(0xdc, 0xd8, 0xd2);
        visuals.widgets.open.bg_stroke = egui::Stroke::new(1.0, theme.border);
        visuals.widgets.open.rounding = egui::Rounding::same(RADIUS_MD);
    } else {
        visuals.widgets.noninteractive.bg_fill = theme.card;
        visuals.widgets.noninteractive.bg_stroke = bdr;
        visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, theme.muted);
        visuals.widgets.noninteractive.rounding = egui::Rounding::same(RADIUS_MD);

        visuals.widgets.inactive.bg_fill = theme.card;
        visuals.widgets.inactive.bg_stroke = bdr;
        visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, theme.secondary);
        visuals.widgets.inactive.rounding = egui::Rounding::same(RADIUS_MD);

        visuals.widgets.hovered.bg_fill = theme.elevated;
        visuals.widgets.hovered.bg_stroke = bdr2;
        visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, theme.active);
        visuals.widgets.hovered.rounding = egui::Rounding::same(RADIUS_MD);

        visuals.widgets.active.bg_fill = theme.elevated;
        visuals.widgets.active.bg_stroke = bdr2;
        visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, theme.active);
        visuals.widgets.active.rounding = egui::Rounding::same(RADIUS_MD);

        visuals.widgets.open.bg_fill = theme.card;
        visuals.widgets.open.bg_stroke = bdr2;
        visuals.widgets.open.rounding = egui::Rounding::same(RADIUS_MD);
    }

    visuals.window_stroke = bdr2;
    visuals.popup_shadow = egui::epaint::Shadow::NONE;
    visuals.window_shadow = egui::epaint::Shadow::NONE;
    visuals.resize_corner_size = 0.0;

    // Hide panel separator/resize lines by making them match the bg
    visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, theme.bg);

    visuals.override_text_color = Some(theme.text);

    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(6.0, 4.0);
    style.spacing.button_padding = egui::vec2(10.0, 4.0);
    style.spacing.window_margin = egui::Margin::same(0.0);
    style.spacing.menu_margin = egui::Margin::same(4.0);
    style.interaction.selectable_labels = false;
    ctx.set_style(style);
}
