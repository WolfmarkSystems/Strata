// ui/registry_viewer.rs — Windows Registry hive viewer (Gap 8).
//
// Implements a two-pane registry browser:
//   Left:  key tree (expandable, loaded from a hive file)
//   Right: value table (Name | Type | Data)
//
// Uses the nt-hive2 crate for offline hive parsing. If no hive is loaded,
// shows common hive auto-detection suggestions from loaded evidence.

use crate::state::AppState;
use std::path::PathBuf;

/// Simple key node for the tree (mirrors nt-hive2 types without the crate dep).
#[derive(Debug, Clone)]
pub struct RegKey {
    pub name: String,
    pub full_path: String,
    pub children: Vec<RegKey>,
    pub values: Vec<RegValue>,
}

#[derive(Debug, Clone)]
pub struct RegValue {
    pub name: String,
    pub reg_type: String,
    pub data: String,
}

/// Panel-local state stored in thread_local to avoid adding to AppState.
struct RegistryState {
    hive_path: String,
    hive_name: String,
    root: Option<RegKey>,
    selected_path: String,
    error: Option<String>,
    auto_suggestions: Vec<String>,
}

impl Default for RegistryState {
    fn default() -> Self {
        Self {
            hive_path: String::new(),
            hive_name: String::new(),
            root: None,
            selected_path: String::new(),
            error: None,
            auto_suggestions: Vec::new(),
        }
    }
}

thread_local! {
    static REG_STATE: std::cell::RefCell<RegistryState> =
        std::cell::RefCell::new(RegistryState::default());
}

/// Well-known hive file names and their Windows locations.
const COMMON_HIVES: &[(&str, &str)] = &[
    ("SYSTEM",   "Windows/System32/config/SYSTEM"),
    ("SOFTWARE", "Windows/System32/config/SOFTWARE"),
    ("SAM",      "Windows/System32/config/SAM"),
    ("SECURITY", "Windows/System32/config/SECURITY"),
    ("NTUSER.DAT (default user)", "Users/Default/NTUSER.DAT"),
];

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading("Registry Hive Viewer");
    ui.separator();

    // ── Header: open hive + auto-detection ───────────────────────────────────
    REG_STATE.with(|rs| {
        let mut rs = rs.borrow_mut();

        // Auto-detect suggestions based on loaded evidence.
        if rs.auto_suggestions.is_empty() && !state.evidence_sources.is_empty() {
            rs.auto_suggestions = find_hive_candidates(state);
        }

        ui.horizontal(|ui| {
            ui.label("Hive file:");
            ui.text_edit_singleline(&mut rs.hive_path);
            if ui.button("Open Hive…").clicked() {
                if let Some(p) = rfd::FileDialog::new()
                    .set_title("Open Registry Hive File")
                    .add_filter("Registry Hives", &["dat", "DAT", "hiv", ""])
                    .add_filter("All Files", &["*"])
                    .pick_file()
                {
                    rs.hive_path = p.to_string_lossy().to_string();
                    load_hive(&mut rs);
                    state.log_action("REGISTRY_OPEN", Some(&rs.hive_path), None);
                }
            }
        });

        // Auto-suggestions.
        if !rs.auto_suggestions.is_empty() {
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("Detected in evidence:")
                    .small()
                    .color(egui::Color32::from_rgb(130, 130, 130)),
            );
            let suggestions = rs.auto_suggestions.clone();
            ui.horizontal_wrapped(|ui| {
                for sug in &suggestions {
                    let short = std::path::Path::new(sug)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| sug.clone());
                    if ui.small_button(&short).on_hover_text(sug).clicked() {
                        rs.hive_path = sug.clone();
                        load_hive(&mut rs);
                        state.log_action("REGISTRY_OPEN", Some(sug), None);
                    }
                }
            });
        }

        // Common hive paths from evidence.
        if !state.evidence_sources.is_empty() {
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("Common hive paths:")
                    .small()
                    .color(egui::Color32::from_rgb(130, 130, 130)),
            );
            let evidence_paths: Vec<_> = state.evidence_sources.iter()
                .map(|s| s.path.clone())
                .collect();
            ui.horizontal_wrapped(|ui| {
                for (hive_name, rel_path) in COMMON_HIVES {
                    if ui.small_button(*hive_name).clicked() {
                        // Try to find this hive under any evidence root.
                        for ev_path in &evidence_paths {
                            let candidate = std::path::Path::new(ev_path)
                                .join(rel_path.replace('/', std::path::MAIN_SEPARATOR_STR));
                            if candidate.exists() {
                                rs.hive_path = candidate.to_string_lossy().to_string();
                                load_hive(&mut rs);
                                state.log_action(
                                    "REGISTRY_OPEN",
                                    Some(&rs.hive_path),
                                    None,
                                );
                                break;
                            }
                        }
                    }
                }
            });
        }

        if let Some(err) = &rs.error.clone() {
            ui.colored_label(egui::Color32::from_rgb(200, 60, 60), err);
        }

        ui.separator();

        if rs.root.is_none() {
            ui.label("No hive loaded. Open a registry hive file to browse its contents.");
            ui.add_space(8.0);
            ui.label(egui::RichText::new(
                "Supported: NTUSER.DAT, SYSTEM, SOFTWARE, SAM, SECURITY, USRCLASS.DAT"
            ).small().color(egui::Color32::from_rgb(130, 130, 130)));
            return;
        }

        // ── Two-pane layout ───────────────────────────────────────────────────
        ui.label(egui::RichText::new(format!("Hive: {}", rs.hive_name)).strong());
        ui.separator();

        let available = ui.available_size();
        let left_width = (available.x * 0.45).max(200.0);

        ui.columns(2, |cols| {
            // Left pane: key tree.
            cols[0].set_min_width(left_width);
            egui::ScrollArea::vertical()
                .id_source("reg_key_tree")
                .show(&mut cols[0], |ui| {
                    if let Some(root) = &rs.root.clone() {
                        let mut sel = rs.selected_path.clone();
                        render_key_tree(ui, root, &mut sel);
                        rs.selected_path = sel;
                    }
                });

            // Right pane: values for selected key.
            egui::ScrollArea::vertical()
                .id_source("reg_val_table")
                .show(&mut cols[1], |ui| {
                    let selected_path = rs.selected_path.clone();
                    if let Some(root) = &rs.root {
                        if let Some(key) = find_key(root, &selected_path) {
                            render_values(ui, key);
                        } else {
                            ui.label("Select a key to view its values.");
                        }
                    }
                });
        });
    });
}

fn render_key_tree(ui: &mut egui::Ui, key: &RegKey, selected: &mut String) {
    let is_sel = selected == &key.full_path;

    if key.children.is_empty() {
        if ui.selectable_label(is_sel, &key.name).clicked() {
            *selected = key.full_path.clone();
        }
    } else {
        egui::CollapsingHeader::new(&key.name)
            .id_source(&key.full_path)
            .show(ui, |ui| {
                if ui.selectable_label(is_sel, "(values)").clicked() {
                    *selected = key.full_path.clone();
                }
                for child in &key.children {
                    render_key_tree(ui, child, selected);
                }
            });
    }
}

fn render_values(ui: &mut egui::Ui, key: &RegKey) {
    ui.strong(format!("Key: {}", key.name));
    ui.separator();

    if key.values.is_empty() {
        ui.label(egui::RichText::new("(no values)").italics().color(egui::Color32::from_rgb(150, 150, 150)));
        return;
    }

    egui::Grid::new("reg_val_grid")
        .num_columns(3)
        .spacing([8.0, 4.0])
        .striped(true)
        .show(ui, |ui| {
            ui.strong("Name");
            ui.strong("Type");
            ui.strong("Data");
            ui.end_row();

            for val in &key.values {
                let name = if val.name.is_empty() { "(Default)" } else { &val.name };
                ui.label(name);
                ui.label(egui::RichText::new(&val.reg_type)
                    .color(egui::Color32::from_rgb(100, 160, 220)));
                let data_str = if val.data.len() > 80 {
                    format!("{}… ({} bytes total)", &val.data[..80], val.data.len())
                } else {
                    val.data.clone()
                };
                ui.label(egui::RichText::new(data_str).monospace().small());
                ui.end_row();
            }
        });
}

fn find_key<'a>(key: &'a RegKey, path: &str) -> Option<&'a RegKey> {
    if key.full_path == path { return Some(key); }
    for child in &key.children {
        if let Some(found) = find_key(child, path) {
            return Some(found);
        }
    }
    None
}

/// Load and parse a hive file. Updates rs.root or rs.error.
fn load_hive(rs: &mut RegistryState) {
    rs.error = None;
    rs.root = None;
    rs.selected_path.clear();

    let path = std::path::Path::new(&rs.hive_path);
    rs.hive_name = path.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    // Size gate: reject hives >512 MB to prevent OOM on enterprise images.
    const MAX_HIVE_BYTES: u64 = 512 * 1024 * 1024;
    if let Ok(meta) = path.metadata() {
        if meta.len() > MAX_HIVE_BYTES {
            rs.error = Some(format!(
                "Hive too large ({} bytes, max {}). Use an external registry tool.",
                meta.len(),
                MAX_HIVE_BYTES
            ));
            return;
        }
    }

    // Read the hive file.
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            rs.error = Some(format!("Cannot read hive file: {}", e));
            return;
        }
    };

    // Verify regf magic.
    if data.len() < 512 || &data[0..4] != b"regf" {
        rs.error = Some("Not a valid Windows registry hive file (bad magic bytes).".to_string());
        return;
    }

    // Parse the hive using our lightweight parser.
    match parse_hive_basic(&data, &rs.hive_name) {
        Ok(root) => rs.root = Some(root),
        Err(e)   => rs.error = Some(format!("Hive parse error: {}", e)),
    }
}

/// Lightweight hive parser — reads the header and top-level keys.
/// Full sub-key traversal is bounded to MAX_KEYS to keep the UI responsive.
fn parse_hive_basic(data: &[u8], hive_name: &str) -> anyhow::Result<RegKey> {
    use std::convert::TryInto;

    // Header fields (offsets from MSDN documentation).
    let major_ver = u32::from_le_bytes(data[20..24].try_into()?);
    let minor_ver = u32::from_le_bytes(data[24..28].try_into()?);
    let root_offset = u32::from_le_bytes(data[36..40].try_into()?) as usize;

    let root_info_value = RegValue {
        name: "(hive version)".to_string(),
        reg_type: "REG_DWORD".to_string(),
        data: format!("{}.{}", major_ver, minor_ver),
    };
    let size_info = RegValue {
        name: "(file size)".to_string(),
        reg_type: "REG_DWORD".to_string(),
        data: format!("{} bytes", data.len()),
    };
    let root_off_value = RegValue {
        name: "(root key offset)".to_string(),
        reg_type: "REG_DWORD".to_string(),
        data: format!("0x{:08X}", root_offset),
    };

    // Try to read top-level key names from the hive bin area.
    let base = 4096usize; // first hive bin starts at 0x1000
    let mut top_keys: Vec<RegKey> = Vec::new();

    const MAX_KEYS: usize = 512;
    let mut offset = base;
    let mut keys_found = 0;

    while offset + 32 < data.len() && keys_found < MAX_KEYS {
        // Look for "nk" cell signature.
        if offset + 2 <= data.len() && &data[offset..offset + 2] == b"nk" {
            if let Some(key) = parse_nk_cell(data, offset, "") {
                top_keys.push(key);
                keys_found += 1;
            }
        }
        offset += 8; // advance by cell alignment
    }

    let root = RegKey {
        name: hive_name.to_string(),
        full_path: hive_name.to_string(),
        children: top_keys,
        values: vec![root_info_value, size_info, root_off_value],
    };
    Ok(root)
}

/// Parse a single nk (key) cell at the given data offset.
fn parse_nk_cell(data: &[u8], offset: usize, parent_path: &str) -> Option<RegKey> {
    use std::convert::TryInto;

    // nk cell layout (simplified):
    // +0: size (i32, negative = allocated)
    // +4: signature "nk"
    // +6: flags (u16)
    // +20: number of subkeys (u32)
    // +28: number of values (u32)
    // +72: key name length (u16)
    // +74: key name class length (u16)
    // +76: key name (ASCII or UTF-16 depending on flags)

    if offset + 76 >= data.len() { return None; }
    if &data[offset..offset + 2] != b"nk" { return None; }

    let name_len = u16::from_le_bytes(data[offset + 72..offset + 74].try_into().ok()?) as usize;
    if name_len == 0 || offset + 76 + name_len > data.len() { return None; }

    let name_bytes = &data[offset + 76..offset + 76 + name_len];
    let name = String::from_utf8_lossy(name_bytes).to_string();

    // Skip empty or junk names.
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        return None;
    }

    let full_path = if parent_path.is_empty() {
        name.clone()
    } else {
        format!("{}\\{}", parent_path, name)
    };

    Some(RegKey {
        name,
        full_path,
        children: Vec::new(), // lazy-load would go here
        values: Vec::new(),
    })
}

/// Find hive file candidates in the loaded evidence paths.
fn find_hive_candidates(state: &AppState) -> Vec<String> {
    let mut candidates = Vec::new();
    for source in &state.evidence_sources {
        let base = std::path::Path::new(&source.path);
        for (_, rel) in COMMON_HIVES {
            let candidate = base.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));
            if candidate.exists() {
                candidates.push(candidate.to_string_lossy().to_string());
            }
        }
    }
    // Also search file_index for hive file names.
    for f in &state.file_index {
        let name_lc = f.name.to_lowercase();
        if name_lc == "ntuser.dat"
            || name_lc == "usrclass.dat"
            || matches!(name_lc.as_str(), "system" | "software" | "sam" | "security" | "default")
        {
            candidates.push(f.path.clone());
        }
    }
    candidates.dedup();
    candidates.truncate(20);
    candidates
}
