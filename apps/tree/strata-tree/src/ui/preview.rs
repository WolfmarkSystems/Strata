// ui/preview.rs — Right-pane file content preview (Gap 2).
// Four modes: Metadata | Text | Hex | Image
// Evidence access is strictly read-only.

use crate::state::AppState;

const PREVIEW_HEX_BYTES: usize = 4096;
const PREVIEW_TEXT_BYTES: usize = 8192;
const IMAGE_EXTS: &[&str] = &["jpg", "jpeg", "png", "gif", "bmp", "webp", "tiff", "tif"];

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading("Preview");
    ui.separator();

    let file = match &state.selected_file {
        Some(id) => state.file_index.iter().find(|f| &f.id == id).cloned(),
        None => None,
    };

    let Some(f) = file else {
        ui.label("Select a file to preview.");
        return;
    };

    if f.is_dir {
        ui.label(egui::RichText::new(format!("📁 {}", f.name)).strong());
        ui.label(format!("Directory: {}", f.path));
        return;
    }

    // ── Tab bar ───────────────────────────────────────────────────────────────
    let ext_lc = f.extension.as_deref().unwrap_or("").to_lowercase();
    let is_image = IMAGE_EXTS.contains(&ext_lc.as_str());

    let tab_count = if is_image { 4 } else { 3 };
    // Clamp tab to valid range.
    if state.ui_state.preview_tab >= tab_count {
        state.ui_state.preview_tab = 0;
    }

    ui.horizontal(|ui| {
        for (i, label) in ["Metadata", "Text", "Hex"].iter().enumerate() {
            if ui.selectable_label(state.ui_state.preview_tab == i, *label).clicked() {
                state.ui_state.preview_tab = i;
            }
        }
        if is_image {
            if ui.selectable_label(state.ui_state.preview_tab == 3, "Image").clicked() {
                state.ui_state.preview_tab = 3;
            }
        }
    });
    ui.separator();

    match state.ui_state.preview_tab {
        0 => render_metadata(ui, &f),
        1 => render_text(ui, &f),
        2 => render_hex(ui, &f),
        3 if is_image => render_image(ui, &f),
        _ => {}
    }
}

// ─── Metadata ─────────────────────────────────────────────────────────────────

fn render_metadata(ui: &mut egui::Ui, f: &crate::state::IndexedFile) {
    egui::Grid::new("meta_grid")
        .num_columns(2)
        .spacing([6.0, 4.0])
        .striped(true)
        .show(ui, |ui| {
            row(ui, "Name",       &f.name);
            row(ui, "Path",       &f.path);
            row(ui, "Extension",  f.extension.as_deref().unwrap_or("—"));
            row(ui, "Size",       &format_size(f.size));
            row(ui, "Category",   f.category.as_deref().unwrap_or("—"));
            row(ui, "Created",    f.created_utc.as_deref().unwrap_or("—"));
            row(ui, "Modified",   f.modified_utc.as_deref().unwrap_or("—"));
            row(ui, "Accessed",   f.accessed_utc.as_deref().unwrap_or("—"));
            row(ui, "MFT Changed",f.mft_changed_utc.as_deref().unwrap_or("—"));
            row(ui, "MFT Record", &f.mft_record.map(|v| v.to_string()).unwrap_or_else(|| "—".to_string()));
            row(ui, "Inode",      &f.inode.map(|v| v.to_string()).unwrap_or_else(|| "—".to_string()));
            row(ui, "Filesystem", f.filesystem.as_deref().unwrap_or("—"));
            row(ui, "Permissions",f.permissions.as_deref().unwrap_or("—"));
            ui.label("MD5");
            ui.label(f.md5.as_deref().unwrap_or("not computed")).on_hover_text("Run Hash Files to compute");
            ui.end_row();
            ui.label("SHA-256");
            ui.label(f.sha256.as_deref().unwrap_or("not computed")).on_hover_text("Run Hash Files to compute");
            ui.end_row();

            // Flags.
            ui.label("Deleted");
            if f.is_deleted {
                ui.colored_label(egui::Color32::from_rgb(200, 60, 60), "YES (deleted)");
            } else {
                ui.label("No");
            }
            ui.end_row();

            ui.label("Carved");
            if f.is_carved {
                ui.colored_label(egui::Color32::from_rgb(200, 140, 30), "YES (carved)");
            } else {
                ui.label("No");
            }
            ui.end_row();

            // Hash set match.
            ui.label("Hash Set Match");
            match f.hash_flagged.as_deref() {
                Some("KnownBad") => {
                    ui.colored_label(egui::Color32::from_rgb(200, 30, 30),
                        egui::RichText::new("⚠ KNOWN BAD").strong());
                }
                Some("KnownGood") => {
                    ui.colored_label(egui::Color32::from_rgb(60, 160, 60), "Known Good");
                }
                Some("Notable") => {
                    ui.colored_label(egui::Color32::from_rgb(200, 140, 30), "Notable");
                }
                _ => { ui.label("None"); }
            }
            ui.end_row();
        });
}

fn row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(label);
    ui.label(value);
    ui.end_row();
}

fn format_size(size: Option<i64>) -> String {
    match size {
        None => "—".to_string(),
        Some(b) => {
            let b = b as u64;
            const GB: u64 = 1 << 30;
            const MB: u64 = 1 << 20;
            const KB: u64 = 1 << 10;
            if b >= GB      { format!("{:.1} GB ({} bytes)", b as f64 / GB as f64, b) }
            else if b >= MB { format!("{:.1} MB ({} bytes)", b as f64 / MB as f64, b) }
            else if b >= KB { format!("{:.0} KB ({} bytes)", b as f64 / KB as f64, b) }
            else            { format!("{} bytes", b) }
        }
    }
}

// ─── Text preview ────────────────────────────────────────────────────────────

fn render_text(ui: &mut egui::Ui, f: &crate::state::IndexedFile) {
    let path = std::path::Path::new(&f.path);
    let raw = match std::fs::read(path) {
        Err(e) => {
            ui.colored_label(egui::Color32::from_rgb(200, 60, 60),
                format!("Cannot read file: {}", e));
            return;
        }
        Ok(data) => {
            if data.len() > PREVIEW_TEXT_BYTES * 2 {
                data[..PREVIEW_TEXT_BYTES].to_vec()
            } else {
                data
            }
        }
    };

    let truncated = raw.len() < f.size.unwrap_or(0) as usize;

    // Try UTF-8 first, then UTF-16 LE.
    let (text, encoding) = if let Ok(s) = std::str::from_utf8(&raw) {
        (s.to_string(), "UTF-8")
    } else if raw.len() >= 2 && raw[0] == 0xFF && raw[1] == 0xFE {
        // UTF-16 LE BOM
        let pairs: Vec<u16> = raw[2..].chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        match String::from_utf16(&pairs) {
            Ok(s) => (s, "UTF-16 LE"),
            Err(_) => (format!("Binary data — {} bytes", raw.len()), "Binary"),
        }
    } else {
        // Check if it's mostly printable ASCII.
        let printable = raw.iter().filter(|&&b| b >= 0x20 || b == b'\n' || b == b'\r' || b == b'\t').count();
        if printable as f64 / raw.len() as f64 > 0.85 {
            (String::from_utf8_lossy(&raw).to_string(), "UTF-8 (lossy)")
        } else {
            (format!("Binary data — {} bytes shown", raw.len()), "Binary (not text)")
        }
    };

    ui.horizontal(|ui| {
        ui.label("Encoding:");
        ui.strong(encoding);
        if truncated {
            ui.separator();
            ui.label(egui::RichText::new(
                format!("Showing first {} — file too large for full preview", format_size(Some(PREVIEW_TEXT_BYTES as i64)))
            ).small().color(egui::Color32::from_rgb(150, 120, 60)));
        }
    });
    ui.separator();

    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.add(
            egui::TextEdit::multiline(&mut text.as_str())
                .font(egui::TextStyle::Monospace)
                .desired_width(f32::INFINITY)
                .interactive(false),
        );
    });
}

// ─── Hex preview ─────────────────────────────────────────────────────────────

fn render_hex(ui: &mut egui::Ui, f: &crate::state::IndexedFile) {
    let path = std::path::Path::new(&f.path);
    let data = match read_first_n(path, PREVIEW_HEX_BYTES) {
        Err(e) => {
            ui.colored_label(egui::Color32::from_rgb(200, 60, 60),
                format!("Cannot read file: {}", e));
            return;
        }
        Ok(d) => d,
    };

    let file_size = f.size.unwrap_or(0) as usize;
    if file_size > PREVIEW_HEX_BYTES {
        ui.label(egui::RichText::new(
            format!("Showing first 4 KB of {} — full hex view available in bottom panel",
                format_size(f.size))
        ).small().color(egui::Color32::from_rgb(150, 120, 60)));
    }
    ui.separator();

    let bytes_per_row: usize = 16;
    egui::ScrollArea::vertical().show(ui, |ui| {
        egui::Grid::new("hex_preview")
            .num_columns(3)
            .spacing([8.0, 2.0])
            .show(ui, |ui| {
                for (row_i, chunk) in data.chunks(bytes_per_row).enumerate() {
                    let offset = row_i * bytes_per_row;
                    // Offset column.
                    ui.label(
                        egui::RichText::new(format!("{:08X}", offset))
                            .monospace()
                            .color(egui::Color32::from_rgb(120, 120, 180)),
                    );
                    // Hex column.
                    let hex: String = chunk.iter().enumerate().map(|(i, b)| {
                        if i == 8 { format!(" {:02X}", b) } else { format!("{:02X} ", b) }
                    }).collect();
                    ui.label(egui::RichText::new(hex.trim_end()).monospace());
                    // ASCII column.
                    let ascii: String = chunk.iter().map(|&b| {
                        if b >= 0x20 && b < 0x7F { b as char } else { '.' }
                    }).collect();
                    ui.label(egui::RichText::new(ascii).monospace());
                    ui.end_row();
                }
            });
    });
}

// ─── Image preview ────────────────────────────────────────────────────────────

fn render_image(ui: &mut egui::Ui, f: &crate::state::IndexedFile) {
    const MAX_IMAGE_BYTES: u64 = 20 * 1024 * 1024; // 20 MB

    let path = std::path::Path::new(&f.path);
    match std::fs::metadata(path) {
        Ok(meta) if meta.len() > MAX_IMAGE_BYTES => {
            ui.colored_label(
                egui::Color32::from_rgb(200, 160, 60),
                format!(
                    "File too large for image preview ({:.1} MB). Max: 20 MB.",
                    meta.len() as f64 / (1024.0 * 1024.0)
                ),
            );
            return;
        }
        Err(e) => {
            ui.colored_label(
                egui::Color32::from_rgb(200, 60, 60),
                format!("Cannot stat file: {}", e),
            );
            return;
        }
        _ => {}
    }
    let data = match std::fs::read(path) {
        Err(e) => {
            ui.colored_label(egui::Color32::from_rgb(200, 60, 60),
                format!("Cannot read image: {}", e));
            return;
        }
        Ok(d) => d,
    };

    match image::load_from_memory(&data) {
        Err(e) => {
            ui.colored_label(egui::Color32::from_rgb(200, 60, 60),
                format!("Cannot decode image: {}", e));
        }
        Ok(img) => {
            let rgba = img.to_rgba8();
            let (w, h) = rgba.dimensions();
            ui.label(format!("{}×{} pixels", w, h));
            ui.separator();

            let color_img = egui::ColorImage::from_rgba_unmultiplied(
                [w as usize, h as usize],
                &rgba,
            );
            // Load as a texture with a stable id based on path.
            let tex = ui.ctx().load_texture(
                &f.path,
                color_img,
                egui::TextureOptions::LINEAR,
            );

            let available = ui.available_size();
            let scale = (available.x / w as f32).min(available.y / h as f32).min(1.0);
            let display_size = egui::vec2(w as f32 * scale, h as f32 * scale);

            egui::ScrollArea::both().show(ui, |ui| {
                ui.image((tex.id(), display_size));
            });
        }
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn read_first_n(path: &std::path::Path, n: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; n];
    let read = f.read(&mut buf)?;
    buf.truncate(read);
    Ok(buf)
}
