// ui/hex_editor.rs — Read-only forensic hex editor with data interpreter.
// Evidence integrity preserved — NO write operations ever.

use crate::state::{AppState, HexViewState};

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("HEX EDITOR").strong());
        ui.separator();
        ui.colored_label(
            egui::Color32::from_rgb(200, 60, 60),
            "READ ONLY — Evidence integrity preserved",
        );
        if state.hex_view.total_size > 0 {
            ui.separator();
            let pct = if state.hex_view.total_size > 0 {
                state.hex_view.offset as f64 / state.hex_view.total_size as f64 * 100.0
            } else {
                0.0
            };
            ui.label(format!(
                "Offset {} of {} ({:.1}%)",
                state.hex_view.offset, state.hex_view.total_size, pct
            ));
        }
    });

    if state.hex_view.data.is_empty() {
        ui.label("Select a file to view its hex content.");
        return;
    }

    let hex = &state.hex_view;
    let bytes_per_row = hex.bytes_per_row.max(1);

    egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
        egui::Grid::new("hex_grid").striped(true).show(ui, |ui| {
            let chunks = hex.data.chunks(bytes_per_row);
            for (row_idx, chunk) in chunks.enumerate() {
                let row_offset = hex.offset + (row_idx * bytes_per_row) as u64;

                // Offset column
                ui.label(
                    egui::RichText::new(format!("{:08X}:", row_offset))
                        .monospace()
                        .color(egui::Color32::from_rgb(100, 150, 200)),
                );

                // Hex bytes
                let mut hex_str = String::new();
                for (i, b) in chunk.iter().enumerate() {
                    if i == 8 { hex_str.push(' '); }
                    hex_str.push_str(&format!("{:02X} ", b));
                }
                ui.label(egui::RichText::new(hex_str).monospace());

                // ASCII column
                let ascii: String = chunk
                    .iter()
                    .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
                    .collect();
                ui.label(egui::RichText::new(ascii).monospace());

                ui.end_row();
            }
        });
    });

    // Data interpreter panel.
    ui.separator();
    render_data_interpreter(ui, &state.hex_view);
}

fn render_data_interpreter(ui: &mut egui::Ui, hex: &HexViewState) {
    let sel = hex.selected_offset as usize;
    let data = &hex.data;

    let read_u8 = |off: usize| data.get(off).copied();
    let read_bytes = |off: usize, len: usize| -> Option<Vec<u8>> {
        if off + len <= data.len() { Some(data[off..off+len].to_vec()) } else { None }
    };

    ui.horizontal_wrapped(|ui| {
        if let Some(b) = read_u8(sel) {
            ui.label(format!("UInt8: {}", b));
            ui.label(format!("Int8: {}", b as i8));
        }
        if let Some(bs) = read_bytes(sel, 2) {
            let le = u16::from_le_bytes([bs[0], bs[1]]);
            let be = u16::from_be_bytes([bs[0], bs[1]]);
            ui.label(format!("UInt16 LE: {}  BE: {}", le, be));
        }
        if let Some(bs) = read_bytes(sel, 4) {
            let le = u32::from_le_bytes([bs[0], bs[1], bs[2], bs[3]]);
            let be = u32::from_be_bytes([bs[0], bs[1], bs[2], bs[3]]);
            ui.label(format!("UInt32 LE: {}  BE: {}", le, be));
        }
        if let Some(bs) = read_bytes(sel, 8) {
            if let Ok(arr) = <[u8; 8]>::try_from(bs.as_slice()) {
                let le = u64::from_le_bytes(arr);
                let be = u64::from_be_bytes(arr);
                ui.label(format!("UInt64 LE: {}  BE: {}", le, be));

                // Windows FILETIME (100ns intervals since 1601-01-01)
                let filetime = le;
                if filetime > 0 {
                    let unix_secs = (filetime / 10_000_000).saturating_sub(11_644_473_600);
                    ui.label(format!("FILETIME (UTC approx): {}s epoch", unix_secs));
                }
            }
        }
        if let Some(bs) = read_bytes(sel, 4) {
            let bits = u32::from_le_bytes([bs[0], bs[1], bs[2], bs[3]]);
            let f = f32::from_bits(bits);
            if f.is_finite() {
                ui.label(format!("Float32 LE: {:.6}", f));
            }
        }
    });
}
