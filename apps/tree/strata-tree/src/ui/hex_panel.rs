//! Bottom pane — Hex editor (read-only, virtualized paging).

use crate::state::AppState;

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    let t = *state.theme();
    // ── Header ────────────────────────────────────────────────────────────────
    egui::Frame::none()
        .inner_margin(egui::Margin {
            left: 8.0,
            right: 8.0,
            top: 4.0,
            bottom: 2.0,
        })
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("HEX EDITOR")
                        .color(t.muted)
                        .size(8.5)
                        .strong(),
                );
                if !state.hex.file_name.is_empty() {
                    ui.separator();
                    let abs = state.hex.absolute_cursor_offset();
                    ui.label(
                        egui::RichText::new(format!("OFFSET: 0x{:08X}", abs))
                            .color(t.active)
                            .size(8.5)
                            .monospace(),
                    );
                    if state.hex.file_size > 0 {
                        ui.separator();
                        ui.label(
                            egui::RichText::new(format!(
                                "WINDOW: 0x{:08X} ({} / {} bytes)",
                                state.hex.window_offset,
                                state
                                    .hex
                                    .window_offset
                                    .saturating_add(state.hex.data.len() as u64),
                                state.hex.file_size
                            ))
                            .color(t.muted)
                            .size(8.0)
                            .monospace(),
                        );
                    }
                    ui.separator();
                    ui.label(
                        egui::RichText::new(&state.hex.file_name)
                            .color(t.secondary)
                            .size(8.5),
                    );
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        egui::RichText::new("READ-ONLY")
                            .color(t.flagged)
                            .size(8.0)
                            .strong(),
                    );
                });
            });
        });
    ui.separator();

    if state.hex.data.is_empty() {
        egui::Frame::none()
            .inner_margin(egui::Margin { left: 10.0, right: 8.0, top: 4.0, bottom: 4.0 })
            .show(ui, |ui| {
                if state.hex.file_name.is_empty() {
                    ui.label(egui::RichText::new("Select a file to view hex content.").color(t.muted).size(9.5));
                } else if state.hex_window_loading {
                    ui.label(egui::RichText::new("Loading hex page(s)...").color(t.suspicious).size(9.0));
                } else if state.hex.load_error {
                    ui.label(egui::RichText::new(format!(
                        "Cannot read bytes from '{}'. File is inside a forensic container — hex view requires VFS byte-level access.",
                        state.hex.file_name
                    )).color(t.suspicious).size(9.0));
                } else {
                    ui.label(egui::RichText::new("File is empty (0 bytes).").color(t.muted).size(9.5));
                }
            });
        return;
    }

    // ── Search and offset navigation ────────────────────────────────────────
    egui::Frame::none()
        .inner_margin(egui::Margin {
            left: 8.0,
            right: 8.0,
            top: 2.0,
            bottom: 2.0,
        })
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Search").color(t.muted).size(8.5));
                let resp = ui.text_edit_singleline(&mut state.hex.search_query);
                if resp.changed() {
                    state.start_hex_search();
                }

                let hit_count = state.hex_search_hits_abs.len();
                if ui.small_button("← Prev").clicked() && hit_count > 0 {
                    if state.hex.search_hit_index == 0 {
                        state.hex.search_hit_index = hit_count - 1;
                    } else {
                        state.hex.search_hit_index -= 1;
                    }
                    if let Some(abs) = state
                        .hex_search_hits_abs
                        .get(state.hex.search_hit_index)
                        .copied()
                    {
                        state.seek_hex_offset(abs);
                        sync_visible_hits(state);
                    }
                }
                if ui.small_button("Next →").clicked() && hit_count > 0 {
                    state.hex.search_hit_index = (state.hex.search_hit_index + 1) % hit_count;
                    if let Some(abs) = state
                        .hex_search_hits_abs
                        .get(state.hex.search_hit_index)
                        .copied()
                    {
                        state.seek_hex_offset(abs);
                        sync_visible_hits(state);
                    }
                }
                ui.label(
                    egui::RichText::new(format!(
                        "{} of {}",
                        if hit_count == 0 {
                            0
                        } else {
                            state.hex.search_hit_index + 1
                        },
                        hit_count
                    ))
                    .color(t.secondary)
                    .size(8.0),
                );
                if state.hex_search_active {
                    let (scanned, total) = state.hex_search_progress;
                    if total > 0 {
                        let pct = (scanned as f64 / total as f64) * 100.0;
                        ui.label(
                            egui::RichText::new(format!(
                                "Searching... {:.0}% ({} / {})",
                                pct,
                                fmt_bytes(scanned),
                                fmt_bytes(total)
                            ))
                            .color(t.suspicious)
                            .size(8.0),
                        );
                    } else {
                        ui.label(
                            egui::RichText::new("Searching...")
                                .color(t.suspicious)
                                .size(8.0),
                        );
                    }
                } else if let Some(err) = &state.hex_search_error {
                    ui.label(egui::RichText::new(err).color(t.flagged).size(8.0));
                }

                ui.separator();
                ui.label(egui::RichText::new("Go to").color(t.muted).size(8.5));
                ui.text_edit_singleline(&mut state.hex.goto_offset_input);
                if ui.small_button("Go").clicked() {
                    if let Some(off) = parse_offset_input(&state.hex.goto_offset_input) {
                        if off < state.hex.file_size || state.hex.file_size == 0 {
                            state.seek_hex_offset(off);
                            sync_visible_hits(state);
                        }
                    }
                }
                if ui.small_button("Page -").clicked() && state.hex.file_size > 0 {
                    let new_off = state.hex.window_offset.saturating_sub(256 * 1024);
                    if let Some(fid) = state.hex.file_id.clone() {
                        state.load_hex_window(&fid, new_off);
                        sync_visible_hits(state);
                    }
                }
                if ui.small_button("Page +").clicked() && state.hex.file_size > 0 {
                    let new_off = state.hex.window_offset.saturating_add(256 * 1024);
                    if let Some(fid) = state.hex.file_id.clone() {
                        state.load_hex_window(
                            &fid,
                            new_off.min(state.hex.file_size.saturating_sub(1)),
                        );
                        sync_visible_hits(state);
                    }
                }
            });
        });
    ui.separator();

    // ── Hex rows ──────────────────────────────────────────────────────────────
    let bpr = 16usize;
    let data_len = state.hex.data.len();
    let row_h = 18.0;
    // Only virtualize the loaded hex window (max 256 KB ≈ 16K rows).
    // The full file may be gigabytes — we CANNOT put that into egui's
    // scroll area without exceeding f32 precision and crashing.
    // Page+/Page-/GoTo handle navigation to other file regions.
    let total_rows = data_len.div_ceil(bpr);
    let cursor_byte = state.hex.cursor_byte;
    let selected_hit_abs = state
        .hex_search_hits_abs
        .get(state.hex.search_hit_index)
        .copied();
    let match_start = selected_hit_abs.and_then(|abs| {
        if abs < state.hex.window_offset {
            None
        } else {
            let rel = (abs - state.hex.window_offset) as usize;
            if rel < data_len {
                Some(rel)
            } else {
                None
            }
        }
    });
    let match_end = match_start.map(|s| s.saturating_add(state.hex.search_match_len));

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show_viewport(ui, |ui, viewport| {
            if total_rows == 0 {
                return;
            }

            let first_row = ((viewport.min.y.max(0.0) / row_h).floor() as usize)
                .min(total_rows.saturating_sub(1));
            let visible_rows = ((viewport.height() / row_h).ceil() as usize).saturating_add(2);
            let last_row = first_row.saturating_add(visible_rows).min(total_rows);
            state.hex.scroll_offset = first_row.saturating_mul(bpr);

            let top_spacer = (first_row as f32) * row_h;
            if top_spacer > 0.0 {
                ui.allocate_space(egui::vec2(ui.available_width(), top_spacer));
            }

            for row in first_row..last_row {
                let abs_off = (row as u64).saturating_mul(bpr as u64);
                let rel_off = abs_off.saturating_sub(state.hex.window_offset) as usize;
                let row_loaded = abs_off >= state.hex.window_offset && rel_off < data_len;

                ui.horizontal(|ui| {
                    ui.add_space(10.0);
                    let off_resp = ui.label(
                        egui::RichText::new(format!("{:08X}", abs_off))
                            .color(t.muted)
                            .size(10.5)
                            .monospace(),
                    );
                    if off_resp.clicked() {
                        ui.ctx().copy_text(format!("0x{:08X}", abs_off));
                    }
                    ui.add_space(4.0);

                    if !row_loaded {
                        ui.label(
                            egui::RichText::new("Loading...")
                                .color(t.suspicious)
                                .size(9.5)
                                .monospace(),
                        );
                        return;
                    }

                    let end = (rel_off + bpr).min(data_len);
                    let chunk = &state.hex.data[rel_off..end];
                    for (i, &b) in chunk.iter().enumerate() {
                        let at = rel_off + i;
                        let is_cursor = at == cursor_byte;
                        let is_match = match_start
                            .zip(match_end)
                            .map(|(s, e)| at >= s && at < e)
                            .unwrap_or(false);
                        let color = if is_cursor {
                            egui::Color32::from_rgb(0xba, 0xe6, 0xfd)
                        } else if is_match {
                            egui::Color32::from_rgb(0xff, 0xd6, 0x7a)
                        } else {
                            t.secondary
                        };
                        let bg = if is_cursor {
                            egui::Color32::from_rgb(0x0f, 0x25, 0x40)
                        } else if is_match {
                            egui::Color32::from_rgb(0x2a, 0x22, 0x10)
                        } else {
                            egui::Color32::TRANSPARENT
                        };

                        if i == 8 {
                            ui.add_space(4.0);
                        }

                        let resp = egui::Frame::none()
                            .fill(bg)
                            .show(ui, |ui| {
                                ui.label(
                                    egui::RichText::new(format!("{:02X}", b))
                                        .color(color)
                                        .size(10.5)
                                        .monospace(),
                                )
                            })
                            .response;

                        if resp.clicked() {
                            state.hex.cursor_byte = rel_off + i;
                        }
                    }

                    ui.add_space(4.0);
                    let ascii: String = chunk
                        .iter()
                        .map(|&b| {
                            if (0x20..0x7F).contains(&b) {
                                b as char
                            } else {
                                '.'
                            }
                        })
                        .collect();
                    ui.label(
                        egui::RichText::new(ascii)
                            .color(t.muted)
                            .size(10.5)
                            .monospace(),
                    );
                });
            }

            let bottom_spacer = (total_rows.saturating_sub(last_row) as f32) * row_h;
            if bottom_spacer > 0.0 {
                ui.allocate_space(egui::vec2(ui.available_width(), bottom_spacer));
            }
        });

    // ── Data interpreter ──────────────────────────────────────────────────────
    if cursor_byte < data_len {
        ui.separator();
        let off = cursor_byte;
        let b0 = state.hex.data[off];
        egui::Frame::none()
            .inner_margin(egui::Margin {
                left: 10.0,
                right: 8.0,
                top: 2.0,
                bottom: 2.0,
            })
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    interp(ui, "UINT8", &b0.to_string(), &t);
                    interp(ui, "INT8", &(b0 as i8).to_string(), &t);
                    if off + 2 <= data_len {
                        let u16v =
                            u16::from_le_bytes([state.hex.data[off], state.hex.data[off + 1]]);
                        interp(ui, "UINT16-LE", &u16v.to_string(), &t);
                    }
                    if off + 4 <= data_len {
                        let u32v = u32::from_le_bytes([
                            state.hex.data[off],
                            state.hex.data[off + 1],
                            state.hex.data[off + 2],
                            state.hex.data[off + 3],
                        ]);
                        interp(ui, "UINT32-LE", &u32v.to_string(), &t);
                        let f32v = f32::from_le_bytes([
                            state.hex.data[off],
                            state.hex.data[off + 1],
                            state.hex.data[off + 2],
                            state.hex.data[off + 3],
                        ]);
                        interp(ui, "FLOAT32", &format!("{:.4}", f32v), &t);
                    }
                });
            });
    }
}

fn interp(ui: &mut egui::Ui, label: &str, value: &str, t: &crate::theme::StrataTheme) {
    ui.label(egui::RichText::new(label).color(t.muted).size(8.0));
    ui.label(
        egui::RichText::new(value)
            .color(t.active)
            .size(8.0)
            .monospace(),
    );
    ui.separator();
}

fn parse_offset_input(v: &str) -> Option<u64> {
    let s = v.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

fn sync_visible_hits(state: &mut crate::state::AppState) {
    let start = state.hex.window_offset;
    let end = start.saturating_add(state.hex.data.len() as u64);
    state.hex.search_hits.clear();
    for &abs in &state.hex_search_hits_abs {
        if abs >= start && abs < end {
            state.hex.search_hits.push((abs - start) as usize);
        }
    }
}

fn fmt_bytes(v: u64) -> String {
    const GB: u64 = 1 << 30;
    const MB: u64 = 1 << 20;
    const KB: u64 = 1 << 10;
    if v >= GB {
        format!("{:.1}GB", v as f64 / GB as f64)
    } else if v >= MB {
        format!("{:.1}MB", v as f64 / MB as f64)
    } else if v >= KB {
        format!("{:.1}KB", v as f64 / KB as f64)
    } else {
        format!("{}B", v)
    }
}
