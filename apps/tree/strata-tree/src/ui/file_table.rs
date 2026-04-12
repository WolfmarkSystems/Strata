//! Center pane — Sortable file table.

use crate::state::{AppState, FileEntry};
use rayon::slice::ParallelSliceMut;

const COLS: &[&str] = &["NAME", "SIZE", "MODIFIED", "CREATED", "SHA-256", "CATEGORY"];
const MIN_COL_WIDTH: f32 = 40.0;
const BUFFER_ROWS: usize = 50;

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    let t = *state.theme();
    state.refresh_filtered_files();
    let mut col_widths = state.file_table_state.column_widths.clone();
    ensure_column_widths(&mut col_widths);

    // ── Header row ────────────────────────────────────────────────────────────
    egui::Frame::none()
        .inner_margin(egui::Margin {
            left: 8.0,
            right: 8.0,
            top: 4.0,
            bottom: 4.0,
        })
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let path = state.selected_tree_path.as_deref().unwrap_or("/");
                ui.label(
                    egui::RichText::new(format!("FILE LISTING \u{2014} {}", path))
                        .color(t.muted)
                        .size(8.5)
                        .strong(),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        egui::RichText::new(format!("{} items", state.filtered_file_indices.len()))
                            .color(t.active)
                            .size(8.5),
                    );
                });
            });
        });

    // ── Column headers ────────────────────────────────────────────────────────
    egui::Frame::none()
        .fill(t.card)
        .stroke(egui::Stroke::new(2.0, t.border))
        .inner_margin(egui::Margin {
            left: 8.0,
            right: 8.0,
            top: 3.0,
            bottom: 3.0,
        })
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                for (i, col) in COLS.iter().enumerate() {
                    let active = state.sort_col == i;
                    let arrow = if active {
                        if state.sort_asc {
                            " \u{25b2}"
                        } else {
                            " \u{25bc}"
                        }
                    } else {
                        ""
                    };
                    let text = egui::RichText::new(format!("{}{}", col, arrow))
                        .color(if active { t.text } else { t.secondary })
                        .size(10.0)
                        .strong();
                    let resp = ui.add_sized(
                        [col_widths[i], 18.0],
                        egui::Label::new(text).sense(egui::Sense::click()),
                    );
                    if resp.clicked() {
                        if state.sort_col == i {
                            state.sort_asc = !state.sort_asc;
                        } else {
                            state.sort_col = i;
                            state.sort_asc = true;
                        }
                        state.file_table_state.sort_col = state.sort_col;
                        state.file_table_state.sort_asc = state.sort_asc;
                        state.file_table_state.sort_dirty = true;
                    }
                    resp.context_menu(|ui| {
                        if ui.button("Sort Ascending").clicked() {
                            state.sort_col = i;
                            state.sort_asc = true;
                            state.file_table_state.sort_col = state.sort_col;
                            state.file_table_state.sort_asc = state.sort_asc;
                            state.file_table_state.sort_dirty = true;
                            ui.close_menu();
                        }
                        if ui.button("Sort Descending").clicked() {
                            state.sort_col = i;
                            state.sort_asc = false;
                            state.file_table_state.sort_col = state.sort_col;
                            state.file_table_state.sort_asc = state.sort_asc;
                            state.file_table_state.sort_dirty = true;
                            ui.close_menu();
                        }
                        if ui.button("Reset Column Width").clicked() {
                            let defaults = [280.0, 90.0, 160.0, 160.0, 200.0, 80.0];
                            if i < defaults.len() {
                                col_widths[i] = defaults[i];
                                state.mark_case_dirty();
                            }
                            ui.close_menu();
                        }
                    });
                    if i < COLS.len() - 1 {
                        let dragged = drag_column_divider(ui, &mut col_widths[i], &t);
                        if dragged {
                            state.mark_case_dirty();
                        }
                    }
                }
            });
        });

    // ── File rows ─────────────────────────────────────────────────────────────
    if state.file_table_state.sort_dirty {
        sort_file_indices(
            &mut state.filtered_file_indices,
            &state.file_index,
            state.sort_col,
            state.sort_asc,
        );
        state.file_table_state.sort_dirty = false;
    }

    let row_height = 20.0;
    let selected_id = state.selected_file_id.clone();
    let total_rows = state.filtered_file_indices.len();
    state.file_table_state.total_rows = total_rows;

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show_viewport(ui, |ui, viewport| {
            state.file_table_state.scroll_offset = viewport.min.y.max(0.0);
            let first_visible =
                (state.file_table_state.scroll_offset / row_height).floor() as usize;
            let viewport_rows = (viewport.height() / row_height).ceil() as usize + 1;
            let render_start = first_visible.saturating_sub(BUFFER_ROWS);
            let render_end = first_visible
                .saturating_add(viewport_rows)
                .saturating_add(BUFFER_ROWS)
                .min(total_rows);

            state.file_table_state.visible_start = render_start;
            state.file_table_state.visible_end = render_end;

            let top_spacer = (render_start as f32) * row_height;
            if top_spacer > 0.0 {
                ui.allocate_space(egui::vec2(ui.available_width(), top_spacer));
            }

            for row in render_start..render_end {
                let Some(idx) = state.filtered_file_indices.get(row).copied() else {
                    continue;
                };
                let Some(f) = state.file_index.get(idx).cloned() else {
                    continue;
                };
                let is_sel = selected_id.as_deref() == Some(f.id.as_str());
                let stripe_bg = if row % 2 == 0 {
                    egui::Color32::TRANSPARENT
                } else {
                    // Subtle stripe: card + 2% lighter
                    let c = t.card;
                    egui::Color32::from_rgb(
                        c.r().saturating_add(5),
                        c.g().saturating_add(5),
                        c.b().saturating_add(5),
                    )
                };
                let row_bg = if is_sel {
                    t.selection
                } else if f.is_deleted {
                    egui::Color32::from_rgb(0x08, 0x04, 0x04)
                } else if f.hash_flag.as_deref() == Some("KnownBad") {
                    egui::Color32::from_rgb(0x0d, 0x0a, 0x04)
                } else if f.hash_flag.as_deref() == Some("KnownGood") {
                    egui::Color32::from_rgba_unmultiplied(6, 22, 10, 80)
                } else {
                    stripe_bg
                };

                egui::Frame::none()
                    .fill(row_bg)
                    .stroke(egui::Stroke::new(1.0, t.border))
                    .inner_margin(egui::Margin {
                        left: 6.0,
                        right: 6.0,
                        top: 1.0,
                        bottom: 1.0,
                    })
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            let name_color = if f.hash_flag.as_deref() == Some("KnownGood") {
                                egui::Color32::from_rgba_unmultiplied(
                                    t.text.r(),
                                    t.text.g(),
                                    t.text.b(),
                                    140,
                                )
                            } else if f.is_deleted {
                                t.muted
                            } else {
                                t.text
                            };
                            let mut name_rt =
                                egui::RichText::new(&f.name).color(name_color).size(10.5);
                            if f.is_deleted {
                                name_rt = name_rt.strikethrough();
                            }
                            let name_text = name_rt;
                            let resp = ui.add_sized(
                                [col_widths[0], row_height - 2.0],
                                egui::Label::new(name_text).sense(egui::Sense::click()),
                            );
                            if resp.clicked() {
                                state.selected_file_id = Some(f.id.clone());
                                state.file_table_state.selected_id = Some(f.id.clone());
                                state.load_hex_for_file(&f.id);
                                if let Some(selected) =
                                    state.file_index.iter_mut().find(|e| e.id == f.id)
                                {
                                    if selected.signature.is_none() {
                                        selected.signature =
                                            crate::state::detect_signature(&state.hex.data)
                                                .map(|s| s.to_string());
                                    }
                                }
                                state.log_action(
                                    "FILE_ACCESSED",
                                    &format!("name={} path={} size={:?}", f.name, f.path, f.size),
                                );
                            }
                            resp.context_menu(|ui| {
                                if ui.button("Bookmark (Notable)").clicked() {
                                    let examiner = state.examiner_name.clone();
                                    if let Some(existing) =
                                        state.bookmark_for_file_mut(&f.id, &examiner)
                                    {
                                        existing.tag = "NOTABLE".to_string();
                                    } else {
                                        state.bookmarks.push(crate::state::Bookmark {
                                            id: uuid::Uuid::new_v4().to_string(),
                                            file_id: Some(f.id.clone()),
                                            registry_path: None,
                                            tag: "NOTABLE".to_string(),
                                            examiner: examiner.clone(),
                                            note: String::new(),
                                            created_utc: chrono::Utc::now()
                                                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                                        });
                                    }
                                    state.mark_case_dirty();
                                    state.log_action(
                                        "BOOKMARK_SET",
                                        &format!("file={} tag=NOTABLE", f.path),
                                    );
                                    ui.close_menu();
                                }
                                if ui.button("Copy Path").clicked() {
                                    ui.ctx().copy_text(f.path.clone());
                                    ui.close_menu();
                                }
                                if ui.button("Filter To Parent").clicked() {
                                    state.selected_tree_path = Some(f.parent_path.clone());
                                    state.file_filter = f.parent_path.clone();
                                    state.mark_filter_dirty();
                                    ui.close_menu();
                                }
                                if ui.button("Hash File").clicked() {
                                    let files = vec![f.clone()];
                                    let (tx, rx) = std::sync::mpsc::channel();
                                    crate::evidence::hasher::spawn_hash_worker(
                                        files,
                                        state.vfs_context.clone(),
                                        tx,
                                    );
                                    state.hashing_rx = Some(rx);
                                    state.hashing_active = true;
                                    state.status = format!("Hashing file: {}", f.name);
                                    ui.close_menu();
                                }
                                if ui.button("Export File").clicked() {
                                    if let Some(dest) = rfd::FileDialog::new()
                                        .set_file_name(&f.name)
                                        .save_file()
                                    {
                                        if let Some(ctx) = &state.vfs_context {
                                            match ctx.read_file(&f) {
                                                Ok(bytes) => {
                                                    match std::fs::write(&dest, &bytes) {
                                                        Ok(_) => {
                                                            state.status = format!("Exported: {}", dest.display());
                                                            state.log_action("FILE_EXPORT", &format!("path={}", f.path));
                                                        }
                                                        Err(e) => state.status = format!("Export failed: {}", e),
                                                    }
                                                }
                                                Err(e) => state.status = format!("Read failed: {}", e),
                                            }
                                        }
                                    }
                                    ui.close_menu();
                                }
                                if ui.button("Add to Report").clicked() {
                                    let examiner = state.examiner_name.clone();
                                    if state.bookmarks.iter().all(|b| b.file_id.as_deref() != Some(&f.id)) {
                                        state.bookmarks.push(crate::state::Bookmark {
                                            id: uuid::Uuid::new_v4().to_string(),
                                            file_id: Some(f.id.clone()),
                                            registry_path: None,
                                            tag: "REPORT".to_string(),
                                            examiner: examiner.clone(),
                                            note: String::new(),
                                            created_utc: chrono::Utc::now()
                                                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                                        });
                                    }
                                    state.mark_case_dirty();
                                    state.log_action("ADD_TO_REPORT", &format!("file={}", f.path));
                                    state.status = format!("Added to report: {}", f.name);
                                    ui.close_menu();
                                }
                            });

                            let marks = state.bookmarks_for_file(&f.id);
                            if !marks.is_empty() {
                                ui.label(egui::RichText::new("●").color(t.active).size(9.5));
                                let initials = marks
                                    .iter()
                                    .map(|b| {
                                        b.examiner
                                            .split_whitespace()
                                            .filter_map(|w| w.chars().next())
                                            .take(2)
                                            .collect::<String>()
                                            .to_uppercase()
                                    })
                                    .filter(|s| !s.is_empty())
                                    .collect::<Vec<_>>()
                                    .join(",");
                                if !initials.is_empty() {
                                    ui.label(
                                        egui::RichText::new(initials).color(t.muted).size(8.0),
                                    );
                                }
                            }

                            if f.is_deleted {
                                badge(ui, "DEL", t.flagged);
                            }
                            if f.is_carved {
                                badge(ui, "CARVED", t.suspicious);
                            }
                            if f.hash_flag.as_deref() == Some("KnownGood") {
                                badge(ui, "KNOWN_GOOD", t.clean);
                            }
                            if f.hash_flag.as_deref() == Some("KnownBad") {
                                badge(ui, "FLAGGED", t.flagged);
                            }
                            if f.hash_flag.as_deref() == Some("Notable") {
                                badge(ui, "NOTABLE", t.suspicious);
                            }

                            let sz = f
                                .size
                                .map(fmt_size)
                                .unwrap_or_else(|| "\u{2014}".to_string());
                            ui.add_sized(
                                [col_widths[1], row_height - 2.0],
                                egui::Label::new(
                                    egui::RichText::new(sz).color(t.secondary).size(9.0),
                                ),
                            );
                            let mo = f
                                .modified_utc
                                .as_deref()
                                .map(|s| &s[..10.min(s.len())])
                                .unwrap_or("\u{2014}");
                            ui.add_sized(
                                [col_widths[2], row_height - 2.0],
                                egui::Label::new(
                                    egui::RichText::new(mo).color(t.secondary).size(9.0),
                                ),
                            );
                            let cr = f
                                .created_utc
                                .as_deref()
                                .map(|s| &s[..10.min(s.len())])
                                .unwrap_or("\u{2014}");
                            ui.add_sized(
                                [col_widths[3], row_height - 2.0],
                                egui::Label::new(
                                    egui::RichText::new(cr).color(t.secondary).size(9.0),
                                ),
                            );
                            let hash_prefix = match f.hash_flag.as_deref() {
                                Some("KnownGood") => "✓ ",
                                Some("KnownBad") => "! ",
                                Some("Notable") => "• ",
                                _ => "",
                            };
                            let hash = f
                                .sha256
                                .as_deref()
                                .map(|h| &h[..12.min(h.len())])
                                .unwrap_or("\u{2014}");
                            ui.add_sized(
                                [col_widths[4], row_height - 2.0],
                                egui::Label::new(
                                    egui::RichText::new(format!("{}{}", hash_prefix, hash))
                                        .color(t.active)
                                        .size(9.0)
                                        .monospace(),
                                ),
                            );
                            let cat = f.category.as_deref().unwrap_or("\u{2014}");
                            ui.add_sized(
                                [col_widths[5], row_height - 2.0],
                                egui::Label::new(egui::RichText::new(cat).color(t.muted).size(9.0)),
                            );
                        });
                    });
            }

            let bottom_spacer = (total_rows.saturating_sub(render_end) as f32) * row_height;
            if bottom_spacer > 0.0 {
                ui.allocate_space(egui::vec2(ui.available_width(), bottom_spacer));
            }
        });

    state.file_table_state.column_widths = col_widths;

    // ── Collapsible metadata strip ──────────────────────────────────────────
    render_metadata_strip(ui, state, &t);
}

fn render_metadata_strip(ui: &mut egui::Ui, state: &mut AppState, t: &crate::theme::StrataTheme) {
    let file = state.selected_file().cloned();
    let label = file
        .as_ref()
        .map(|f| f.name.as_str())
        .unwrap_or("No file selected");
    let arrow = if state.metadata_expanded {
        "\u{25BC}"
    } else {
        "\u{25B6}"
    };

    // Header bar (always visible)
    egui::Frame::none()
        .fill(t.panel)
        .inner_margin(egui::Margin::symmetric(10.0, 4.0))
        .show(ui, |ui| {
            let resp = ui
                .horizontal(|ui| {
                    ui.label(egui::RichText::new(arrow).color(t.muted).size(8.0));
                    ui.label(
                        egui::RichText::new("METADATA")
                            .color(t.muted)
                            .size(9.0)
                            .strong(),
                    );
                    ui.separator();
                    ui.label(egui::RichText::new(label).color(t.secondary).size(9.0));
                })
                .response;
            let click = ui.interact(resp.rect, resp.id.with("meta_toggle"), egui::Sense::click());
            if click.clicked() {
                state.metadata_expanded = !state.metadata_expanded;
            }
        });

    if !state.metadata_expanded {
        return;
    }

    let Some(f) = file else {
        return;
    };

    // Expanded metadata (two columns)
    egui::Frame::none()
        .fill(t.panel)
        .inner_margin(egui::Margin::symmetric(10.0, 6.0))
        .show(ui, |ui| {
            ui.columns(2, |cols| {
                // Left column
                meta_kv(
                    &mut cols[0],
                    "SIZE",
                    &f.size
                        .map(fmt_size_meta)
                        .unwrap_or_else(|| "\u{2014}".to_string()),
                    t,
                );
                meta_kv(
                    &mut cols[0],
                    "MODIFIED",
                    &f.modified_utc
                        .clone()
                        .unwrap_or_else(|| "\u{2014}".to_string()),
                    t,
                );
                meta_kv(
                    &mut cols[0],
                    "CREATED",
                    &f.created_utc
                        .clone()
                        .unwrap_or_else(|| "\u{2014}".to_string()),
                    t,
                );
                meta_kv(
                    &mut cols[0],
                    "ACCESSED",
                    &f.accessed_utc
                        .clone()
                        .unwrap_or_else(|| "\u{2014}".to_string()),
                    t,
                );

                // Right column
                meta_kv(
                    &mut cols[1],
                    "MD5",
                    &f.md5.clone().unwrap_or_else(|| "not computed".to_string()),
                    t,
                );
                meta_kv(
                    &mut cols[1],
                    "SHA-256",
                    &f.sha256
                        .clone()
                        .unwrap_or_else(|| "not computed".to_string()),
                    t,
                );
                meta_kv(
                    &mut cols[1],
                    "MFT REC",
                    &f.mft_record
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "\u{2014}".to_string()),
                    t,
                );
                meta_kv(
                    &mut cols[1],
                    "CATEGORY",
                    &f.category.clone().unwrap_or_else(|| "\u{2014}".to_string()),
                    t,
                );
                let del = if f.is_deleted { "Yes" } else { "No" };
                let carv = if f.is_carved { "Yes" } else { "No" };
                meta_kv(&mut cols[1], "DELETED", del, t);
                meta_kv(&mut cols[1], "CARVED", carv, t);
            });
        });
}

fn meta_kv(ui: &mut egui::Ui, label: &str, value: &str, t: &crate::theme::StrataTheme) {
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(label).color(t.muted).size(9.0).strong());
        ui.label(egui::RichText::new(value).color(t.text).size(10.0));
    });
}

fn fmt_size_meta(bytes: u64) -> String {
    if bytes < 1024 {
        return format!("{} B", bytes);
    }
    if bytes < 1024 * 1024 {
        return format!("{:.1} KB ({} bytes)", bytes as f64 / 1024.0, bytes);
    }
    if bytes < 1024 * 1024 * 1024 {
        return format!(
            "{:.1} MB ({} bytes)",
            bytes as f64 / (1024.0 * 1024.0),
            bytes
        );
    }
    format!(
        "{:.1} GB ({} bytes)",
        bytes as f64 / (1024.0 * 1024.0 * 1024.0),
        bytes
    )
}

fn badge(ui: &mut egui::Ui, text: &str, color: egui::Color32) {
    egui::Frame::none()
        .fill(egui::Color32::from_rgba_unmultiplied(
            color.r(),
            color.g(),
            color.b(),
            30,
        ))
        .stroke(egui::Stroke::new(1.0, color))
        .inner_margin(egui::Margin::symmetric(4.0, 1.0))
        .rounding(2.0)
        .show(ui, |ui| {
            ui.label(egui::RichText::new(text).color(color).size(7.5).strong());
        });
}

fn sort_file_indices(indices: &mut [usize], file_index: &[FileEntry], col: usize, asc: bool) {
    let comparator = |ia: &usize, ib: &usize| {
        let a = &file_index[*ia];
        let b = &file_index[*ib];
        let ord = match col {
            0 => a.name.cmp(&b.name),
            1 => a.size.cmp(&b.size),
            2 => a.modified_utc.cmp(&b.modified_utc),
            3 => a.created_utc.cmp(&b.created_utc),
            4 => a.sha256.cmp(&b.sha256),
            5 => a.category.cmp(&b.category),
            _ => std::cmp::Ordering::Equal,
        };
        if asc {
            ord
        } else {
            ord.reverse()
        }
    };

    if indices.len() > 10_000 {
        indices.par_sort_unstable_by(comparator);
    } else {
        indices.sort_unstable_by(comparator);
    }
}

fn fmt_size(b: u64) -> String {
    const GB: u64 = 1 << 30;
    const MB: u64 = 1 << 20;
    const KB: u64 = 1 << 10;
    if b >= GB {
        format!("{:.1} GB", b as f64 / GB as f64)
    } else if b >= MB {
        format!("{:.1} MB", b as f64 / MB as f64)
    } else if b >= KB {
        format!("{:.0} KB", b as f64 / KB as f64)
    } else {
        format!("{} B", b)
    }
}

fn ensure_column_widths(widths: &mut Vec<f32>) {
    if widths.len() != COLS.len() {
        *widths = vec![280.0, 90.0, 160.0, 160.0, 200.0, 80.0];
    }
    for w in widths {
        if *w < MIN_COL_WIDTH {
            *w = MIN_COL_WIDTH;
        }
    }
}

fn drag_column_divider(ui: &mut egui::Ui, width: &mut f32, t: &crate::theme::StrataTheme) -> bool {
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(6.0, 18.0), egui::Sense::click_and_drag());
    if response.dragged() {
        *width = (*width + response.drag_delta().x).max(MIN_COL_WIDTH);
    }
    ui.painter().line_segment(
        [rect.center_top(), rect.center_bottom()],
        egui::Stroke::new(1.0, t.border),
    );
    response.dragged()
}

#[cfg(test)]
mod tests {
    use super::sort_file_indices;
    use crate::state::{AppState, FileEntry};

    fn build_entries(count: usize) -> Vec<FileEntry> {
        (0..count)
            .map(|i| FileEntry {
                id: format!("id-{}", i),
                evidence_id: "ev1".to_string(),
                path: format!("Windows/System32/dir_{}/file_{:06}.txt", i % 32, count - i),
                parent_path: format!("Windows/System32/dir_{}", i % 32),
                name: format!("file_{:06}.txt", count - i),
                extension: Some("txt".to_string()),
                size: Some((count - i) as u64),
                modified_utc: Some(format!("2026-03-{:02}T{:02}:00:00Z", (i % 28) + 1, i % 24)),
                ..Default::default()
            })
            .collect()
    }

    #[test]
    fn sort_performance_smoke() {
        let file_index = build_entries(120_000);
        let mut indices: Vec<usize> = (0..file_index.len()).collect();
        let start = std::time::Instant::now();
        sort_file_indices(&mut indices, &file_index, 0, true);
        let elapsed_ms = start.elapsed().as_millis();
        eprintln!("sort_performance_smoke elapsed={}ms", elapsed_ms);
        let threshold_ms = if cfg!(debug_assertions) { 15_000 } else { 500 };
        assert!(elapsed_ms <= threshold_ms, "sort took {}ms", elapsed_ms);
    }

    #[test]
    fn filter_performance_smoke() {
        let mut state = AppState {
            file_index: build_entries(180_000),
            file_filter: "Windows/System32/dir_7".to_string(),
            ..AppState::default()
        };

        let start = std::time::Instant::now();
        state.rebuild_filtered_files_now();
        let elapsed_ms = start.elapsed().as_millis();
        eprintln!(
            "filter_performance_smoke elapsed={}ms matched={}",
            elapsed_ms,
            state.filtered_file_indices.len()
        );
        assert!(!state.filtered_file_indices.is_empty());
        let threshold_ms = if cfg!(debug_assertions) { 12_000 } else { 300 };
        assert!(elapsed_ms <= threshold_ms, "filter took {}ms", elapsed_ms);
    }
}
