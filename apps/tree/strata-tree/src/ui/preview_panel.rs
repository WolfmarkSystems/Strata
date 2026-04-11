//! Right pane — file metadata / hex / text / image preview.

use crate::state::AppState;

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    let t = *state.theme();
    let file = state.selected_file().cloned();

    // ── Pill tab bar ────────────────────────────────────────────────────────
    egui::Frame::none()
        .inner_margin(egui::Margin {
            left: 10.0,
            right: 10.0,
            top: 6.0,
            bottom: 4.0,
        })
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing = egui::vec2(4.0, 0.0);
                let has_hash_match = file.as_ref().and_then(|f| f.hash_flag.as_ref()).is_some();
                let has_knowledge = file.as_ref().map(|f| {
                    strata_core::knowledge_bank::lookup_knowledge(&f.name, &f.path).is_some()
                }).unwrap_or(false);
                let mut tab_labels: Vec<&str> = vec!["META", "HEX", "TEXT", "IMAGE"];
                if has_knowledge {
                    tab_labels.push("DETAILS");
                }
                if has_hash_match {
                    tab_labels.push("HASH \u{26A0}");
                }
                let hash_tab_idx = tab_labels.iter().position(|&l| l.starts_with("HASH"));
                for (i, label) in tab_labels.iter().enumerate() {
                    let active = state.preview_tab == i as u8;
                    let is_hash_tab = hash_tab_idx == Some(i);
                    let hash_tab_color = match file.as_ref().and_then(|f| f.hash_flag.as_deref()) {
                        Some("KnownBad") => egui::Color32::from_rgb(0xef, 0x44, 0x44),
                        Some("KnownGood") => egui::Color32::from_rgb(0x4a, 0xde, 0x80),
                        Some("Notable") => egui::Color32::from_rgb(0xf5, 0x9e, 0x0b),
                        _ => t.active,
                    };
                    let text_color = if active {
                        t.bg
                    } else if is_hash_tab {
                        hash_tab_color
                    } else {
                        t.muted
                    };
                    let pill_bg = if active {
                        if is_hash_tab { hash_tab_color } else { t.active }
                    } else {
                        egui::Color32::TRANSPARENT
                    };

                    let resp = egui::Frame::none()
                        .fill(pill_bg)
                        .rounding(crate::theme::RADIUS_PILL)
                        .inner_margin(egui::Margin::symmetric(8.0, 3.0))
                        .show(ui, |ui| {
                            ui.label(
                                egui::RichText::new(*label)
                                    .color(text_color)
                                    .size(9.0)
                                    .strong(),
                            )
                        })
                        .response;
                    let click =
                        ui.interact(resp.rect, resp.id.with("tab_click"), egui::Sense::click());
                    if click.clicked() {
                        state.preview_tab = i as u8;
                        state.mark_case_dirty();
                    }
                    if click.hovered() && !active {
                        ui.painter()
                            .rect_filled(resp.rect, crate::theme::RADIUS_PILL, t.elevated);
                    }
                }
            });
        });

    // Thin border under tabs
    let cursor = ui.cursor().min;
    let w = ui.available_width();
    ui.painter().line_segment(
        [
            egui::pos2(cursor.x + 8.0, cursor.y),
            egui::pos2(cursor.x + w - 8.0, cursor.y),
        ],
        egui::Stroke::new(1.0, t.border),
    );
    ui.add_space(2.0);

    // ── No file selected state ──────────────────────────────────────────────
    if file.is_none() {
        ui.vertical_centered(|ui| {
            ui.add_space(ui.available_height() / 3.0);
            ui.label(
                egui::RichText::new("Select a file to preview")
                    .color(t.muted)
                    .size(13.0),
            );
        });
        return;
    }
    let Some(f) = file else {
        return;
    };

    // ── Content based on active tab ─────────────────────────────────────────
    // Rebuild tab labels to map index → label for correct routing
    let has_knowledge = strata_core::knowledge_bank::lookup_knowledge(&f.name, &f.path).is_some();
    let has_hash_match_flag = f.hash_flag.is_some();
    let mut content_tabs: Vec<&str> = vec!["META", "HEX", "TEXT", "IMAGE"];
    if has_knowledge {
        content_tabs.push("DETAILS");
    }
    if has_hash_match_flag {
        content_tabs.push("HASH");
    }
    let active_label = content_tabs.get(state.preview_tab as usize).copied().unwrap_or("META");

    egui::ScrollArea::vertical().show(ui, |ui| {
        egui::Frame::none()
            .inner_margin(egui::Margin::symmetric(10.0, 6.0))
            .show(ui, |ui| match active_label {
                "META" => render_metadata(ui, &f, state, &t),
                "HEX" => super::hex_panel::render(ui, state),
                "TEXT" => render_text_preview(ui, state, &f),
                "IMAGE" => render_image_preview(ui, state, &f, &t),
                "DETAILS" => render_details_tab(ui, &f, &t),
                "HASH" => render_hash_match(ui, &f, state, &t),
                _ => {}
            });
    });
}

fn render_metadata(
    ui: &mut egui::Ui,
    f: &crate::state::FileEntry,
    state: &mut AppState,
    t: &crate::theme::StrataTheme,
) {
    ui.label(
        egui::RichText::new(&f.name)
            .color(t.active)
            .size(11.0)
            .strong(),
    );
    ui.label(egui::RichText::new(&f.path).color(t.muted).size(8.5));
    ui.add_space(4.0);

    egui::Grid::new("meta_grid")
        .num_columns(2)
        .spacing([4.0, 3.0])
        .min_col_width(86.0)
        .striped(true)
        .show(ui, |ui| {
            meta_row(
                ui,
                "SIZE",
                &f.size
                    .map(fmt_size)
                    .unwrap_or_else(|| "\u{2014}".to_string()),
                t.secondary,
                t,
            );
            meta_row(
                ui,
                "MODIFIED",
                &f.modified_utc
                    .clone()
                    .unwrap_or_else(|| "\u{2014}".to_string()),
                t.secondary,
                t,
            );
            meta_row(
                ui,
                "CREATED",
                &f.created_utc
                    .clone()
                    .unwrap_or_else(|| "\u{2014}".to_string()),
                t.secondary,
                t,
            );
            meta_row(
                ui,
                "ACCESSED",
                &f.accessed_utc
                    .clone()
                    .unwrap_or_else(|| "\u{2014}".to_string()),
                t.secondary,
                t,
            );
            meta_row(
                ui,
                "MFT REC",
                &f.mft_record
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "\u{2014}".to_string()),
                t.secondary,
                t,
            );
            meta_row(
                ui,
                "MD5",
                &f.md5.clone().unwrap_or_else(|| "not computed".to_string()),
                t.active,
                t,
            );
            meta_row(
                ui,
                "SHA-256",
                &f.sha256
                    .clone()
                    .unwrap_or_else(|| "not computed".to_string()),
                t.active,
                t,
            );
            {
                let del_val = if f.is_deleted {
                    "YES".to_string()
                } else {
                    "No".to_string()
                };
                let del_color = if f.is_deleted { t.flagged } else { t.secondary };
                meta_row(ui, "DELETED", &del_val, del_color, t);
            }
            {
                let carv_val = if f.is_carved {
                    "YES".to_string()
                } else {
                    "No".to_string()
                };
                let carv_color = if f.is_carved {
                    t.suspicious
                } else {
                    t.secondary
                };
                meta_row(ui, "CARVED", &carv_val, carv_color, t);
            }
            {
                let hs_val = f.hash_flag.clone().unwrap_or_else(|| "None".to_string());
                let hs_color = match hs_val.as_str() {
                    "KnownBad" => t.flagged,
                    "KnownGood" => t.clean,
                    _ => t.secondary,
                };
                meta_row(ui, "HASH SET", &hs_val, hs_color, t);
            }
            meta_row(
                ui,
                "CATEGORY",
                &f.category.clone().unwrap_or_else(|| "\u{2014}".to_string()),
                t.secondary,
                t,
            );
        });

    if f.is_carved {
        ui.add_space(8.0);
        ui.separator();
        ui.label(
            egui::RichText::new("CARVED FILE DETAILS")
                .color(t.suspicious)
                .size(8.5)
                .strong(),
        );
        meta_line(
            ui,
            "Signature",
            f.signature
                .as_deref()
                .or(f.category.as_deref())
                .unwrap_or("Unknown"),
            t,
        );
        meta_line(
            ui,
            "Source Offset",
            &parse_carved_offset(f)
                .map(|off| format!("0x{:016X}", off))
                .unwrap_or_else(|| "Unknown".to_string()),
            t,
        );
        meta_line(
            ui,
            "Length",
            &f.size
                .map(|v| format!("{} bytes", v))
                .unwrap_or_else(|| "Unknown".to_string()),
            t,
        );
        meta_line(ui, "Confidence", "Heuristic carve match", t);

        if ui
            .button(egui::RichText::new("EXPORT FILE").color(t.active).size(8.5))
            .clicked()
        {
            if let Some(path) = rfd::FileDialog::new().set_file_name(&f.name).save_file() {
                if let Err(err) = state.ensure_output_path_safe(path.as_path()) {
                    state.status = err;
                    return;
                }
                match read_all(state, f) {
                    Ok(bytes) => match std::fs::write(&path, &bytes) {
                        Ok(_) => {
                            state.log_action(
                                "CARVED_EXPORT",
                                &format!("source={} dest={}", f.path, path.display()),
                            );
                            state.status = format!("Exported carved file to {}", path.display());
                        }
                        Err(e) => {
                            state.status = format!("Carved export failed: {}", e);
                        }
                    },
                    Err(e) => {
                        state.status = format!("Carved read failed: {}", e);
                    }
                }
            }
        }
    }

    if is_prefetch_file(f) {
        ui.add_space(8.0);
        ui.separator();
        ui.label(
            egui::RichText::new("PREFETCH ARTIFACT")
                .color(t.suspicious)
                .size(8.5)
                .strong(),
        );
        render_prefetch_preview(ui, state, f, t);
    }

    if is_lnk_file(f) {
        ui.add_space(8.0);
        ui.separator();
        ui.label(
            egui::RichText::new("LNK SHORTCUT ARTIFACT")
                .color(t.suspicious)
                .size(8.5)
                .strong(),
        );
        render_lnk_preview(ui, state, f, t);
    }

    if is_browser_history_db(f) {
        ui.add_space(8.0);
        ui.separator();
        ui.label(
            egui::RichText::new("BROWSER HISTORY ARTIFACT")
                .color(t.suspicious)
                .size(8.5)
                .strong(),
        );
        render_browser_preview(ui, state, f, t);
    }

    if is_event_log_file(f) {
        ui.add_space(8.0);
        ui.separator();
        ui.label(
            egui::RichText::new("EVENT LOG ARTIFACT")
                .color(t.suspicious)
                .size(8.5)
                .strong(),
        );
        render_evtx_preview(ui, state, f, t);
    }

    ui.add_space(8.0);
    ui.separator();

    ui.label(
        egui::RichText::new("EXAMINER NOTES")
            .color(t.muted)
            .size(8.5)
            .strong(),
    );
    ui.add_space(2.0);
    egui::Frame::none()
        .fill(egui::Color32::from_rgb(0x0a, 0x1a, 0x2e))
        .stroke(egui::Stroke::new(2.0, t.border))
        .inner_margin(egui::Margin::same(4.0))
        .show(ui, |ui| {
            ui.add(
                egui::TextEdit::multiline(&mut state.examiner_note)
                    .font(egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY)
                    .desired_rows(4),
            );
        });
    if ui
        .button(egui::RichText::new("+ SAVE NOTE").color(t.active))
        .clicked()
    {
        let examiner = state.examiner_name.clone();
        let note = state.examiner_note.clone();
        if let Some(existing) = state.bookmark_for_file_mut(&f.id, &examiner) {
            existing.note = note;
        } else {
            state.bookmarks.push(crate::state::Bookmark {
                id: uuid::Uuid::new_v4().to_string(),
                file_id: Some(f.id.clone()),
                registry_path: None,
                tag: state.active_tag.clone(),
                examiner,
                note,
                created_utc: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            });
        }
        state.mark_case_dirty();
        persist_bookmarks(state);
        state.log_action("NOTE_SAVE", &format!("file={}", f.path));
        state.status = "Note saved.".to_string();
    }

    ui.add_space(6.0);
    ui.separator();

    ui.label(
        egui::RichText::new("BOOKMARKS")
            .color(t.muted)
            .size(8.5)
            .strong(),
    );
    ui.horizontal_wrapped(|ui| {
        for tag in &[
            "NOTABLE",
            "RELEVANT",
            "REVIEWED",
            "IRRELEVANT",
            "SUSPICIOUS",
            "EXCULPATORY",
        ] {
            let active = state.active_tag == *tag;
            let bg = if active {
                egui::Color32::from_rgb(0x15, 0x30, 0x50)
            } else {
                t.card
            };
            let border = if active { t.active } else { t.border };
            let frame = egui::Frame::none()
                .fill(bg)
                .stroke(egui::Stroke::new(1.0, border))
                .inner_margin(egui::Margin::symmetric(6.0, 2.0))
                .rounding(2.0);
            let resp = frame
                .show(ui, |ui| {
                    ui.label(
                        egui::RichText::new(*tag)
                            .color(if active { t.active } else { t.muted })
                            .size(8.5),
                    )
                })
                .response;
            if ui
                .interact(resp.rect, resp.id.with("tag"), egui::Sense::click())
                .clicked()
            {
                state.active_tag = tag.to_string();
                let file_id = f.id.clone();
                let examiner = state.examiner_name.clone();
                if let Some(existing) = state.bookmark_for_file_mut(&file_id, &examiner) {
                    existing.tag = tag.to_string();
                    state.mark_case_dirty();
                    persist_bookmarks(state);
                }
            }
        }
    });

    let all_marks = state.bookmarks_for_file(&f.id);
    if !all_marks.is_empty() {
        ui.add_space(4.0);
        ui.label(
            egui::RichText::new("Bookmarks for this file")
                .color(t.muted)
                .size(8.5),
        );
        for mark in all_marks {
            let initials = mark
                .examiner
                .split_whitespace()
                .filter_map(|w| w.chars().next())
                .take(2)
                .collect::<String>()
                .to_uppercase();
            ui.label(
                egui::RichText::new(format!(
                    "[{}] {} - {}",
                    if initials.is_empty() { "??" } else { &initials },
                    mark.tag,
                    mark.note
                ))
                .size(8.5)
                .color(t.secondary),
            );
        }
    }
}

fn persist_bookmarks(state: &mut AppState) {
    let Some(case_path) = state.case.as_ref().map(|c| c.path.clone()) else {
        return;
    };
    if case_path.is_empty() {
        return;
    }
    if let Ok(project) = crate::case::project::VtpProject::open(&case_path) {
        let _ = project.save_bookmarks(&state.bookmarks);
    }
}

fn meta_row(
    ui: &mut egui::Ui,
    label: &str,
    value: &str,
    color: egui::Color32,
    t: &crate::theme::StrataTheme,
) {
    ui.label(egui::RichText::new(label).color(t.muted).size(9.0));
    ui.label(
        egui::RichText::new(value)
            .color(color)
            .size(9.0)
            .monospace(),
    );
    ui.end_row();
}

fn render_text_preview(ui: &mut egui::Ui, state: &AppState, f: &crate::state::FileEntry) {
    let data = read_first(state, f, 8192);
    let text = String::from_utf8_lossy(&data).to_string();
    let mut text_ref = text.as_str();
    ui.add(
        egui::TextEdit::multiline(&mut text_ref)
            .font(egui::TextStyle::Monospace)
            .desired_width(f32::INFINITY)
            .interactive(false),
    );
}

fn render_image_preview(
    ui: &mut egui::Ui,
    state: &AppState,
    f: &crate::state::FileEntry,
    t: &crate::theme::StrataTheme,
) {
    let ext = f.extension.as_deref().unwrap_or("").to_lowercase();
    let is_img = matches!(
        ext.as_str(),
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "webp" | "tiff" | "tif"
    );
    if !is_img {
        ui.label(
            egui::RichText::new("Not an image file.")
                .color(t.muted)
                .size(9.5),
        );
        return;
    }
    // Size gate: refuse to decode images >20 MB to prevent OOM.
    // A crafted large TIFF could allocate hundreds of MB for the
    // decoded RGBA bitmap on top of the raw file bytes.
    const MAX_IMAGE_PREVIEW_BYTES: u64 = 20 * 1024 * 1024;
    if f.size.unwrap_or(0) > MAX_IMAGE_PREVIEW_BYTES {
        ui.label(
            egui::RichText::new(format!(
                "Image too large for preview ({} bytes, max {} MB). Use an external viewer.",
                f.size.unwrap_or(0),
                MAX_IMAGE_PREVIEW_BYTES / (1024 * 1024)
            ))
            .color(t.muted)
            .size(9.5),
        );
        return;
    }
    let data = match read_all(state, f) {
        Ok(d) => d,
        Err(_) => {
            ui.label(
                egui::RichText::new("Cannot read file.")
                    .color(t.flagged)
                    .size(9.5),
            );
            return;
        }
    };
    match image::load_from_memory(&data) {
        Ok(img) => {
            let rgba = img.to_rgba8();
            let (w, h) = rgba.dimensions();
            let color_img =
                egui::ColorImage::from_rgba_unmultiplied([w as usize, h as usize], &rgba);
            let tex = ui
                .ctx()
                .load_texture(&f.path, color_img, egui::TextureOptions::LINEAR);
            let avail = ui.available_size();
            let scale = (avail.x / w as f32).min(avail.y / h as f32).min(1.0);
            ui.image((tex.id(), egui::vec2(w as f32 * scale, h as f32 * scale)));

            ui.add_space(6.0);
            ui.separator();
            ui.label(
                egui::RichText::new("EXIF Metadata")
                    .color(t.muted)
                    .size(8.5)
                    .strong(),
            );
            render_exif_metadata(ui, &data, t);
        }
        Err(e) => {
            ui.label(
                egui::RichText::new(format!("Decode error: {}", e))
                    .color(t.flagged)
                    .size(9.0),
            );
        }
    }
}

fn render_prefetch_preview(
    ui: &mut egui::Ui,
    state: &mut AppState,
    f: &crate::state::FileEntry,
    t: &crate::theme::StrataTheme,
) {
    let data = match read_all(state, f) {
        Ok(d) => d,
        Err(e) => {
            ui.label(
                egui::RichText::new(format!("Cannot read prefetch: {}", e))
                    .color(t.flagged)
                    .size(8.5),
            );
            return;
        }
    };

    match crate::artifacts::prefetch::parse_prefetch(&data) {
        Ok(pf) => {
            meta_line(ui, "Executable", &pf.executable_name, t);
            let format_label = if pf.compressed {
                format!("Win{} (MAM-compressed)", pf.version)
            } else {
                format!("Win{}", pf.version)
            };
            meta_line(ui, "Format", &format_label, t);
            meta_line(ui, "Run Count", &pf.run_count.to_string(), t);
            meta_line(ui, "Hash", &format!("{:08X}", pf.prefetch_hash), t);
            let added = append_prefetch_timeline(state, f, &pf);
            if added > 0 {
                ui.label(
                    egui::RichText::new(format!("Timeline +{} ProcessExecuted events", added))
                        .color(t.muted)
                        .size(8.0),
                );
            }

            if let Some(last) = pf.last_run_times.first() {
                meta_line(
                    ui,
                    "Last Run",
                    &last.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    t,
                );
            }
            if pf.last_run_times.len() > 1 {
                ui.label(egui::RichText::new("Prior Runs").color(t.muted).size(8.5));
                for run in pf.last_run_times.iter().skip(1) {
                    ui.label(
                        egui::RichText::new(run.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                            .size(8.0)
                            .monospace()
                            .color(t.secondary),
                    );
                }
            }

            if !pf.volume_paths.is_empty() {
                ui.label(egui::RichText::new("Volumes").color(t.muted).size(8.5));
                for vol in pf.volume_paths.iter().take(8) {
                    ui.label(
                        egui::RichText::new(vol)
                            .size(8.0)
                            .monospace()
                            .color(t.secondary),
                    );
                }
            }
            if !pf.file_references.is_empty() {
                ui.label(
                    egui::RichText::new("Files Loaded (first 20)")
                        .color(t.muted)
                        .size(8.5),
                );
                for file_ref in pf.file_references.iter().take(20) {
                    ui.label(
                        egui::RichText::new(file_ref)
                            .size(8.0)
                            .monospace()
                            .color(t.secondary),
                    );
                }
            }
            if is_prefetch_suspicious(&pf.executable_name, &f.path, &pf.file_references) {
                ui.colored_label(t.suspicious, "SUSPICIOUS PREFETCH INDICATORS");
            }
        }
        Err(err) => {
            ui.label(
                egui::RichText::new(format!("Prefetch parse note: {}", err))
                    .color(t.suspicious)
                    .size(8.5),
            );
        }
    }
}

fn render_lnk_preview(
    ui: &mut egui::Ui,
    state: &AppState,
    f: &crate::state::FileEntry,
    t: &crate::theme::StrataTheme,
) {
    let data = match read_all(state, f) {
        Ok(d) => d,
        Err(e) => {
            ui.label(
                egui::RichText::new(format!("Cannot read shortcut: {}", e))
                    .color(t.flagged)
                    .size(8.5),
            );
            return;
        }
    };

    match crate::artifacts::lnk::parse_lnk(&data) {
        Ok(lnk) => {
            meta_line(
                ui,
                "Target Path",
                lnk.target_path.as_deref().unwrap_or("Unknown"),
                t,
            );
            meta_line(
                ui,
                "Target Size",
                &lnk.target_size
                    .map(|v| format!("{} bytes", v))
                    .unwrap_or_else(|| "Unknown".to_string()),
                t,
            );
            meta_line(
                ui,
                "Target Modified",
                &lnk.target_modified
                    .map(|ts| ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                    .unwrap_or_else(|| "Unknown".to_string()),
                t,
            );
            meta_line(
                ui,
                "Target Created",
                &lnk.target_created
                    .map(|ts| ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                    .unwrap_or_else(|| "Unknown".to_string()),
                t,
            );
            meta_line(
                ui,
                "Target Accessed",
                &lnk.target_accessed
                    .map(|ts| ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                    .unwrap_or_else(|| "Unknown".to_string()),
                t,
            );
            meta_line(
                ui,
                "Working Dir",
                lnk.working_directory.as_deref().unwrap_or("[none]"),
                t,
            );
            meta_line(
                ui,
                "Arguments",
                lnk.arguments.as_deref().unwrap_or("[none]"),
                t,
            );
            meta_line(
                ui,
                "Machine ID",
                lnk.machine_id.as_deref().unwrap_or("Unknown"),
                t,
            );
            meta_line(
                ui,
                "Volume Label",
                lnk.volume_label.as_deref().unwrap_or("Unknown"),
                t,
            );
            meta_line(
                ui,
                "Drive Type",
                lnk.drive_type.as_deref().unwrap_or("Unknown"),
                t,
            );
            meta_line(
                ui,
                "LNK Created",
                &lnk.lnk_created
                    .map(|ts| ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                    .unwrap_or_else(|| "Unknown".to_string()),
                t,
            );
            meta_line(
                ui,
                "LNK Modified",
                &lnk.lnk_modified
                    .map(|ts| ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                    .unwrap_or_else(|| "Unknown".to_string()),
                t,
            );

            if let Some(tp) = &lnk.target_path {
                let suspicious = tp.starts_with("\\\\")
                    || tp.to_lowercase().contains("\\appdata\\local\\temp\\")
                    || tp.to_lowercase().contains("\\downloads\\");
                if suspicious {
                    ui.colored_label(t.suspicious, "Potentially suspicious shortcut target");
                }

                let target_lc = tp.replace('\\', "/").to_lowercase();
                let found_target = state.file_index.iter().any(|entry| {
                    let p = entry.path.replace('\\', "/").to_lowercase();
                    p.ends_with(&target_lc) || p.contains(&target_lc)
                });
                if !found_target {
                    ui.colored_label(t.flagged, "TARGET NOT FOUND IN EVIDENCE (deleted or moved)");
                }
            }
        }
        Err(err) => {
            ui.label(
                egui::RichText::new(format!("LNK parse note: {}", err))
                    .color(t.suspicious)
                    .size(8.5),
            );
        }
    }
}

fn append_prefetch_timeline(
    state: &mut AppState,
    file: &crate::state::FileEntry,
    pf: &crate::artifacts::prefetch::PrefetchEntry,
) -> usize {
    use crate::state::{TimelineEntry, TimelineEventType};

    let mut added = 0usize;
    for (idx, ts) in pf.last_run_times.iter().enumerate() {
        let detail = format!(
            "{} executed (run {} of {})",
            pf.executable_name,
            idx + 1,
            pf.last_run_times.len()
        );

        let exists = state.timeline_entries.iter().any(|entry| {
            matches!(entry.event_type, TimelineEventType::ProcessExecuted)
                && entry.path == file.path
                && entry.timestamp.timestamp() == ts.timestamp()
        });
        if exists {
            continue;
        }

        let suspicious =
            is_prefetch_suspicious(&pf.executable_name, &file.path, &pf.file_references);
        state.timeline_entries.push(TimelineEntry {
            timestamp: *ts,
            event_type: TimelineEventType::ProcessExecuted,
            path: file.path.clone(),
            evidence_id: file.evidence_id.clone(),
            detail,
            file_id: Some(file.id.clone()),
            suspicious,
        });
        added += 1;
    }

    if added > 0 {
        state.timeline_entries.sort_by_key(|e| e.timestamp);
        state.suspicious_event_count = state
            .timeline_entries
            .iter()
            .filter(|e| e.suspicious)
            .count();
    }

    added
}

fn is_prefetch_suspicious(executable_name: &str, pf_path: &str, file_refs: &[String]) -> bool {
    let exe = executable_name.to_lowercase();
    let p = pf_path.to_lowercase();
    let refs_suspicious = file_refs.iter().any(|r| {
        let lr = r.to_lowercase();
        (lr.contains("\\users\\") && lr.contains("\\downloads\\"))
            || (lr.contains("\\users\\") && lr.contains("\\appdata\\local\\temp\\"))
            || lr.contains("\\programdata\\")
            || lr.contains("mimikatz")
            || lr.contains("meterpreter")
            || lr.contains("cobalt")
    });
    exe.contains("mimikatz")
        || exe.contains("meterpreter")
        || exe.contains("cobalt")
        || p.contains("/users/") && p.contains("/downloads/")
        || p.contains("/users/") && p.contains("/appdata/local/temp/")
        || p.contains("/programdata/")
        || refs_suspicious
}

fn render_browser_preview(
    ui: &mut egui::Ui,
    state: &AppState,
    f: &crate::state::FileEntry,
    t: &crate::theme::StrataTheme,
) {
    let data = match read_all(state, f) {
        Ok(d) => d,
        Err(e) => {
            ui.label(
                egui::RichText::new(format!("Cannot read browser DB: {}", e))
                    .color(t.flagged)
                    .size(8.5),
            );
            return;
        }
    };

    match crate::artifacts::browser::parse_browser_db_bytes(&f.path, &data) {
        Ok(bundle) => {
            meta_line(ui, "Visits Parsed", &bundle.history.len().to_string(), t);
            meta_line(
                ui,
                "Downloads Parsed",
                &bundle.downloads.len().to_string(),
                t,
            );

            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("Recent Visits")
                    .color(t.muted)
                    .size(8.5),
            );
            for visit in bundle.history.iter().take(20) {
                let ts = visit
                    .visit_time
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                let title = visit.title.as_deref().unwrap_or("(no title)");
                ui.label(
                    egui::RichText::new(format!("{} | {} | {}", ts, visit.browser, visit.url))
                        .size(8.0)
                        .monospace()
                        .color(t.secondary),
                );
                ui.label(
                    egui::RichText::new(format!(
                        "title={} visits={} typed={} transition={}",
                        title, visit.visit_count, visit.typed_count, visit.transition
                    ))
                    .size(7.8)
                    .monospace()
                    .color(t.muted),
                );
            }

            if !bundle.downloads.is_empty() {
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new("Recent Downloads")
                        .color(t.muted)
                        .size(8.5),
                );
                for dl in bundle.downloads.iter().take(20) {
                    let ts = dl
                        .start_time
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                    ui.label(
                        egui::RichText::new(format!(
                            "{} | {} | {} bytes | {}",
                            ts, dl.state, dl.total_bytes, dl.url
                        ))
                        .size(8.0)
                        .monospace()
                        .color(t.secondary),
                    );
                    ui.label(
                        egui::RichText::new(format!("target={}", dl.target_path))
                            .size(7.8)
                            .monospace()
                            .color(t.muted),
                    );
                }
            }
        }
        Err(err) => {
            ui.label(
                egui::RichText::new(format!("Browser parse note: {}", err))
                    .color(t.suspicious)
                    .size(8.5),
            );
        }
    }
}

fn render_evtx_preview(
    ui: &mut egui::Ui,
    state: &mut AppState,
    f: &crate::state::FileEntry,
    t: &crate::theme::StrataTheme,
) {
    let data = match read_all(state, f) {
        Ok(d) => d,
        Err(e) => {
            ui.label(
                egui::RichText::new(format!("Cannot read EVTX: {}", e))
                    .color(t.flagged)
                    .size(8.5),
            );
            return;
        }
    };

    match crate::artifacts::evtx::parse_evtx_bytes(&f.path, &data, 1200) {
        Ok(events) => {
            let high_value = events
                .iter()
                .filter(|evt| crate::artifacts::evtx::is_high_value_event_id(evt.event_id))
                .count();
            let suspicious = events
                .iter()
                .filter(|evt| crate::artifacts::evtx::is_suspicious_event(evt))
                .count();
            meta_line(ui, "Events Parsed", &events.len().to_string(), t);
            meta_line(ui, "High-value IDs", &high_value.to_string(), t);
            meta_line(ui, "Suspicious", &suspicious.to_string(), t);

            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("Recent Events")
                    .color(t.muted)
                    .size(8.5),
            );
            for event in events.iter().take(25) {
                let ts = event
                    .timestamp
                    .map(|ev_t| ev_t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                    .unwrap_or_else(|| "-".to_string());
                let color = if crate::artifacts::evtx::is_suspicious_event(event) {
                    t.flagged
                } else if crate::artifacts::evtx::is_high_value_event_id(event.event_id) {
                    t.suspicious
                } else {
                    t.secondary
                };
                ui.label(
                    egui::RichText::new(format!(
                        "{} | {} | {} | {} | {}",
                        ts, event.event_id, event.channel, event.provider, event.summary
                    ))
                    .size(8.0)
                    .monospace()
                    .color(color),
                );
            }
        }
        Err(err) => {
            ui.label(
                egui::RichText::new(format!("EVTX parse note: {}", err))
                    .color(t.suspicious)
                    .size(8.5),
            );
        }
    }
}

fn render_exif_metadata(ui: &mut egui::Ui, data: &[u8], t: &crate::theme::StrataTheme) {
    let mut cursor = std::io::Cursor::new(data);
    let exif = exif::Reader::new().read_from_container(&mut cursor);
    let Ok(exif) = exif else {
        ui.label(
            egui::RichText::new("No EXIF metadata found.")
                .color(t.muted)
                .size(8.5),
        );
        return;
    };

    let make = exif
        .get_field(exif::Tag::Make, exif::In::PRIMARY)
        .map(|f| f.display_value().with_unit(&exif).to_string())
        .unwrap_or_else(|| "—".to_string());
    let model = exif
        .get_field(exif::Tag::Model, exif::In::PRIMARY)
        .map(|f| f.display_value().with_unit(&exif).to_string())
        .unwrap_or_else(|| "—".to_string());
    let date_original = exif
        .get_field(exif::Tag::DateTimeOriginal, exif::In::PRIMARY)
        .or_else(|| exif.get_field(exif::Tag::DateTime, exif::In::PRIMARY))
        .map(|f| f.display_value().with_unit(&exif).to_string())
        .unwrap_or_else(|| "—".to_string());
    let software = exif
        .get_field(exif::Tag::Software, exif::In::PRIMARY)
        .map(|f| f.display_value().with_unit(&exif).to_string())
        .unwrap_or_else(|| "—".to_string());

    meta_line(ui, "Make", &make, t);
    meta_line(ui, "Model", &model, t);
    meta_line(ui, "Date/Time Original", &date_original, t);
    meta_line(ui, "Software", &software, t);

    let lat = gps_decimal(
        exif.get_field(exif::Tag::GPSLatitude, exif::In::PRIMARY),
        exif.get_field(exif::Tag::GPSLatitudeRef, exif::In::PRIMARY),
    );
    let lon = gps_decimal(
        exif.get_field(exif::Tag::GPSLongitude, exif::In::PRIMARY),
        exif.get_field(exif::Tag::GPSLongitudeRef, exif::In::PRIMARY),
    );

    if let (Some(lat), Some(lon)) = (lat, lon) {
        let lat_hemi = if lat >= 0.0 { "N" } else { "S" };
        let lon_hemi = if lon >= 0.0 { "E" } else { "W" };
        let formatted = format!(
            "Lat: {:.4}° {}  Lon: {:.4}° {}",
            lat.abs(),
            lat_hemi,
            lon.abs(),
            lon_hemi
        );
        ui.colored_label(t.suspicious, "LOCATION DATA EMBEDDED");
        ui.label(
            egui::RichText::new(formatted.clone())
                .color(t.active)
                .monospace()
                .size(8.5),
        );
        if ui.button("Copy coordinates").clicked() {
            ui.ctx().copy_text(formatted);
        }
    }
}

fn meta_line(ui: &mut egui::Ui, label: &str, value: &str, t: &crate::theme::StrataTheme) {
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(label).color(t.muted).size(8.5));
        ui.label(
            egui::RichText::new(value)
                .color(t.secondary)
                .size(8.5)
                .monospace(),
        );
    });
}

fn gps_decimal(value: Option<&exif::Field>, reference: Option<&exif::Field>) -> Option<f64> {
    let val = value?;
    let exif::Value::Rational(parts) = &val.value else {
        return None;
    };
    if parts.len() < 3 {
        return None;
    }
    let deg = parts[0].to_f64();
    let min = parts[1].to_f64();
    let sec = parts[2].to_f64();
    let mut decimal = deg + (min / 60.0) + (sec / 3600.0);

    if let Some(reference) = reference {
        let sign = reference.display_value().to_string();
        if sign.eq_ignore_ascii_case("S") || sign.eq_ignore_ascii_case("W") {
            decimal = -decimal;
        }
    }
    Some(decimal)
}

fn read_first(state: &AppState, f: &crate::state::FileEntry, n: usize) -> Vec<u8> {
    if let Some(ctx) = state.vfs_context.as_deref() {
        if let Ok(data) = ctx.read_range(f, 0, n) {
            return data;
        }
    }
    Vec::new()
}

fn read_all(state: &AppState, f: &crate::state::FileEntry) -> Result<Vec<u8>, String> {
    if let Some(ctx) = state.vfs_context.as_deref() {
        return ctx.read_file(f).map_err(|e| e.to_string());
    }
    Err("VFS read context unavailable".to_string())
}

fn fmt_size(b: u64) -> String {
    const GB: u64 = 1 << 30;
    const MB: u64 = 1 << 20;
    const KB: u64 = 1 << 10;
    if b >= GB {
        format!("{:.1} GB ({} bytes)", b as f64 / GB as f64, b)
    } else if b >= MB {
        format!("{:.1} MB ({} bytes)", b as f64 / MB as f64, b)
    } else if b >= KB {
        format!("{:.0} KB ({} bytes)", b as f64 / KB as f64, b)
    } else {
        format!("{} bytes", b)
    }
}

fn parse_carved_offset(f: &crate::state::FileEntry) -> Option<u64> {
    let name = f.name.to_lowercase();
    let marker = "carved_";
    let pos = name.find(marker)?;
    let rest = &name[(pos + marker.len())..];
    let hex = rest.split('.').next().unwrap_or("");
    if hex.is_empty() {
        return None;
    }
    u64::from_str_radix(hex, 16).ok()
}

fn is_prefetch_file(f: &crate::state::FileEntry) -> bool {
    if matches!(f.category.as_deref(), Some("Prefetch")) {
        return true;
    }
    f.extension
        .as_deref()
        .map(|e| e.eq_ignore_ascii_case("pf"))
        .unwrap_or(false)
}

fn is_lnk_file(f: &crate::state::FileEntry) -> bool {
    if matches!(f.category.as_deref(), Some("LNK Shortcut")) {
        return true;
    }
    f.extension
        .as_deref()
        .map(|e| e.eq_ignore_ascii_case("lnk"))
        .unwrap_or(false)
}

fn is_browser_history_db(f: &crate::state::FileEntry) -> bool {
    if matches!(f.category.as_deref(), Some("Browser History")) {
        return true;
    }
    let p = f.path.replace('\\', "/").to_lowercase();
    p.contains("/appdata/local/google/chrome/user data/")
        || p.contains("/appdata/local/microsoft/edge/user data/")
        || p.contains("/appdata/roaming/mozilla/firefox/profiles/")
}

fn is_event_log_file(f: &crate::state::FileEntry) -> bool {
    if matches!(f.category.as_deref(), Some("Event Log")) {
        return true;
    }
    if f.extension
        .as_deref()
        .map(|e| e.eq_ignore_ascii_case("evtx"))
        .unwrap_or(false)
    {
        return true;
    }
    let p = f.path.replace('\\', "/").to_lowercase();
    p.contains("/windows/system32/winevt/logs/")
}

fn render_hash_match(
    ui: &mut egui::Ui,
    f: &crate::state::FileEntry,
    state: &mut crate::state::AppState,
    t: &crate::theme::StrataTheme,
) {
    let flag = f.hash_flag.as_deref().unwrap_or("Unknown");
    let (banner_color, risk_label) = match flag {
        "KnownBad" => (egui::Color32::from_rgb(0xef, 0x44, 0x44), "CRITICAL"),
        "KnownGood" => (egui::Color32::from_rgb(0x4a, 0xde, 0x80), "SAFE"),
        "Notable" => (egui::Color32::from_rgb(0xf5, 0x9e, 0x0b), "NOTABLE"),
        _ => (t.muted, "UNKNOWN"),
    };

    // Banner
    egui::Frame::none()
        .fill(egui::Color32::from_rgba_unmultiplied(
            banner_color.r(), banner_color.g(), banner_color.b(), 30,
        ))
        .stroke(egui::Stroke::new(1.0, banner_color))
        .inner_margin(egui::Margin::symmetric(12.0, 8.0))
        .rounding(6.0)
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(format!("\u{26A0} HASH MATCH DETECTED — {}", flag.to_uppercase()))
                    .color(banner_color)
                    .size(12.0)
                    .strong(),
            );
        });

    ui.add_space(8.0);

    egui::Grid::new("hash_match_grid")
        .num_columns(2)
        .spacing([8.0, 6.0])
        .show(ui, |ui| {
            ui.label(egui::RichText::new("File").color(t.muted).size(9.5));
            ui.label(egui::RichText::new(&f.name).color(t.text).size(10.0));
            ui.end_row();

            ui.label(egui::RichText::new("SHA-256").color(t.muted).size(9.5));
            ui.label(
                egui::RichText::new(f.sha256.as_deref().unwrap_or("—"))
                    .color(t.text)
                    .size(9.0)
                    .monospace(),
            );
            ui.end_row();

            ui.label(egui::RichText::new("Match").color(t.muted).size(9.5));
            ui.label(
                egui::RichText::new(flag.to_uppercase())
                    .color(banner_color)
                    .size(10.0)
                    .strong(),
            );
            ui.end_row();

            ui.label(egui::RichText::new("Risk").color(t.muted).size(9.5));
            ui.label(
                egui::RichText::new(risk_label)
                    .color(banner_color)
                    .size(10.0)
                    .strong(),
            );
            ui.end_row();

            ui.label(egui::RichText::new("Category").color(t.muted).size(9.5));
            ui.label(
                egui::RichText::new(f.category.as_deref().unwrap_or("—"))
                    .color(t.text)
                    .size(10.0),
            );
            ui.end_row();
        });

    ui.add_space(12.0);

    // Action buttons
    ui.horizontal(|ui| {
        if ui.button("Bookmark").clicked() {
            let examiner = state.examiner_name.clone();
            state.bookmarks.push(crate::state::Bookmark {
                id: uuid::Uuid::new_v4().to_string(),
                file_id: Some(f.id.clone()),
                registry_path: None,
                tag: flag.to_uppercase(),
                examiner,
                note: format!("Hash match: {}", flag),
                created_utc: chrono::Utc::now()
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            });
            state.mark_case_dirty();
            state.log_action("HASH_MATCH_BOOKMARK", &format!("file={} flag={}", f.path, flag));
        }
        if ui.button("Add to Report").clicked() {
            state.bookmarks.push(crate::state::Bookmark {
                id: uuid::Uuid::new_v4().to_string(),
                file_id: Some(f.id.clone()),
                registry_path: None,
                tag: "REPORT".to_string(),
                examiner: state.examiner_name.clone(),
                note: format!("Hash match: {} — added to report", flag),
                created_utc: chrono::Utc::now()
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            });
            state.mark_case_dirty();
            state.log_action("HASH_MATCH_REPORT", &format!("file={} flag={}", f.path, flag));
        }
    });
}

// ─── DETAILS tab — forensic artifact knowledge ─────────────────────────────

fn render_details_tab(
    ui: &mut egui::Ui,
    f: &crate::state::FileEntry,
    t: &crate::theme::StrataTheme,
) {
    let knowledge = strata_core::knowledge_bank::lookup_knowledge(&f.name, &f.path);

    let Some(k) = knowledge else {
        ui.vertical_centered(|ui| {
            ui.add_space(ui.available_height() / 3.0);
            ui.label(
                egui::RichText::new("No artifact context available for this file type.")
                    .color(t.muted)
                    .size(10.0),
            );
        });
        return;
    };

    // Artifact name header
    ui.label(
        egui::RichText::new(k.name)
            .color(t.active)
            .size(13.0)
            .strong(),
    );
    ui.add_space(2.0);
    ui.separator();
    ui.add_space(4.0);

    // WHAT IT IS
    details_section(ui, t, "WHAT IT IS", k.description);

    // FORENSIC VALUE
    details_section(ui, t, "FORENSIC VALUE", k.forensic_value);

    // COMMON LOCATIONS
    if !k.locations.is_empty() {
        ui.label(
            egui::RichText::new("COMMON LOCATIONS")
                .color(t.active)
                .size(9.0)
                .strong(),
        );
        ui.add_space(2.0);
        for loc in k.locations {
            ui.label(
                egui::RichText::new(format!("  {}", loc))
                    .color(t.secondary)
                    .size(9.0)
                    .monospace(),
            );
        }
        ui.add_space(4.0);
        ui.separator();
        ui.add_space(4.0);
    }

    // WHAT TO LOOK FOR
    details_section(ui, t, "WHAT TO LOOK FOR", k.what_to_look_for);

    // MITRE ATT&CK
    if !k.mitre_techniques.is_empty() {
        ui.horizontal_wrapped(|ui| {
            ui.label(
                egui::RichText::new("MITRE:")
                    .color(t.active)
                    .size(9.0)
                    .strong(),
            );
            for tech in k.mitre_techniques {
                egui::Frame::none()
                    .fill(t.elevated)
                    .rounding(3.0)
                    .inner_margin(egui::Margin::symmetric(5.0, 2.0))
                    .show(ui, |ui| {
                        ui.label(
                            egui::RichText::new(*tech)
                                .color(t.secondary)
                                .size(8.5)
                                .monospace(),
                        );
                    });
            }
        });
        ui.add_space(4.0);
    }

    // RELATED ARTIFACTS
    if !k.related_artifacts.is_empty() {
        ui.horizontal_wrapped(|ui| {
            ui.label(
                egui::RichText::new("RELATED:")
                    .color(t.active)
                    .size(9.0)
                    .strong(),
            );
            for artifact in k.related_artifacts {
                egui::Frame::none()
                    .fill(t.elevated)
                    .rounding(3.0)
                    .inner_margin(egui::Margin::symmetric(5.0, 2.0))
                    .show(ui, |ui| {
                        ui.label(
                            egui::RichText::new(*artifact)
                                .color(t.muted)
                                .size(8.5),
                        );
                    });
            }
        });
    }
}

fn details_section(
    ui: &mut egui::Ui,
    t: &crate::theme::StrataTheme,
    heading: &str,
    body: &str,
) {
    ui.label(
        egui::RichText::new(heading)
            .color(t.active)
            .size(9.0)
            .strong(),
    );
    ui.add_space(2.0);
    ui.label(
        egui::RichText::new(body)
            .color(t.secondary)
            .size(9.5),
    );
    ui.add_space(4.0);
    ui.separator();
    ui.add_space(4.0);
}
