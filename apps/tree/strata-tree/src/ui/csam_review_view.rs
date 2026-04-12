//! CSAM Review Mode — dedicated view for CSAM scan results.
//!
//! Safety guarantees:
//! - No auto-display of images. "Review Image" requires explicit click.
//! - Every image reveal is logged in the audit trail.
//! - All hits route through `publish_csam_plugin_output()` in state_csam.rs.
//! - The detail format `[match_type=X] [confidence=Y] ...` is never modified here.

use crate::state::AppState;

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    let t = *state.theme();

    ui.heading(
        egui::RichText::new("CSAM REVIEW")
            .color(t.csam_alert)
            .strong(),
    );
    let case_name = state
        .case
        .as_ref()
        .map(|c| c.name.as_str())
        .unwrap_or("No Case");
    ui.label(
        egui::RichText::new(case_name)
            .color(t.secondary)
            .size(crate::theme::FONT_CAPTION),
    );
    ui.separator();

    // ── Status panel ──
    let scan_complete = !state.csam_scan_running;
    let hit_count = state.csam_hits.len();
    let confirmed = state
        .csam_hits
        .iter()
        .filter(|h| h.examiner_confirmed)
        .count();
    let reviewed_not_confirmed = state
        .csam_hits
        .iter()
        .filter(|h| h.examiner_reviewed && !h.examiner_confirmed)
        .count();
    let pending = hit_count - confirmed - reviewed_not_confirmed;

    egui::Frame::none()
        .fill(t.card)
        .stroke(egui::Stroke::new(1.0, t.border))
        .inner_margin(egui::Margin::same(8.0))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(if scan_complete {
                    format!("Scan: Complete ({} files scanned)", state.total_files_count)
                } else {
                    "Scan: Running...".to_string()
                })
                .color(t.secondary)
                .size(crate::theme::FONT_BODY),
            );
            ui.label(
                egui::RichText::new(format!(
                    "Hits: {} confirmed  ·  {} pending review  ·  {} dismissed",
                    confirmed, pending, reviewed_not_confirmed
                ))
                .color(if hit_count > 0 {
                    t.csam_alert
                } else {
                    t.secondary
                })
                .size(crate::theme::FONT_BODY),
            );
        });

    if hit_count == 0 {
        ui.add_space(16.0);
        ui.label(
            egui::RichText::new(if scan_complete {
                "No CSAM hits detected."
            } else {
                "Scan in progress — results will appear here."
            })
            .color(t.muted),
        );
        render_reporting_notice(ui, &t);
        return;
    }

    ui.add_space(8.0);

    // ── Hit table ──
    ui.label(
        egui::RichText::new("HIT TABLE")
            .color(t.secondary)
            .strong()
            .size(crate::theme::FONT_CAPTION),
    );

    let hits: Vec<(String, String, String, String, bool, bool)> = state
        .csam_hits
        .iter()
        .map(|h| {
            (
                h.hit_id.to_string(),
                h.file_path.clone(),
                h.sha256.clone(),
                format!("{:?}", h.match_type),
                h.examiner_confirmed,
                h.examiner_reviewed,
            )
        })
        .collect();
    let selected_pending = state.csam_pending_review.clone();

    egui::ScrollArea::vertical()
        .max_height(ui.available_height() * 0.45)
        .show(ui, |ui| {
            for (hit_id, path, sha256, match_type, is_confirmed, is_reviewed) in &hits {
                let status_icon = if *is_confirmed {
                    "●"
                } else if *is_reviewed {
                    "✕"
                } else {
                    "○"
                };
                let status_color = if *is_confirmed {
                    t.csam_alert
                } else if *is_reviewed {
                    t.muted
                } else {
                    t.suspicious
                };
                let is_selected = selected_pending.as_deref() == Some(hit_id.as_str());
                let row_bg = if is_selected {
                    t.selection
                } else {
                    egui::Color32::TRANSPARENT
                };

                let resp = egui::Frame::none()
                    .fill(row_bg)
                    .inner_margin(egui::Margin::symmetric(4.0, 1.0))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(status_icon).color(status_color));
                            ui.label(
                                egui::RichText::new(path)
                                    .color(t.text)
                                    .size(crate::theme::FONT_BODY)
                                    .monospace(),
                            );
                            ui.label(
                                egui::RichText::new(&sha256[..16.min(sha256.len())])
                                    .color(t.muted)
                                    .size(crate::theme::FONT_CAPTION)
                                    .monospace(),
                            );
                            ui.label(
                                egui::RichText::new(match_type)
                                    .color(t.secondary)
                                    .size(crate::theme::FONT_CAPTION),
                            );
                        });
                    })
                    .response;

                if resp.clicked() {
                    state.csam_pending_review = Some(hit_id.clone());
                }
            }
        });

    ui.separator();

    // ── Selected hit detail ──
    if let Some(ref selected_id) = state.csam_pending_review.clone() {
        if let Some(hit_idx) = state
            .csam_hits
            .iter()
            .position(|h| h.hit_id.to_string() == *selected_id)
        {
            let path = state.csam_hits[hit_idx].file_path.clone();
            let sha256 = state.csam_hits[hit_idx].sha256.clone();
            let match_type = format!("{:?}", state.csam_hits[hit_idx].match_type);
            let confidence = format!("{:?}", state.csam_hits[hit_idx].confidence);

            egui::Frame::none()
                .fill(t.card)
                .stroke(egui::Stroke::new(1.0, t.border))
                .inner_margin(egui::Margin::same(8.0))
                .show(ui, |ui| {
                    ui.label(
                        egui::RichText::new(format!("Path: {}", path))
                            .color(t.text)
                            .monospace(),
                    );
                    ui.label(
                        egui::RichText::new(format!("SHA-256: {}", sha256))
                            .color(t.secondary)
                            .monospace(),
                    );
                    ui.label(
                        egui::RichText::new(format!(
                            "Match: {} | Confidence: {}",
                            match_type, confidence,
                        ))
                        .color(t.secondary),
                    );

                    ui.add_space(8.0);
                    ui.label(
                        egui::RichText::new(
                            "⚠ IMAGE NOT DISPLAYED — explicit examiner action required.",
                        )
                        .color(t.csam_alert)
                        .strong(),
                    );

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Confirm").clicked() {
                            state.csam_hits[hit_idx].examiner_confirmed = true;
                            state.csam_hits[hit_idx].examiner_reviewed = true;
                            state.log_action(
                                "CSAM_CONFIRM",
                                &format!("hit_id={} path={}", selected_id, path),
                            );
                            state.mark_case_dirty();
                        }
                        if ui.button("Dismiss").clicked() {
                            state.csam_hits[hit_idx].examiner_reviewed = true;
                            state.csam_hits[hit_idx].examiner_confirmed = false;
                            state.log_action(
                                "CSAM_DISMISS",
                                &format!("hit_id={} path={}", selected_id, path),
                            );
                            state.mark_case_dirty();
                        }
                        if ui.button("Review Image").clicked() {
                            state.log_action(
                                "CSAM_IMAGE_REVIEW",
                                &format!(
                                    "hit_id={} path={} sha256={}",
                                    selected_id, path, sha256,
                                ),
                            );
                        }
                    });
                });
        }
    }

    render_reporting_notice(ui, &t);
}

fn render_reporting_notice(ui: &mut egui::Ui, t: &crate::theme::StrataTheme) {
    ui.add_space(8.0);
    egui::Frame::none()
        .fill(t.card)
        .stroke(egui::Stroke::new(1.0, t.csam_alert))
        .inner_margin(egui::Margin::same(8.0))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(
                    "18 U.S.C. § 2258A: Electronic service providers and certain persons \
                     are required to report apparent CSAM to NCMEC.",
                )
                .color(t.csam_alert)
                .size(crate::theme::FONT_CAPTION),
            );
        });
}
