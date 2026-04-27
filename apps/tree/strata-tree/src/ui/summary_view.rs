//! Executive Summary panel — ML-assisted draft review and approval.
//!
//! Three states: Generating / Draft Review / Approved.
//! The summary NEVER auto-populates a report without examiner approval.

use crate::state::AppState;
use strata_ml_summary::{SectionType, SummaryStatus};

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    match &state.generated_summary {
        None if state.summary_generating => {
            render_generating(ui);
        }
        None => {
            render_empty(ui, state);
        }
        Some(summary) => match summary.status {
            SummaryStatus::Draft | SummaryStatus::UnderReview => {
                render_draft_review(ui, state);
            }
            SummaryStatus::Approved => {
                render_approved(ui, state);
            }
            SummaryStatus::Rejected => {
                render_rejected(ui, state);
            }
        },
    }
}

fn render_generating(ui: &mut egui::Ui) {
    ui.heading("EXECUTIVE SUMMARY");
    ui.separator();
    ui.label("Generating executive summary...");
    ui.label("Analyzing artifacts across forensic plugins.");
    ui.spinner();
}

fn render_empty(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading("EXECUTIVE SUMMARY");
    ui.separator();
    ui.label("No executive summary has been generated for this case.");
    ui.label("Run all plugins first, then generate a summary.");

    let has_artifacts = !state.file_index.is_empty();
    ui.add_enabled_ui(has_artifacts, |ui| {
        if ui.button("Generate Summary").clicked() {
            generate_summary(state);
        }
    });
}

fn render_draft_review(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.heading("EXECUTIVE SUMMARY — DRAFT");
        if ui.button("Approve").clicked() {
            state.approve_summary();
        }
        if ui.button("Reject").clicked() {
            state.reject_summary();
        }
        if ui.button("Regenerate").clicked() {
            generate_summary(state);
        }
    });
    ui.separator();
    ui.label(
        egui::RichText::new("ML-ASSISTED DRAFT — Review required before use in any report")
            .color(egui::Color32::from_rgb(230, 160, 0))
            .strong(),
    );
    ui.add_space(8.0);

    render_sections(ui, state);
}

fn render_approved(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.heading(
            egui::RichText::new("EXECUTIVE SUMMARY — APPROVED")
                .color(egui::Color32::from_rgb(100, 200, 100)),
        );
        if ui.button("Revoke Approval").clicked() {
            if let Some(ref mut s) = state.generated_summary {
                s.examiner_approved = false;
                s.status = SummaryStatus::UnderReview;
            }
        }
    });
    ui.separator();
    if let Some(ref summary) = state.generated_summary {
        ui.label(format!(
            "Approved at: {} | Edits: {}",
            summary.generated_at,
            summary.examiner_edits.len()
        ));
    }
    ui.add_space(8.0);

    render_sections(ui, state);
}

fn render_rejected(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.heading(
            egui::RichText::new("EXECUTIVE SUMMARY — REJECTED")
                .color(egui::Color32::from_rgb(200, 80, 80)),
        );
        if ui.button("Regenerate").clicked() {
            generate_summary(state);
        }
    });
    ui.separator();
    ui.label("This summary was rejected by the examiner. Regenerate to create a new draft.");
}

fn render_sections(ui: &mut egui::Ui, state: &mut AppState) {
    let sections: Vec<(SectionType, String, String, bool)> = state
        .generated_summary
        .as_ref()
        .map(|s| {
            s.sections
                .iter()
                .map(|sec| {
                    (
                        sec.section_type.clone(),
                        sec.title.clone(),
                        sec.content.clone(),
                        sec.is_editable,
                    )
                })
                .collect()
        })
        .unwrap_or_default();

    egui::ScrollArea::vertical().show(ui, |ui| {
        for (section_type, title, content, is_editable) in &sections {
            ui.horizontal(|ui| {
                ui.strong(title);
                if *is_editable {
                    ui.label(
                        egui::RichText::new("[editable]")
                            .small()
                            .color(egui::Color32::GRAY),
                    );
                }
            });
            ui.label(content);
            ui.add_space(8.0);

            let _ = (section_type, is_editable);
        }
    });
}

fn generate_summary(state: &mut AppState) {
    let generator = match strata_ml_summary::SummaryGenerator::new() {
        Ok(g) => g,
        Err(e) => {
            tracing::error!("Failed to create summary generator: {}", e);
            return;
        }
    };

    let charges: Vec<strata_ml_summary::ChargeRef> = state
        .selected_charges
        .charges
        .iter()
        .map(|c| strata_ml_summary::ChargeRef {
            citation: c.citation.clone(),
            short_title: c.short_title.clone(),
            artifact_tags: c.artifact_tags.clone(),
        })
        .collect();

    let plugin_outputs: Vec<strata_plugin_sdk::PluginOutput> = state.plugin_results.clone();

    let case_id = state
        .case
        .as_ref()
        .map(|c| c.id.clone())
        .unwrap_or_else(|| "unknown".into());
    let case_number = state
        .case
        .as_ref()
        .map(|c| c.name.clone())
        .unwrap_or_else(|| "unknown".into());
    let device = state
        .evidence_sources
        .first()
        .map(|s| s.path.clone())
        .unwrap_or_else(|| "unknown device".into());

    let input = strata_ml_summary::SummaryInput {
        case_id,
        case_number,
        device_identifier: device,
        examiner_name: state.examiner_name.clone(),
        selected_charges: charges,
        plugin_outputs,
        anomaly_report: None,
        artifact_count: state.total_files_count,
        generated_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    };

    match generator.generate(&input) {
        Ok(summary) => {
            state.generated_summary = Some(summary);
        }
        Err(e) => {
            tracing::error!("Summary generation failed: {}", e);
        }
    }
}

/// Format the approved summary for HTML report inclusion.
/// Returns empty string if no approved summary exists.
#[allow(dead_code)]
pub fn format_summary_html(state: &AppState) -> String {
    let Some(ref summary) = state.generated_summary else {
        return String::new();
    };
    if !summary.examiner_approved {
        return String::new();
    }

    let mut html = String::from(
        "<h2>EXECUTIVE SUMMARY</h2>\n\
         <p class=\"notice\">ML-Assisted Summary — Reviewed and approved by examiner</p>\n",
    );

    for section in &summary.sections {
        if section.section_type == SectionType::AdvisoryNotice {
            continue;
        }
        html.push_str(&format!("<h3>{}</h3>\n", section.title));
        let escaped = section
            .content
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('\n', "<br>\n");
        html.push_str(&format!("<p>{}</p>\n", escaped));
    }

    if !summary.examiner_edits.is_empty() {
        html.push_str(&format!(
            "<p class=\"notice\"><em>Note: {} examiner edit(s) applied to this summary.</em></p>\n",
            summary.examiner_edits.len()
        ));
    }

    html.push_str(
        "<p class=\"notice\"><em>This executive summary was auto-generated from case artifacts \
         and reviewed by the examiner. All claims should be independently verified \
         against source artifacts.</em></p>\n",
    );

    html
}
