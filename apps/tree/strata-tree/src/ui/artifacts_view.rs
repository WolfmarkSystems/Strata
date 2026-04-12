//! Artifacts panel — 3-pane Axiom-style: categories | results | detail.

use crate::state::{colors::*, AppState};

struct ArtifactCategory {
    name: &'static str,
    icon: &'static str,
    subcategories: &'static [&'static str],
}

const CATEGORIES: &[ArtifactCategory] = &[
    ArtifactCategory { name: "Communications",          icon: "\u{1F4AC}", subcategories: &["iMessage/SMS", "WhatsApp", "Signal", "Telegram", "Facebook Messenger", "Email"] },
    ArtifactCategory { name: "Social Media",            icon: "\u{1F4F1}", subcategories: &["Facebook", "Instagram", "Twitter/X", "Snapchat", "TikTok"] },
    ArtifactCategory { name: "Web Activity",            icon: "\u{1F310}", subcategories: &["Browser History", "Downloads", "Searches", "Cookies"] },
    ArtifactCategory { name: "User Activity",           icon: "\u{1F464}", subcategories: &["Recent Files", "Installed Apps", "USB Devices", "Prefetch Executions", "UserAssist"] },
    ArtifactCategory { name: "System Activity",         icon: "\u{2699}",  subcategories: &["Event Logs", "Services", "Scheduled Tasks", "Startup Items", "BITS Jobs"] },
    ArtifactCategory { name: "Cloud & Sync",            icon: "\u{2601}",  subcategories: &["OneDrive", "Google Drive", "iCloud", "Dropbox"] },
    ArtifactCategory { name: "Accounts & Credentials",  icon: "\u{1F511}", subcategories: &["Saved Passwords", "WiFi Networks", "User Accounts", "SSH Keys"] },
    ArtifactCategory { name: "Media",                   icon: "\u{1F5BC}", subcategories: &["Images", "Videos", "Audio"] },
    ArtifactCategory { name: "Deleted & Recovered",     icon: "\u{1F5D1}", subcategories: &["Recycle Bin", "Carved Files", "Shadow Copy Items"] },
    ArtifactCategory { name: "Execution History",       icon: "\u{25B6}",  subcategories: &["Prefetch Executions", "AmCache Entries", "ShimCache Entries", "LOLBIN Detections", "Correlated Executions"] },
    ArtifactCategory { name: "Network Artifacts",       icon: "\u{1F517}", subcategories: &["DNS Queries", "Network Connections", "PCAP Artifacts", "Firewall Logs"] },
    ArtifactCategory { name: "Encryption & Keys",       icon: "\u{1F510}", subcategories: &["Certificates", "Private Keys", "Encrypted Containers", "BitLocker Metadata"] },
];

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    let t = *state.theme();

    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("ARTIFACTS")
                .color(t.active)
                .size(11.0)
                .strong(),
        );
        ui.separator();
        ui.label(
            egui::RichText::new(format!("{} total", state.artifact_total))
                .color(t.muted)
                .size(9.5),
        );
    });
    ui.add_space(4.0);

    render_obstruction_gauge(ui, state, &t);
    ui.add_space(4.0);

    if state.artifact_total == 0 && state.artifact_counts.is_empty() {
        ui.add_space(20.0);
        ui.label(egui::RichText::new("No artifacts parsed yet.").color(t.muted).size(10.0));
        ui.add_space(8.0);
        ui.label(egui::RichText::new("Run artifact plugins to populate categories.").color(t.muted).size(9.0));
        ui.add_space(12.0);
        if ui.button(egui::RichText::new("Open Plugins \u{2192}").color(t.active)).clicked() {
            state.view_mode = crate::state::ViewMode::Plugins;
        }
        return;
    }

    let total_w = ui.available_width();
    let cat_w = total_w * 0.20;
    let results_w = total_w * 0.48;
    let detail_w = total_w * 0.30;

    ui.horizontal(|ui| {
        // ── LEFT: Category tree ──────────────────────────────────────────
        ui.vertical(|ui| {
            ui.set_width(cat_w);
            ui.label(egui::RichText::new("ARTIFACT CATEGORIES").color(t.muted).size(8.5).strong());
            ui.add_space(4.0);

            egui::ScrollArea::vertical().id_source("artifact_cats").show(ui, |ui| {
                for category in CATEGORIES {
                    let total_count: usize = category.subcategories.iter()
                        .map(|sub| state.artifact_counts.get(*sub).copied().unwrap_or(0))
                        .sum();

                    let is_active = state.active_tag == category.name;
                    let text_color = if is_active { t.text } else if total_count > 0 { t.secondary } else { t.muted };
                    let _count_color = if total_count > 0 { t.active } else { t.muted };

                    let resp = ui.selectable_label(
                        is_active,
                        egui::RichText::new(format!("{} {}  {}", category.icon, category.name, total_count))
                            .color(text_color)
                            .size(11.0),
                    );
                    if resp.clicked() {
                        state.active_tag = category.name.to_string();
                        state.selected_artifact_idx = None;
                    }
                }
            });
        });

        ui.add_space(4.0);

        // ── CENTER: Results table ────────────────────────────────────────
        ui.vertical(|ui| {
            ui.set_width(results_w);

            let active_cat = CATEGORIES.iter().find(|c| c.name == state.active_tag);
            if let Some(cat) = active_cat {
                let records: Vec<&strata_plugin_sdk::ArtifactRecord> = state.plugin_results.iter()
                    .flat_map(|o| o.artifacts.iter())
                    .filter(|r| { let c = r.category.as_str(); c == cat.name || cat.subcategories.iter().any(|s| r.subcategory == *s || c == *s) })
                    .take(500)
                    .collect();

                ui.label(egui::RichText::new(format!("{} \u{2014} {} results", cat.name, records.len())).color(t.active).size(10.0).strong());
                ui.add_space(4.0);

                // Column headers
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("NAME").color(t.muted).size(8.5).strong());
                    ui.add_space(results_w * 0.35);
                    ui.label(egui::RichText::new("VALUE").color(t.muted).size(8.5).strong());
                    ui.add_space(results_w * 0.2);
                    ui.label(egui::RichText::new("TIMESTAMP").color(t.muted).size(8.5).strong());
                });
                ui.separator();

                egui::ScrollArea::vertical().id_source("artifact_results").show(ui, |ui| {
                    for (idx, record) in records.iter().enumerate() {
                        let is_selected = state.selected_artifact_idx == Some(idx);
                        let value_color = match record.forensic_value {
                            strata_plugin_sdk::ForensicValue::Critical => DANGER,
                            strata_plugin_sdk::ForensicValue::High => AMBER,
                            _ => TEXT_SEC,
                        };

                        let bg = if is_selected { t.elevated } else if idx % 2 == 0 { t.bg } else { t.card };
                        egui::Frame::none().fill(bg).show(ui, |ui| {
                            ui.set_min_height(28.0);
                            ui.horizontal(|ui| {
                                if record.is_suspicious {
                                    ui.label(egui::RichText::new("!").color(AMBER).strong().size(10.0));
                                }
                                let title_short: String = record.title.chars().take(40).collect();
                                ui.label(egui::RichText::new(&title_short).color(value_color).size(10.0));
                                ui.add_space(8.0);
                                let detail_short: String = record.detail.chars().take(30).collect();
                                ui.label(egui::RichText::new(&detail_short).color(t.muted).size(9.0));
                                ui.add_space(8.0);
                                let ts = record.timestamp.map(|ts| {
                                    chrono::DateTime::from_timestamp(ts, 0)
                                        .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                                        .unwrap_or_else(|| ts.to_string())
                                }).unwrap_or_default();
                                ui.label(egui::RichText::new(&ts).color(t.muted).size(8.5));
                            });
                        });
                        let row_rect = ui.min_rect();
                        let click = ui.interact(row_rect, egui::Id::new(format!("artifact_row_{}", idx)), egui::Sense::click());
                        if click.clicked() {
                            state.selected_artifact_idx = Some(idx);
                        }
                    }
                });
            } else {
                ui.vertical_centered(|ui| {
                    ui.add_space(ui.available_height() / 3.0);
                    ui.label(egui::RichText::new("Select a category").color(t.muted).size(12.0));
                });
            }
        });

        ui.add_space(4.0);

        // ── RIGHT: Record detail ─────────────────────────────────────────
        ui.vertical(|ui| {
            ui.set_width(detail_w);
            egui::Frame::none()
                .fill(t.card)
                .stroke(egui::Stroke::new(1.0, t.border))
                .rounding(crate::theme::RADIUS_MD)
                .inner_margin(egui::Margin::symmetric(10.0, 8.0))
                .show(ui, |ui| {
                    ui.set_min_height(200.0);
                    ui.label(egui::RichText::new("ARTIFACT DETAIL").color(t.muted).size(8.5).strong());
                    ui.add_space(4.0);

                    // Find the selected record
                    let active_cat = CATEGORIES.iter().find(|c| c.name == state.active_tag);
                    let selected_record = active_cat.and_then(|cat| {
                        let records: Vec<&strata_plugin_sdk::ArtifactRecord> = state.plugin_results.iter()
                            .flat_map(|o| o.artifacts.iter())
                            .filter(|r| { let c = r.category.as_str(); c == cat.name || cat.subcategories.iter().any(|s| r.subcategory == *s || c == *s) })
                            .take(500)
                            .collect();
                        state.selected_artifact_idx.and_then(|idx| records.get(idx).copied())
                    });

                    if let Some(record) = selected_record {
                        ui.label(egui::RichText::new(&record.title).color(t.text).size(13.0).strong());
                        ui.label(egui::RichText::new(format!("{} \u{2022} {}", record.category.as_str(), record.subcategory)).color(t.muted).size(9.0));
                        ui.add_space(8.0);

                        egui::ScrollArea::vertical().id_source("artifact_detail").show(ui, |ui| {
                            // Key-value fields
                            detail_field(ui, &t, "Detail", &record.detail);
                            if let Some(ts) = record.timestamp {
                                let formatted = chrono::DateTime::from_timestamp(ts, 0)
                                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                                    .unwrap_or_else(|| ts.to_string());
                                detail_field(ui, &t, "Timestamp", &formatted);
                            }
                            detail_field(ui, &t, "Source", &record.source_path);
                            detail_field(ui, &t, "Category", record.category.as_str());

                            // Forensic value
                            let (fv_label, fv_color) = match record.forensic_value {
                                strata_plugin_sdk::ForensicValue::Critical => ("Critical", DANGER),
                                strata_plugin_sdk::ForensicValue::High => ("High", AMBER),
                                strata_plugin_sdk::ForensicValue::Medium => ("Medium", TEXT_SEC),
                                _ => ("Low", TEXT_MUTED),
                            };
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new("Forensic Value:").color(t.muted).size(9.0));
                                ui.label(egui::RichText::new(fv_label).color(fv_color).size(9.0).strong());
                            });

                            // Confidence badge
                            if record.confidence > 0 {
                                let (conf_label, conf_color) = if record.confidence >= 80 {
                                    ("HIGH", t.clean)
                                } else if record.confidence >= 50 {
                                    ("MED", t.suspicious)
                                } else {
                                    ("LOW", TEXT_MUTED)
                                };
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("Confidence:").color(t.muted).size(9.0));
                                    egui::Frame::none()
                                        .fill(conf_color)
                                        .rounding(3.0)
                                        .inner_margin(egui::Margin::symmetric(5.0, 1.0))
                                        .show(ui, |ui| {
                                            ui.label(egui::RichText::new(
                                                format!("{} {}", record.confidence, conf_label)
                                            ).color(t.bg).size(8.5).strong());
                                        });
                                });
                            }

                            // MITRE technique
                            if let Some(mitre) = &record.mitre_technique {
                                if !mitre.is_empty() {
                                    ui.horizontal(|ui| {
                                        ui.label(egui::RichText::new("MITRE:").color(t.muted).size(9.0));
                                        ui.label(egui::RichText::new(mitre).color(t.active).size(9.0).background_color(t.bg));
                                    });
                                }
                            }

                            // Raw data (collapsed)
                            if let Some(raw) = &record.raw_data {
                                ui.add_space(8.0);
                                egui::CollapsingHeader::new(egui::RichText::new("RAW DATA").color(t.muted).size(8.5))
                                    .default_open(false)
                                    .show(ui, |ui| {
                                        let json_text = serde_json::to_string_pretty(raw).unwrap_or_default();
                                        let display: String = json_text.chars().take(500).collect();
                                        ui.label(egui::RichText::new(display).monospace().size(8.0).color(t.secondary));
                                    });
                            }
                        });
                    } else {
                        ui.vertical_centered(|ui| {
                            ui.add_space(ui.available_height() / 3.0);
                            ui.label(egui::RichText::new("Select an artifact to view details").color(t.muted).size(12.0));
                        });
                    }
                });
        });
    });
}

fn detail_field(ui: &mut egui::Ui, t: &crate::theme::StrataTheme, key: &str, value: &str) {
    if value.is_empty() { return; }
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(format!("{}:", key)).color(t.muted).size(9.0));
        ui.label(egui::RichText::new(value).color(t.text).size(9.0));
    });
}

fn render_obstruction_gauge(
    ui: &mut egui::Ui,
    state: &AppState,
    t: &crate::theme::StrataTheme,
) {
    let assessment = match &state.obstruction_assessment {
        Some(a) if a.score > 0 => a,
        _ => return,
    };

    let gauge_color = match assessment.score {
        0..=20 => t.muted,
        21..=40 => t.clean,
        41..=60 => t.suspicious,
        61..=80 => egui::Color32::from_rgb(0xe0, 0x70, 0x30),
        _ => t.flagged,
    };

    egui::Frame::none()
        .fill(t.elevated)
        .rounding(crate::theme::RADIUS_MD)
        .inner_margin(egui::Margin::symmetric(10.0, 6.0))
        .stroke(egui::Stroke::new(1.0, t.border))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("ANTI-FORENSIC ACTIVITY")
                        .color(t.muted)
                        .size(8.5)
                        .strong(),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        egui::RichText::new(assessment.severity.label())
                            .color(gauge_color)
                            .size(9.0)
                            .strong(),
                    );
                });
            });
            ui.add_space(2.0);

            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(format!("{}/100", assessment.score))
                        .color(t.text)
                        .size(14.0)
                        .strong(),
                );
                ui.add_space(8.0);

                let avail_w = ui.available_width().min(200.0);
                let (rect, _) =
                    ui.allocate_exact_size(egui::vec2(avail_w, 8.0), egui::Sense::hover());
                ui.painter().rect_filled(rect, 4.0, t.border);
                let fill_w = avail_w * (assessment.score as f32 / 100.0);
                let fill_rect = egui::Rect::from_min_size(rect.min, egui::vec2(fill_w, 8.0));
                ui.painter().rect_filled(fill_rect, 4.0, gauge_color);
            });
            ui.add_space(2.0);

            ui.label(
                egui::RichText::new(format!(
                    "{} contributing factor{}",
                    assessment.factors.len(),
                    if assessment.factors.len() == 1 { "" } else { "s" }
                ))
                .color(t.secondary)
                .size(9.0),
            );
        });
}
