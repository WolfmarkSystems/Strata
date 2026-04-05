//! Artifacts panel — categorized view of parsed forensic artifacts.

use crate::state::{colors::*, AppState};

struct ArtifactCategory {
    name: &'static str,
    icon: &'static str,
    subcategories: &'static [&'static str],
}

const CATEGORIES: &[ArtifactCategory] = &[
    ArtifactCategory {
        name: "Communications",
        icon: "\u{E148}",
        subcategories: &["iMessage/SMS", "WhatsApp", "Signal", "Telegram", "Facebook Messenger", "Email"],
    },
    ArtifactCategory {
        name: "Social Media",
        icon: "\u{E730}",
        subcategories: &["Facebook", "Instagram", "Twitter/X", "Snapchat", "TikTok"],
    },
    ArtifactCategory {
        name: "Web Activity",
        icon: "\u{E288}",
        subcategories: &["Browser History", "Downloads", "Searches", "Cookies"],
    },
    ArtifactCategory {
        name: "User Activity",
        icon: "\u{E730}",
        subcategories: &["Recent Files", "Installed Apps", "USB Devices", "Prefetch Executions", "UserAssist"],
    },
    ArtifactCategory {
        name: "System Activity",
        icon: "\u{E270}",
        subcategories: &["Event Logs", "Services", "Scheduled Tasks", "Startup Items", "BITS Jobs"],
    },
    ArtifactCategory {
        name: "Cloud & Sync",
        icon: "\u{E178}",
        subcategories: &["OneDrive", "Google Drive", "iCloud", "Dropbox"],
    },
    ArtifactCategory {
        name: "Accounts & Credentials",
        icon: "\u{E360}",
        subcategories: &["Saved Passwords", "WiFi Networks", "User Accounts", "SSH Keys"],
    },
    ArtifactCategory {
        name: "Media",
        icon: "\u{E2CA}",
        subcategories: &["Images", "Videos", "Audio"],
    },
    ArtifactCategory {
        name: "Deleted & Recovered",
        icon: "\u{E6AC}",
        subcategories: &["Recycle Bin", "Carved Files", "Shadow Copy Items"],
    },
    ArtifactCategory {
        name: "Execution History",
        icon: "\u{E596}",
        subcategories: &["Prefetch Executions", "AmCache Entries", "ShimCache Entries", "LOLBIN Detections", "Correlated Executions"],
    },
    ArtifactCategory {
        name: "Network Artifacts",
        icon: "\u{E288}",
        subcategories: &["DNS Queries", "Network Connections", "PCAP Artifacts", "Firewall Logs"],
    },
    ArtifactCategory {
        name: "Encryption Key Material",
        icon: "\u{E360}",
        subcategories: &["Certificates", "Private Keys", "Encrypted Containers", "BitLocker Metadata"],
    },
];

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("ARTIFACTS")
                .color(ACCENT)
                .size(11.0)
                .strong(),
        );
        ui.separator();
        ui.label(
            egui::RichText::new(format!("{} total", state.artifact_total))
                .color(TEXT_MUTED)
                .size(9.5),
        );
    });
    ui.add_space(4.0);

    if state.artifact_total == 0 && state.artifact_counts.is_empty() {
        ui.add_space(20.0);
        ui.label(
            egui::RichText::new("No artifacts parsed yet.")
                .color(TEXT_MUTED)
                .size(10.0),
        );
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new(
                "Run artifact plugins to populate categories.\nUse the Plugins panel to load and run analyzers.",
            )
            .color(TEXT_MUTED)
            .size(9.0),
        );
        ui.add_space(12.0);
        if ui
            .button(egui::RichText::new("Open Plugins →").color(ACCENT))
            .clicked()
        {
            state.view_mode = crate::state::ViewMode::Plugins;
        }
        return;
    }

    egui::ScrollArea::vertical().show(ui, |ui| {
        for category in CATEGORIES {
            let total_count: usize = category
                .subcategories
                .iter()
                .map(|sub| state.artifact_counts.get(*sub).copied().unwrap_or(0))
                .sum();

            let _count_color = if total_count > 0 { ACCENT } else { TEXT_MUTED };
            let header_text = format!(
                "{} {} ({})",
                category.icon, category.name, total_count
            );

            egui::CollapsingHeader::new(
                egui::RichText::new(&header_text)
                    .color(if total_count > 0 { TEXT_PRI } else { TEXT_MUTED })
                    .size(10.5)
                    .strong(),
            )
            .default_open(total_count > 0)
            .show(ui, |ui| {
                if total_count == 0 {
                    let plugin_hint = match category.name {
                        "Web Activity" | "User Activity" => "Chronicle",
                        "System Activity" | "Execution History" => "Trace",
                        "Accounts & Credentials" | "Encryption Key Material" => "Cipher",
                        "Deleted & Recovered" | "Media" => "Remnant",
                        _ => "the appropriate",
                    };
                    ui.label(
                        egui::RichText::new(format!(
                            "No {} artifacts found. Run the {} plugin.",
                            category.name.to_lowercase(), plugin_hint
                        ))
                        .color(TEXT_MUTED)
                        .size(8.5),
                    );
                    return;
                }

                // Collect all records matching this top-level category
                let cat_name = category.name;
                let records: Vec<&strata_plugin_sdk::ArtifactRecord> = state
                    .plugin_results
                    .iter()
                    .flat_map(|o| o.artifacts.iter())
                    .filter(|r| {
                        r.category.as_str() == cat_name
                            || category.subcategories.iter().any(|s| {
                                r.subcategory == *s || r.category.as_str() == *s
                            })
                    })
                    .take(200)
                    .collect();

                // Render category-specific table view
                match cat_name {
                    "Web Activity" => render_table_view(ui, &records, &["TIME", "URL", "TITLE", "VISITS"]),
                    "System Activity" => render_table_view(ui, &records, &["TIME", "EVENT", "DETAIL", "MITRE"]),
                    "Execution History" => render_table_view(ui, &records, &["TIME", "EXECUTABLE", "DETAIL", "MITRE"]),
                    "User Activity" => render_table_view(ui, &records, &["TIME", "ACTION", "PATH"]),
                    _ => {
                        // Default: expandable subcategory list
                        for sub in category.subcategories {
                            let count = state.artifact_counts.get(*sub).copied().unwrap_or(0);
                            if count > 0 {
                                egui::CollapsingHeader::new(
                                    egui::RichText::new(format!("{} ({})", sub, count))
                                        .color(TEXT_SEC)
                                        .size(9.5),
                                )
                                .id_source(format!("{}_{}", cat_name, sub))
                                .default_open(false)
                                .show(ui, |ui| {
                                    for record in &records {
                                        if record.subcategory == *sub || record.category.as_str() == *sub {
                                            render_record_row(ui, record);
                                        }
                                    }
                                });
                            } else {
                                ui.horizontal(|ui| {
                                    ui.add_space(16.0);
                                    ui.label(egui::RichText::new(format!("{} (0)", sub)).color(TEXT_MUTED).size(9.5));
                                });
                            }
                        }
                    }
                }
            });
        }
    });
}

/// Render artifacts as a table with column headers.
fn render_table_view(
    ui: &mut egui::Ui,
    records: &[&strata_plugin_sdk::ArtifactRecord],
    columns: &[&str],
) {
    // Header row
    ui.horizontal(|ui| {
        for col in columns {
            ui.label(
                egui::RichText::new(*col)
                    .color(TEXT_MUTED)
                    .size(8.5)
                    .strong(),
            );
            ui.add_space(40.0);
        }
    });
    ui.separator();

    // Data rows
    egui::ScrollArea::vertical()
        .max_height(300.0)
        .show(ui, |ui| {
            for record in records.iter().take(100) {
                render_table_row(ui, record, columns);
            }
            if records.len() > 100 {
                ui.label(
                    egui::RichText::new(format!("… {} more records", records.len() - 100))
                        .color(TEXT_MUTED)
                        .size(8.0),
                );
            }
        });
}

fn render_table_row(
    ui: &mut egui::Ui,
    record: &strata_plugin_sdk::ArtifactRecord,
    columns: &[&str],
) {
    let value_color = match record.forensic_value {
        strata_plugin_sdk::ForensicValue::Critical => DANGER,
        strata_plugin_sdk::ForensicValue::High => AMBER,
        _ => TEXT_SEC,
    };

    ui.horizontal(|ui| {
        if record.is_suspicious {
            ui.label(egui::RichText::new("!").color(AMBER).strong());
        }

        for col in columns {
            let text = match *col {
                "TIME" => record
                    .timestamp
                    .map(|ts| {
                        chrono::DateTime::from_timestamp(ts, 0)
                            .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                            .unwrap_or_else(|| ts.to_string())
                    })
                    .unwrap_or_else(|| "—".to_string()),
                "URL" | "PATH" | "EXECUTABLE" | "ACTION" | "EVENT" => record.title.clone(),
                "TITLE" => record.detail.chars().take(40).collect(),
                "VISITS" | "RUN COUNT" => {
                    record.raw_data.as_ref()
                        .and_then(|d| d.get("visit_count").or(d.get("run_count")))
                        .and_then(|v| v.as_i64())
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "—".to_string())
                }
                "DETAIL" => {
                    let d = &record.detail;
                    if d.len() > 50 { format!("{}…", &d[..50]) } else { d.clone() }
                }
                "MITRE" => record.mitre_technique.clone().unwrap_or_default(),
                "SOURCE" => record.source_path.chars().take(30).collect(),
                _ => "—".to_string(),
            };

            ui.label(egui::RichText::new(&text).color(value_color).size(8.5));
            ui.add_space(20.0);
        }
    });
}

fn render_record_row(ui: &mut egui::Ui, record: &strata_plugin_sdk::ArtifactRecord) {
    let value_color = match record.forensic_value {
        strata_plugin_sdk::ForensicValue::Critical => DANGER,
        strata_plugin_sdk::ForensicValue::High => AMBER,
        _ => TEXT_SEC,
    };

    ui.horizontal(|ui| {
        ui.add_space(24.0);
        if record.is_suspicious {
            ui.label(egui::RichText::new("!").color(AMBER).strong());
        }
        ui.label(egui::RichText::new(&record.title).color(value_color).size(9.0));
    });
    ui.horizontal(|ui| {
        ui.add_space(32.0);
        ui.label(egui::RichText::new(&record.detail).color(TEXT_MUTED).size(8.0));
    });
}
