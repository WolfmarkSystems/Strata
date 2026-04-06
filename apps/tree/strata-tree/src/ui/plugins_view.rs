//! Plugins view — parser/analyzer plugin management.

use crate::state::{colors::*, AppState};
use anyhow::Context;
use libloading::{Library, Symbol};
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct PluginInfo {
    name: String,
    version: String,
    plugin_type: String,
    description: String,
    path: String,
    formats: String,
    author: String,
    processed: u64,
    elapsed_ms: u64,
    log: Vec<String>,
    last_result: Option<String>,
    last_success: Option<bool>,
    last_run_utc: Option<String>,
    signature_status: String,
    signature_verified: bool,
}

thread_local! {
    static PLUGINS: std::cell::RefCell<Vec<PluginInfo>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[derive(Debug, Clone)]
struct SandboxRunResult {
    success: bool,
    message: String,
    elapsed_ms: u64,
}

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    if state.plugin_enabled.is_empty() {
        load_plugin_config(state);
    }
    ensure_builtin_integrations();

    let t = *state.theme();

    // ── Header ─────────────────────────────────────────────────────────────
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("ANALYSIS PLUGINS")
                .color(t.active)
                .size(11.0)
                .strong(),
        );
        ui.separator();
        ui.label(
            egui::RichText::new(format!("{} plugins", state.plugin_host.list().len()))
                .color(t.muted)
                .size(9.5),
        );
    });
    ui.add_space(4.0);

    let has_evidence = !state.evidence_sources.is_empty();

    // RUN ALL button
    ui.add_enabled_ui(has_evidence, |ui| {
        let run_all = ui.add(
            egui::Button::new(
                egui::RichText::new("RUN ALL PLUGINS")
                    .color(t.text)
                    .strong()
                    .size(11.0),
            )
            .fill(t.card)
            .stroke(egui::Stroke::new(1.0, t.active))
            .rounding(6.0),
        );
        if run_all.clicked() {
            run_all_plugins(state);
        }
    });
    ui.add_space(8.0);

    // Collect plugin info upfront to avoid borrow conflicts
    let plugin_infos: Vec<(String, String, String, String)> = state
        .plugin_host
        .list()
        .iter()
        .map(|p| (
            p.name().to_string(),
            p.version().to_string(),
            p.description().to_string(),
            format!("{:?}", p.plugin_type()),
        ))
        .collect();

    // ── Grid (left 60%) + Details (right 40%) ──────────────────────────────
    let total_w = ui.available_width();
    let grid_w = total_w * 0.58;
    let detail_w = total_w * 0.40;
    let mut clicked_builtin: Option<String> = None;

    ui.horizontal(|ui| {
        // ── LEFT: Plugin grid ──────────────────────────────────────────
        ui.vertical(|ui| {
            ui.set_width(grid_w);
            ui.set_min_height(500.0);
            egui::ScrollArea::vertical().id_source("plugin_grid_scroll").show(ui, |ui| {
                let col_count = 3usize;
                let card_w = (grid_w - 16.0) / col_count as f32;

                // Chunk plugins into rows of 3
                for row_plugins in plugin_infos.chunks(col_count) {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing = egui::vec2(4.0, 0.0);
                        for (name, version, description, plugin_type) in row_plugins {
                            let accent = plugin_accent_color(name);
                            let icon = plugin_icon(name);
                            let is_selected = state.selected_plugin.as_deref() == Some(name.as_str());
                            let border = if is_selected { accent } else { t.border };
                            let fill = if is_selected { t.elevated } else { t.card };

                            let already_ran = state.plugin_results.iter().any(|r| r.plugin_name == *name);

                            let card = egui::Frame::none()
                                .fill(fill)
                                .stroke(egui::Stroke::new(1.0, border))
                                .rounding(crate::theme::RADIUS_MD)
                                .inner_margin(egui::Margin::symmetric(12.0, 10.0))
                                .show(ui, |ui| {
                                    ui.set_width(card_w - 32.0);
                                    ui.set_min_height(120.0);
                                    // Row 1: icon + name + version + type
                                    ui.horizontal(|ui| {
                                        ui.label(egui::RichText::new(icon).size(20.0).color(accent));
                                        ui.label(egui::RichText::new(name.as_str()).color(accent).size(14.0).strong());
                                        ui.label(egui::RichText::new(format!("v{}", version)).color(t.muted).size(11.0));
                                    });
                                    ui.label(egui::RichText::new(format!("[{}]", plugin_type)).color(t.muted).size(10.0));
                                    ui.add_space(4.0);
                                    // Row 2: description (truncated)
                                    let desc_short = if description.len() > 80 { &description[..80] } else { description.as_str() };
                                    ui.label(egui::RichText::new(desc_short).color(t.secondary).size(12.0));
                                    ui.add_space(6.0);
                                    // Row 3: RUN button
                                    let run_clicked = ui.add_enabled(has_evidence, egui::Button::new(
                                        egui::RichText::new(if already_ran { "RE-RUN" } else { "RUN" })
                                            .color(t.text).size(12.0).strong(),
                                    ).fill(t.bg).rounding(3.0)).clicked();
                                    if run_clicked {
                                        state.run_plugin(name);
                                    }
                                });

                            // Paint accent left border
                            let rect = card.response.rect;
                            ui.painter().rect_filled(
                                egui::Rect::from_min_size(rect.left_top(), egui::vec2(3.0, rect.height())),
                                egui::Rounding { nw: crate::theme::RADIUS_MD, sw: crate::theme::RADIUS_MD, ..Default::default() },
                                accent,
                            );

                            let click = ui.interact(rect, egui::Id::new(format!("plugin_card_{}", name)), egui::Sense::click());
                            if click.clicked() {
                                clicked_builtin = Some(name.clone());
                            }
                        }
                    });
                    ui.add_space(4.0);
                }

                if !has_evidence {
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new("Load evidence to enable plugin execution.").color(t.muted).size(9.0));
                }
            });
        });

        ui.add_space(8.0);

        // ── RIGHT: Details pane ────────────────────────────────────────
        ui.vertical(|ui| {
            ui.set_width(detail_w);
            egui::Frame::none()
                .fill(t.card)
                .stroke(egui::Stroke::new(1.0, t.border))
                .rounding(crate::theme::RADIUS_MD)
                .inner_margin(egui::Margin::symmetric(12.0, 10.0))
                .show(ui, |ui| {
                    ui.set_min_height(300.0);
                    render_builtin_detail(ui, state, &plugin_infos);
                });
        });
    });

    if let Some(name) = clicked_builtin {
        state.selected_plugin = Some(name);
    }

}

fn render_builtin_detail(
    ui: &mut egui::Ui,
    state: &mut AppState,
    plugin_infos: &[(String, String, String, String)],
) {
    let t = *state.theme();
    let Some(selected) = state.selected_plugin.as_deref() else {
        ui.vertical_centered(|ui| {
            ui.add_space(ui.available_height() / 3.0);
            ui.label(egui::RichText::new("Select a plugin to view details").color(t.muted).size(12.0));
        });
        return;
    };

    let Some((name, version, _description, plugin_type)) = plugin_infos.iter().find(|(n, ..)| n == selected) else {
        ui.label(egui::RichText::new("Select a plugin to view details").color(t.muted).size(12.0));
        return;
    };

    let accent = plugin_accent_color(name);

    // Accent bar
    let bar_rect = ui.available_rect_before_wrap();
    ui.painter().rect_filled(
        egui::Rect::from_min_size(bar_rect.left_top(), egui::vec2(bar_rect.width(), 3.0)),
        2.0, accent,
    );
    ui.add_space(6.0);

    // Name + version
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(name.as_str()).color(t.text).size(16.0).strong());
        ui.label(egui::RichText::new(format!("v{}", version)).color(t.muted).size(11.0));
    });
    ui.label(egui::RichText::new(format!("Type: {}", plugin_type)).color(t.secondary).size(10.0));
    ui.add_space(8.0);

    egui::ScrollArea::vertical().show(ui, |ui| {
        // Full description
        ui.label(egui::RichText::new("WHAT IT DOES").color(t.muted).size(10.0));
        ui.add_space(2.0);
        ui.label(egui::RichText::new(plugin_full_description(name)).color(t.secondary).size(10.0));
        ui.add_space(10.0);

        // Categories
        let (categories, mitre) = plugin_categories_mitre(name);
        ui.label(egui::RichText::new("FORENSIC CATEGORIES").color(t.muted).size(10.0));
        ui.add_space(2.0);
        ui.label(egui::RichText::new(categories).color(t.secondary).size(9.5));
        ui.add_space(10.0);

        // MITRE
        ui.label(egui::RichText::new("MITRE COVERAGE").color(t.muted).size(10.0));
        ui.add_space(2.0);
        ui.horizontal_wrapped(|ui| {
            for technique in mitre.split(", ") {
                ui.label(
                    egui::RichText::new(technique)
                        .color(accent)
                        .size(8.5)
                        .background_color(t.bg),
                );
            }
        });
        ui.add_space(10.0);

        // Results if already ran
        let result_count: usize = state.plugin_results.iter()
            .filter(|r| r.plugin_name == *name)
            .map(|r| r.artifacts.len())
            .sum();
        if result_count > 0 {
            let sus_count = state.plugin_results.iter()
                .filter(|r| r.plugin_name == *name)
                .flat_map(|r| r.artifacts.iter())
                .filter(|a| a.is_suspicious)
                .count();
            ui.label(egui::RichText::new(format!(
                "Results: {} artifacts ({} suspicious)", result_count, sus_count
            )).color(if sus_count > 0 { t.suspicious } else { t.clean }).size(10.0));
            ui.add_space(10.0);
        }

        // Changelog
        ui.label(egui::RichText::new("CHANGELOG").color(t.muted).size(10.0));
        ui.add_space(2.0);
        for line in plugin_changelog(name) {
            ui.label(egui::RichText::new(line).color(t.secondary).size(9.0));
        }
        ui.add_space(10.0);

        // RUN button
        let has_evidence = !state.evidence_sources.is_empty();
        let already_ran = state.plugin_results.iter().any(|r| r.plugin_name == *name);
        ui.add_enabled_ui(has_evidence, |ui| {
            if ui.add(egui::Button::new(
                egui::RichText::new(if already_ran { "RE-RUN THIS PLUGIN" } else { "RUN THIS PLUGIN" })
                    .color(t.text).strong().size(11.0),
            ).fill(t.bg).stroke(egui::Stroke::new(1.0, accent)).rounding(6.0)).clicked() {
                state.run_plugin(name);
            }
        });
    });
}

fn plugin_changelog(name: &str) -> Vec<&'static str> {
    match plugin_short_name(name) {
        "Remnant" => vec![
            "v2.0.0 — Full $I Recycle Bin binary parse",
            "  $UsnJrnl complete reason flag decode",
            "  Anti-forensic tool detection added",
            "  SQLite WAL recovery detection",
            "v1.0.0 — Initial release — file carving",
        ],
        "Chronicle" => vec![
            "v2.0.0 — UserAssist ROT13 + GUID decode",
            "  RecentDocs binary MRU decode",
            "  Jump List CFB full parse",
            "  TypedPaths + WordWheelQuery added",
            "v1.0.0 — Initial release — timeline building",
        ],
        "Cipher" => vec![
            "v2.0.0 — WiFi XML full profile parse",
            "  TeamViewer session log parsing",
            "  AnyDesk connection trace parse",
            "  FileZilla FTP credential extraction",
            "v1.0.0 — Initial release — credential extraction",
        ],
        "Trace" => vec![
            "v2.0.0 — BAM/DAM registry full parse",
            "  Scheduled Tasks XML decode",
            "  BITS job database detection",
            "  Timestomp $SI vs $FN detection",
            "v1.0.0 — Initial release — execution tracking",
        ],
        "Specter" => vec![
            "v1.0.0 — iOS KnowledgeC + DataUsage parse",
            "  WhatsApp iOS + Android schemas",
            "  Signal + Telegram databases",
            "  ADB backup detection",
        ],
        "Conduit" => vec![
            "v1.0.0 — Network profile history",
            "  RDP connection history",
            "  VPN artifact detection",
            "  Hosts file modification detection",
        ],
        "Nimbus" => vec![
            "v1.0.0 — OneDrive sync log parsing",
            "  Google DriveFS detection",
            "  Teams + Slack + Zoom artifacts",
            "  Dropbox nucleus.sqlite",
        ],
        "Wraith" => vec![
            "v1.0.0 — hiberfil.sys detection",
            "  Crash dump MDMP parsing",
            "  pagefile string extraction",
        ],
        "Vector" => vec![
            "v1.0.0 — PE header + compile timestamp",
            "  Import table injection detection",
            "  OLE2 macro detection",
            "  Script obfuscation analysis",
            "  Known malware string matching",
        ],
        "Recon" => vec![
            "v1.0.0 — Username harvesting",
            "  Email address extraction",
            "  Public IP detection",
            "  AWS key pattern detection",
        ],
        "Sigma" => vec![
            "v1.0.0 — Kill chain coverage mapping",
            "  Attack pattern correlation",
            "  Confidence scoring",
            "  Threat assessment summary",
            "  Reads all prior plugin results",
        ],
        _ => vec!["No changelog available"],
    }
}

#[allow(dead_code)]
fn render_plugin_detail(ui: &mut egui::Ui, state: &mut AppState) {
    let Some(selected) = state.selected_plugin.clone() else {
        ui.label(egui::RichText::new("Select a plugin for details.").color(TEXT_MUTED));
        return;
    };

    PLUGINS.with(|plugins| {
        let plugins = plugins.borrow();
        let Some(plugin) = plugins.iter().find(|p| p.name == selected) else {
            ui.label(egui::RichText::new("Plugin not found.").color(DANGER));
            return;
        };

        ui.label(
            egui::RichText::new("Plugin Details")
                .color(ACCENT)
                .strong()
                .size(9.0),
        );
        ui.label(format!("Description: {}", plugin.description));
        ui.label(format!("Supported formats: {}", plugin.formats));
        ui.label(format!(
            "Author: {}  Version: {}",
            plugin.author, plugin.version
        ));
        ui.label(format!(
            "Run statistics: files processed={} time={}ms",
            plugin.processed, plugin.elapsed_ms
        ));
        if let Some(last) = &plugin.last_result {
            let success = plugin.last_success.unwrap_or(true);
            let color = if success { GREEN_OK } else { DANGER };
            let ts = plugin
                .last_run_utc
                .clone()
                .unwrap_or_else(|| "-".to_string());
            ui.label(
                egui::RichText::new(format!("Last run: {} | {}", ts, last))
                    .color(color)
                    .size(8.5),
            );
        }
        ui.label(format!("Path: {}", plugin.path));
        let sig_color = if plugin.signature_verified {
            GREEN_OK
        } else {
            AMBER
        };
        ui.label(
            egui::RichText::new(format!("Signature: {}", plugin.signature_status))
                .color(sig_color)
                .size(8.5),
        );
        ui.add_space(4.0);
        let dynamic_run_supported = is_dynamic_plugin_file(Path::new(plugin.path.as_str()));
        ui.add_enabled_ui(dynamic_run_supported, |ui| {
            if ui.button("Run Plugin").clicked() {
                let now_utc = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                let run = run_plugin_sandbox(plugin.path.as_str(), Duration::from_secs(30));
                let level = if run.success { "INFO" } else { "ERROR" };
                PLUGINS.with(|plugins_mut| {
                    if let Some(mut_ref) = plugins_mut
                        .borrow_mut()
                        .iter_mut()
                        .find(|p| p.name == plugin.name)
                    {
                        mut_ref.elapsed_ms = mut_ref.elapsed_ms.saturating_add(run.elapsed_ms);
                        mut_ref.processed = mut_ref.processed.saturating_add(1);
                        mut_ref.last_result = Some(run.message.clone());
                        mut_ref.last_success = Some(run.success);
                        mut_ref.last_run_utc = Some(now_utc.clone());
                        mut_ref.log.push(format!(
                            "{} {} Plugin '{}' run result: {}",
                            now_utc, level, plugin.name, run.message
                        ));
                    }
                });
                state.status = format!("Plugin '{}' run: {}", plugin.name, run.message);
                state.log_action(
                    "PLUGIN_RUN",
                    &format!(
                        "name={} success={} elapsed_ms={} detail={}",
                        plugin.name, run.success, run.elapsed_ms, run.message
                    ),
                );
            }
        });
        if !dynamic_run_supported {
            ui.label(
                egui::RichText::new("Built-in integration (dynamic run unavailable)")
                    .color(TEXT_MUTED)
                    .size(8.0),
            );
        }

        ui.separator();
        ui.label(
            egui::RichText::new("Execution Log (last 100)")
                .color(TEXT_MUTED)
                .size(8.5),
        );
        egui::ScrollArea::vertical()
            .max_height(180.0)
            .show(ui, |ui| {
                for line in plugin.log.iter().rev().take(100).rev() {
                    ui.label(egui::RichText::new(line).monospace().size(8.0));
                }
            });
    });
}

#[allow(dead_code)]
fn infer_plugin_type(name: &str) -> String {
    let n = name.to_lowercase();
    if n.contains("parser") {
        "Parser".to_string()
    } else if n.contains("analy") {
        "Analyzer".to_string()
    } else if n.contains("carv") {
        "Carver".to_string()
    } else if n.contains("hash") {
        "Hasher".to_string()
    } else if n.contains("report") {
        "Reporter".to_string()
    } else {
        "Parser".to_string()
    }
}

#[allow(dead_code)]
fn save_plugin_config(state: &AppState) {
    let Some(case_path) = state.case.as_ref().map(|c| c.path.clone()) else {
        return;
    };
    if case_path.is_empty() {
        return;
    }
    if let Ok(project) = crate::case::project::VtpProject::open(&case_path) {
        if let Ok(json) = serde_json::to_string(&state.plugin_enabled) {
            let _ = project.set_meta("plugin_enabled_json", &json);
        }
    }
}

fn load_plugin_config(state: &mut AppState) {
    let Some(case_path) = state.case.as_ref().map(|c| c.path.clone()) else {
        return;
    };
    if case_path.is_empty() {
        return;
    }
    if let Ok(project) = crate::case::project::VtpProject::open(&case_path) {
        if let Some(json) = project.get_meta("plugin_enabled_json") {
            if let Ok(map) = serde_json::from_str::<std::collections::HashMap<String, bool>>(&json)
            {
                state.plugin_enabled = map;
            }
        }
    }
}

/// Strip "Strata " prefix for metadata lookup — plugins report as "Strata Remnant" etc.
fn plugin_short_name(name: &str) -> &str {
    name.strip_prefix("Strata ").unwrap_or(name)
}

fn plugin_accent_color(name: &str) -> egui::Color32 {
    match plugin_short_name(name) {
        "Remnant"   => egui::Color32::from_rgb(0x4a, 0x90, 0x60),
        "Chronicle" => egui::Color32::from_rgb(0xc8, 0xa0, 0x40),
        "Cipher"    => egui::Color32::from_rgb(0xc0, 0x50, 0x50),
        "Trace"     => egui::Color32::from_rgb(0x4a, 0x70, 0xc0),
        "Specter"   => egui::Color32::from_rgb(0x80, 0x50, 0xc0),
        "Conduit"   => egui::Color32::from_rgb(0x40, 0xa0, 0xa0),
        "Nimbus"    => egui::Color32::from_rgb(0x60, 0x90, 0xd0),
        "Wraith"    => egui::Color32::from_rgb(0x80, 0x90, 0xa0),
        "Vector"    => egui::Color32::from_rgb(0xc0, 0x70, 0x40),
        "Recon"     => egui::Color32::from_rgb(0xa0, 0xa0, 0x40),
        "Sigma"     => egui::Color32::from_rgb(0xc0, 0x40, 0x80),
        _ => egui::Color32::from_rgb(0x88, 0x99, 0xaa),
    }
}

fn plugin_icon(name: &str) -> &'static str {
    match plugin_short_name(name) {
        "Remnant"   => "\u{1F5D1}",  // 🗑
        "Chronicle" => "\u{23F1}",   // ⏱
        "Cipher"    => "\u{1F511}",  // 🔑
        "Trace"     => "\u{1F43E}",  // 🐾
        "Specter"   => "\u{1F4F1}",  // 📱
        "Conduit"   => "\u{1F517}",  // 🔗
        "Nimbus"    => "\u{2601}",   // ☁
        "Wraith"    => "\u{1F4BE}",  // 💾
        "Vector"    => "\u{1F6E1}",  // 🛡
        "Recon"     => "\u{1F3AF}",  // 🎯
        "Sigma"     => "\u{03A3}",   // Σ
        _ => "\u{2699}",             // ⚙
    }
}

fn plugin_full_description(name: &str) -> &'static str {
    match plugin_short_name(name) {
        "Remnant" => "Remnant recovers what investigators were never supposed to find. It parses the Windows Recycle Bin metadata to reconstruct deleted file paths and exact deletion timestamps, reads the NTFS change journal to surface every file operation ever recorded on the volume, and identifies the fingerprints of secure deletion tools like SDelete, CCleaner, and Eraser. When evidence has been deliberately destroyed, Remnant finds the proof it existed.",
        "Chronicle" => "Chronicle rebuilds the complete story of what a user did on a system. It decodes the UserAssist registry to reveal every GUI application launched with run counts and timestamps, reconstructs the recent documents list in access order, parses Jump Lists to show which files each application opened, and surfaces typed paths and search terms that prove what the user was looking for.",
        "Cipher" => "Cipher finds everything that was hidden, saved, or sent. It extracts saved browser credentials, identifies Windows Credential Manager entries encrypted with DPAPI, parses WiFi profile XML files for network history, finds TeamViewer and AnyDesk remote access session logs, and recovers FTP credentials from FileZilla. When data left the building, Cipher proves how and where it went.",
        "Trace" => "Trace answers the two most important questions in any investigation: what ran on this system, and what will keep running after a reboot. It parses the Windows Background Activity Monitor for precise execution timestamps, decodes scheduled task XML files for hidden persistence mechanisms, scans autorun registry keys, and detects BITS job abuse for stealthy downloads.",
        "Specter" => "Specter reaches into the digital lives stored on mobile devices. It queries the iOS KnowledgeC database for precise application usage timelines, parses DataUsage records for per-app network activity, and extracts message data from WhatsApp, Signal, Telegram, Snapchat, Instagram, and Discord databases on both iOS and Android.",
        "Conduit" => "Conduit maps every network connection a system made. It reconstructs the complete WiFi and wired network connection history from the Windows registry, identifies VPN configuration artifacts, extracts Remote Desktop connection history, and flags non-standard hosts file entries that could indicate DNS manipulation.",
        "Nimbus" => "Nimbus uncovers what lived in the cloud. It parses OneDrive synchronization logs to identify uploaded and downloaded files, examines Google DriveFS and Dropbox activity databases, and detects Microsoft Teams, Slack, and Zoom usage through their local application artifacts and log files.",
        "Wraith" => "Wraith examines the ghosts of running processes. It detects and profiles hibernation files containing compressed snapshots of RAM, identifies crash dump files that may contain process memory snapshots, and extracts suspicious strings including URLs, IP addresses, and known malware signatures from page files.",
        "Vector" => "Vector answers the question every investigator asks when they find a suspicious file: is this malicious? It analyzes PE executable headers for anomalous compilation timestamps, detects VBA macros in Office documents, identifies obfuscated PowerShell, and scans file content against a library of known malware tool signatures.",
        "Recon" => "Recon connects the artifacts to real people. It harvests system usernames from multiple sources, extracts email addresses from documents and log files, identifies public IP addresses in scripts and configuration files, and detects cloud API credentials including AWS access keys. All analysis is completely offline.",
        "Sigma" => "Sigma runs last because it needs everything the other plugins found. It reads every artifact record produced by all ten preceding plugins and maps them against the MITRE ATT&CK framework to build a kill chain coverage map, detects known attack sequences, assigns confidence scores, and produces a threat assessment summary.",
        _ => "Plugin description unavailable.",
    }
}

fn plugin_categories_mitre(name: &str) -> (&'static str, &'static str) {
    match plugin_short_name(name) {
        "Remnant"   => ("Deleted Files, File System, Anti-Forensics Detection", "T1070.004, T1485, T1083"),
        "Chronicle" => ("User Activity, Application Execution, Timeline", "T1204, T1547, T1083"),
        "Cipher"    => ("Credentials, Remote Access, Cloud Sync, Exfiltration", "T1552, T1078, T1567, T1021.001"),
        "Trace"     => ("Execution History, Persistence, Anti-Forensics, Scheduled Tasks", "T1053, T1547, T1070.006, T1197"),
        "Specter"   => ("Mobile Devices, Social Media, Communications, Messaging", "T1636, T1430, T1409"),
        "Conduit"   => ("Network History, Remote Access, VPN, RDP, DNS", "T1021.001, T1071, T1090, T1018"),
        "Nimbus"    => ("Cloud Storage, Enterprise Comms, File Uploads, Collaboration", "T1567, T1213, T1530"),
        "Wraith"    => ("Memory Artifacts, Hibernation, Crash Dumps, Volatile Evidence", "T1005, T1212, T1083"),
        "Vector"    => ("Malware Detection, Static Analysis, Indicators of Compromise", "T1059, T1027, T1055, T1566.001"),
        "Recon"     => ("Identity, Account Artifacts, Infrastructure, Credentials", "T1087, T1589, T1552.001"),
        "Sigma"     => ("Threat Intelligence, Kill Chain, ATT&CK Mapping, Correlation", "Cross-tactic correlation"),
        _ => ("Unknown", "N/A"),
    }
}

fn run_all_plugins(state: &mut crate::state::AppState) {
    let plugin_names: Vec<String> = state.plugin_host.list().iter().map(|p| p.name().to_string()).collect();
    let count = plugin_names.len();

    state.log_action("PLUGIN_RUN_ALL", &format!("Starting {} plugins", count));

    let mut total_artifacts = 0usize;
    let mut total_suspicious = 0usize;

    for (i, name) in plugin_names.iter().enumerate() {
        state.status = format!("Running {}... ({}/{})", name, i + 1, count);
        state.run_plugin(name);

        // Accumulate totals
        if let Some(last) = state.plugin_results.last() {
            total_artifacts += last.artifacts.len();
            total_suspicious += last.artifacts.iter().filter(|a| a.is_suspicious).count();
        }
    }

    state.log_action(
        "PLUGIN_RUN_ALL_COMPLETE",
        &format!("{} plugins — {} artifacts total, {} suspicious", count, total_artifacts, total_suspicious),
    );
    state.status = format!("All {} plugins complete — {} artifacts found", count, total_artifacts);
}

fn ensure_builtin_integrations() {
    let Some(repo_root) = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .map(|p| p.to_path_buf())
    else {
        return;
    };

    let builtins = [
        (
            "Remnant",
            "strata-plugin-remnant",
            "Carver",
            "Signature carving engine integration",
        ),
        (
            "Chronicle",
            "strata-plugin-chronicle",
            "Analyzer",
            "Timeline and correlation integration",
        ),
        (
            "Cipher",
            "strata-plugin-cipher",
            "Analyzer",
            "Credential and crypto artifact integration",
        ),
        (
            "Trace",
            "strata-plugin-trace",
            "Analyzer",
            "Pattern tracing and hunt integration",
        ),
    ];

    PLUGINS.with(|plugins| {
        let mut plugins = plugins.borrow_mut();
        for (name, dir, plugin_type, description) in builtins {
            if plugins.iter().any(|p| p.name.eq_ignore_ascii_case(name)) {
                continue;
            }
            let path = repo_root.join("plugins").join(dir);
            if !path.exists() {
                continue;
            }

            let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            plugins.push(PluginInfo {
                name: name.to_string(),
                version: "0.1.0".to_string(),
                plugin_type: plugin_type.to_string(),
                description: description.to_string(),
                path: path.to_string_lossy().to_string(),
                formats: "*".to_string(),
                author: "Wolfmark Systems".to_string(),
                processed: 0,
                elapsed_ms: 0,
                log: vec![format!("{} INFO Built-in integration registered", now)],
                last_result: None,
                last_success: None,
                last_run_utc: None,
                signature_status: "INTEGRATED".to_string(),
                signature_verified: true,
            });
        }
    });
}

#[allow(dead_code)]
fn verify_plugin_signature(path: &std::path::Path) -> (bool, String) {
    use sha2::Digest;

    let mut sidecar = path.to_path_buf();
    let file_name = path
        .file_name()
        .and_then(|v| v.to_str())
        .map(|v| format!("{}.sha256", v))
        .unwrap_or_else(|| "plugin.sha256".to_string());
    sidecar.set_file_name(file_name);

    if !sidecar.exists() {
        return (false, "UNSIGNED".to_string());
    }

    let expected = match std::fs::read_to_string(&sidecar)
        .ok()
        .and_then(|txt| txt.split_whitespace().next().map(|s| s.trim().to_string()))
    {
        Some(v) if v.len() == 64 => v.to_lowercase(),
        _ => return (false, "SIGNATURE INVALID".to_string()),
    };

    let bytes = match std::fs::read(path) {
        Ok(v) => v,
        Err(_) => return (false, "SIGNATURE CHECK FAILED".to_string()),
    };
    let mut hasher = sha2::Sha256::new();
    hasher.update(&bytes);
    let actual = format!("{:x}", hasher.finalize());

    if actual.eq_ignore_ascii_case(&expected) {
        (true, "SIGNATURE VERIFIED".to_string())
    } else {
        (false, "SIGNATURE MISMATCH".to_string())
    }
}

#[allow(dead_code)]
fn run_plugin_sandbox(plugin_path: &str, timeout: Duration) -> SandboxRunResult {
    let started = Instant::now();
    let path = Path::new(plugin_path);

    if !path.exists() {
        return SandboxRunResult {
            success: false,
            message: format!("Plugin path not found: {}", plugin_path),
            elapsed_ms: started.elapsed().as_millis() as u64,
        };
    }
    if !path.is_file() || !is_dynamic_plugin_file(path) {
        return SandboxRunResult {
            success: false,
            message: "Plugin must be a .dll/.so/.dylib file".to_string(),
            elapsed_ms: started.elapsed().as_millis() as u64,
        };
    }

    let plugin_path_buf = path.to_path_buf();
    let (tx, rx) = mpsc::channel::<Result<(), String>>();
    std::thread::spawn(move || {
        let call = std::panic::catch_unwind(move || -> Result<(), String> {
            // SAFETY: library path comes from explicit user plugin selection.
            let lib = unsafe { Library::new(&plugin_path_buf) }
                .with_context(|| format!("load failed: {}", plugin_path_buf.display()))
                .map_err(|e| e.to_string())?;
            // SAFETY: symbol name is derived from the plugin C-ABI contract.
            // Try plugin-specific name first, then legacy fallbacks.
            let sym_name = plugin_symbol_name(&plugin_path_buf);
            let entry: Symbol<unsafe extern "C" fn() -> *mut std::ffi::c_void> = unsafe {
                lib.get(sym_name.as_bytes())
                    .or_else(|_| lib.get(b"create_plugin\0"))
                    .or_else(|_| lib.get(b"strata_tree_plugin_entry\0"))
            }
            .context("missing symbol: create_plugin_*/create_plugin/strata_tree_plugin_entry")
            .map_err(|e| e.to_string())?;
            // SAFETY: calling plugin entrypoint is required to validate runtime contract.
            let ptr = unsafe { entry() };
            if ptr.is_null() {
                return Err("entrypoint returned null plugin pointer".to_string());
            }
            Ok(())
        });
        let payload = match call {
            Ok(v) => v,
            Err(_) => Err("plugin panicked during invocation".to_string()),
        };
        let _ = tx.send(payload);
    });

    let result = match rx.recv_timeout(timeout) {
        Ok(Ok(())) => SandboxRunResult {
            success: true,
            message: "sandbox invocation succeeded".to_string(),
            elapsed_ms: started.elapsed().as_millis() as u64,
        },
        Ok(Err(err)) => SandboxRunResult {
            success: false,
            message: err,
            elapsed_ms: started.elapsed().as_millis() as u64,
        },
        Err(_) => SandboxRunResult {
            success: false,
            message: format!("plugin timed out after {}s", timeout.as_secs()),
            elapsed_ms: started.elapsed().as_millis() as u64,
        },
    };
    result
}

/// Derive the plugin-specific FFI symbol name from a library path.
#[allow(dead_code)]
fn plugin_symbol_name(path: &Path) -> String {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let stem = stem.strip_prefix("lib").unwrap_or(stem);
    let name = stem
        .strip_prefix("strata_plugin_")
        .or_else(|| stem.strip_prefix("strata-plugin-"))
        .unwrap_or(stem)
        .replace('-', "_");
    format!("create_plugin_{}\0", name)
}

#[allow(dead_code)]
fn is_dynamic_plugin_file(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|v| v.to_str())
        .map(|v| v.to_ascii_lowercase())
        .unwrap_or_default();
    ext == "dll" || ext == "so" || ext == "dylib"
}

#[cfg(test)]
mod tests {
    use super::{is_dynamic_plugin_file, run_plugin_sandbox};
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::Duration;

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .map(PathBuf::from)
            .expect("repo root")
    }

    fn example_plugin_path() -> PathBuf {
        let ext = if cfg!(target_os = "windows") {
            "dll"
        } else if cfg!(target_os = "macos") {
            "dylib"
        } else {
            "so"
        };
        let name = if cfg!(target_os = "windows") {
            format!("strata_plugin_tree_example.{}", ext)
        } else {
            format!("libstrata_plugin_tree_example.{}", ext)
        };
        repo_root().join("target").join("debug").join(name)
    }

    #[test]
    fn sandbox_rejects_non_dynamic_paths() {
        let result = run_plugin_sandbox("D:/not/a/plugin.txt", Duration::from_secs(1));
        assert!(!result.success);
    }

    #[test]
    fn sandbox_loads_tree_example_plugin() {
        let plugin_path = example_plugin_path();
        let status = Command::new("cargo")
            .args(["build", "-p", "strata-plugin-tree-example"])
            .current_dir(repo_root())
            .status()
            .expect("build test plugin");
        assert!(status.success(), "failed to build test plugin");

        assert!(
            is_dynamic_plugin_file(&plugin_path),
            "plugin artifact does not look like a dynamic library: {}",
            plugin_path.display()
        );

        let result = run_plugin_sandbox(
            plugin_path.to_string_lossy().as_ref(),
            Duration::from_secs(10),
        );
        assert!(
            result.success,
            "plugin sandbox invocation failed: {}",
            result.message
        );
    }
}
