//! Plugins view — parser/analyzer plugin management.

use crate::state::{colors::*, AppState};
use anyhow::Context;
use libloading::{Library, Symbol};
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

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
            egui::ScrollArea::vertical().show(ui, |ui| {
                let col_count = 3usize;
                let card_w = (grid_w - 16.0) / col_count as f32;

                // Chunk plugins into rows of 3
                for row_plugins in plugin_infos.chunks(col_count) {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing = egui::vec2(4.0, 0.0);
                        for (name, version, _description, plugin_type) in row_plugins {
                            let accent = plugin_accent_color(name);
                            let is_selected = state.selected_plugin.as_deref() == Some(name.as_str());
                            let border = if is_selected { accent } else { t.border };
                            let fill = if is_selected { t.elevated } else { t.card };

                            let already_ran = state.plugin_results.iter().any(|r| r.plugin_name == *name);

                            let card = egui::Frame::none()
                                .fill(fill)
                                .stroke(egui::Stroke::new(1.0, border))
                                .rounding(crate::theme::RADIUS_MD)
                                .inner_margin(egui::Margin::symmetric(10.0, 8.0))
                                .show(ui, |ui| {
                                    ui.set_width(card_w - 28.0);
                                    ui.set_height(60.0);
                                    // Row 1: name + version + type
                                    ui.horizontal(|ui| {
                                        ui.label(egui::RichText::new(name.as_str()).color(accent).size(10.0).strong());
                                        ui.label(egui::RichText::new(format!("v{}", version)).color(t.muted).size(8.0));
                                    });
                                    ui.label(egui::RichText::new(format!("[{}]", plugin_type)).color(t.muted).size(7.5));
                                    // Row 3: RUN button
                                    ui.horizontal(|ui| {
                                        let run_clicked = ui.add_enabled(has_evidence, egui::Button::new(
                                            egui::RichText::new(if already_ran { "RE-RUN" } else { "RUN" })
                                                .color(t.text).size(8.5).strong(),
                                        ).fill(t.bg).rounding(3.0)).clicked();
                                        if run_clicked {
                                            state.run_plugin(name);
                                        }
                                    });
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

    ui.add_space(12.0);
    ui.separator();
    ui.add_space(8.0);

    // ── Dynamic Plugins ─────────────────────────────────────────────────────
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("DYNAMIC PLUGINS")
                .color(t.active)
                .size(11.0)
                .strong(),
        );
        ui.separator();
        let count = PLUGINS.with(|p| p.borrow().len());
        ui.label(
            egui::RichText::new(format!("{} available", count))
                .color(t.muted)
                .size(9.5),
        );
    });
    ui.add_space(4.0);

    if ui.button("Load Plugin...").clicked() {
        let ext: &[&str] = if cfg!(target_os = "windows") {
            &["dll"]
        } else if cfg!(target_os = "macos") {
            &["dylib"]
        } else {
            &["so"]
        };
        if let Some(path) = rfd::FileDialog::new().add_filter("Plugin", ext).pick_file() {
            let path_s = path.to_string_lossy().to_string();
            let stem = path
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let already_loaded = PLUGINS.with(|p| {
                p.borrow()
                    .iter()
                    .any(|it| it.path.eq_ignore_ascii_case(&path_s))
            });
            if already_loaded {
                state.status = format!("Plugin already loaded: {}", stem);
                return;
            }
            let plugin_type = infer_plugin_type(&stem);
            let (signature_verified, signature_status) = verify_plugin_signature(&path);
            PLUGINS.with(|p| {
                p.borrow_mut().push(PluginInfo {
                    name: stem.clone(),
                    version: "0.1".to_string(),
                    plugin_type,
                    description: "Loaded dynamic plugin".to_string(),
                    path: path_s.clone(),
                    formats: "*".to_string(),
                    author: "Unknown".to_string(),
                    processed: 0,
                    elapsed_ms: 0,
                    log: vec![format!(
                        "{} INFO Loaded plugin {}",
                        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                        path_s
                    )],
                    last_result: None,
                    last_success: None,
                    last_run_utc: None,
                    signature_status: signature_status.clone(),
                    signature_verified,
                });
            });
            state.plugin_enabled.insert(stem.clone(), true);
            state.selected_plugin = Some(stem.clone());
            state.status = format!("Plugin loaded: {} ({})", stem, signature_status);
            state.mark_case_dirty();
            save_plugin_config(state);
            state.log_action("PLUGIN_LOAD", &format!("name={} path={}", stem, path_s));
        }
    }

    ui.separator();
    ui.label(
        egui::RichText::new("NAME | VERSION | TYPE | STATUS | DESCRIPTION")
            .color(TEXT_MUTED)
            .size(8.5)
            .strong(),
    );
    ui.separator();

    let mut clicked_name: Option<String> = None;
    PLUGINS.with(|plugins| {
        for plugin in plugins.borrow().iter() {
            ui.horizontal(|ui| {
                let row_resp = ui.selectable_label(
                    state.selected_plugin.as_deref() == Some(plugin.name.as_str()),
                    egui::RichText::new(&plugin.name).color(ACCENT),
                );
                row_resp.context_menu(|ui| {
                    if ui.button("Copy Plugin Path").clicked() {
                        ui.ctx().copy_text(plugin.path.clone());
                        ui.close_menu();
                    }
                    if ui.button("Copy Plugin Name").clicked() {
                        ui.ctx().copy_text(plugin.name.clone());
                        ui.close_menu();
                    }
                });
                if row_resp.clicked() {
                    clicked_name = Some(plugin.name.clone());
                }
                ui.separator();
                ui.label(plugin.version.as_str());
                ui.separator();
                ui.label(plugin.plugin_type.as_str());
                ui.separator();
                let enabled = state
                    .plugin_enabled
                    .get(&plugin.name)
                    .copied()
                    .unwrap_or(true);
                let mut enabled_mut = enabled;
                if ui
                    .checkbox(
                        &mut enabled_mut,
                        if enabled { "Enabled" } else { "Disabled" },
                    )
                    .changed()
                {
                    state
                        .plugin_enabled
                        .insert(plugin.name.clone(), enabled_mut);
                    save_plugin_config(state);
                    state.log_action(
                        "PLUGIN_TOGGLE",
                        &format!(
                            "{}={}",
                            plugin.name,
                            if enabled_mut { "enabled" } else { "disabled" }
                        ),
                    );
                }
                ui.separator();
                let sig_color = if plugin.signature_verified {
                    GREEN_OK
                } else {
                    AMBER
                };
                ui.label(
                    egui::RichText::new(plugin.signature_status.as_str())
                        .color(sig_color)
                        .size(8.0),
                );
                ui.separator();
                ui.label(plugin.description.as_str());
            });
        }
    });
    if let Some(name) = clicked_name {
        state.selected_plugin = Some(name);
    }

    ui.separator();
    render_plugin_detail(ui, state);
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

    let Some((name, version, description, plugin_type)) = plugin_infos.iter().find(|(n, ..)| n == selected) else {
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
        // Description
        ui.label(egui::RichText::new("\u{2500}\u{2500} WHAT IT DOES \u{2500}\u{2500}").color(t.muted).size(9.0));
        ui.add_space(2.0);
        ui.label(egui::RichText::new(description.as_str()).color(t.secondary).size(10.0));
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
        ui.label(egui::RichText::new("\u{2500}\u{2500} CHANGELOG \u{2500}\u{2500}").color(t.muted).size(9.0));
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
    match name {
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

fn plugin_accent_color(name: &str) -> egui::Color32 {
    let lower = name.to_lowercase();
    if lower.contains("remnant") { egui::Color32::from_rgb(0x81, 0x8c, 0xf8) }
    else if lower.contains("chronicle") { egui::Color32::from_rgb(0xfb, 0xbf, 0x24) }
    else if lower.contains("cipher") { egui::Color32::from_rgb(0xf4, 0x3f, 0x5e) }
    else if lower.contains("trace") { egui::Color32::from_rgb(0x4a, 0xde, 0x80) }
    else if lower.contains("specter") { egui::Color32::from_rgb(0x38, 0xbd, 0xf8) }
    else if lower.contains("conduit") { egui::Color32::from_rgb(0x22, 0xd3, 0xee) }
    else if lower.contains("nimbus") { egui::Color32::from_rgb(0x7c, 0x3a, 0xed) }
    else if lower.contains("wraith") { egui::Color32::from_rgb(0x94, 0xa3, 0xb8) }
    else if lower.contains("vector") { egui::Color32::from_rgb(0xf9, 0x73, 0x16) }
    else if lower.contains("recon") { egui::Color32::from_rgb(0xa3, 0xe6, 0x35) }
    else if lower.contains("sigma") { egui::Color32::from_rgb(0xe8, 0x79, 0xf9) }
    else { egui::Color32::from_rgb(0x88, 0x99, 0xaa) }
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
