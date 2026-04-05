// ui/hash_panel.rs — Hash calculation panel with content index prompt (Gap 15).

use crate::state::AppState;

pub fn render(ctx: &egui::Context, state: &mut AppState) {
    egui::Window::new("Hash Files")
        .resizable(true)
        .default_width(440.0)
        .show(ctx, |ui| {
            ui.heading("Hash Computation");
            ui.separator();

            // ── Algorithm selection ───────────────────────────────────────────
            ui.label("Algorithms:");
            ui.checkbox(&mut state.hash_md5,    "MD5");
            ui.checkbox(&mut state.hash_sha256, "SHA-256");

            ui.separator();

            let file_count = state.file_index.iter().filter(|f| !f.is_dir).count();
            ui.label(format!("Files to hash: {}", file_count));

            let can_hash = file_count > 0 && !state.pending_hash;
            ui.add_enabled_ui(can_hash, |ui| {
                if ui.button("▶ Hash All Files").clicked() {
                    state.pending_hash = true;
                    state.status_message = "Hash computation queued…".to_string();
                    state.log_action(
                        "HASH_START",
                        Some(&format!("files={} md5={} sha256={}", file_count, state.hash_md5, state.hash_sha256)),
                        None,
                    );
                }
            });
            if state.pending_hash {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Hashing in background…");
                });
            }
            if !can_hash && !state.pending_hash && file_count == 0 {
                ui.label(egui::RichText::new("Load evidence first.")
                    .small().color(egui::Color32::from_rgb(150, 120, 60)));
            }

            // ── Content index prompt (Gap 15) ─────────────────────────────────
            if state.ui_state.hash_done_prompt {
                ui.separator();
                ui.label(egui::RichText::new("Hash computation complete. Build content search index now?").strong());
                ui.horizontal(|ui| {
                    if ui.button("Yes").clicked() {
                        state.pending_content_index = true;
                        state.ui_state.hash_done_prompt = false;
                    }
                    if ui.button("Later").clicked() {
                        state.ui_state.hash_done_prompt = false;
                    }
                });
            }

            ui.separator();
            ui.heading("Hash Sets");

            if ui.button("Load NSRL (Known-Good)").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .set_title("Load NSRL Hash Set")
                    .add_filter("Text files", &["txt", "csv"])
                    .pick_file()
                {
                    match state.hash_set_manager.load_custom(&path, "KnownGood") {
                        Ok(count) => {
                            state.status_message = format!("NSRL loaded: {} hashes", count);
                            state.log_action("HASHSET_LOAD", Some(&format!("kind=NSRL hashes={}", count)), None);
                        }
                        Err(e) => {
                            state.error_message = Some(format!("NSRL load failed: {}", e));
                        }
                    }
                }
            }

            if ui.button("Load Custom Known-Bad List").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .set_title("Load Known-Bad Hash List")
                    .add_filter("Text files", &["txt", "csv"])
                    .pick_file()
                {
                    match state.hash_set_manager.load_custom(&path, "KnownBad") {
                        Ok(count) => {
                            state.status_message = format!("Known-bad list loaded: {} hashes", count);
                            state.log_action("HASHSET_LOAD", Some(&format!("kind=KnownBad hashes={}", count)), None);
                        }
                        Err(e) => {
                            state.error_message = Some(format!("Known-bad load failed: {}", e));
                        }
                    }
                }
            }

            ui.separator();

            let known_bad: usize = state.file_index.iter()
                .filter(|f| f.hash_flagged.as_deref() == Some("KnownBad"))
                .count();

            if known_bad > 0 {
                ui.colored_label(
                    egui::Color32::RED,
                    egui::RichText::new(format!("⚠ KNOWN-BAD MATCHES: {}", known_bad))
                        .strong()
                        .size(16.0),
                );
            } else {
                ui.label("No known-bad matches.");
            }

            ui.separator();
            if ui.button("Close").clicked() {
                state.ui_state.show_hash_panel = false;
            }
        });
}
