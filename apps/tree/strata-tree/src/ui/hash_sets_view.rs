//! Hash sets view — load and manage known-good/known-bad/notable hash sets.

use crate::state::{colors::*, AppState, HashSetListItem};

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    maybe_load_case_hash_sets(state);

    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("HASH SETS")
                .color(ACCENT)
                .size(11.0)
                .strong(),
        );
        ui.separator();
        ui.label(
            egui::RichText::new("Load NSRL/custom lists and match against computed hashes")
                .color(TEXT_MUTED)
                .size(9.0),
        );
    });
    ui.add_space(6.0);

    ui.horizontal(|ui| {
        if ui.button("IMPORT KNOWN GOOD").clicked() {
            import_hash_set(state, "KnownGood");
        }
        if ui.button("IMPORT KNOWN BAD").clicked() {
            import_hash_set(state, "KnownBad");
        }
        if ui.button("IMPORT NOTABLE").clicked() {
            import_hash_set(state, "Notable");
        }
        if ui.button("CLEAR ALL").clicked() {
            state.hash_set_manager.clear();
            state.hash_sets.clear();
            clear_hash_flags(state);
            state.hash_set_status = "Hash sets cleared.".to_string();
            state.mark_case_dirty();
            state.log_action("HASHSET_CLEAR", "all hash sets cleared");
            save_case_hash_sets(state);
        }
    });

    if !state.hash_set_status.is_empty() {
        ui.add_space(4.0);
        ui.label(
            egui::RichText::new(&state.hash_set_status)
                .color(TEXT_SEC)
                .size(9.0),
        );
    }

    ui.add_space(8.0);
    ui.label(
        egui::RichText::new("NAME | CATEGORY | ENTRIES | SOURCE")
            .color(TEXT_MUTED)
            .size(8.5)
            .strong(),
    );
    ui.separator();

    egui::ScrollArea::vertical().show(ui, |ui| {
        if state.hash_sets.is_empty() {
            ui.label(
                egui::RichText::new("No hash sets loaded.")
                    .color(TEXT_MUTED)
                    .size(9.5),
            );
            return;
        }
        let mut remove_idx: Option<usize> = None;
        for (idx, hs) in state.hash_sets.iter().enumerate() {
            ui.horizontal(|ui| {
                let name_resp = ui.label(egui::RichText::new(&hs.name).color(ACCENT).size(9.5));
                name_resp.context_menu(|ui| {
                    if ui.button("Copy Name").clicked() {
                        ui.ctx().copy_text(hs.name.clone());
                        ui.close_menu();
                    }
                    if ui.button("Copy Source Path").clicked() {
                        ui.ctx().copy_text(hs.source.clone());
                        ui.close_menu();
                    }
                });
                ui.separator();
                ui.label(hs.category.as_str());
                ui.separator();
                ui.label(hs.entry_count.to_string());
                ui.separator();
                ui.label(hs.source.as_str());
                ui.separator();
                if ui.small_button("Remove").clicked() {
                    remove_idx = Some(idx);
                }
            });
        }
        if let Some(idx) = remove_idx {
            let removed = state.hash_sets.remove(idx);
            rebuild_hash_set_manager(state);
            state.recompute_hash_flags();
            state.mark_case_dirty();
            state.hash_set_status = format!("Removed hash set: {}", removed.name);
            state.log_action(
                "HASHSET_REMOVE",
                &format!("name={} source={}", removed.name, removed.source),
            );
            save_case_hash_sets(state);
        }
    });

    ui.add_space(8.0);
    ui.label(
        egui::RichText::new("NIST NSRL download: https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl")
            .color(TEXT_MUTED)
            .size(8.5),
    );
}

fn import_hash_set(state: &mut AppState, category: &str) {
    let Some(path) = rfd::FileDialog::new()
        .set_title("Import Hash Set")
        .add_filter("Hash Lists", &["txt", "csv", "tsv"])
        .pick_file()
    else {
        return;
    };

    let file_name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "hashset".to_string());

    let loaded = if file_name.to_lowercase().contains("nsrl") {
        state.hash_set_manager.load_nsrl(&path)
    } else {
        state.hash_set_manager.load_custom(&path, category)
    };

    match loaded {
        Ok(count) => {
            let source = path.to_string_lossy().to_string();
            if state.hash_sets.iter().any(|s| {
                s.source.eq_ignore_ascii_case(&source) && s.category.eq_ignore_ascii_case(category)
            }) {
                state.hash_set_status = format!("Already loaded: {}", file_name);
                return;
            }
            state.hash_sets.push(HashSetListItem {
                name: file_name.clone(),
                category: category.to_string(),
                source,
                entry_count: count,
            });
            state.recompute_hash_flags();
            state.hash_set_status = format!("Loaded {} entries from {}", count, file_name);
            state.mark_case_dirty();
            state.log_action(
                "HASHSET_LOAD",
                &format!(
                    "category={} count={} source={}",
                    category,
                    count,
                    path.display()
                ),
            );
            save_case_hash_sets(state);
        }
        Err(err) => {
            state.hash_set_status = format!("Hash set import failed: {}", err);
        }
    }
}

fn clear_hash_flags(state: &mut AppState) {
    for file in &mut state.file_index {
        file.hash_flag = None;
    }
}

fn maybe_load_case_hash_sets(state: &mut AppState) {
    if !state.hash_sets.is_empty() {
        return;
    }
    let Some(case_path) = state.case.as_ref().map(|c| c.path.clone()) else {
        return;
    };
    if case_path.is_empty() {
        return;
    }
    let Ok(project) = crate::case::project::VtpProject::open(&case_path) else {
        return;
    };
    let mut items = project.load_hash_sets().ok().unwrap_or_default();
    if items.is_empty() {
        let Some(json) = project.get_meta("hash_sets_json") else {
            return;
        };
        let Ok(json_items) = serde_json::from_str::<Vec<HashSetListItem>>(&json) else {
            return;
        };
        items = json_items;
    }

    for item in &mut items {
        let path = std::path::PathBuf::from(&item.source);
        if !path.exists() {
            continue;
        }
        let loaded = if item.name.to_lowercase().contains("nsrl")
            || item.category.eq_ignore_ascii_case("KnownGood")
        {
            state.hash_set_manager.load_nsrl(&path)
        } else {
            state.hash_set_manager.load_custom(&path, &item.category)
        };
        if let Ok(count) = loaded {
            item.entry_count = count;
        } else {
            continue;
        }
    }
    state.hash_sets = items;
    state.recompute_hash_flags();
}

fn save_case_hash_sets(state: &AppState) {
    let Some(case_path) = state.case.as_ref().map(|c| c.path.clone()) else {
        return;
    };
    if case_path.is_empty() {
        return;
    }
    if let Ok(project) = crate::case::project::VtpProject::open(&case_path) {
        if let Ok(json) = serde_json::to_string(&state.hash_sets) {
            let _ = project.set_meta("hash_sets_json", &json);
        }
        let _ = project.save_hash_sets(&state.hash_sets);
    }
}

fn rebuild_hash_set_manager(state: &mut AppState) {
    state.hash_set_manager.clear();
    for item in &mut state.hash_sets {
        let path = std::path::PathBuf::from(&item.source);
        if !path.exists() {
            item.entry_count = 0;
            continue;
        }
        let loaded = if item.name.to_lowercase().contains("nsrl")
            || item.category.eq_ignore_ascii_case("KnownGood")
        {
            state.hash_set_manager.load_nsrl(&path)
        } else {
            state.hash_set_manager.load_custom(&path, &item.category)
        };
        item.entry_count = loaded.unwrap_or_default();
    }
}
