//! StrataTreeApp — main eframe::App implementation.
//! Drives the egui render loop and dispatches background channel results.

use crate::state::{
    AppState, FileEntry, IndexBatch, IndexingState, TimelineEntry, TimelineEventType,
};
use crate::ui;
use chrono::Timelike;

pub struct StrataTreeApp {
    pub state: AppState,
    last_theme_index: usize,
    first_frame: bool,
}

impl StrataTreeApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut state = AppState::default();

        // Apply theme FIRST — before any UI renders
        crate::theme::apply_theme(&cc.egui_ctx, state.theme());

        // Load Phosphor icon font into egui's font system
        let mut fonts = egui::FontDefinitions::default();
        let phosphor_bytes = egui_phosphor::Variant::Regular.font_bytes();
        fonts.font_data.insert(
            "phosphor".to_owned(),
            egui::FontData::from_static(phosphor_bytes),
        );
        if let Some(font_keys) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
            font_keys.insert(1, "phosphor".to_owned());
        }
        cc.egui_ctx.set_fonts(fonts);

        // Check license — show splash if no valid license
        let needs_splash = matches!(state.license_state.tier, strata_license::LicenseTier::Free)
            && !state.license_state.is_trial
            && state.license_state.days_remaining.is_none();
        state.show_splash = needs_splash;

        if needs_splash {
            state.log_action("LAUNCH", "No valid license — showing activation splash");
        } else {
            state.log_action(
                "LAUNCH",
                &format!(
                    "Strata v{} launched — {}",
                    env!("CARGO_PKG_VERSION"),
                    state.license_state.display_status()
                ),
            );
        }

        if let Some(profile) = crate::case::profile::load_examiner_profile() {
            if profile.name.trim().len() >= 2 {
                state.examiner_name = profile.name.clone();
                state.examiner_setup_dlg.name = profile.name;
                state.examiner_setup_dlg.agency = profile.agency;
                state.examiner_setup_dlg.badge = profile.badge_number;
                state.examiner_setup_dlg.email = profile.email.unwrap_or_default();
                state.examiner_setup_dlg.timezone = profile.timezone;
                state.examiner_setup_dlg.is_open = false;
                if !needs_splash {
                    state.open_ev_dlg.open = true;
                }
            }
        }
        let theme_idx = state.theme_index;
        Self {
            state,
            last_theme_index: theme_idx,
            first_frame: true,
        }
    }
}

impl eframe::App for StrataTreeApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // First frame: make window visible now that theme + fonts are loaded
        if self.first_frame {
            self.first_frame = false;
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        }
        // Only re-apply theme when it changes (hot-swap), not every frame.
        if self.last_theme_index != self.state.theme_index {
            crate::theme::apply_theme(ctx, self.state.theme());
            self.last_theme_index = self.state.theme_index;
        }
        self.poll_indexer(ctx);
        self.poll_timeline(ctx);
        self.poll_content_index(ctx);
        self.poll_hasher(ctx);
        self.poll_carver(ctx);
        self.poll_hex_search(ctx);
        self.poll_hex_pages(ctx);
        if self.state.hex_window_loading {
            ctx.request_repaint_after(std::time::Duration::from_millis(16));
        }
        self.state.refresh_running_counters();
        self.state.maybe_auto_save_case();
        ui::render(ctx, &mut self.state);
    }
}

impl StrataTreeApp {
    fn poll_indexer(&mut self, ctx: &egui::Context) {
        if self.state.vfs_context.is_none() && !self.state.evidence_sources.is_empty() {
            self.state.rebuild_vfs_context();
        }

        // Drain channel into a local vec to avoid borrow conflicts.
        let batches: Vec<IndexBatch> = if let Some(rx) = &self.state.indexing_rx {
            let mut v = Vec::new();
            while let Ok(b) = rx.try_recv() {
                v.push(b);
            }
            v
        } else {
            return;
        };

        let mut done = false;
        for batch in batches {
            match batch {
                IndexBatch::Files(entries) => {
                    let n = entries.len() as u64;
                    let current = match &self.state.indexing_state {
                        IndexingState::Running { files_found } => *files_found,
                        _ => 0,
                    };
                    self.state.file_index.extend(entries);
                    self.state.mark_counters_dirty();
                    self.state.mark_filter_dirty();
                    self.state.indexing_state = IndexingState::Running {
                        files_found: current + n,
                    };
                    self.state.status = format!("INDEXING: {} files\u{2026}", current + n);
                    if current == 0 && n > 0 {
                        self.state
                            .log_action("INDEX_FIRST_BATCH", &format!("files={}", n));
                    }
                }
                IndexBatch::Done { total, elapsed_ms } => {
                    self.state.refresh_running_counters();
                    let actual = self.state.total_files_count as u64;
                    self.state.indexing_state = IndexingState::Complete { file_count: actual };
                    self.state.status = format!(
                        "Indexing complete: {} files in {}ms (reported {})",
                        actual, elapsed_ms, total
                    );
                    self.state.log_action(
                        "INDEX_COMPLETE",
                        &format!(
                            "files={} elapsed={}ms reported={}",
                            actual, elapsed_ms, total
                        ),
                    );

                    let maybe_case_path = self.state.case.as_ref().map(|c| c.path.clone());
                    if let Some(case_path) = maybe_case_path {
                        if !case_path.is_empty() {
                            if let Ok(project) = crate::case::project::VtpProject::open(&case_path)
                            {
                                let _ = project.save_evidence_sources(&self.state.evidence_sources);
                                let _ = project.save_file_index(&self.state.file_index);

                                let integrity = project
                                    .integrity_check()
                                    .unwrap_or_else(|_| "unknown".to_string());
                                let mut parts = Vec::new();
                                for src in &self.state.evidence_sources {
                                    if let Ok(count) = project.count_files_for_evidence(&src.id) {
                                        parts.push(format!("{}={}", src.id, count));
                                    }
                                }
                                if !parts.is_empty() {
                                    let msg =
                                        format!("{} integrity={}", parts.join(" "), integrity);
                                    self.state.log_action("INDEX_DB_COUNT", &msg);
                                }
                            }
                        }
                    }
                    let timeline_sources = build_timeline_sources(&self.state.file_index);
                    self.state.timeline_rx = Some(spawn_timeline_builder(timeline_sources));
                    done = true;
                }
                IndexBatch::Error(e) => {
                    self.state.error = Some(e.clone());
                    self.state.indexing_state = IndexingState::Failed(e.clone());
                    self.state.status = format!("Indexing failed: {}", e);
                    self.state.log_action("INDEX_FAILED", &e);
                    done = true;
                }
            }
        }

        if done {
            self.state.indexing_rx = None;
        }
        if matches!(self.state.indexing_state, IndexingState::Running { .. }) {
            ctx.request_repaint();
        }
    }

    fn poll_timeline(&mut self, ctx: &egui::Context) {
        let Some(rx) = &self.state.timeline_rx else {
            return;
        };
        let Ok(entries) = rx.try_recv() else {
            return;
        };

        self.state.suspicious_event_count = entries.iter().filter(|e| e.suspicious).count();
        self.state.timeline_entries = entries;
        self.state.timeline_rx = None;
        self.state.log_action(
            "TIMELINE_READY",
            &format!(
                "entries={} suspicious={}",
                self.state.timeline_entries.len(),
                self.state.suspicious_event_count
            ),
        );
        ctx.request_repaint();
    }

    fn poll_content_index(&mut self, ctx: &egui::Context) {
        use crate::search::content::ContentIndexProgress;

        let msgs: Vec<ContentIndexProgress> = if let Some(rx) = &self.state.content_index_rx {
            let mut v = Vec::new();
            while let Ok(msg) = rx.try_recv() {
                v.push(msg);
            }
            v
        } else {
            return;
        };

        let mut done = false;
        for msg in msgs {
            match msg {
                ContentIndexProgress::Progress { indexed, total } => {
                    self.state.content_index_progress = (indexed, total);
                    self.state.status = format!("Content indexing: {} / {} files", indexed, total);
                }
                ContentIndexProgress::Complete(stats) => {
                    self.state.content_indexing_active = false;
                    self.state.content_index_ready = true;
                    self.state.content_indexed_files = stats.indexed;
                    self.state.status = format!(
                        "Content index complete: {} indexed, {} skipped",
                        stats.indexed, stats.skipped
                    );
                    self.state.log_action(
                        "CONTENT_INDEX_COMPLETE",
                        &format!("indexed={} skipped={}", stats.indexed, stats.skipped),
                    );
                    done = true;
                }
                ContentIndexProgress::Failed(err) => {
                    self.state.content_indexing_active = false;
                    self.state.content_index_ready = false;
                    self.state.content_index_error = Some(err.clone());
                    self.state.status = format!("Content index failed: {}", err);
                    self.state.log_action("CONTENT_INDEX_FAILED", &err);
                    done = true;
                }
            }
        }

        if done {
            self.state.content_index_rx = None;
        }
        if self.state.content_indexing_active {
            ctx.request_repaint();
        }
    }

    fn poll_hasher(&mut self, ctx: &egui::Context) {
        use crate::evidence::hasher::HashMessage;

        let msgs: Vec<HashMessage> = if let Some(rx) = &self.state.hashing_rx {
            let mut v = Vec::new();
            while let Ok(m) = rx.try_recv() {
                v.push(m);
            }
            v
        } else {
            return;
        };

        let mut done = false;
        let mut counters_changed = false;
        for msg in msgs {
            match msg {
                HashMessage::Result(hr) => {
                    if let Some(entry) = self
                        .state
                        .file_index
                        .iter_mut()
                        .find(|f| f.id == hr.file_id)
                    {
                        entry.md5 = hr.md5;
                        entry.sha256 = hr.sha256;
                        entry.hash_flag = resolve_hash_flag(
                            entry.sha256.as_deref(),
                            entry.md5.as_deref(),
                            &self.state.hash_set_manager,
                        );
                        counters_changed = true;
                    }
                    if let Some(err) = hr.error {
                        self.state.log_action(
                            "HASH_ERROR",
                            &format!("file_id={} error={}", hr.file_id, err),
                        );
                    }
                }
                HashMessage::Progress { completed, total } => {
                    self.state.hashing_progress = (completed, total);
                    self.state.status = format!("Hashing: {}/{} files", completed, total);
                }
                HashMessage::Done {
                    total_hashed,
                    elapsed_ms,
                } => {
                    self.state.status =
                        format!("Hash complete: {} files in {}ms", total_hashed, elapsed_ms);
                    self.state.log_action(
                        "HASH_COMPLETE",
                        &format!("hashed={} elapsed={}ms", total_hashed, elapsed_ms),
                    );
                    self.state.hashing_active = false;
                    done = true;
                }
            }
        }
        if counters_changed {
            self.state.mark_counters_dirty();
        }

        if done {
            self.state.hashing_rx = None;
        }
        if self.state.hashing_active {
            ctx.request_repaint();
        }
    }

    fn poll_carver(&mut self, ctx: &egui::Context) {
        use crate::carve::engine::CarveProgress;

        let msgs: Vec<CarveProgress> = if let Some(rx) = &self.state.carve_rx {
            let mut v = Vec::new();
            while let Ok(m) = rx.try_recv() {
                v.push(m);
            }
            v
        } else {
            return;
        };

        let mut done = false;
        let source_evidence_id = self
            .state
            .carve_source_evidence_id
            .clone()
            .unwrap_or_default();

        for msg in msgs {
            match msg {
                CarveProgress::Scanning {
                    bytes_done,
                    bytes_total,
                } => {
                    self.state.carve_progress_bytes = (bytes_done, bytes_total);
                    self.state.status = format!("Carving: {} / {} bytes", bytes_done, bytes_total);
                }
                CarveProgress::FileCarved(carved) => {
                    let sig = carved.signature_name.replace(' ', "_");
                    let ext = carved.extension.trim_start_matches('.');
                    let virtual_parent = format!("$CARVED/{}", sig);
                    let name = format!("carved_{:016x}.{}", carved.offset, ext);
                    let virtual_path = format!("{}/{}", virtual_parent, name);

                    self.state.file_index.push(crate::state::FileEntry {
                        id: uuid::Uuid::new_v4().to_string(),
                        evidence_id: source_evidence_id.clone(),
                        path: virtual_path,
                        vfs_path: carved.output_path.to_string_lossy().to_string(),
                        parent_path: virtual_parent,
                        name,
                        extension: Some(ext.to_string()),
                        size: Some(carved.size),
                        is_dir: false,
                        is_deleted: false,
                        is_carved: true,
                        is_system: false,
                        is_hidden: false,
                        created_utc: None,
                        modified_utc: None,
                        accessed_utc: None,
                        mft_record: None,
                        md5: None,
                        sha256: None,
                        category: Some("Carved File".to_string()),
                        hash_flag: None,
                        signature: Some(carved.signature_name),
                    });
                    self.state.mark_counters_dirty();
                    self.state.mark_filter_dirty();
                    self.state.carve_files_found = self.state.carve_files_found.saturating_add(1);
                }
                CarveProgress::Complete(stats) => {
                    self.state.carve_progress_bytes = (stats.bytes_scanned, stats.bytes_scanned);
                    self.state.status = format!(
                        "Carving complete: {} files in {}ms",
                        stats.files_carved, stats.elapsed_ms
                    );
                    self.state.log_action(
                        "CARVE_COMPLETE",
                        &format!(
                            "files={} bytes_scanned={} elapsed={}ms",
                            stats.files_carved, stats.bytes_scanned, stats.elapsed_ms
                        ),
                    );
                    self.state.carve_active = false;
                    self.state.carve_cancel_flag = None;
                    done = true;
                }
                CarveProgress::Failed(err) => {
                    self.state.status = format!("Carving failed: {}", err);
                    self.state.log_action("CARVE_FAILED", &err);
                    self.state.carve_active = false;
                    self.state.carve_cancel_flag = None;
                    done = true;
                }
            }
        }

        if done {
            self.state.carve_rx = None;
            self.state.carve_source_evidence_id = None;
        }
        if self.state.carve_active {
            ctx.request_repaint();
        }
    }

    fn poll_hex_search(&mut self, ctx: &egui::Context) {
        use crate::state::HexSearchMessage;

        let msgs: Vec<HexSearchMessage> = if let Some(rx) = &self.state.hex_search_rx {
            let mut v = Vec::new();
            while let Ok(m) = rx.try_recv() {
                v.push(m);
            }
            v
        } else {
            return;
        };

        let mut done = false;
        for msg in msgs {
            match msg {
                HexSearchMessage::Progress { scanned, total } => {
                    self.state.hex_search_progress = (scanned, total);
                    self.state.status = format!("Hex search: {} / {} bytes", scanned, total);
                }
                HexSearchMessage::Done { hits, match_len } => {
                    self.state.hex_search_hits_abs = hits;
                    self.state.hex.search_match_len = match_len;
                    self.state.hex.search_hit_index = 0;
                    if let Some(first) = self.state.hex_search_hits_abs.first().copied() {
                        self.state.seek_hex_offset(first);
                    }
                    sync_visible_hex_hits(&mut self.state);
                    self.state.hex_search_active = false;
                    self.state.status = format!(
                        "Hex search complete: {} hit(s)",
                        self.state.hex_search_hits_abs.len()
                    );
                    done = true;
                }
                HexSearchMessage::Error(err) => {
                    self.state.hex_search_active = false;
                    self.state.hex_search_error = Some(err.clone());
                    self.state.status = format!("Hex search failed: {}", err);
                    done = true;
                }
            }
        }

        if done {
            self.state.hex_search_rx = None;
        }
        if self.state.hex_search_active {
            ctx.request_repaint();
        }
    }

    fn poll_hex_pages(&mut self, ctx: &egui::Context) {
        use crate::state::HexPageMessage;

        let msgs: Vec<HexPageMessage> = if let Some(rx) = &self.state.hex_page_rx {
            let mut v = Vec::new();
            while let Ok(m) = rx.try_recv() {
                v.push(m);
            }
            v
        } else {
            return;
        };

        if msgs.is_empty() {
            return;
        }

        for msg in msgs {
            self.state.apply_hex_page_message(msg);
        }

        if self.state.hex_window_loading || !self.state.hex.data.is_empty() {
            ctx.request_repaint();
        }
    }
}

fn sync_visible_hex_hits(state: &mut AppState) {
    let start = state.hex.window_offset;
    let end = start.saturating_add(state.hex.data.len() as u64);
    state.hex.search_hits.clear();
    for &abs in &state.hex_search_hits_abs {
        if abs >= start && abs < end {
            state.hex.search_hits.push((abs - start) as usize);
        }
    }
}

fn resolve_hash_flag(
    sha256: Option<&str>,
    md5: Option<&str>,
    manager: &crate::hash::hashset::HashSetManager,
) -> Option<String> {
    fn map_match(m: crate::hash::hashset::HashMatch) -> Option<String> {
        match m {
            crate::hash::hashset::HashMatch::KnownBad => Some("KnownBad".to_string()),
            crate::hash::hashset::HashMatch::KnownGood => Some("KnownGood".to_string()),
            crate::hash::hashset::HashMatch::Notable => Some("Notable".to_string()),
            crate::hash::hashset::HashMatch::Unknown => None,
        }
    }

    if let Some(sha) = sha256 {
        let v = map_match(manager.lookup(sha));
        if v.is_some() {
            return v;
        }
    }
    if let Some(md5) = md5 {
        return map_match(manager.lookup(md5));
    }
    None
}

fn spawn_timeline_builder(
    files: Vec<TimelineSourceEntry>,
) -> std::sync::mpsc::Receiver<Vec<TimelineEntry>> {
    let (tx, rx) = std::sync::mpsc::channel::<Vec<TimelineEntry>>();
    std::thread::spawn(move || {
        use chrono::{DateTime, Utc};
        use std::collections::HashSet;

        let mut entries = Vec::new();

        for file in &files {
            if file.is_dir {
                continue;
            }

            let mut push_event = |ts_text: &str, event_type: TimelineEventType| {
                if let Ok(parsed) = DateTime::parse_from_rfc3339(ts_text) {
                    let timestamp = parsed.with_timezone(&Utc);
                    let detail = match &event_type {
                        TimelineEventType::ProcessExecuted => {
                            format!("{} executed (prefetch)", file.name)
                        }
                        _ => file
                            .category
                            .clone()
                            .unwrap_or_else(|| "File event".to_string()),
                    };
                    entries.push(TimelineEntry {
                        timestamp,
                        suspicious: is_suspicious_event(file, &event_type, timestamp),
                        event_type,
                        path: file.path.clone(),
                        evidence_id: file.evidence_id.clone(),
                        detail,
                        file_id: Some(file.id.clone()),
                    });
                }
            };

            if let Some(ts) = &file.created_utc {
                push_event(ts, TimelineEventType::FileCreated);
            }
            if let Some(ts) = &file.modified_utc {
                push_event(ts, TimelineEventType::FileModified);
            }
            if let Some(ts) = &file.accessed_utc {
                push_event(ts, TimelineEventType::FileAccessed);
            }
            if file.is_deleted {
                if let Some(ts) = &file.modified_utc {
                    push_event(ts, TimelineEventType::FileDeleted);
                }
            }

            if matches!(file.category.as_deref(), Some("Prefetch")) {
                if let Some(ts) = &file.modified_utc {
                    push_event(ts, TimelineEventType::ProcessExecuted);
                }
            }

            if matches!(file.category.as_deref(), Some("Browser History")) {
                if let Some(ts) = &file.modified_utc {
                    push_event(ts, TimelineEventType::WebVisit);
                }
            }

            if matches!(file.category.as_deref(), Some("LNK Shortcut")) {
                if let Some(ts) = &file.created_utc {
                    if let Ok(parsed) = DateTime::parse_from_rfc3339(ts) {
                        let timestamp = parsed.with_timezone(&Utc);
                        entries.push(TimelineEntry {
                            timestamp,
                            suspicious: is_suspicious_lnk_path(&file.path),
                            event_type: TimelineEventType::UserActivity,
                            path: file.path.clone(),
                            evidence_id: file.evidence_id.clone(),
                            detail: "LNK created/accessed target".to_string(),
                            file_id: Some(file.id.clone()),
                        });
                    }
                }
                if let Some(ts) = &file.modified_utc {
                    if let Ok(parsed) = DateTime::parse_from_rfc3339(ts) {
                        let timestamp = parsed.with_timezone(&Utc);
                        entries.push(TimelineEntry {
                            timestamp,
                            suspicious: is_suspicious_lnk_path(&file.path),
                            event_type: TimelineEventType::UserActivity,
                            path: file.path.clone(),
                            evidence_id: file.evidence_id.clone(),
                            detail: "LNK target metadata referenced/updated".to_string(),
                            file_id: Some(file.id.clone()),
                        });
                    }
                }
            }
        }

        entries.sort_by_key(|e| e.timestamp);

        let mut deduped = Vec::with_capacity(entries.len());
        let mut seen = HashSet::<(i64, String, String)>::new();
        for e in entries {
            let sec = e.timestamp.timestamp();
            let key = (sec, e.path.clone(), format!("{:?}", e.event_type));
            if seen.insert(key) {
                deduped.push(e);
            }
        }

        let _ = tx.send(deduped);
    });
    rx
}

fn is_suspicious_event(
    file: &TimelineSourceEntry,
    event_type: &TimelineEventType,
    timestamp: chrono::DateTime<chrono::Utc>,
) -> bool {
    let hour = timestamp.hour();
    if hour < 6 {
        return true;
    }

    let path_lc = file.path.to_lowercase();
    if path_lc.contains("/users/") && path_lc.contains("/appdata/local/temp/")
        || path_lc.contains("\\users\\") && path_lc.contains("\\appdata\\local\\temp\\")
    {
        return true;
    }

    if matches!(
        event_type,
        TimelineEventType::FileModified | TimelineEventType::FileCreated
    ) && ["mimikatz", "meterpreter", "cobalt"]
        .iter()
        .any(|n| path_lc.contains(n))
    {
        return true;
    }

    // Inference: mismatch between extension and known signature can indicate masquerading.
    if let (Some(ext), Some(sig)) = (&file.extension, &file.signature) {
        let ext = ext.to_lowercase();
        let sig_lc = sig.to_lowercase();
        if (sig_lc.contains("jpeg") && ext != "jpg" && ext != "jpeg")
            || (sig_lc.contains("png") && ext != "png")
            || (sig_lc.contains("pe executable") && ext != "exe" && ext != "dll")
        {
            return true;
        }
    }

    false
}

fn is_suspicious_lnk_path(path: &str) -> bool {
    let p = path.to_lowercase();
    p.contains("/appdata/local/temp/")
        || p.contains("\\appdata\\local\\temp\\")
        || p.contains("/downloads/")
        || p.contains("\\downloads\\")
        || p.starts_with("\\\\")
}

#[derive(Clone)]
struct TimelineSourceEntry {
    id: String,
    evidence_id: String,
    path: String,
    name: String,
    extension: Option<String>,
    created_utc: Option<String>,
    modified_utc: Option<String>,
    accessed_utc: Option<String>,
    is_dir: bool,
    is_deleted: bool,
    category: Option<String>,
    signature: Option<String>,
}

fn build_timeline_sources(files: &[FileEntry]) -> Vec<TimelineSourceEntry> {
    files
        .iter()
        .map(|f| TimelineSourceEntry {
            id: f.id.clone(),
            evidence_id: f.evidence_id.clone(),
            path: f.path.clone(),
            name: f.name.clone(),
            extension: f.extension.clone(),
            created_utc: f.created_utc.clone(),
            modified_utc: f.modified_utc.clone(),
            accessed_utc: f.accessed_utc.clone(),
            is_dir: f.is_dir,
            is_deleted: f.is_deleted,
            category: f.category.clone(),
            signature: f.signature.clone(),
        })
        .collect()
}

// Old setup_theme removed — now handled by crate::theme::apply_theme().
