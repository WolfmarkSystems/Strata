//! CSAM Sentinel plugin — `AppState` integration.
//!
//! All CSAM-specific methods on `AppState` live here. The state
//! fields themselves live in `state.rs` under the `// ── CSAM
//! Sentinel plugin state ──` section. The plugin shell that
//! registers CSAM with the unified plugin host lives in
//! `plugins/strata-plugin-csam/src/lib.rs`.
//!
//! ## Architectural notes
//!
//! - **Unified audit chain (Decision 3 / Option i):** CSAM events
//!   are recorded into the case's existing `audit_log` SQLite table
//!   via `self.log_action(action_tag, detail)` — the same path used
//!   by every other strata-tree audit event. There is no separate
//!   in-memory CSAM chain in `AppState`. The strata-csam crate's
//!   `CsamAuditLog` / `flush_to_sqlite` helpers remain correct and
//!   tested but are used only by the strata-engine-adapter / Forge
//!   IPC layer, where there is no shared in-memory chain to merge
//!   into. Routing through `log_action` here means:
//!     * One sequence numbering across CSAM and case events
//!     * One set of `prev_hash` links across the unified chain
//!     * `verify_audit_chain` validates CSAM and case events together
//!     * Strata-tree's existing snapshot save persists everything
//!       in one DELETE+re-insert pass — no race window
//!
//! - `EvidenceSource` here is `strata_fs::container::EvidenceSource`
//!   (the one that carries `Box<dyn VirtualFileSystem>`), NOT the
//!   strata-tree-local DTO of the same name. The CSAM scanner needs
//!   the real container, so we re-open it from the path string at
//!   scan time. The strata-tree DTO at `state::EvidenceSource` only
//!   stores the path + metadata.
//!
//! - Image content is NEVER auto-displayed. The [REVIEW] button sets
//!   `csam_pending_review` and the UI renders an acknowledgement
//!   modal. The audit log records the review intent at the moment
//!   the modal is acknowledged.

use std::path::Path;

use crate::state::{verify_audit_chain, AppState, AuditEntry, ChainVerifyResult};
use strata_csam::audit::CsamAuditEntry;
use strata_csam::{
    CsamAuditAction, CsamHashDb, CsamHit, CsamReport, CsamScanner, HashSetSummary, MatchType,
    ScanConfigSummary,
};

impl AppState {
    /// Record a CSAM audit event into the unified case audit log.
    /// This is the **only** way CSAM events should land — never via
    /// a parallel in-memory chain. The action's tag becomes the
    /// `action_type` column; its `detail_string()` becomes `detail`.
    fn log_csam(&mut self, action: CsamAuditAction) {
        let tag = action.tag();
        let detail = action.detail_string();
        self.log_action(tag, &detail);
    }

    /// Import a CSAM hash set from a file. The format is auto-detected
    /// (NCMEC, Project VIC VICS JSON, or generic hash list). The
    /// imported db is appended to `csam_hash_dbs` and a CSAM audit
    /// event is recorded.
    ///
    /// `name` is the human-readable label shown in the UI; if blank,
    /// the file stem is used.
    pub fn import_csam_hash_set(&mut self, path: &Path, name: &str) {
        let label = if name.trim().is_empty() {
            path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("hash_set")
                .to_string()
        } else {
            name.trim().to_string()
        };

        match CsamHashDb::import_from_file(path, &self.examiner_name, &label) {
            Ok(db) => {
                let format_str = db.source_format.as_str().to_string();
                let entries = db.entry_count;
                let display_name = db.name.clone();

                self.csam_hash_dbs.push(db);
                self.log_csam(CsamAuditAction::HashSetImported {
                    name: display_name.clone(),
                    entries,
                    format: format_str.clone(),
                });
                self.csam_status = format!(
                    "Imported {} ({} entries, {})",
                    display_name, entries, format_str
                );
            }
            Err(e) => {
                self.csam_status = format!("Hash set import failed: {} — {:#}", path.display(), e);
            }
        }
    }

    /// Run a CSAM scan over the currently loaded evidence using all
    /// previously imported hash databases. Hits replace any prior
    /// scan's results. The scan is synchronous and will block the UI
    /// thread for the duration; large evidence should run from a
    /// background thread (the IPC layer in strata-engine-adapter
    /// wraps this in `tokio::task::spawn_blocking` for the Tauri
    /// command surface).
    pub fn run_csam_scan(&mut self) {
        if self.csam_scan_running {
            self.csam_status = "Scan already in progress.".to_string();
            return;
        }
        let evidence_path = match self.evidence_sources.first() {
            Some(s) => s.path.clone(),
            None => {
                self.csam_status = "No evidence loaded.".to_string();
                return;
            }
        };
        if self.csam_hash_dbs.is_empty() && !self.csam_scan_config.run_perceptual {
            self.csam_status =
                "No hash sets loaded — import at least one before running a scan.".to_string();
            return;
        }

        self.csam_scan_running = true;
        self.log_csam(CsamAuditAction::ScanStarted);

        // Re-open the evidence source from its path to get a fresh
        // strata_fs::container::EvidenceSource (the one with the VFS).
        // The strata-tree state::EvidenceSource is only a UI DTO.
        let source = match strata_fs::container::EvidenceSource::open(Path::new(&evidence_path)) {
            Ok(s) => s,
            Err(e) => {
                self.csam_status = format!("Failed to open evidence: {:?}", e);
                self.log_csam(CsamAuditAction::ScanAborted {
                    reason: format!("evidence open: {:?}", e),
                });
                self.csam_scan_running = false;
                return;
            }
        };

        let case_number = self
            .case
            .as_ref()
            .map(|c| c.id.clone())
            .unwrap_or_else(|| "UNCASED".to_string());

        let mut scanner = CsamScanner::new(&self.examiner_name, &case_number);
        // Move the existing hash dbs into the scanner. They are
        // returned to AppState after the scan completes so subsequent
        // scans can re-use them without re-importing.
        let dbs = std::mem::take(&mut self.csam_hash_dbs);
        for db in dbs {
            scanner.add_hash_db(db);
        }

        let (tx, _rx) = std::sync::mpsc::channel();
        let scan_result = scanner.scan_evidence(&source, &self.csam_scan_config, tx);

        match scan_result {
            Ok(hits) => {
                let hit_count = hits.len();
                // Snapshot the per-hit data BEFORE the borrow handoff
                // so we can call self.log_csam without conflicting
                // with the &self borrow on `hits`.
                let hit_log_data: Vec<(String, String)> = hits
                    .iter()
                    .map(|h| (h.file_path.clone(), h.match_type.as_str().to_string()))
                    .collect();
                self.csam_hits = hits;
                for (file_path, match_type) in hit_log_data {
                    self.log_csam(CsamAuditAction::HitDetected {
                        file_path,
                        match_type,
                    });
                }
                self.log_csam(CsamAuditAction::ScanCompleted {
                    files_scanned: 0, // populated from progress channel by IPC layer
                    hits_found: hit_count,
                });

                // Bridge CSAM hits into the plugin_results pipeline so
                // Sigma's correlation engine sees them on its next run.
                // See state_csam.rs::publish_csam_plugin_output and the
                // v1.4.0 CSAM rules in plugins/strata-plugin-sigma.
                self.publish_csam_plugin_output();

                self.csam_status = if hit_count == 0 {
                    "Scan complete — no hits.".to_string()
                } else {
                    format!("Scan complete — {} hit(s) detected.", hit_count)
                };
            }
            Err(e) => {
                self.log_csam(CsamAuditAction::ScanAborted {
                    reason: format!("{:#}", e),
                });
                self.csam_status = format!("Scan failed: {:#}", e);
            }
        }

        self.csam_scan_running = false;
    }

    /// Build a synthetic `PluginOutput` from the current CSAM hits and
    /// publish it into `self.plugin_results`, replacing any prior
    /// CSAM entry. This is the bridge that lets Sigma's correlation
    /// engine see CSAM hits as ordinary plugin artifacts.
    ///
    /// ## Detail string format (load-bearing)
    ///
    /// Each per-hit `ArtifactRecord.detail` is formatted as a series
    /// of bracket-delimited tokens:
    ///
    /// ```text
    /// [match_type=ExactSha256] [confidence=Confirmed] [source=ncmec_2024] [sha256=abc...]
    /// [match_type=Perceptual] [confidence=High] [source=db_x] [sha256=...] [distance=3]
    /// ```
    ///
    /// Sigma rules 28 and 29 do substring matching against these
    /// tokens. The bracket delimiters make matches unambiguous —
    /// `[confidence=High]` cannot be a prefix of any other token.
    /// **Do not change this format without updating the matching
    /// rules in plugins/strata-plugin-sigma/src/lib.rs in lockstep.**
    fn publish_csam_plugin_output(&mut self) {
        use strata_plugin_sdk::{
            ArtifactCategory, ArtifactRecord, ForensicValue, PluginOutput, PluginSummary,
        };

        let records: Vec<ArtifactRecord> = self
            .csam_hits
            .iter()
            .map(|hit| {
                let distance_token = match hit.perceptual_distance {
                    Some(d) => format!(" [distance={}]", d),
                    None => String::new(),
                };
                let detail = format!(
                    "[match_type={}] [confidence={}] [source={}] [sha256={}]{}",
                    hit.match_type.as_str(),
                    hit.confidence.as_str(),
                    hit.match_source,
                    hit.sha256,
                    distance_token,
                );
                ArtifactRecord {
                    category: ArtifactCategory::Media,
                    subcategory: "CSAM Hit".to_string(),
                    timestamp: Some(hit.timestamp_utc.timestamp()),
                    title: hit.file_path.clone(),
                    detail,
                    source_path: hit.file_path.clone(),
                    forensic_value: ForensicValue::Critical,
                    // Per spec: "mitre: N/A — child safety". CSAM
                    // detection is not adversary-tactic correlation.
                    mitre_technique: None,
                    is_suspicious: true,
                    raw_data: None,
                    confidence: 0,
                }
            })
            .collect();

        let total = records.len();
        let output = PluginOutput {
            plugin_name: "Strata CSAM Scanner".to_string(),
            plugin_version: env!("CARGO_PKG_VERSION").to_string(),
            executed_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            duration_ms: 0,
            artifacts: records,
            summary: PluginSummary {
                total_artifacts: total,
                suspicious_count: total,
                categories_populated: vec!["Media".to_string()],
                headline: format!("CSAM scan: {} hit(s)", total),
            },
            warnings: Vec::new(),
        };

        // Replace any prior CSAM PluginOutput; otherwise append.
        self.plugin_results
            .retain(|o| o.plugin_name != "Strata CSAM Scanner");
        self.plugin_results.push(output);
    }

    /// The examiner has acknowledged the [REVIEW] warning modal and
    /// chosen to proceed. This records the review intent in the
    /// unified audit chain and marks the hit as `examiner_reviewed`.
    /// **It does NOT auto-display the image** — that remains the
    /// spec-mandated rule. The actual viewing UI (if any) must be
    /// explicitly opened by the examiner from a separate action.
    pub fn csam_mark_reviewed(&mut self, hit_id: &str) {
        if let Some(hit) = self
            .csam_hits
            .iter_mut()
            .find(|h| h.hit_id.to_string() == hit_id)
        {
            hit.examiner_reviewed = true;
        }
        self.log_csam(CsamAuditAction::HitReviewed {
            hit_id: hit_id.to_string(),
        });
        self.csam_pending_review = None;
    }

    /// Examiner confirms a hit. Records `examiner_confirmed = true`,
    /// stores any examiner notes from the buffer, writes a
    /// `CSAM_HIT_CONFIRMED` event into the unified audit log.
    pub fn csam_confirm_hit(&mut self, hit_id: &str) {
        let notes = self
            .csam_note_buffers
            .get(hit_id)
            .cloned()
            .unwrap_or_default();
        if let Some(hit) = self
            .csam_hits
            .iter_mut()
            .find(|h| h.hit_id.to_string() == hit_id)
        {
            hit.examiner_confirmed = true;
            hit.examiner_reviewed = true;
            hit.examiner_notes = notes;
        }
        self.log_csam(CsamAuditAction::HitConfirmed {
            hit_id: hit_id.to_string(),
        });
        self.csam_status = format!("Hit {} confirmed.", hit_id);
    }

    /// Examiner dismisses a hit as a false positive. The hit stays
    /// in the results list (so it remains in the audit trail and the
    /// report) but is marked as dismissed via the audit action.
    pub fn csam_dismiss_hit(&mut self, hit_id: &str, reason: &str) {
        self.log_csam(CsamAuditAction::HitDismissed {
            hit_id: hit_id.to_string(),
            reason: reason.to_string(),
        });
        self.csam_status = format!("Hit {} dismissed.", hit_id);
    }

    /// Filter the unified `audit_log` for entries with a `CSAM_*`
    /// action tag and convert them to the strata-csam `CsamAuditEntry`
    /// shape (which is field-for-field identical to strata-tree's
    /// `AuditEntry`). Used by the report generator and the audit-log
    /// export button.
    fn collect_csam_audit_entries(&self) -> Vec<CsamAuditEntry> {
        self.audit_log
            .iter()
            .filter(|e| e.action.starts_with("CSAM_"))
            .map(audit_entry_to_csam)
            .collect()
    }

    /// Build a `CsamReport` from current state and write it as PDF
    /// plus JSON. The JSON file is named alongside the PDF with a
    /// `.json` extension.
    ///
    /// The report's `audit_log` field contains only CSAM-tagged
    /// entries (filtered from the unified case log). The
    /// `audit_integrity_verified` flag, however, reflects whether the
    /// **entire** case audit chain verifies — chain-of-custody is a
    /// global property; if any link in the unified chain is broken,
    /// every claim downstream of it is suspect.
    pub fn generate_csam_report(&mut self, pdf_path: &Path) {
        let unified_chain_ok = matches!(
            verify_audit_chain(&self.audit_log),
            ChainVerifyResult::Verified { .. }
        );
        let csam_entries = self.collect_csam_audit_entries();

        let report = CsamReport {
            case_number: self
                .case
                .as_ref()
                .map(|c| c.id.clone())
                .unwrap_or_else(|| "UNCASED".to_string()),
            examiner_name: self.examiner_name.clone(),
            examiner_agency: String::new(), // TODO: pull from case metadata when added
            scan_date_utc: chrono::Utc::now(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            evidence_path: self
                .evidence_sources
                .first()
                .map(|s| s.path.clone())
                .unwrap_or_default(),
            evidence_sha256: self
                .evidence_sources
                .first()
                .and_then(|s| s.sha256.clone())
                .unwrap_or_default(),
            hash_sets_used: self
                .csam_hash_dbs
                .iter()
                .map(|db| HashSetSummary {
                    name: db.name.clone(),
                    format: db.source_format.as_str().to_string(),
                    entry_count: db.entry_count,
                    imported_at: db
                        .imported_at
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                })
                .collect(),
            scan_config: ScanConfigSummary {
                run_exact_hash: self.csam_scan_config.run_exact_hash,
                run_perceptual: self.csam_scan_config.run_perceptual,
                perceptual_threshold: self.csam_scan_config.perceptual_threshold,
                scan_all_files: self.csam_scan_config.scan_all_files,
                image_extensions: self.csam_scan_config.image_extensions.clone(),
            },
            hits: self.csam_hits.clone(),
            audit_log: csam_entries,
            audit_integrity_verified: unified_chain_ok,
        };

        match report.generate_pdf(pdf_path) {
            Ok(()) => {
                let json_path = pdf_path.with_extension("json");
                if let Err(e) = report.generate_json(&json_path) {
                    self.csam_status = format!("PDF written, JSON failed: {:#}", e);
                    return;
                }
                self.log_csam(CsamAuditAction::ReportGenerated {
                    path: pdf_path.display().to_string(),
                });
                self.csam_status = format!(
                    "Report written to {} (+ {})",
                    pdf_path.display(),
                    json_path.display()
                );
            }
            Err(e) => {
                self.csam_status = format!("Report PDF failed: {:#}", e);
            }
        }
    }

    /// Export CSAM audit events as JSON. Filtered from the unified
    /// case audit log; the result is a list of `CsamAuditEntry`
    /// records that round-trip through `serde_json`.
    pub fn export_csam_audit_log(&self, output_path: &Path) -> std::io::Result<()> {
        let entries = self.collect_csam_audit_entries();
        let json = serde_json::to_string_pretty(&entries).map_err(std::io::Error::other)?;
        std::fs::write(output_path, json)
    }

    /// Quick read-only summary used by the Plugins panel CSAM
    /// details pane. Returns (hash_sets_count, hits_count, confirmed_count).
    pub fn csam_summary(&self) -> (usize, usize, usize) {
        let confirmed = self
            .csam_hits
            .iter()
            .filter(|h| h.examiner_confirmed)
            .count();
        (self.csam_hash_dbs.len(), self.csam_hits.len(), confirmed)
    }

    /// Helper for the UI: render-ready label for a hit's match type.
    pub fn csam_hit_match_label(hit: &CsamHit) -> &'static str {
        match hit.match_type {
            MatchType::ExactMd5 => "Exact MD5",
            MatchType::ExactSha1 => "Exact SHA1",
            MatchType::ExactSha256 => "Exact SHA256",
            MatchType::Perceptual => "Perceptual (dHash)",
        }
    }
}

/// Field-for-field clone from strata-tree's `AuditEntry` to the
/// strata-csam `CsamAuditEntry`. The two types are deliberately the
/// same shape (the strata-csam crate mirrors the strata-tree schema
/// exactly per Decision 3) but live in different crates, so we need
/// an explicit conversion.
fn audit_entry_to_csam(e: &AuditEntry) -> CsamAuditEntry {
    CsamAuditEntry {
        id: e.id.clone(),
        sequence: e.sequence,
        timestamp_utc: e.timestamp_utc.clone(),
        examiner: e.examiner.clone(),
        action: e.action.clone(),
        detail: e.detail.clone(),
        evidence_id: e.evidence_id.clone(),
        file_path: e.file_path.clone(),
        prev_hash: e.prev_hash.clone(),
        entry_hash: e.entry_hash.clone(),
    }
}
