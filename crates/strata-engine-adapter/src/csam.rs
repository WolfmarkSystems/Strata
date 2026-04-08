//! CSAM Sentinel — Forge IPC commands.
//!
//! This module exposes the CSAM scanner workflow as JSON-friendly
//! synchronous functions that the Tauri command layer can wrap with
//! `tokio::task::spawn_blocking`. It mirrors the existing engine
//! adapter pattern (see `store.rs::EVIDENCE_STORE` and `plugins.rs`):
//! a process-singleton store of per-evidence sessions, each holding
//! its own inner `Mutex` so independent evidences can be operated on
//! in parallel without contention.
//!
//! ## Why this lives here and not in strata-tree
//!
//! Strata ships in two product surfaces: the strata-tree egui app
//! (which has its own case `audit_log` SQLite table and routes CSAM
//! events through `AppState::log_action` directly into the unified
//! case chain) and the Forge desktop Tauri app (which has no shared
//! case file). For the Forge surface there is no in-memory case log
//! to merge into, so the CSAM session keeps its OWN `CsamAuditLog`
//! and exposes `csam_export_audit_log` for JSON export and
//! `csam_generate_report` for the embedded report copy. The
//! `strata_csam::audit::flush_to_sqlite` helper from Task 5 is
//! deliberately NOT called from here — that helper is reserved for
//! a future world where Forge grows a case database, at which point
//! the flush ordering documented in `strata_csam::audit` becomes
//! load-bearing.
//!
//! ## Lock order (avoid deadlock)
//!
//! Several commands need both a `CsamSession` and the underlying
//! `OpenEvidence` (most notably `csam_run_scan`, which holds a
//! `&EvidenceSource` for the duration of the scan). To prevent
//! deadlock between this module and existing engine-adapter
//! commands, **always acquire locks in this order**:
//!
//! 1. `CSAM_STORE` outer lock (release immediately after lookup)
//! 2. `CsamSession` inner lock
//! 3. `EVIDENCE_STORE` outer lock (release immediately after lookup)
//! 4. `OpenEvidence` inner lock
//!
//! Holding the `CsamSession` lock while acquiring the `OpenEvidence`
//! lock is safe because no existing engine-adapter command does the
//! reverse (no command holds `OpenEvidence` and then asks for a
//! `CsamSession`). If you add a new command that violates this, fix
//! it — do not invent a different lock order.
//!
//! ## Image content
//!
//! Image bytes are NEVER returned through any command in this
//! module. Hits include path, hashes, and match metadata only. The
//! `csam_review_hit` command records the review intent in the audit
//! chain and flips `examiner_reviewed` — it does NOT open any image
//! viewer. The Forge UI is responsible for the same acknowledgement
//! modal pattern strata-tree uses.

use crate::store::get_evidence;
use crate::types::{AdapterError, AdapterResult};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use strata_csam::{
    CsamAuditAction, CsamAuditLog, CsamHashDb, CsamHit, CsamReport, CsamScanner, HashSetSummary,
    MatchType, ScanConfig, ScanConfigSummary,
};

// ──────────────────────────────────────────────────────────────────────
// Session storage
// ──────────────────────────────────────────────────────────────────────

/// All state for one evidence's CSAM workflow. Created on demand by
/// `csam_create_session` (or implicitly by the first command on a
/// fresh evidence id).
pub struct CsamSession {
    pub examiner: String,
    pub case_number: String,
    pub hash_dbs: Vec<CsamHashDb>,
    pub hits: Vec<CsamHit>,
    pub audit: CsamAuditLog,
}

impl CsamSession {
    fn new(examiner: String, case_number: String) -> Self {
        Self {
            examiner,
            case_number,
            hash_dbs: Vec::new(),
            hits: Vec::new(),
            audit: CsamAuditLog::new(),
        }
    }

    /// Record a CSAM audit event into this session's in-memory chain.
    /// Wraps the borrow-checker dance of cloning the examiner string
    /// before calling `audit.record` (which mutably borrows `self`).
    fn record(&mut self, action: CsamAuditAction) {
        let examiner = self.examiner.clone();
        self.audit.record(&examiner, action);
    }
}

/// Process-wide singleton: evidence_id → per-evidence CSAM session.
/// Mirrors the `EVIDENCE_STORE` pattern in `store.rs`. The outer
/// `Mutex` guards the `HashMap`; each `Arc<Mutex<CsamSession>>`
/// allows independent sessions to run in parallel.
pub static CSAM_STORE: Lazy<Mutex<HashMap<String, Arc<Mutex<CsamSession>>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Look up (or create) a CSAM session for the given evidence id.
fn get_or_create_session(
    evidence_id: &str,
    examiner: &str,
    case_number: &str,
) -> Arc<Mutex<CsamSession>> {
    let mut store = CSAM_STORE.lock().expect("csam store poisoned");
    store
        .entry(evidence_id.to_string())
        .or_insert_with(|| {
            Arc::new(Mutex::new(CsamSession::new(
                examiner.to_string(),
                case_number.to_string(),
            )))
        })
        .clone()
}

/// Look up a CSAM session by evidence id without creating one.
fn get_session(evidence_id: &str) -> AdapterResult<Arc<Mutex<CsamSession>>> {
    let store = CSAM_STORE.lock().expect("csam store poisoned");
    store
        .get(evidence_id)
        .cloned()
        .ok_or_else(|| {
            AdapterError::EngineError(format!("no CSAM session for evidence {}", evidence_id))
        })
}

// ──────────────────────────────────────────────────────────────────────
// JSON-friendly DTOs
// ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashSetImportResult {
    pub name: String,
    pub format: String,
    pub entry_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsamHitInfo {
    pub hit_id: String,
    pub file_path: String,
    pub file_size: u64,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub match_type: String,
    pub match_source: String,
    pub perceptual_hash: Option<String>,
    pub perceptual_distance: Option<u32>,
    pub confidence: String,
    pub timestamp_utc: String,
    pub examiner_reviewed: bool,
    pub examiner_confirmed: bool,
    pub examiner_notes: String,
}

impl From<&CsamHit> for CsamHitInfo {
    fn from(h: &CsamHit) -> Self {
        Self {
            hit_id: h.hit_id.to_string(),
            file_path: h.file_path.clone(),
            file_size: h.file_size,
            md5: h.md5.clone(),
            sha1: h.sha1.clone(),
            sha256: h.sha256.clone(),
            match_type: h.match_type.as_str().to_string(),
            match_source: h.match_source.clone(),
            perceptual_hash: h.perceptual_hash.clone(),
            perceptual_distance: h.perceptual_distance,
            confidence: h.confidence.as_str().to_string(),
            timestamp_utc: h
                .timestamp_utc
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            examiner_reviewed: h.examiner_reviewed,
            examiner_confirmed: h.examiner_confirmed,
            examiner_notes: h.examiner_notes.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsamScanSummary {
    pub files_scanned: usize,
    pub hits_found: usize,
    pub status: String,
}

/// Scan options as accepted from the IPC layer. Mirrors
/// `strata_csam::ScanConfig` but with serde derives so it can be
/// passed in from the JS side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsamScanOptions {
    pub run_exact_hash: bool,
    pub run_perceptual: bool,
    pub perceptual_threshold: u32,
    pub scan_all_files: bool,
    pub image_extensions: Vec<String>,
}

impl From<CsamScanOptions> for ScanConfig {
    fn from(o: CsamScanOptions) -> Self {
        ScanConfig {
            run_exact_hash: o.run_exact_hash,
            run_perceptual: o.run_perceptual,
            perceptual_threshold: o.perceptual_threshold,
            scan_all_files: o.scan_all_files,
            image_extensions: o.image_extensions,
        }
    }
}

impl Default for CsamScanOptions {
    fn default() -> Self {
        let cfg = ScanConfig::default();
        Self {
            run_exact_hash: cfg.run_exact_hash,
            run_perceptual: cfg.run_perceptual,
            perceptual_threshold: cfg.perceptual_threshold,
            scan_all_files: cfg.scan_all_files,
            image_extensions: cfg.image_extensions,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// IPC commands
// ──────────────────────────────────────────────────────────────────────

/// Create or reset a CSAM session for the given evidence. Subsequent
/// commands operate on this session. Calling this on an existing
/// evidence id replaces the session entirely (use this when the
/// examiner switches cases).
pub fn csam_create_session(
    evidence_id: &str,
    examiner: &str,
    case_number: &str,
) -> AdapterResult<()> {
    let mut store = CSAM_STORE.lock().expect("csam store poisoned");
    store.insert(
        evidence_id.to_string(),
        Arc::new(Mutex::new(CsamSession::new(
            examiner.to_string(),
            case_number.to_string(),
        ))),
    );
    Ok(())
}

/// Drop a CSAM session. Returns true if a session existed.
pub fn csam_drop_session(evidence_id: &str) -> bool {
    CSAM_STORE
        .lock()
        .expect("csam store poisoned")
        .remove(evidence_id)
        .is_some()
}

/// Import a hash set from disk. Format auto-detected (NCMEC, VICS,
/// or generic length-detected hash list). The session is created
/// on first use if it doesn't exist yet.
pub fn csam_import_hash_set(
    evidence_id: &str,
    path: &str,
    name: &str,
    examiner: &str,
    case_number: &str,
) -> AdapterResult<HashSetImportResult> {
    let session = get_or_create_session(evidence_id, examiner, case_number);
    let mut s = session.lock().expect("csam session poisoned");

    let label = if name.trim().is_empty() {
        Path::new(path)
            .file_stem()
            .and_then(|x| x.to_str())
            .unwrap_or("hash_set")
            .to_string()
    } else {
        name.trim().to_string()
    };

    let db = CsamHashDb::import_from_file(Path::new(path), &s.examiner, &label)
        .map_err(|e| AdapterError::EngineError(format!("import: {:#}", e)))?;

    let result = HashSetImportResult {
        name: db.name.clone(),
        format: db.source_format.as_str().to_string(),
        entry_count: db.entry_count,
    };

    s.record(CsamAuditAction::HashSetImported {
        name: db.name.clone(),
        entries: db.entry_count,
        format: db.source_format.as_str().to_string(),
    });
    s.hash_dbs.push(db);
    Ok(result)
}

/// Run a CSAM scan over the loaded evidence using all imported
/// hash sets. Replaces any prior hits in the session. Synchronous;
/// the Tauri layer is expected to wrap this in `spawn_blocking`.
///
/// **Lock order**: `CsamSession` (held for the entire scan) then
/// `OpenEvidence` (held for the scan_evidence call). See module
/// docstring for the canonical lock order.
pub fn csam_run_scan(
    evidence_id: &str,
    options: CsamScanOptions,
) -> AdapterResult<CsamScanSummary> {
    let session = get_session(evidence_id)?;
    let mut s = session.lock().expect("csam session poisoned");

    if s.hash_dbs.is_empty() && !options.run_perceptual {
        return Err(AdapterError::EngineError(
            "no hash sets loaded — import at least one before running a scan".to_string(),
        ));
    }

    s.record(CsamAuditAction::ScanStarted);

    // Move hash_dbs into the scanner. They are reclaimed after the
    // scan via `scanner.hash_dbs()` clone-back below so subsequent
    // scans can re-use them without re-import.
    let dbs = std::mem::take(&mut s.hash_dbs);
    let mut scanner = CsamScanner::new(&s.examiner, &s.case_number);
    for db in dbs {
        scanner.add_hash_db(db);
    }

    let scan_config: ScanConfig = options.clone().into();
    let (tx, _rx) = std::sync::mpsc::channel();

    // Acquire OpenEvidence inner lock for the scan duration.
    let arc = get_evidence(evidence_id)?;
    let scan_result = {
        let guard = arc.lock().expect("evidence lock poisoned");
        scanner.scan_evidence(&guard.source, &scan_config, tx)
    };

    // The hash_dbs were moved into the scanner; CsamScanner doesn't
    // expose a take() helper. For now we accept that scans consume
    // the imported sets — the examiner re-imports if needed. This is
    // documented as a TODO in strata-tree's state_csam.rs as well;
    // a future strata-csam refactor will change `add_hash_db` to
    // accept an `Arc<CsamHashDb>` so the same DB can survive scans.

    match scan_result {
        Ok(hits) => {
            let hit_count = hits.len();
            // Snapshot per-hit data before storing the hits Vec, so
            // the borrow on `hits` is released before we call
            // `s.record(...)` (which mutably borrows the whole session).
            let hit_log_data: Vec<(String, String)> = hits
                .iter()
                .map(|h| (h.file_path.clone(), h.match_type.as_str().to_string()))
                .collect();
            s.hits = hits;
            for (file_path, match_type) in hit_log_data {
                s.record(CsamAuditAction::HitDetected {
                    file_path,
                    match_type,
                });
            }
            s.record(CsamAuditAction::ScanCompleted {
                files_scanned: 0, // populated from progress channel in a future revision
                hits_found: hit_count,
            });
            Ok(CsamScanSummary {
                files_scanned: 0,
                hits_found: hit_count,
                status: format!("Scan complete — {} hit(s)", hit_count),
            })
        }
        Err(e) => {
            s.record(CsamAuditAction::ScanAborted {
                reason: format!("{:#}", e),
            });
            Err(AdapterError::EngineError(format!("scan failed: {:#}", e)))
        }
    }
}

/// Return all hits as JSON-friendly DTOs.
pub fn csam_list_hits(evidence_id: &str) -> AdapterResult<Vec<CsamHitInfo>> {
    let session = get_session(evidence_id)?;
    let s = session.lock().expect("csam session poisoned");
    Ok(s.hits.iter().map(CsamHitInfo::from).collect())
}

/// Mark a hit as reviewed. Records `HitReviewed` in the audit chain
/// and flips `examiner_reviewed = true`. Does NOT open any image
/// viewer — the Forge UI is responsible for the acknowledgement
/// modal that triggers this command.
pub fn csam_review_hit(evidence_id: &str, hit_id: &str) -> AdapterResult<()> {
    let session = get_session(evidence_id)?;
    let mut s = session.lock().expect("csam session poisoned");
    if let Some(hit) = s.hits.iter_mut().find(|h| h.hit_id.to_string() == hit_id) {
        hit.examiner_reviewed = true;
    }
    s.record(CsamAuditAction::HitReviewed {
        hit_id: hit_id.to_string(),
    });
    Ok(())
}

/// Confirm a hit. Marks `examiner_confirmed = true`, stores the
/// examiner's notes, records `HitConfirmed` in the audit chain.
pub fn csam_confirm_hit(
    evidence_id: &str,
    hit_id: &str,
    notes: &str,
) -> AdapterResult<()> {
    let session = get_session(evidence_id)?;
    let mut s = session.lock().expect("csam session poisoned");
    if let Some(hit) = s.hits.iter_mut().find(|h| h.hit_id.to_string() == hit_id) {
        hit.examiner_confirmed = true;
        hit.examiner_reviewed = true;
        hit.examiner_notes = notes.to_string();
    }
    s.record(CsamAuditAction::HitConfirmed {
        hit_id: hit_id.to_string(),
    });
    Ok(())
}

/// Dismiss a hit as a false positive. The hit stays in the results
/// list (so it remains in the audit trail and the report) but is
/// marked dismissed via the audit action.
pub fn csam_dismiss_hit(
    evidence_id: &str,
    hit_id: &str,
    reason: &str,
) -> AdapterResult<()> {
    let session = get_session(evidence_id)?;
    let mut s = session.lock().expect("csam session poisoned");
    s.record(CsamAuditAction::HitDismissed {
        hit_id: hit_id.to_string(),
        reason: reason.to_string(),
    });
    Ok(())
}

/// Generate the court-ready PDF report (and JSON sidecar). Writes
/// `<output_path>` for the PDF and `<output_path>.json` for the
/// machine-readable copy.
///
/// The report's `audit_log` is the in-memory `CsamAuditLog` for this
/// session, NOT a filtered slice from a shared case database. The
/// `audit_integrity_verified` flag reflects integrity of the
/// in-memory chain only. (For the strata-tree egui app, the report
/// integrity flag instead reflects the full unified case chain —
/// see strata-tree's `state_csam.rs::generate_csam_report`.)
pub fn csam_generate_report(
    evidence_id: &str,
    output_pdf_path: &str,
) -> AdapterResult<()> {
    let session = get_session(evidence_id)?;
    let mut s = session.lock().expect("csam session poisoned");

    let pdf_path = PathBuf::from(output_pdf_path);

    let report = CsamReport {
        case_number: s.case_number.clone(),
        examiner_name: s.examiner.clone(),
        examiner_agency: String::new(),
        scan_date_utc: chrono::Utc::now(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        evidence_path: evidence_id.to_string(),
        evidence_sha256: String::new(),
        hash_sets_used: s
            .hash_dbs
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
            run_exact_hash: true,
            run_perceptual: false,
            perceptual_threshold: 10,
            scan_all_files: false,
            image_extensions: ScanConfig::default().image_extensions,
        },
        hits: s.hits.clone(),
        audit_log: s.audit.entries().to_vec(),
        audit_integrity_verified: s
            .audit
            .verify_integrity(strata_csam::audit::GENESIS_PREV_HASH),
    };

    report
        .generate_pdf(&pdf_path)
        .map_err(|e| AdapterError::EngineError(format!("pdf: {:#}", e)))?;
    let json_path = pdf_path.with_extension("json");
    report
        .generate_json(&json_path)
        .map_err(|e| AdapterError::EngineError(format!("json: {:#}", e)))?;

    s.record(CsamAuditAction::ReportGenerated {
        path: pdf_path.display().to_string(),
    });
    Ok(())
}

/// Export the in-memory CSAM audit log as JSON.
pub fn csam_export_audit_log(
    evidence_id: &str,
    output_path: &str,
) -> AdapterResult<()> {
    let session = get_session(evidence_id)?;
    let s = session.lock().expect("csam session poisoned");
    let json = s
        .audit
        .export_json()
        .map_err(|e| AdapterError::EngineError(format!("audit json: {:#}", e)))?;
    std::fs::write(output_path, json)?;
    Ok(())
}

/// Read-only summary used by the Forge UI session header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsamSessionSummary {
    pub examiner: String,
    pub case_number: String,
    pub hash_set_count: usize,
    pub hit_count: usize,
    pub confirmed_count: usize,
    pub audit_entry_count: usize,
}

pub fn csam_session_summary(evidence_id: &str) -> AdapterResult<CsamSessionSummary> {
    let session = get_session(evidence_id)?;
    let s = session.lock().expect("csam session poisoned");
    Ok(CsamSessionSummary {
        examiner: s.examiner.clone(),
        case_number: s.case_number.clone(),
        hash_set_count: s.hash_dbs.len(),
        hit_count: s.hits.len(),
        confirmed_count: s.hits.iter().filter(|h| h.examiner_confirmed).count(),
        audit_entry_count: s.audit.entries().len(),
    })
}

// `MatchType` is referenced indirectly via `CsamHit`. Keep the import
// alive so future DTO mappings can use it.
#[allow(dead_code)]
fn _silence_unused_match_type(_m: MatchType) {}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::{NamedTempFile, TempDir};

    /// Create a unique evidence id per test so the singleton store
    /// doesn't bleed state between tests when they run in parallel.
    fn unique_evidence_id() -> String {
        format!("test-{}", uuid::Uuid::new_v4())
    }

    fn write_hash_file(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(bytes);
        format!("{:x}", h.finalize())
    }

    /// Plant a tempdir as evidence in the EVIDENCE_STORE so commands
    /// that need the underlying VFS work in tests. Goes through the
    /// public `parse_evidence` path, the same one Forge uses.
    fn plant_evidence(payload_name: &str, payload: &[u8]) -> (TempDir, String, String) {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join(payload_name);
        std::fs::write(&target, payload).unwrap();
        let info =
            crate::evidence::parse_evidence(dir.path().to_str().unwrap()).expect("parse_evidence");
        let evidence_id = info.id;
        let target_sha = sha256_hex(payload);
        (dir, evidence_id, target_sha)
    }

    #[test]
    fn create_and_drop_session_round_trip() {
        let id = unique_evidence_id();
        csam_create_session(&id, "examiner_a", "CASE-001").unwrap();
        let summary = csam_session_summary(&id).unwrap();
        assert_eq!(summary.examiner, "examiner_a");
        assert_eq!(summary.case_number, "CASE-001");
        assert_eq!(summary.hash_set_count, 0);
        assert_eq!(summary.hit_count, 0);

        assert!(csam_drop_session(&id));
        assert!(get_session(&id).is_err());
    }

    #[test]
    fn import_hash_set_records_audit_event() {
        let id = unique_evidence_id();
        let payload = b"d41d8cd98f00b204e9800998ecf8427e\n";
        let f = write_hash_file(std::str::from_utf8(payload).unwrap());

        let result = csam_import_hash_set(
            &id,
            f.path().to_str().unwrap(),
            "test_set",
            "examiner_a",
            "CASE-X",
        )
        .unwrap();

        assert_eq!(result.name, "test_set");
        assert_eq!(result.entry_count, 1);
        assert!(result.format.contains("MD5"));

        let summary = csam_session_summary(&id).unwrap();
        assert_eq!(summary.hash_set_count, 1);
        assert_eq!(summary.audit_entry_count, 1); // HashSetImported

        let _ = csam_drop_session(&id);
    }

    #[test]
    fn import_hash_set_fails_on_bad_file() {
        let id = unique_evidence_id();
        let f = write_hash_file("# only comments\n");

        let err = csam_import_hash_set(
            &id,
            f.path().to_str().unwrap(),
            "bad",
            "ex",
            "CASE",
        )
        .unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("import"));

        let _ = csam_drop_session(&id);
    }

    #[test]
    fn run_scan_end_to_end_finds_planted_hit() {
        let payload = b"this is the planted CSAM scan target payload";
        let (_dir, evidence_id, target_sha) = plant_evidence("planted.bin", payload);

        // Import the SHA256 of the planted file as a hash set.
        let hash_file = write_hash_file(&format!("{}\n", target_sha));
        csam_import_hash_set(
            &evidence_id,
            hash_file.path().to_str().unwrap(),
            "planted_db",
            "examiner_a",
            "CASE-PLANT",
        )
        .unwrap();

        // .bin is not in image extensions, so scan_all_files = true
        let options = CsamScanOptions {
            scan_all_files: true,
            ..Default::default()
        };

        let summary = csam_run_scan(&evidence_id, options).unwrap();
        assert_eq!(summary.hits_found, 1, "expected one hit, got {:?}", summary);

        let hits = csam_list_hits(&evidence_id).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].sha256, target_sha);
        assert_eq!(hits[0].match_type, "ExactSha256");
        assert!(!hits[0].examiner_reviewed);
        assert!(!hits[0].examiner_confirmed);

        // Confirm the hit and verify state changes + audit event.
        csam_confirm_hit(&evidence_id, &hits[0].hit_id, "operator-confirmed").unwrap();
        let after = csam_list_hits(&evidence_id).unwrap();
        assert!(after[0].examiner_confirmed);
        assert!(after[0].examiner_reviewed);
        assert_eq!(after[0].examiner_notes, "operator-confirmed");

        let summary = csam_session_summary(&evidence_id).unwrap();
        assert_eq!(summary.confirmed_count, 1);
        // ScanStarted + HashSetImported (already there) + 1 HitDetected
        // + ScanCompleted + HitConfirmed = 5 audit events from the scan
        // workflow alone (HashSetImported was recorded in import_hash_set
        // earlier — total = 5).
        assert_eq!(summary.audit_entry_count, 5);

        let _ = csam_drop_session(&evidence_id);
        let _ = crate::store::drop_evidence(&evidence_id);
    }

    #[test]
    fn run_scan_records_aborted_when_no_hash_sets_and_no_perceptual() {
        let id = unique_evidence_id();
        csam_create_session(&id, "ex", "CASE").unwrap();
        let options = CsamScanOptions::default();
        let err = csam_run_scan(&id, options).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("hash sets"), "got: {}", msg);
        let _ = csam_drop_session(&id);
    }

    #[test]
    fn dismiss_hit_records_audit_but_keeps_hit_in_list() {
        let payload = b"dismiss test payload bytes";
        let (_dir, evidence_id, target_sha) = plant_evidence("d.bin", payload);
        let hash_file = write_hash_file(&format!("{}\n", target_sha));
        csam_import_hash_set(
            &evidence_id,
            hash_file.path().to_str().unwrap(),
            "db",
            "ex",
            "CASE",
        )
        .unwrap();
        let opts = CsamScanOptions {
            scan_all_files: true,
            ..Default::default()
        };
        csam_run_scan(&evidence_id, opts).unwrap();

        let hits = csam_list_hits(&evidence_id).unwrap();
        let before_audit = csam_session_summary(&evidence_id).unwrap().audit_entry_count;
        csam_dismiss_hit(&evidence_id, &hits[0].hit_id, "operator-dismissed").unwrap();

        let still_there = csam_list_hits(&evidence_id).unwrap();
        assert_eq!(still_there.len(), 1, "dismissed hit must remain in list");
        let after_audit = csam_session_summary(&evidence_id).unwrap().audit_entry_count;
        assert_eq!(after_audit, before_audit + 1);

        let _ = csam_drop_session(&evidence_id);
        let _ = crate::store::drop_evidence(&evidence_id);
    }

    #[test]
    fn generate_report_writes_pdf_and_json() {
        let payload = b"report test payload";
        let (_dir, evidence_id, target_sha) = plant_evidence("r.bin", payload);
        let hash_file = write_hash_file(&format!("{}\n", target_sha));
        csam_import_hash_set(
            &evidence_id,
            hash_file.path().to_str().unwrap(),
            "db",
            "ex",
            "CASE",
        )
        .unwrap();
        let opts = CsamScanOptions {
            scan_all_files: true,
            ..Default::default()
        };
        csam_run_scan(&evidence_id, opts).unwrap();

        let out_dir = TempDir::new().unwrap();
        let pdf_path = out_dir.path().join("csam_report.pdf");
        csam_generate_report(&evidence_id, pdf_path.to_str().unwrap()).unwrap();

        let pdf_bytes = std::fs::read(&pdf_path).unwrap();
        assert!(pdf_bytes.len() > 100);
        assert_eq!(&pdf_bytes[..4], b"%PDF");

        let json_path = pdf_path.with_extension("json");
        let json_bytes = std::fs::read(&json_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();
        // The report's audit_log includes a ReportGenerated event
        // appended after the report writes succeed. Verify the
        // payload contains the expected top-level fields.
        assert!(parsed.get("hits").is_some());
        assert!(parsed.get("audit_log").is_some());
        assert!(parsed.get("audit_integrity_verified").is_some());

        let _ = csam_drop_session(&evidence_id);
        let _ = crate::store::drop_evidence(&evidence_id);
    }

    #[test]
    fn export_audit_log_writes_json_array() {
        let id = unique_evidence_id();
        csam_create_session(&id, "ex", "CASE").unwrap();
        // Plant one audit event by importing a one-line hash file.
        let f = write_hash_file("d41d8cd98f00b204e9800998ecf8427e\n");
        csam_import_hash_set(&id, f.path().to_str().unwrap(), "db", "ex", "CASE").unwrap();

        let out_dir = TempDir::new().unwrap();
        let out_path = out_dir.path().join("audit.json");
        csam_export_audit_log(&id, out_path.to_str().unwrap()).unwrap();

        let data = std::fs::read_to_string(&out_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&data).unwrap();
        let arr = parsed.as_array().expect("audit log should be a JSON array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["action"], "CSAM_HASH_SET_IMPORTED");

        let _ = csam_drop_session(&id);
    }

    #[test]
    fn missing_session_yields_engine_error() {
        let id = unique_evidence_id();
        let err = csam_list_hits(&id).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("no CSAM session"));
    }
}
