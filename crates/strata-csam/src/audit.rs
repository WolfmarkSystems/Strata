//! CSAM audit log — chain-of-custody for CSAM scanning events.
//!
//! ## Byte-for-byte compatibility with strata-tree
//!
//! Every entry in this log is hashed using the **exact same recipe**
//! as the case-level audit log in `strata-tree::state::AuditEntry`.
//! The chain hash for entry `n` is:
//!
//! ```text
//! SHA256("{sequence}|{timestamp_utc}|{examiner}|{action}|{detail}|{evidence_id_or_empty}|{prev_hash}")
//! ```
//!
//! Field separator is the ASCII pipe `|`. The genesis prev_hash is
//! 64 ASCII zero characters. Output is lowercase hex via `format!("{:x}", _)`.
//!
//! **DO NOT change this recipe without re-hashing every stored CSAM
//! audit chain AND coordinating with strata-tree's identical function.**
//! Court-defensible chain-of-custody requires that the same verifier
//! can validate both case events and CSAM events from a single chain.
//!
//! ## Persistence model
//!
//! CSAM events live in the *same* `audit_log` SQLite table as case
//! events, distinguished by their `CSAM_*` action tag namespace. This
//! is the unified-chain decision (Option i) — there is exactly one
//! chain per case, and CSAM events are interleaved with case events
//! in sequence order.
//!
//! `flush_to_sqlite` is **append-only**. It never deletes existing
//! rows. The caller must ensure no concurrent writer is mutating the
//! `audit_log` table while flush is in flight; in practice, the IPC
//! layer (Task 8) wraps the flush in the same case-level mutex that
//! strata-tree uses for its own snapshot saves.
//!
//! Note that strata-tree's `save_audit_log` does `DELETE FROM audit_log`
//! followed by re-insert of every in-memory entry. If strata-tree
//! saves *after* a CSAM flush without first reloading the log into
//! its in-memory state, the CSAM rows will be clobbered. The IPC
//! integration is responsible for sequencing these operations.

use anyhow::{anyhow, bail, Result};
use rusqlite::Connection;
use sha2::Digest;

/// Genesis prev_hash — 64 ASCII zeros. Mirrors strata-tree's
/// `"0".repeat(64)` literal at `state.rs:1335,1352`.
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

// ──────────────────────────────────────────────────────────────────────
// Entry & action types
// ──────────────────────────────────────────────────────────────────────

/// One entry in the CSAM audit chain.
///
/// Field layout matches the `audit_log` SQLite schema column-for-column
/// (id, sequence, timestamp_utc, examiner_id→examiner, action_type→action,
/// detail, evidence_id, file_path, prev_hash, entry_hash).
///
/// The chain hash recipe inputs are: sequence, timestamp_utc, examiner,
/// action, detail, evidence_id, prev_hash. **`id` and `file_path` are
/// metadata only — they are NOT in the hash recipe.** That mirrors
/// strata-tree exactly: `id` is a UUID for SQL primary key uniqueness,
/// `file_path` is a queryability column derived from the action payload.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CsamAuditEntry {
    pub id: String,
    pub sequence: u64,
    pub timestamp_utc: String,
    pub examiner: String,
    pub action: String,
    pub detail: String,
    pub evidence_id: Option<String>,
    pub file_path: Option<String>,
    pub prev_hash: String,
    pub entry_hash: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum CsamAuditAction {
    ScanStarted,
    HashSetImported {
        name: String,
        entries: usize,
        format: String,
    },
    ScanCompleted {
        files_scanned: usize,
        hits_found: usize,
    },
    HitDetected {
        file_path: String,
        match_type: String,
    },
    HitReviewed {
        hit_id: String,
    },
    HitConfirmed {
        hit_id: String,
    },
    HitDismissed {
        hit_id: String,
        reason: String,
    },
    ReportGenerated {
        path: String,
    },
    ScanAborted {
        reason: String,
    },
}

impl CsamAuditAction {
    /// Stable string tag for the audit log `action_type` column.
    /// Namespaced under `CSAM_*` so the unified case audit_log table
    /// can distinguish CSAM events from other case actions.
    pub fn tag(&self) -> &'static str {
        match self {
            CsamAuditAction::ScanStarted => "CSAM_SCAN_STARTED",
            CsamAuditAction::HashSetImported { .. } => "CSAM_HASH_SET_IMPORTED",
            CsamAuditAction::ScanCompleted { .. } => "CSAM_SCAN_COMPLETED",
            CsamAuditAction::HitDetected { .. } => "CSAM_HIT_DETECTED",
            CsamAuditAction::HitReviewed { .. } => "CSAM_HIT_REVIEWED",
            CsamAuditAction::HitConfirmed { .. } => "CSAM_HIT_CONFIRMED",
            CsamAuditAction::HitDismissed { .. } => "CSAM_HIT_DISMISSED",
            CsamAuditAction::ReportGenerated { .. } => "CSAM_REPORT_GENERATED",
            CsamAuditAction::ScanAborted { .. } => "CSAM_SCAN_ABORTED",
        }
    }

    /// Deterministic, human-readable detail string for the variant
    /// payload. Format: `key=value key=value ...`. The chain hash
    /// includes this string as one of its inputs, so the format must
    /// be stable across releases — see the file-level docstring.
    ///
    /// Field values are written verbatim. Callers must avoid embedding
    /// `|` (the hash recipe separator) in identifiers or messages,
    /// because that would create chain-hash inputs that are ambiguous
    /// to a future verifier. The IPC layer enforces this on user input.
    pub fn detail_string(&self) -> String {
        match self {
            CsamAuditAction::ScanStarted => String::new(),
            CsamAuditAction::HashSetImported {
                name,
                entries,
                format,
            } => format!("name={} entries={} format={}", name, entries, format),
            CsamAuditAction::ScanCompleted {
                files_scanned,
                hits_found,
            } => format!("files_scanned={} hits_found={}", files_scanned, hits_found),
            CsamAuditAction::HitDetected {
                file_path,
                match_type,
            } => format!("file_path={} match_type={}", file_path, match_type),
            CsamAuditAction::HitReviewed { hit_id } => format!("hit_id={}", hit_id),
            CsamAuditAction::HitConfirmed { hit_id } => format!("hit_id={}", hit_id),
            CsamAuditAction::HitDismissed { hit_id, reason } => {
                format!("hit_id={} reason={}", hit_id, reason)
            }
            CsamAuditAction::ReportGenerated { path } => format!("path={}", path),
            CsamAuditAction::ScanAborted { reason } => format!("reason={}", reason),
        }
    }

    /// Optional `file_path` column value for variants that carry one.
    /// This is duplicated from `detail_string` for SQL queryability;
    /// the canonical, hash-protected value lives in `detail`.
    pub fn file_path_column(&self) -> Option<String> {
        match self {
            CsamAuditAction::HitDetected { file_path, .. } => Some(file_path.clone()),
            CsamAuditAction::ReportGenerated { path } => Some(path.clone()),
            _ => None,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// Hash recipe — must remain byte-for-byte compatible with strata-tree
// ──────────────────────────────────────────────────────────────────────

/// Compute the chain hash for one audit entry.
///
/// **Byte-for-byte identical to strata-tree's `compute_audit_entry_hash`
/// at `apps/tree/strata-tree/src/state.rs:2042-2065`.** Any change to
/// this function or its input layout invalidates every stored chain
/// and breaks unified verification with strata-tree.
///
/// Recipe:
/// `SHA256("{sequence}|{timestamp_utc}|{examiner}|{action}|{detail}|{evidence_id_or_empty}|{prev_hash}")`
pub fn compute_audit_entry_hash(
    sequence: u64,
    timestamp_utc: &str,
    examiner: &str,
    action: &str,
    detail: &str,
    evidence_id: Option<&str>,
    prev_hash: &str,
) -> String {
    let data = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        sequence,
        timestamp_utc,
        examiner,
        action,
        detail,
        evidence_id.unwrap_or(""),
        prev_hash,
    );
    let mut hasher = sha2::Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}

// ──────────────────────────────────────────────────────────────────────
// In-memory audit log
// ──────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct CsamAuditLog {
    entries: Vec<CsamAuditEntry>,
    next_sequence: u64,
    last_hash: String,
}

impl Default for CsamAuditLog {
    fn default() -> Self {
        Self::new()
    }
}

impl CsamAuditLog {
    /// Start a fresh log at sequence 0 with the genesis prev_hash.
    /// Use this when CSAM is the only writer and there is no existing
    /// case audit chain to continue from.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_sequence: 0,
            last_hash: GENESIS_PREV_HASH.to_string(),
        }
    }

    /// Continue from an existing chain tail. Use this when appending
    /// CSAM events into a case that already has its own audit chain.
    /// `next_sequence` is the sequence number to assign to the FIRST
    /// new entry; `last_hash` is the `entry_hash` of the case's most
    /// recent existing entry (which becomes the `prev_hash` of the
    /// first new entry).
    pub fn continuing_from(next_sequence: u64, last_hash: String) -> Self {
        Self {
            entries: Vec::new(),
            next_sequence,
            last_hash,
        }
    }

    pub fn entries(&self) -> &[CsamAuditEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    pub fn last_hash(&self) -> &str {
        &self.last_hash
    }

    /// Record one event. Computes timestamp, action tag, detail string,
    /// chain hash, and pushes a new entry. Idempotent only at the level
    /// of the chain — each call advances the sequence by 1 and changes
    /// `last_hash`.
    pub fn record(&mut self, examiner: &str, action: CsamAuditAction) -> &CsamAuditEntry {
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let action_tag = action.tag().to_string();
        let detail = action.detail_string();
        let file_path_col = action.file_path_column();
        let evidence_id: Option<String> = None;

        let entry_hash = compute_audit_entry_hash(
            self.next_sequence,
            &now,
            examiner,
            &action_tag,
            &detail,
            evidence_id.as_deref(),
            &self.last_hash,
        );

        self.entries.push(CsamAuditEntry {
            id: uuid::Uuid::new_v4().to_string(),
            sequence: self.next_sequence,
            timestamp_utc: now,
            examiner: examiner.to_string(),
            action: action_tag,
            detail,
            evidence_id,
            file_path: file_path_col,
            prev_hash: self.last_hash.clone(),
            entry_hash: entry_hash.clone(),
        });

        self.next_sequence += 1;
        self.last_hash = entry_hash;
        self.entries.last().expect("just pushed")
    }

    /// Verify the integrity of the chain.
    ///
    /// `expected_starting_prev_hash` is the prev_hash that the FIRST
    /// entry in this in-memory log should reference. For a log built
    /// via `new()`, that's `GENESIS_PREV_HASH`. For a log built via
    /// `continuing_from(_, last_hash)`, it's that same `last_hash`.
    ///
    /// Returns `true` only if every entry's stored `entry_hash` matches
    /// the recomputed hash AND every `prev_hash` link is intact AND
    /// sequence numbers are strictly contiguous starting from the
    /// first entry's sequence.
    pub fn verify_integrity(&self, expected_starting_prev_hash: &str) -> bool {
        let mut expected_prev = expected_starting_prev_hash.to_string();
        // None on the first iteration — the first entry can carry any
        // starting sequence number; subsequent entries must be strictly
        // contiguous (`prev + 1`).
        let mut expected_seq: Option<u64> = None;

        for entry in &self.entries {
            if let Some(s) = expected_seq {
                if s != entry.sequence {
                    return false;
                }
            }

            // prev_hash must link to the previous entry's entry_hash
            // (or the expected starting prev_hash for the first entry).
            if entry.prev_hash != expected_prev {
                return false;
            }

            // entry_hash must recompute correctly.
            let recomputed = compute_audit_entry_hash(
                entry.sequence,
                &entry.timestamp_utc,
                &entry.examiner,
                &entry.action,
                &entry.detail,
                entry.evidence_id.as_deref(),
                &entry.prev_hash,
            );
            if entry.entry_hash != recomputed {
                return false;
            }

            expected_prev = entry.entry_hash.clone();
            expected_seq = Some(entry.sequence + 1);
        }
        true
    }

    /// Pretty-printed JSON dump of every entry. Used by the report
    /// generator and the `[EXPORT AUDIT LOG]` UI button.
    pub fn export_json(&self) -> Result<String> {
        serde_json::to_string_pretty(&self.entries)
            .map_err(|e| anyhow!("audit log serialization failed: {}", e))
    }

    /// Append every in-memory entry to the case's `audit_log` SQLite
    /// table, in a single transaction. Append-only — never deletes.
    ///
    /// Before inserting, this function reads the current chain tail
    /// from the table and **fails fast** if it does not match the
    /// `prev_hash` of the first in-memory entry. That mismatch means
    /// some other writer (most likely strata-tree's snapshot save)
    /// advanced the table after this log was constructed, and the
    /// CSAM entries' chain links would be invalid if inserted as-is.
    /// The caller must rebuild the log via `continuing_from(...)`
    /// using the fresh tail and re-record events.
    pub fn flush_to_sqlite(&self, conn: &Connection) -> Result<()> {
        if self.entries.is_empty() {
            return Ok(());
        }
        ensure_audit_log_schema(conn)?;

        let (db_next_seq, db_tail_hash) = read_chain_tail(conn)?;
        let first = &self.entries[0];

        if first.sequence != db_next_seq {
            bail!(
                "csam audit flush: in-memory log starts at sequence {} but db tail expects {}",
                first.sequence,
                db_next_seq
            );
        }
        if first.prev_hash != db_tail_hash {
            bail!(
                "csam audit flush: in-memory log prev_hash does not match db tail entry_hash \
                 (concurrent writer detected)"
            );
        }

        let tx = conn.unchecked_transaction()?;
        for e in &self.entries {
            tx.execute(
                "INSERT INTO audit_log (
                    id, sequence, timestamp_utc, examiner_id, action_type, detail, evidence_id, file_path, prev_hash, entry_hash
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params![
                    e.id,
                    e.sequence as i64,
                    e.timestamp_utc,
                    e.examiner,
                    e.action,
                    e.detail,
                    e.evidence_id,
                    e.file_path,
                    e.prev_hash,
                    e.entry_hash,
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────────
// SQLite helpers
// ──────────────────────────────────────────────────────────────────────

/// Read the current tail of the case's `audit_log` table.
///
/// Returns `(next_sequence, last_entry_hash)`:
/// - For an empty table: `(0, GENESIS_PREV_HASH)`
/// - For a populated table: `(max_sequence + 1, entry_hash_of_max_row)`
///
/// Fails if the table exists but the max-sequence row has a NULL or
/// empty `entry_hash`, which would mean the chain is already broken
/// and CSAM cannot safely append to it.
pub fn read_chain_tail(conn: &Connection) -> Result<(u64, String)> {
    ensure_audit_log_schema(conn)?;

    let row: Option<(i64, Option<String>)> = conn
        .query_row(
            "SELECT sequence, entry_hash FROM audit_log
             WHERE sequence IS NOT NULL
             ORDER BY sequence DESC LIMIT 1",
            [],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?)),
        )
        .ok();

    match row {
        None => Ok((0, GENESIS_PREV_HASH.to_string())),
        Some((seq, Some(hash))) if !hash.is_empty() => Ok((seq as u64 + 1, hash)),
        Some((seq, _)) => bail!(
            "audit_log tail entry at sequence {} has no entry_hash; chain is broken",
            seq
        ),
    }
}

/// Ensure the `audit_log` table exists and has every column the chain
/// needs. Mirrors strata-tree's `ensure_audit_log_columns` plus the
/// fresh-table case (which strata-tree handles via its case-init code
/// path that we don't have access to from here).
pub fn ensure_audit_log_schema(conn: &Connection) -> Result<()> {
    let exists: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit_log'",
            [],
            |_| Ok(true),
        )
        .unwrap_or(false);

    if !exists {
        conn.execute_batch(
            "CREATE TABLE audit_log (
                id            TEXT PRIMARY KEY,
                sequence      INTEGER,
                timestamp_utc TEXT NOT NULL,
                examiner_id   TEXT NOT NULL,
                action_type   TEXT NOT NULL,
                detail        TEXT,
                evidence_id   TEXT,
                file_path     TEXT,
                prev_hash     TEXT,
                entry_hash    TEXT
            );",
        )?;
        return Ok(());
    }

    let mut cols = std::collections::HashSet::<String>::new();
    let mut stmt = conn.prepare("PRAGMA table_info(audit_log)")?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(1))?;
    for row in rows {
        cols.insert(row?.to_lowercase());
    }

    // Mirror strata-tree's defensive ALTERs for legacy DBs.
    if !cols.contains("evidence_id") {
        let _ = conn.execute("ALTER TABLE audit_log ADD COLUMN evidence_id TEXT", []);
    }
    if !cols.contains("file_path") {
        let _ = conn.execute("ALTER TABLE audit_log ADD COLUMN file_path TEXT", []);
    }
    if !cols.contains("prev_hash") {
        let _ = conn.execute("ALTER TABLE audit_log ADD COLUMN prev_hash TEXT", []);
    }
    if !cols.contains("entry_hash") {
        let _ = conn.execute("ALTER TABLE audit_log ADD COLUMN entry_hash TEXT", []);
    }
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Hash recipe ────────────────────────────────────────────────

    #[test]
    fn hash_recipe_byte_compat_with_strata_tree() {
        // This is the load-bearing test: it locks in the exact byte
        // input that goes into SHA256, computed independently from
        // the production function. If this assertion ever changes,
        // every stored chain (CSAM and strata-tree) is invalidated.
        let computed = compute_audit_entry_hash(
            7,
            "2026-04-08T12:34:56Z",
            "examiner_a",
            "CSAM_HIT_DETECTED",
            "file_path=/evidence/x.jpg match_type=ExactSha256",
            Some("evidence-1"),
            "deadbeef",
        );

        // Independent SHA256 of the same concatenation.
        let expected_input = "7|2026-04-08T12:34:56Z|examiner_a|CSAM_HIT_DETECTED|\
                              file_path=/evidence/x.jpg match_type=ExactSha256|\
                              evidence-1|deadbeef";
        let mut h = sha2::Sha256::new();
        h.update(expected_input.as_bytes());
        let expected = format!("{:x}", h.finalize());

        assert_eq!(computed, expected);
    }

    #[test]
    fn hash_recipe_treats_none_evidence_id_as_empty_string() {
        let with_none = compute_audit_entry_hash(
            0,
            "2026-04-08T00:00:00Z",
            "ex",
            "CSAM_SCAN_STARTED",
            "",
            None,
            GENESIS_PREV_HASH,
        );
        let with_empty = compute_audit_entry_hash(
            0,
            "2026-04-08T00:00:00Z",
            "ex",
            "CSAM_SCAN_STARTED",
            "",
            Some(""),
            GENESIS_PREV_HASH,
        );
        assert_eq!(with_none, with_empty);
    }

    #[test]
    fn genesis_constant_is_64_zeros() {
        assert_eq!(GENESIS_PREV_HASH.len(), 64);
        assert!(GENESIS_PREV_HASH.chars().all(|c| c == '0'));
    }

    // ── Action enum ────────────────────────────────────────────────

    #[test]
    fn action_tags_are_csam_namespaced() {
        assert_eq!(CsamAuditAction::ScanStarted.tag(), "CSAM_SCAN_STARTED");
        assert_eq!(
            CsamAuditAction::HashSetImported {
                name: String::new(),
                entries: 0,
                format: String::new()
            }
            .tag(),
            "CSAM_HASH_SET_IMPORTED"
        );
        assert_eq!(
            CsamAuditAction::ScanCompleted {
                files_scanned: 0,
                hits_found: 0
            }
            .tag(),
            "CSAM_SCAN_COMPLETED"
        );
        assert_eq!(
            CsamAuditAction::HitDetected {
                file_path: String::new(),
                match_type: String::new()
            }
            .tag(),
            "CSAM_HIT_DETECTED"
        );
        assert_eq!(
            CsamAuditAction::HitReviewed {
                hit_id: String::new()
            }
            .tag(),
            "CSAM_HIT_REVIEWED"
        );
        assert_eq!(
            CsamAuditAction::HitConfirmed {
                hit_id: String::new()
            }
            .tag(),
            "CSAM_HIT_CONFIRMED"
        );
        assert_eq!(
            CsamAuditAction::HitDismissed {
                hit_id: String::new(),
                reason: String::new()
            }
            .tag(),
            "CSAM_HIT_DISMISSED"
        );
        assert_eq!(
            CsamAuditAction::ReportGenerated {
                path: String::new()
            }
            .tag(),
            "CSAM_REPORT_GENERATED"
        );
        assert_eq!(
            CsamAuditAction::ScanAborted {
                reason: String::new()
            }
            .tag(),
            "CSAM_SCAN_ABORTED"
        );
    }

    #[test]
    fn detail_strings_are_deterministic() {
        let a = CsamAuditAction::HashSetImported {
            name: "ncmec_2024".into(),
            entries: 12345,
            format: "NCMEC MD5".into(),
        };
        let b = CsamAuditAction::HashSetImported {
            name: "ncmec_2024".into(),
            entries: 12345,
            format: "NCMEC MD5".into(),
        };
        assert_eq!(a.detail_string(), b.detail_string());
        assert_eq!(
            a.detail_string(),
            "name=ncmec_2024 entries=12345 format=NCMEC MD5"
        );
    }

    #[test]
    fn file_path_column_only_for_path_carrying_variants() {
        assert_eq!(
            CsamAuditAction::HitDetected {
                file_path: "/x.jpg".into(),
                match_type: "ExactSha256".into()
            }
            .file_path_column(),
            Some("/x.jpg".to_string())
        );
        assert_eq!(
            CsamAuditAction::ReportGenerated {
                path: "/r.pdf".into()
            }
            .file_path_column(),
            Some("/r.pdf".to_string())
        );
        assert_eq!(CsamAuditAction::ScanStarted.file_path_column(), None);
        assert_eq!(
            CsamAuditAction::HitReviewed {
                hit_id: "x".into()
            }
            .file_path_column(),
            None
        );
    }

    // ── Recording & verification ───────────────────────────────────

    #[test]
    fn record_increments_sequence_and_chains() {
        let mut log = CsamAuditLog::new();
        log.record("ex", CsamAuditAction::ScanStarted);
        log.record(
            "ex",
            CsamAuditAction::HashSetImported {
                name: "n".into(),
                entries: 1,
                format: "f".into(),
            },
        );
        log.record(
            "ex",
            CsamAuditAction::ScanCompleted {
                files_scanned: 10,
                hits_found: 1,
            },
        );

        let entries = log.entries();
        assert_eq!(entries.len(), 3);

        assert_eq!(entries[0].sequence, 0);
        assert_eq!(entries[0].prev_hash, GENESIS_PREV_HASH);

        assert_eq!(entries[1].sequence, 1);
        assert_eq!(entries[1].prev_hash, entries[0].entry_hash);

        assert_eq!(entries[2].sequence, 2);
        assert_eq!(entries[2].prev_hash, entries[1].entry_hash);

        // Each entry has a UUID id and a non-empty entry_hash.
        for e in entries {
            assert!(!e.id.is_empty());
            assert_eq!(e.entry_hash.len(), 64);
        }
    }

    #[test]
    fn verify_integrity_returns_true_on_clean_chain() {
        let mut log = CsamAuditLog::new();
        log.record("ex", CsamAuditAction::ScanStarted);
        log.record(
            "ex",
            CsamAuditAction::HitDetected {
                file_path: "/a.jpg".into(),
                match_type: "ExactSha256".into(),
            },
        );
        log.record(
            "ex",
            CsamAuditAction::ScanCompleted {
                files_scanned: 5,
                hits_found: 1,
            },
        );
        assert!(log.verify_integrity(GENESIS_PREV_HASH));
    }

    #[test]
    fn verify_integrity_returns_true_on_empty_log() {
        let log = CsamAuditLog::new();
        assert!(log.verify_integrity(GENESIS_PREV_HASH));
    }

    #[test]
    fn verify_integrity_detects_tampered_detail() {
        // Build a real log via the public record() path (no private
        // field access), then export to JSON, deserialize, tamper
        // with one entry's detail, and verify the chain rejects it.
        // Tests must exercise the same code path examiners use.
        let mut log = CsamAuditLog::new();
        log.record(
            "ex",
            CsamAuditAction::HitDetected {
                file_path: "/legit.jpg".into(),
                match_type: "ExactSha256".into(),
            },
        );
        log.record(
            "ex",
            CsamAuditAction::HitConfirmed {
                hit_id: "abc".into(),
            },
        );

        let json = log.export_json().unwrap();
        let mut entries: Vec<CsamAuditEntry> = serde_json::from_str(&json).unwrap();
        entries[0].detail = "file_path=/different.jpg match_type=ExactSha256".to_string();

        // Tampered chain must fail verification.
        assert!(!verify_external_chain(&entries, GENESIS_PREV_HASH));
        // Untampered original chain is still valid.
        assert!(log.verify_integrity(GENESIS_PREV_HASH));
    }

    /// Standalone verifier used by tampering tests. Mirrors
    /// `CsamAuditLog::verify_integrity` but accepts raw entries.
    /// Lives in tests because production code already verifies via
    /// the `CsamAuditLog` method on its own owned entries.
    fn verify_external_chain(entries: &[CsamAuditEntry], expected_genesis: &str) -> bool {
        let mut expected_prev = expected_genesis.to_string();
        let mut expected_seq: Option<u64> = None;
        for entry in entries {
            if let Some(s) = expected_seq {
                if s != entry.sequence {
                    return false;
                }
            }
            if entry.prev_hash != expected_prev {
                return false;
            }
            let recomputed = compute_audit_entry_hash(
                entry.sequence,
                &entry.timestamp_utc,
                &entry.examiner,
                &entry.action,
                &entry.detail,
                entry.evidence_id.as_deref(),
                &entry.prev_hash,
            );
            if entry.entry_hash != recomputed {
                return false;
            }
            expected_prev = entry.entry_hash.clone();
            expected_seq = Some(entry.sequence + 1);
        }
        true
    }

    #[test]
    fn continuing_from_starts_at_provided_state() {
        let mut log = CsamAuditLog::continuing_from(42, "deadbeef".repeat(8));
        log.record("ex", CsamAuditAction::ScanStarted);
        let entries = log.entries();
        assert_eq!(entries[0].sequence, 42);
        assert_eq!(entries[0].prev_hash, "deadbeef".repeat(8));
        assert!(log.verify_integrity(&"deadbeef".repeat(8)));
    }

    // ── SQLite persistence ─────────────────────────────────────────

    fn fresh_db_with_genesis() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        ensure_audit_log_schema(&conn).unwrap();

        // Plant a synthetic genesis row, modelling what strata-tree's
        // ensure_audit_genesis() does on case creation.
        let now = "2026-04-08T00:00:00Z";
        let genesis_hash = compute_audit_entry_hash(
            0,
            now,
            "case_examiner",
            "CASE_CREATED",
            "Case initialized",
            None,
            GENESIS_PREV_HASH,
        );
        conn.execute(
            "INSERT INTO audit_log (
                id, sequence, timestamp_utc, examiner_id, action_type, detail, evidence_id, file_path, prev_hash, entry_hash
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                "genesis-id",
                0i64,
                now,
                "case_examiner",
                "CASE_CREATED",
                "Case initialized",
                Option::<String>::None,
                Option::<String>::None,
                GENESIS_PREV_HASH,
                genesis_hash,
            ],
        )
        .unwrap();
        conn
    }

    #[test]
    fn read_chain_tail_empty_table_returns_genesis() {
        let conn = Connection::open_in_memory().unwrap();
        let (seq, prev) = read_chain_tail(&conn).unwrap();
        assert_eq!(seq, 0);
        assert_eq!(prev, GENESIS_PREV_HASH);
    }

    #[test]
    fn read_chain_tail_with_genesis_returns_one_and_genesis_hash() {
        let conn = fresh_db_with_genesis();
        let (next_seq, prev_hash) = read_chain_tail(&conn).unwrap();
        assert_eq!(next_seq, 1);
        // prev_hash here is the genesis row's entry_hash, which is
        // an arbitrary 64-hex computed by the helper.
        assert_eq!(prev_hash.len(), 64);
        assert_ne!(prev_hash, GENESIS_PREV_HASH);
    }

    #[test]
    fn flush_to_sqlite_appends_csam_events_after_genesis() {
        let conn = fresh_db_with_genesis();
        let (next_seq, last_hash) = read_chain_tail(&conn).unwrap();

        let mut log = CsamAuditLog::continuing_from(next_seq, last_hash);
        log.record("csam_examiner", CsamAuditAction::ScanStarted);
        log.record(
            "csam_examiner",
            CsamAuditAction::HitDetected {
                file_path: "/evidence/photo_001.jpg".into(),
                match_type: "ExactSha256".into(),
            },
        );
        log.record(
            "csam_examiner",
            CsamAuditAction::ScanCompleted {
                files_scanned: 1234,
                hits_found: 1,
            },
        );

        log.flush_to_sqlite(&conn).unwrap();

        // Read everything back and verify shape.
        let mut stmt = conn
            .prepare(
                "SELECT id, sequence, timestamp_utc, examiner_id, action_type,
                        detail, evidence_id, file_path, prev_hash, entry_hash
                 FROM audit_log ORDER BY sequence ASC",
            )
            .unwrap();
        #[allow(clippy::type_complexity)]
        let rows: Vec<(
            String,
            i64,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        )> = stmt
            .query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                ))
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect();

        assert_eq!(rows.len(), 4); // genesis + 3 csam
        assert_eq!(rows[0].4, "CASE_CREATED");
        assert_eq!(rows[1].4, "CSAM_SCAN_STARTED");
        assert_eq!(rows[2].4, "CSAM_HIT_DETECTED");
        assert_eq!(rows[3].4, "CSAM_SCAN_COMPLETED");

        // Sequences contiguous 0..4
        for (i, row) in rows.iter().enumerate() {
            assert_eq!(row.1 as usize, i);
        }

        // file_path column is populated for HitDetected, NULL otherwise
        assert_eq!(rows[2].7.as_deref(), Some("/evidence/photo_001.jpg"));
        assert!(rows[1].7.is_none());
        assert!(rows[3].7.is_none());

        // Chain links: each row's prev_hash equals the previous row's entry_hash.
        for w in rows.windows(2) {
            assert_eq!(w[1].8.as_deref(), w[0].9.as_deref());
        }
    }

    #[test]
    fn flush_to_sqlite_creates_table_when_missing() {
        let conn = Connection::open_in_memory().unwrap();
        // No CREATE TABLE — flush must bootstrap.
        let mut log = CsamAuditLog::new();
        log.record("ex", CsamAuditAction::ScanStarted);
        log.flush_to_sqlite(&conn).unwrap();

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM audit_log", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn flush_to_sqlite_detects_concurrent_writer() {
        let conn = fresh_db_with_genesis();
        let (next_seq, last_hash) = read_chain_tail(&conn).unwrap();

        let mut log = CsamAuditLog::continuing_from(next_seq, last_hash);
        log.record("csam_examiner", CsamAuditAction::ScanStarted);

        // Simulate strata-tree saving a new entry between when we
        // read the chain tail and when we try to flush.
        let interloper_hash = compute_audit_entry_hash(
            1,
            "2026-04-08T00:00:01Z",
            "other_examiner",
            "PLUGIN_START",
            "remnant starting",
            None,
            &log.entries()[0].prev_hash,
        );
        conn.execute(
            "INSERT INTO audit_log (
                id, sequence, timestamp_utc, examiner_id, action_type, detail, evidence_id, file_path, prev_hash, entry_hash
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                "interloper",
                1i64,
                "2026-04-08T00:00:01Z",
                "other_examiner",
                "PLUGIN_START",
                "remnant starting",
                Option::<String>::None,
                Option::<String>::None,
                log.entries()[0].prev_hash.clone(),
                interloper_hash,
            ],
        )
        .unwrap();

        // Flushing should now fail because the chain has advanced.
        let err = log.flush_to_sqlite(&conn).unwrap_err();
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("sequence") || msg.contains("concurrent"),
            "got: {}",
            msg
        );
    }

    #[test]
    fn export_json_round_trips() {
        let mut log = CsamAuditLog::new();
        log.record("ex", CsamAuditAction::ScanStarted);
        log.record(
            "ex",
            CsamAuditAction::HitDetected {
                file_path: "/x.jpg".into(),
                match_type: "ExactSha256".into(),
            },
        );

        let json = log.export_json().unwrap();
        let parsed: Vec<CsamAuditEntry> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].action, "CSAM_SCAN_STARTED");
        assert_eq!(parsed[1].action, "CSAM_HIT_DETECTED");
    }
}
