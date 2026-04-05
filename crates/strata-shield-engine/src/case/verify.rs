use rusqlite::{params, Connection, Result as SqliteResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Result as IoResult;
use std::path::Path;
use std::sync::Arc;

use crate::case::watchpoints::{
    fail_if_integrity_violations_with_conn, get_integrity_watchpoints_enabled,
};
use crate::events::{EngineEvent, EngineEventKind, EventBus, EventSeverity};

pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VerificationStatus {
    Pass,
    Warn,
    Fail,
    #[serde(rename = "MISSING")]
    Missing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub name: String,
    pub status: VerificationStatus,
    pub message: String,
    pub details_json: Option<String>,
    pub started_utc: String,
    pub finished_utc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationStats {
    pub activity_events_checked: u64,
    pub packets_checked: u64,
    pub exhibits_checked: u64,
    pub read_models_rebuilt: bool,
    pub timeline_events_checked: u64,
    pub fts_queue_depth: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub case_id: String,
    pub tool_version: String,
    pub schema_version: String,
    pub started_utc: String,
    pub finished_utc: String,
    pub status: VerificationStatus,
    pub checks: Vec<CheckResult>,
    pub stats: VerificationStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyOptions {
    pub verify_activity_hash_chain: bool,
    pub verify_packet_manifests: bool,
    pub verify_db_integrity: bool,
    pub verify_read_models_rebuild: bool,
    pub verify_timeline_idempotency: bool,
    pub verify_fts_queue_empty: bool,
    pub sample_limit: Option<u64>,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            verify_activity_hash_chain: true,
            verify_packet_manifests: true,
            verify_db_integrity: true,
            verify_read_models_rebuild: true,
            verify_timeline_idempotency: true,
            verify_fts_queue_empty: false,
            sample_limit: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportOptions {
    pub require_verification: bool,
    pub max_report_age_seconds: Option<u64>,
    pub allow_warn: bool,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            require_verification: true,
            max_report_age_seconds: Some(86400),
            allow_warn: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExportGuardError {
    pub message: String,
}

impl std::fmt::Display for ExportGuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ExportGuardError {}

pub struct CaseVerifier {
    case_id: String,
    options: VerifyOptions,
    started_utc: String,
    checks: Vec<CheckResult>,
    stats: VerificationStats,
    event_bus: Option<Arc<EventBus>>,
}

impl CaseVerifier {
    pub fn new(_db_path: &Path, case_id: &str, options: VerifyOptions) -> SqliteResult<Self> {
        let now = chrono::Utc::now();
        let started_utc = now.to_rfc3339();

        Ok(Self {
            case_id: case_id.to_string(),
            options,
            started_utc,
            checks: Vec::new(),
            stats: VerificationStats {
                activity_events_checked: 0,
                packets_checked: 0,
                exhibits_checked: 0,
                read_models_rebuilt: false,
                timeline_events_checked: 0,
                fts_queue_depth: 0,
            },
            event_bus: None,
        })
    }

    pub fn with_event_bus(mut self, event_bus: Arc<EventBus>) -> Self {
        self.event_bus = Some(event_bus);
        self
    }

    fn emit_progress(&self, check_name: &str, status: &str, message: &str) {
        if let Some(ref bus) = self.event_bus {
            bus.emit(EngineEvent::new(
                Some(self.case_id.clone()),
                EngineEventKind::VerifyProgress {
                    check_name: check_name.to_string(),
                    status: status.to_string(),
                    message: message.to_string(),
                },
                match status {
                    "fail" => EventSeverity::Error,
                    "warn" => EventSeverity::Warn,
                    _ => EventSeverity::Info,
                },
                format!("Verify: {} - {}", check_name, message),
            ));
        }
    }

    pub fn verify_case(mut self, conn: &mut Connection) -> SqliteResult<VerificationReport> {
        let now = chrono::Utc::now();
        let finished_utc = now.to_rfc3339();

        self.emit_progress("start", "running", "Starting verification");

        if self.options.verify_db_integrity {
            self.emit_progress("db_integrity", "running", "Checking database integrity");
            check_db_integrity(conn, &mut self);
        }

        if self.options.verify_activity_hash_chain {
            self.emit_progress(
                "activity_hash_chain",
                "running",
                "Verifying activity hash chain",
            );
            check_activity_hash_chain(conn, &mut self);
        }

        if self.options.verify_packet_manifests {
            self.emit_progress("packet_manifests", "running", "Checking packet manifests");
            check_packet_manifests(conn, &mut self);
        }

        if self.options.verify_read_models_rebuild {
            self.emit_progress("read_models", "running", "Verifying read model consistency");
            check_read_models_consistency(conn, &mut self);
        }

        if self.options.verify_timeline_idempotency {
            self.emit_progress(
                "timeline_idempotency",
                "running",
                "Checking timeline idempotency",
            );
            check_timeline_idempotency(conn, &mut self);
        }

        self.emit_progress("fts_queue", "running", "Checking FTS queue");
        check_fts_queue(conn, &mut self);

        if let Ok(enabled) = get_integrity_watchpoints_enabled(conn, &self.case_id) {
            if enabled {
                self.emit_progress(
                    "integrity_watchpoints",
                    "running",
                    "Checking integrity watchpoints",
                );
                let check_name = "Integrity watchpoints".to_string();
                let started = chrono::Utc::now().to_rfc3339();
                match fail_if_integrity_violations_with_conn(conn, &self.case_id) {
                    Ok(_) => {
                        self.emit_progress(
                            "integrity_watchpoints",
                            "pass",
                            "No integrity violations",
                        );
                        self.checks.push(CheckResult {
                            name: check_name,
                            status: VerificationStatus::Pass,
                            message: "No integrity violations detected".to_string(),
                            details_json: None,
                            started_utc: started.clone(),
                            finished_utc: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                    Err(e) => {
                        self.emit_progress(
                            "integrity_watchpoints",
                            "fail",
                            &format!("Violations: {}", e),
                        );
                        self.checks.push(CheckResult {
                            name: check_name,
                            status: VerificationStatus::Fail,
                            message: format!("Integrity violations detected: {}", e),
                            details_json: None,
                            started_utc: started.clone(),
                            finished_utc: chrono::Utc::now().to_rfc3339(),
                        });
                    }
                }
            }
        }

        self.checks.sort_by(|a, b| a.name.cmp(&b.name));

        let status = compute_overall_status(&self.checks);

        self.emit_progress(
            "complete",
            match status {
                VerificationStatus::Pass => "pass",
                VerificationStatus::Warn => "warn",
                VerificationStatus::Fail => "fail",
                VerificationStatus::Missing => "fail",
            },
            "Verification complete",
        );

        save_verification_record(
            conn,
            &self.case_id,
            &self.started_utc,
            &finished_utc,
            &status,
            &self.checks,
            &self.stats,
        )?;

        Ok(VerificationReport {
            case_id: self.case_id,
            tool_version: TOOL_VERSION.to_string(),
            schema_version: crate::case::integrity::SCHEMA_VERSION.to_string(),
            started_utc: self.started_utc,
            finished_utc,
            status,
            checks: self.checks,
            stats: self.stats,
        })
    }
}

fn compute_overall_status(checks: &[CheckResult]) -> VerificationStatus {
    if checks.iter().any(|c| c.status == VerificationStatus::Fail) {
        VerificationStatus::Fail
    } else if checks.iter().any(|c| c.status == VerificationStatus::Warn) {
        VerificationStatus::Warn
    } else {
        VerificationStatus::Pass
    }
}

fn add_check(
    verifier: &mut CaseVerifier,
    name: &str,
    status: VerificationStatus,
    message: &str,
    details: Option<String>,
) {
    let now = chrono::Utc::now();
    let finished_utc = now.to_rfc3339();

    verifier.checks.push(CheckResult {
        name: name.to_string(),
        status,
        message: message.to_string(),
        details_json: details,
        started_utc: verifier.started_utc.clone(),
        finished_utc,
    });
}

fn check_db_integrity(conn: &mut Connection, verifier: &mut CaseVerifier) {
    let result: Result<String, _> = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0));

    match result {
        Ok(status) if status == "ok" => {
            add_check(
                verifier,
                "db_integrity",
                VerificationStatus::Pass,
                "Database integrity check passed",
                None,
            );
        }
        Ok(status) => {
            let details =
                serde_json::to_string(&HashMap::from([("integrity_result", status)])).ok();
            add_check(
                verifier,
                "db_integrity",
                VerificationStatus::Fail,
                "Database integrity check failed",
                details,
            );
        }
        Err(e) => {
            let details = serde_json::to_string(&HashMap::from([("error", e.to_string())])).ok();
            add_check(
                verifier,
                "db_integrity",
                VerificationStatus::Fail,
                "Database integrity check error",
                details,
            );
        }
    }
}

fn check_activity_hash_chain(conn: &mut Connection, verifier: &mut CaseVerifier) {
    let case_id = verifier.case_id.clone();
    let sample_limit = verifier.options.sample_limit;

    let limit_clause = match sample_limit {
        Some(limit) => format!("ORDER BY ts_utc DESC, id DESC LIMIT {}", limit),
        None => "ORDER BY ts_utc DESC, id DESC".to_string(),
    };

    let query = format!(
        "SELECT id, case_id, event_type, summary, details_json, ts_utc, ts_local, 
                user_name, session_id, prev_event_hash, event_hash, evidence_id, volume_id
         FROM activity_log 
         WHERE case_id = ?1 
         {}",
        limit_clause
    );

    let mut stmt = match conn.prepare(&query) {
        Ok(s) => s,
        Err(e) => {
            add_check(
                verifier,
                "activity_hash_chain",
                VerificationStatus::Fail,
                "Failed to query activity log",
                serde_json::to_string(&HashMap::from([("error", e.to_string())])).ok(),
            );
            return;
        }
    };

    type ActivityRow = (
        String,
        String,
        String,
        String,
        Option<String>,
        i64,
        String,
        String,
        String,
        Option<String>,
        String,
        Option<String>,
        Option<String>,
    );
    let rows: Vec<ActivityRow> = match stmt.query_map(params![case_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, i64>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, String>(8)?,
            row.get::<_, Option<String>>(9)?,
            row.get::<_, String>(10)?,
            row.get::<_, Option<String>>(11)?,
            row.get::<_, Option<String>>(12)?,
        ))
    }) {
        Ok(r) => match r.collect::<Result<Vec<_>, _>>() {
            Ok(rows) => rows,
            Err(e) => {
                add_check(
                    verifier,
                    "activity_hash_chain",
                    VerificationStatus::Fail,
                    "Failed to read activity log",
                    serde_json::to_string(&HashMap::from([("error", e.to_string())])).ok(),
                );
                return;
            }
        },
        Err(e) => {
            add_check(
                verifier,
                "activity_hash_chain",
                VerificationStatus::Fail,
                "Failed to read activity log",
                serde_json::to_string(&HashMap::from([("error", e.to_string())])).ok(),
            );
            return;
        }
    };

    let mut total_checked: u64 = 0;
    let mut prev_expected_hash: Option<String> = None;
    let mut failures: Vec<HashMap<String, String>> = Vec::new();

    if let Some(limit) = sample_limit {
        if limit > 0 {
            let boundary_check: Result<(String, String), _> = conn.query_row(
                "SELECT event_hash, prev_event_hash FROM activity_log 
                 WHERE case_id = ?1 
                 ORDER BY ts_utc DESC, id DESC 
                 LIMIT 1 OFFSET ?2",
                params![case_id, limit],
                |row| Ok((row.get(0)?, row.get(1)?)),
            );

            if let Ok((actual_prev_event_hash, _stored_prev)) = boundary_check {
                if let Some(first_row_prev) = rows.last() {
                    if let Some(ref stored_prev_hash) = first_row_prev.9 {
                        if *stored_prev_hash != actual_prev_event_hash {
                            let mut failure = HashMap::new();
                            failure.insert("boundary_check".to_string(), "true".to_string());
                            failure.insert("expected_prev".to_string(), actual_prev_event_hash);
                            failure.insert("stored_prev".to_string(), stored_prev_hash.clone());
                            if failures.len() < 5 {
                                failures.push(failure);
                            }
                        }
                    }
                }
            }
        }
    }

    for row in rows.iter().rev() {
        let (
            ref id,
            ref case_id,
            ref event_type,
            ref summary,
            ref details_json,
            ts_utc,
            ref ts_local,
            ref user_name,
            ref session_id,
            ref prev_event_hash,
            ref event_hash,
            ref evidence_id,
            ref volume_id,
        ) = *row;

        let computed_hash = compute_activity_event_hash(
            id,
            case_id,
            event_type,
            summary,
            details_json.as_deref(),
            ts_utc,
            ts_local,
            user_name,
            session_id,
            evidence_id.as_deref(),
            volume_id.as_deref(),
            prev_expected_hash.as_deref(),
        );

        if computed_hash != *event_hash {
            let mut failure = HashMap::new();
            failure.insert("id".to_string(), id.clone());
            failure.insert("expected_hash".to_string(), computed_hash.clone());
            failure.insert("stored_hash".to_string(), event_hash.clone());
            if failures.len() < 5 {
                failures.push(failure);
            }
        }

        if let Some(ref stored_prev) = prev_event_hash {
            if let Some(ref expected_prev) = prev_expected_hash {
                if stored_prev != expected_prev {
                    let mut failure = HashMap::new();
                    failure.insert("id".to_string(), id.clone());
                    failure.insert("expected_prev".to_string(), expected_prev.clone());
                    failure.insert("stored_prev".to_string(), stored_prev.clone());
                    if failures.len() < 5 {
                        failures.push(failure);
                    }
                }
            }
        }

        prev_expected_hash = Some(event_hash.clone());
        total_checked += 1;
    }

    verifier.stats.activity_events_checked = total_checked;

    if failures.is_empty() {
        add_check(
            verifier,
            "activity_hash_chain",
            VerificationStatus::Pass,
            &format!("Activity hash chain verified: {} events", total_checked),
            None,
        );
    } else {
        let details = serde_json::to_string(&HashMap::from([
            (
                "failures",
                serde_json::to_string(&failures).unwrap_or_default(),
            ),
            ("total_checked", total_checked.to_string()),
        ]))
        .ok();
        add_check(
            verifier,
            "activity_hash_chain",
            VerificationStatus::Fail,
            &format!(
                "Activity hash chain verification failed: {} mismatches",
                failures.len()
            ),
            details,
        );
    }
}

fn check_packet_manifests(conn: &mut Connection, verifier: &mut CaseVerifier) {
    let case_id = verifier.case_id.clone();

    let mut stmt = match conn.prepare(
        "SELECT id, name, COALESCE(manifest_hash, ''), total_files FROM exhibit_packets WHERE case_id = ?1",
    ) {
        Ok(s) => s,
        Err(e) => {
            add_check(
                verifier,
                "packet_manifests",
                VerificationStatus::Fail,
                "Failed to query packets",
                serde_json::to_string(&HashMap::from([("error", e.to_string())])).ok(),
            );
            return;
        }
    };

    let packets: Vec<(String, String, String, i64)> =
        match stmt.query_map(params![case_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        }) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                add_check(
                    verifier,
                    "packet_manifests",
                    VerificationStatus::Fail,
                    "Failed to read packets",
                    serde_json::to_string(&HashMap::from([("error", e.to_string())])).ok(),
                );
                return;
            }
        };

    let mut packets_checked: u64 = 0;
    let mut exhibits_checked: u64 = 0;
    let mut hash_mismatches = Vec::new();

    for (packet_id, name, stored_hash, total_files) in packets {
        packets_checked += 1;
        exhibits_checked += total_files as u64;

        if stored_hash.is_empty() {
            continue;
        }

        let manifest_data = format!("{}:{}:{}", packet_id, name, total_files);
        let computed_hash = compute_simple_hash(manifest_data.as_bytes());

        if computed_hash != stored_hash {
            let mut mismatch = HashMap::new();
            mismatch.insert("packet_id".to_string(), packet_id);
            mismatch.insert("packet_name".to_string(), name);
            mismatch.insert("expected_hash".to_string(), computed_hash);
            mismatch.insert("stored_hash".to_string(), stored_hash);
            if hash_mismatches.len() < 5 {
                hash_mismatches.push(mismatch);
            }
        }
    }

    verifier.stats.packets_checked = packets_checked;
    verifier.stats.exhibits_checked = exhibits_checked;

    if hash_mismatches.is_empty() {
        add_check(
            verifier,
            "packet_manifests",
            VerificationStatus::Pass,
            &format!(
                "Verified {} packets with {} exhibits",
                packets_checked, exhibits_checked
            ),
            None,
        );
    } else {
        let details = serde_json::to_string(&HashMap::from([
            ("mismatch_count", hash_mismatches.len().to_string()),
            (
                "failures",
                serde_json::to_string(&hash_mismatches).unwrap_or_default(),
            ),
        ]))
        .ok();
        add_check(
            verifier,
            "packet_manifests",
            VerificationStatus::Fail,
            &format!(
                "Packet manifest verification failed: {} mismatches",
                hash_mismatches.len()
            ),
            details,
        );
    }
}

fn check_read_models_consistency(conn: &mut Connection, verifier: &mut CaseVerifier) {
    let case_id = verifier.case_id.clone();

    let read_models_enabled = match conn.query_row(
        "SELECT value FROM case_settings WHERE case_id = 'system' AND key = 'read_models_enabled'",
        [],
        |row| row.get::<_, String>(0),
    ) {
        Ok(v) => v == "1",
        Err(_) => true,
    };

    if !read_models_enabled {
        add_check(
            verifier,
            "read_models_consistency",
            VerificationStatus::Warn,
            "Read models currently disabled, skipping rebuild check",
            None,
        );
        return;
    }

    let _ = conn.execute(
        "INSERT OR REPLACE INTO case_settings (id, case_id, key, value, modified_at) 
         VALUES (lower(hex(randomblob(16))), 'system', 'read_models_enabled', '0', strftime('%s', 'now'))",
        [],
    );

    let rebuild_result = rebuild_read_models_internal(conn, &case_id);

    let _ = conn.execute(
        "INSERT OR REPLACE INTO case_settings (id, case_id, key, value, modified_at) 
         VALUES (lower(hex(randomblob(16))), 'system', 'read_models_enabled', '1', strftime('%s', 'now'))",
        [],
    );

    verifier.stats.read_models_rebuilt = true;

    match rebuild_result {
        Ok((rebuilt_count, current_count)) if rebuilt_count == current_count => {
            add_check(
                verifier,
                "read_models_consistency",
                VerificationStatus::Pass,
                "Read models consistent after rebuild",
                None,
            );
        }
        Ok((rebuilt, current)) => {
            let details = serde_json::to_string(&HashMap::from([
                ("rebuilt_count", rebuilt.to_string()),
                ("current_count", current.to_string()),
            ]))
            .ok();
            add_check(
                verifier,
                "read_models_consistency",
                VerificationStatus::Warn,
                "Read model counts differ after rebuild",
                details,
            );
        }
        Err(e) => {
            let details = serde_json::to_string(&HashMap::from([("error", e.to_string())])).ok();
            add_check(
                verifier,
                "read_models_consistency",
                VerificationStatus::Fail,
                "Failed to rebuild read models",
                details,
            );
        }
    }
}

fn rebuild_read_models_internal(conn: &mut Connection, case_id: &str) -> SqliteResult<(i64, i64)> {
    conn.execute(
        "INSERT INTO case_stats (id, case_id, total_bookmarks, total_notes, total_exhibits, total_jobs, last_updated)
         VALUES (lower(hex(randomblob(16))), ?1, 
            (SELECT COUNT(*) FROM bookmarks WHERE case_id = ?1),
            (SELECT COUNT(*) FROM notes WHERE case_id = ?1),
            (SELECT COUNT(*) FROM exhibits WHERE case_id = ?1),
            (SELECT COUNT(*) FROM jobs WHERE case_id = ?1),
            strftime('%s', 'now'))
         ON CONFLICT(case_id) DO UPDATE SET
            total_bookmarks = (SELECT COUNT(*) FROM bookmarks WHERE case_id = ?1),
            total_notes = (SELECT COUNT(*) FROM notes WHERE case_id = ?1),
            total_exhibits = (SELECT COUNT(*) FROM exhibits WHERE case_id = ?1),
            total_jobs = (SELECT COUNT(*) FROM jobs WHERE case_id = ?1),
            last_updated = strftime('%s', 'now')",
        [case_id],
    )?;

    let rebuilt: i64 = conn.query_row(
        "SELECT COALESCE(total_bookmarks, 0) + COALESCE(total_notes, 0) + COALESCE(total_exhibits, 0) + COALESCE(total_jobs, 0)
         FROM case_stats WHERE case_id = ?1",
        [case_id],
        |row| row.get(0),
    ).unwrap_or(0);

    let current_bookmarks: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM bookmarks WHERE case_id = ?1",
            [case_id],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let current_notes: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM notes WHERE case_id = ?1",
            [case_id],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let current_exhibits: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM exhibits WHERE case_id = ?1",
            [case_id],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let current_jobs: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM jobs WHERE case_id = ?1",
            [case_id],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let current = current_bookmarks + current_notes + current_exhibits + current_jobs;

    Ok((rebuilt, current))
}

fn check_timeline_idempotency(conn: &mut Connection, verifier: &mut CaseVerifier) {
    let case_id = verifier.case_id.clone();
    let query = "
        SELECT event_time, event_type, artifact_id, source_module, source_record_id, COUNT(*) as cnt
        FROM evidence_timeline 
        WHERE case_id = ?1
        GROUP BY event_time, event_type, artifact_id, source_module, source_record_id
        HAVING COUNT(*) > 1
        LIMIT 10
    ";

    let mut stmt = match conn.prepare(query) {
        Ok(s) => s,
        Err(e) => {
            let details = serde_json::to_string(&HashMap::from([("error", e.to_string())])).ok();
            add_check(
                verifier,
                "timeline_idempotency",
                VerificationStatus::Fail,
                "Failed to check timeline duplicates",
                details,
            );
            return;
        }
    };

    type DuplicateRow = (
        i64,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        i64,
    );
    let duplicates: Vec<DuplicateRow> = match stmt.query_map(params![case_id], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, i64>(5)?,
        ))
    }) {
        Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
        Err(e) => {
            let details = serde_json::to_string(&HashMap::from([("error", e.to_string())])).ok();
            add_check(
                verifier,
                "timeline_idempotency",
                VerificationStatus::Fail,
                "Failed to read timeline",
                details,
            );
            return;
        }
    };

    let total_checked: u64 = conn
        .query_row(
            "SELECT COUNT(*) FROM evidence_timeline WHERE case_id = ?1",
            [&case_id],
            |row| row.get(0),
        )
        .unwrap_or(0);

    verifier.stats.timeline_events_checked = total_checked;

    if duplicates.is_empty() {
        add_check(
            verifier,
            "timeline_idempotency",
            VerificationStatus::Pass,
            &format!("Timeline idempotency verified: {} events", total_checked),
            None,
        );
    } else {
        let sample: Vec<HashMap<String, serde_json::Value>> = duplicates
            .iter()
            .take(5)
            .map(|d| {
                let mut m = HashMap::new();
                m.insert("event_time".to_string(), serde_json::json!(d.0));
                m.insert("event_type".to_string(), serde_json::json!(d.1));
                m.insert("artifact_id".to_string(), serde_json::json!(d.2));
                m.insert("source_module".to_string(), serde_json::json!(d.3));
                m.insert("count".to_string(), serde_json::json!(d.5));
                m
            })
            .collect();

        let details = serde_json::to_string(&HashMap::from([
            ("duplicate_count", duplicates.len().to_string()),
            ("sample", serde_json::to_string(&sample).unwrap_or_default()),
        ]))
        .ok();

        add_check(
            verifier,
            "timeline_idempotency",
            VerificationStatus::Fail,
            &format!("Found {} duplicate timeline events", duplicates.len()),
            details,
        );
    }
}

fn check_fts_queue(conn: &mut Connection, verifier: &mut CaseVerifier) {
    let case_id = verifier.case_id.clone();
    let depth: u64 = conn
        .query_row(
            "SELECT COUNT(*) FROM fts_index_queue WHERE case_id = ?1 AND status = 'pending'",
            [&case_id],
            |row| row.get(0),
        )
        .unwrap_or_default();

    verifier.stats.fts_queue_depth = depth;

    if verifier.options.verify_fts_queue_empty && depth > 0 {
        let details =
            serde_json::to_string(&HashMap::from([("queue_depth", depth.to_string())])).ok();
        add_check(
            verifier,
            "fts_queue",
            VerificationStatus::Warn,
            &format!("FTS queue has {} pending items", depth),
            details,
        );
    } else {
        add_check(
            verifier,
            "fts_queue",
            VerificationStatus::Pass,
            &format!("FTS queue check passed (depth: {})", depth),
            None,
        );
    }
}

fn save_verification_record(
    conn: &mut Connection,
    case_id: &str,
    started_utc: &str,
    finished_utc: &str,
    status: &VerificationStatus,
    checks: &[CheckResult],
    stats: &VerificationStats,
) -> SqliteResult<()> {
    let report_json = serde_json::to_string(&VerificationReport {
        case_id: case_id.to_string(),
        tool_version: TOOL_VERSION.to_string(),
        schema_version: crate::case::integrity::SCHEMA_VERSION.to_string(),
        started_utc: started_utc.to_string(),
        finished_utc: finished_utc.to_string(),
        status: status.clone(),
        checks: checks.to_vec(),
        stats: stats.clone(),
    })
    .unwrap_or_default();

    conn.execute(
        "INSERT INTO case_verifications (case_id, started_utc, finished_utc, status, report_json)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            case_id,
            started_utc,
            finished_utc,
            match status {
                VerificationStatus::Pass => "Pass",
                VerificationStatus::Warn => "Warn",
                VerificationStatus::Fail => "Fail",
                VerificationStatus::Missing => "MISSING",
            },
            report_json
        ],
    )?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn compute_activity_event_hash(
    event_id: &str,
    case_id: &str,
    event_type: &str,
    summary: &str,
    details_json: Option<&str>,
    ts_utc: i64,
    ts_local: &str,
    user_name: &str,
    session_id: &str,
    evidence_id: Option<&str>,
    volume_id: Option<&str>,
    prev_hash: Option<&str>,
) -> String {
    let mut hasher = Sha256::new();

    if let Some(prev) = prev_hash {
        hasher.update(b"prev_hash=");
        hasher.update(prev.as_bytes());
        hasher.update(b"\n");
    }

    hasher.update(b"event_id=");
    hasher.update(event_id.as_bytes());
    hasher.update(b"\ncase_id=");
    hasher.update(case_id.as_bytes());
    hasher.update(b"\nevent_type=");
    hasher.update(event_type.as_bytes());
    hasher.update(b"\nsummary=");
    hasher.update(summary.as_bytes());

    if let Some(details) = details_json {
        hasher.update(b"\ndetails_json=");
        hasher.update(details.as_bytes());
    }

    hasher.update(b"\nts_utc=");
    hasher.update(ts_utc.to_string().as_bytes());
    hasher.update(b"\nts_local=");
    hasher.update(ts_local.as_bytes());
    hasher.update(b"\nuser_name=");
    hasher.update(user_name.as_bytes());
    hasher.update(b"\nsession_id=");
    hasher.update(session_id.as_bytes());

    if let Some(ev) = evidence_id {
        hasher.update(b"\nevidence_id=");
        hasher.update(ev.as_bytes());
    }

    if let Some(vol) = volume_id {
        hasher.update(b"\nvolume_id=");
        hasher.update(vol.as_bytes());
    }

    format!("{:x}", hasher.finalize())
}

fn compute_simple_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

pub fn verify_case(
    case_id: &str,
    db_path: &Path,
    options: VerifyOptions,
) -> SqliteResult<VerificationReport> {
    let mut conn = Connection::open(db_path)?;
    let verifier = CaseVerifier::new(db_path, case_id, options)?;
    verifier.verify_case(&mut conn)
}

pub fn verify_case_with_events(
    case_id: &str,
    db_path: &Path,
    options: VerifyOptions,
    event_bus: Option<Arc<EventBus>>,
) -> SqliteResult<VerificationReport> {
    let mut conn = Connection::open(db_path)?;
    let mut verifier = CaseVerifier::new(db_path, case_id, options)?;

    if let Some(bus) = event_bus {
        verifier = verifier.with_event_bus(bus);
    }

    verifier.verify_case(&mut conn)
}

pub fn insert_verification_report(
    conn: &mut Connection,
    case_id: &str,
    report: &VerificationReport,
) -> SqliteResult<i64> {
    let report_json = serde_json::to_string(report).unwrap_or_default();

    conn.execute(
        "INSERT INTO case_verifications (case_id, started_utc, finished_utc, status, report_json)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            case_id,
            report.started_utc,
            report.finished_utc,
            match report.status {
                VerificationStatus::Pass => "Pass",
                VerificationStatus::Warn => "Warn",
                VerificationStatus::Fail => "Fail",
                VerificationStatus::Missing => "MISSING",
            },
            report_json
        ],
    )?;

    Ok(conn.last_insert_rowid())
}

pub fn get_recent_verifications(
    conn: &mut Connection,
    case_id: &str,
    limit: usize,
) -> SqliteResult<Vec<VerificationReport>> {
    let mut stmt = conn.prepare(
        "SELECT report_json FROM case_verifications 
         WHERE case_id = ?1 
         ORDER BY started_utc DESC 
         LIMIT ?2",
    )?;

    let reports = stmt.query_map(params![case_id, limit as i64], |row| {
        let json: String = row.get(0)?;
        Ok(serde_json::from_str(&json).ok())
    })?;

    Ok(reports.filter_map(|r| r.ok()).flatten().collect())
}

pub fn get_latest_verification(
    conn: &mut Connection,
    case_id: &str,
) -> SqliteResult<Option<VerificationReport>> {
    let mut stmt = conn.prepare(
        "SELECT report_json FROM case_verifications 
         WHERE case_id = ?1 
         ORDER BY started_utc DESC, id DESC 
         LIMIT 1",
    )?;

    let result = stmt.query_row([case_id], |row| {
        let json: String = row.get(0)?;
        Ok(serde_json::from_str::<VerificationReport>(&json).ok())
    });

    match result {
        Ok(Some(report)) => Ok(Some(report)),
        Ok(None) => Ok(None),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

pub fn check_export_guard(
    conn: &mut Connection,
    case_id: &str,
    options: &ExportOptions,
) -> Result<Option<VerificationReport>, ExportGuardError> {
    if !options.require_verification {
        return Ok(None);
    }

    let report = match get_latest_verification(conn, case_id) {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Err(ExportGuardError {
                message: format!(
                    "No verification report found for case '{}'. Run `forensic-cli verify --case {}` before exporting.",
                    case_id, case_id
                ),
            });
        }
        Err(e) => {
            return Err(ExportGuardError {
                message: format!("Failed to retrieve verification report: {}", e),
            });
        }
    };

    match report.status {
        VerificationStatus::Fail => {
            return Err(ExportGuardError {
                message: format!(
                    "Verification failed for case '{}'. Export blocked. Fix the failing checks and re-run verification.",
                    case_id
                ),
            });
        }
        VerificationStatus::Warn if !options.allow_warn => {
            return Err(ExportGuardError {
                message: format!(
                    "Verification has warnings for case '{}'. Use --strict to allow or fix the warnings and re-run verification.",
                    case_id
                ),
            });
        }
        _ => {}
    }

    if let Some(max_age) = options.max_report_age_seconds {
        let report_time = chrono::DateTime::parse_from_rfc3339(&report.started_utc)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .ok();

        if let Some(report_time) = report_time {
            let now = chrono::Utc::now();
            let age_seconds = (now - report_time).num_seconds() as u64;

            if age_seconds > max_age {
                return Err(ExportGuardError {
                    message: format!(
                        "Verification report for case '{}' is too old ({} seconds). Run `forensic-cli verify --case {}` to refresh.",
                        case_id, age_seconds, case_id
                    ),
                });
            }
        }
    }

    Ok(Some(report))
}

pub fn create_missing_verification_report(case_id: &str) -> VerificationReport {
    let now = chrono::Utc::now();
    VerificationReport {
        case_id: case_id.to_string(),
        tool_version: TOOL_VERSION.to_string(),
        schema_version: "1.0".to_string(),
        started_utc: now.to_rfc3339(),
        finished_utc: now.to_rfc3339(),
        status: VerificationStatus::Missing,
        checks: vec![],
        stats: VerificationStats {
            activity_events_checked: 0,
            packets_checked: 0,
            exhibits_checked: 0,
            read_models_rebuilt: false,
            timeline_events_checked: 0,
            fts_queue_depth: 0,
        },
    }
}

pub fn generate_verification_summary(report: &VerificationReport) -> String {
    let mut summary = String::new();
    let overall_status = match report.status {
        VerificationStatus::Pass => "Pass",
        VerificationStatus::Warn => "Warn",
        VerificationStatus::Fail => "Fail",
        VerificationStatus::Missing => "MISSING",
    };

    summary.push_str(&format!("Case: {}\n", report.case_id));
    summary.push_str(&format!("Overall: {}\n", overall_status));
    summary.push_str(&format!("VerifiedAtUTC: {}\n", report.started_utc));
    summary.push_str("Checks:\n");

    let mut sorted_checks = report.checks.clone();
    sorted_checks.sort_by(|a, b| a.name.cmp(&b.name));

    for check in sorted_checks {
        let status_str = match check.status {
            VerificationStatus::Pass => "PASS",
            VerificationStatus::Warn => "WARN",
            VerificationStatus::Fail => "FAIL",
            VerificationStatus::Missing => "MISSING",
        };

        let details = if let Some(ref details) = check.details_json {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(details) {
                if let Some(obj) = parsed.as_object() {
                    if let Some(fts_depth) = obj.get("queue_depth") {
                        format!("  - {}: {} (depth={})\n", check.name, status_str, fts_depth)
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                }
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        if details.is_empty() {
            summary.push_str(&format!("  - {}: {}\n", check.name, status_str));
        } else {
            summary.push_str(&details);
        }
    }

    summary
}

pub fn write_verification_artifacts(
    output_dir: &Path,
    case_id: &str,
    report: Option<&VerificationReport>,
) -> IoResult<()> {
    let owned_report = report
        .cloned()
        .unwrap_or_else(|| create_missing_verification_report(case_id));
    let report_to_write = &owned_report;

    let json_path = output_dir.join("verification_report.latest.json");
    let json_content = serde_json::to_string_pretty(report_to_write).unwrap_or_default();
    std::fs::write(&json_path, json_content)?;

    let summary_path = output_dir.join("verification_summary.txt");
    let summary_content = generate_verification_summary(report_to_write);
    std::fs::write(&summary_path, summary_content)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_db(temp_dir: &TempDir) -> SqliteResult<(Connection, String)> {
        let db_path = temp_dir.path().join("test_case.sqlite");
        let case_id = "test_case_001".to_string();

        let conn = Connection::open(&db_path)?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS cases (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                examiner TEXT NOT NULL,
                description TEXT,
                status TEXT DEFAULT 'open',
                created_at INTEGER NOT NULL,
                modified_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS activity_log (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                evidence_id TEXT,
                volume_id TEXT,
                user_name TEXT NOT NULL,
                session_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                summary TEXT NOT NULL,
                details_json TEXT,
                ts_utc INTEGER NOT NULL,
                ts_local TEXT NOT NULL,
                prev_event_hash TEXT,
                event_hash TEXT NOT NULL,
                schema_version TEXT NOT NULL DEFAULT '1.0',
                tool_version TEXT,
                tool_build TEXT
            );

            CREATE TABLE IF NOT EXISTS exhibit_packets (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                created_by TEXT NOT NULL,
                manifest_hash TEXT,
                total_files INTEGER DEFAULT 0,
                total_size_bytes INTEGER DEFAULT 0,
                export_path TEXT,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS case_stats (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                total_artifacts INTEGER DEFAULT 0,
                total_bookmarks INTEGER DEFAULT 0,
                total_notes INTEGER DEFAULT 0,
                total_exhibits INTEGER DEFAULT 0,
                total_jobs INTEGER DEFAULT 0,
                jobs_completed INTEGER DEFAULT 0,
                jobs_failed INTEGER DEFAULT 0,
                last_updated INTEGER NOT NULL,
                UNIQUE(case_id)
            );

            CREATE TABLE IF NOT EXISTS bookmarks (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                folder_id TEXT,
                title TEXT NOT NULL,
                description TEXT,
                tags_json TEXT,
                color TEXT,
                icon TEXT,
                notes TEXT,
                reviewed INTEGER DEFAULT 0,
                reviewer TEXT,
                reviewed_at INTEGER,
                custom_fields_json TEXT,
                created_by TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                modified_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS notes (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                title TEXT NOT NULL,
                content TEXT,
                tags_json TEXT,
                reviewed INTEGER DEFAULT 0,
                reviewer TEXT,
                reviewed_at INTEGER,
                created_at INTEGER NOT NULL,
                modified_at INTEGER NOT NULL,
                created_by TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS exhibits (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                exhibit_type TEXT NOT NULL,
                file_path TEXT,
                data_path TEXT,
                hash_md5 TEXT,
                hash_sha1 TEXT,
                hash_sha256 TEXT,
                tags_json TEXT,
                notes TEXT,
                metadata_json TEXT,
                created_by TEXT NOT NULL,
                source_evidence_id TEXT,
                packet_index INTEGER DEFAULT 0,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                job_type TEXT NOT NULL,
                status TEXT NOT NULL,
                priority INTEGER DEFAULT 0,
                progress REAL DEFAULT 0,
                progress_message TEXT,
                error TEXT,
                params_json TEXT,
                result_json TEXT,
                created_by TEXT NOT NULL,
                worker_id TEXT,
                retries INTEGER DEFAULT 0,
                max_retries INTEGER DEFAULT 3,
                created_at INTEGER NOT NULL,
                started_at INTEGER,
                completed_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS evidence_timeline (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                evidence_id TEXT,
                event_type TEXT NOT NULL,
                event_category TEXT,
                event_time INTEGER NOT NULL,
                description TEXT,
                artifact_id TEXT,
                data_json TEXT,
                source_module TEXT,
                source_record_id TEXT,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                UNIQUE(case_id, artifact_id, event_type, event_time, source_module, source_record_id)
            );

            CREATE TABLE IF NOT EXISTS fts_index_queue (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                table_name TEXT NOT NULL,
                row_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at INTEGER NOT NULL,
                processed_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS case_settings (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT,
                modified_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                UNIQUE(case_id, key)
            );

            CREATE TABLE IF NOT EXISTS case_verifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                started_utc TEXT NOT NULL,
                finished_utc TEXT NOT NULL,
                status TEXT NOT NULL,
                report_json TEXT,
                FOREIGN KEY (case_id) REFERENCES cases(id)
            );

            CREATE INDEX IF NOT EXISTS idx_case_verifications_case_time 
                ON case_verifications(case_id, started_utc);

            CREATE TABLE IF NOT EXISTS integrity_violations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                occurred_utc TEXT NOT NULL,
                table_name TEXT NOT NULL,
                operation TEXT NOT NULL,
                row_key TEXT,
                actor TEXT,
                reason TEXT NOT NULL,
                details_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_integrity_violations_case_time 
                ON integrity_violations(case_id, occurred_utc);
            CREATE INDEX IF NOT EXISTS idx_integrity_violations_case_table 
                ON integrity_violations(case_id, table_name);
            "
        )?;

        conn.execute(
            "INSERT INTO cases (id, name, examiner, created_at, modified_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![&case_id, "Test Case", "tester", 1700000000, 1700000000],
        )?;

        Ok((conn, case_id))
    }

    fn insert_activity_event_with_hash(
        conn: &Connection,
        case_id: &str,
        prev_hash: Option<&str>,
    ) -> SqliteResult<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let ts_utc: i64 = 1700000000
            + (conn
                .query_row(
                    "SELECT COUNT(*) FROM activity_log WHERE case_id = ?1",
                    [case_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap_or(0));
        let ts_local = "2023-11-15 12:00:00".to_string();
        let event_type = "CaseOpened".to_string();
        let summary = "Test event".to_string();
        let user_name = "tester".to_string();
        let session_id = "session_001".to_string();

        let event_hash = compute_activity_event_hash(
            &id,
            case_id,
            &event_type,
            &summary,
            None,
            ts_utc,
            &ts_local,
            &user_name,
            &session_id,
            None,
            None,
            prev_hash,
        );

        conn.execute(
            "INSERT INTO activity_log (id, case_id, event_type, summary, details_json, ts_utc, ts_local, user_name, session_id, prev_event_hash, event_hash, schema_version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![&id, case_id, event_type, summary, None::<String>, ts_utc, ts_local, user_name, session_id, prev_hash, event_hash, "1.0"],
        )?;

        Ok(event_hash)
    }

    #[test]
    fn test_verify_case_passes_with_valid_data() {
        let temp_dir = TempDir::new().unwrap();
        let (mut conn, case_id) = create_test_db(&temp_dir).unwrap();

        let mut prev_hash: Option<String> = None;
        for _ in 0..3 {
            prev_hash = Some(
                insert_activity_event_with_hash(&conn, &case_id, prev_hash.as_deref()).unwrap(),
            );
        }

        conn.execute(
            "INSERT INTO bookmarks (id, case_id, title, created_by, created_at, modified_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![uuid::Uuid::new_v4().to_string(), &case_id, "Test Bookmark", "tester", 1700000000, 1700000000],
        ).unwrap();

        let options = VerifyOptions::default();
        let verifier = CaseVerifier::new(
            temp_dir.path().join("test_case.sqlite").as_path(),
            &case_id,
            options,
        )
        .unwrap();
        let report = verifier.verify_case(&mut conn).unwrap();

        assert!(
            matches!(
                report.status,
                VerificationStatus::Pass | VerificationStatus::Warn
            ),
            "unexpected status: {:?}; checks: {:?}",
            report.status,
            report.checks
        );
        assert!(!report.checks.is_empty());
    }

    #[test]
    fn test_verify_case_fails_with_tampered_hash() {
        let temp_dir = TempDir::new().unwrap();
        let (mut conn, case_id) = create_test_db(&temp_dir).unwrap();

        let mut prev_hash: Option<String> = None;
        for _ in 0..3 {
            prev_hash = Some(
                insert_activity_event_with_hash(&conn, &case_id, prev_hash.as_deref()).unwrap(),
            );
        }

        conn.execute(
            "UPDATE activity_log SET event_hash = 'tampered_hash_12345' WHERE id = (SELECT id FROM activity_log ORDER BY ts_utc DESC LIMIT 1)",
            [],
        ).unwrap();

        let options = VerifyOptions::default();
        let verifier = CaseVerifier::new(
            temp_dir.path().join("test_case.sqlite").as_path(),
            &case_id,
            options,
        )
        .unwrap();
        let report = verifier.verify_case(&mut conn).unwrap();

        let hash_check = report
            .checks
            .iter()
            .find(|c| c.name == "activity_hash_chain");
        assert!(hash_check.is_some());
        assert!(matches!(
            hash_check.unwrap().status,
            VerificationStatus::Fail
        ));
    }

    #[test]
    fn test_verify_options_defaults() {
        let options = VerifyOptions::default();

        assert!(options.verify_db_integrity);
        assert!(options.verify_activity_hash_chain);
        assert!(options.verify_packet_manifests);
        assert!(options.verify_read_models_rebuild);
        assert!(options.verify_timeline_idempotency);
        assert!(!options.verify_fts_queue_empty);
        assert!(options.sample_limit.is_none());
    }

    #[test]
    fn test_verification_status_ordering() {
        let pass_checks = vec![CheckResult {
            name: "check1".to_string(),
            status: VerificationStatus::Pass,
            message: "Pass".to_string(),
            details_json: None,
            started_utc: "2023-01-01T00:00:00Z".to_string(),
            finished_utc: "2023-01-01T00:01:00Z".to_string(),
        }];

        let warn_checks = vec![CheckResult {
            name: "check1".to_string(),
            status: VerificationStatus::Warn,
            message: "Warn".to_string(),
            details_json: None,
            started_utc: "2023-01-01T00:00:00Z".to_string(),
            finished_utc: "2023-01-01T00:01:00Z".to_string(),
        }];

        let fail_checks = vec![CheckResult {
            name: "check1".to_string(),
            status: VerificationStatus::Fail,
            message: "Fail".to_string(),
            details_json: None,
            started_utc: "2023-01-01T00:00:00Z".to_string(),
            finished_utc: "2023-01-01T00:01:00Z".to_string(),
        }];

        assert!(matches!(
            compute_overall_status(&pass_checks),
            VerificationStatus::Pass
        ));
        assert!(matches!(
            compute_overall_status(&warn_checks),
            VerificationStatus::Warn
        ));
        assert!(matches!(
            compute_overall_status(&fail_checks),
            VerificationStatus::Fail
        ));
    }

    #[test]
    fn test_checks_are_sorted_by_name() {
        let mut checks = [
            CheckResult {
                name: "zebra".to_string(),
                status: VerificationStatus::Pass,
                message: "zebra check".to_string(),
                details_json: None,
                started_utc: "2023-01-01T00:00:00Z".to_string(),
                finished_utc: "2023-01-01T00:01:00Z".to_string(),
            },
            CheckResult {
                name: "alpha".to_string(),
                status: VerificationStatus::Pass,
                message: "alpha check".to_string(),
                details_json: None,
                started_utc: "2023-01-01T00:00:00Z".to_string(),
                finished_utc: "2023-01-01T00:01:00Z".to_string(),
            },
            CheckResult {
                name: "middle".to_string(),
                status: VerificationStatus::Pass,
                message: "middle check".to_string(),
                details_json: None,
                started_utc: "2023-01-01T00:00:00Z".to_string(),
                finished_utc: "2023-01-01T00:01:00Z".to_string(),
            },
        ];

        checks.sort_by(|a, b| a.name.cmp(&b.name));

        assert_eq!(checks[0].name, "alpha");
        assert_eq!(checks[1].name, "middle");
        assert_eq!(checks[2].name, "zebra");
    }

    #[test]
    fn test_db_integrity_check() {
        let temp_dir = TempDir::new().unwrap();
        let (mut conn, case_id) = create_test_db(&temp_dir).unwrap();

        let mut verifier = CaseVerifier::new(
            temp_dir.path().join("test_case.sqlite").as_path(),
            &case_id,
            VerifyOptions::default(),
        )
        .unwrap();

        check_db_integrity(&mut conn, &mut verifier);

        let integrity_check = verifier.checks.iter().find(|c| c.name == "db_integrity");
        assert!(integrity_check.is_some());
        assert!(matches!(
            integrity_check.unwrap().status,
            VerificationStatus::Pass
        ));
    }

    #[test]
    fn test_timeline_idempotency_check() {
        let temp_dir = TempDir::new().unwrap();
        let (mut conn, case_id) = create_test_db(&temp_dir).unwrap();

        conn.execute(
            "INSERT INTO evidence_timeline (id, case_id, event_type, event_time, source_module, source_record_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![uuid::Uuid::new_v4().to_string(), &case_id, "test_event", 1700000000, "module1", "record1"],
        ).unwrap();

        let mut verifier = CaseVerifier::new(
            temp_dir.path().join("test_case.sqlite").as_path(),
            &case_id,
            VerifyOptions::default(),
        )
        .unwrap();

        check_timeline_idempotency(&mut conn, &mut verifier);

        let timeline_check = verifier
            .checks
            .iter()
            .find(|c| c.name == "timeline_idempotency");
        assert!(timeline_check.is_some());
        assert!(matches!(
            timeline_check.unwrap().status,
            VerificationStatus::Pass
        ));
    }

    #[test]
    fn test_fts_queue_check_warns_when_not_empty() {
        let temp_dir = TempDir::new().unwrap();
        let (mut conn, case_id) = create_test_db(&temp_dir).unwrap();

        conn.execute(
            "INSERT INTO fts_index_queue (id, case_id, table_name, row_id, operation, status, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![uuid::Uuid::new_v4().to_string(), &case_id, "notes", "note1", "insert", "pending", 1700000000],
        ).unwrap();

        let options = VerifyOptions {
            verify_fts_queue_empty: true,
            ..Default::default()
        };

        let mut verifier = CaseVerifier::new(
            temp_dir.path().join("test_case.sqlite").as_path(),
            &case_id,
            options,
        )
        .unwrap();

        check_fts_queue(&mut conn, &mut verifier);

        let fts_check = verifier.checks.iter().find(|c| c.name == "fts_queue");
        assert!(fts_check.is_some());
        assert!(matches!(
            fts_check.unwrap().status,
            VerificationStatus::Warn
        ));
    }

    #[test]
    fn test_export_guard_requires_verification() {
        let temp_dir = TempDir::new().unwrap();
        let (mut conn, case_id) = create_test_db(&temp_dir).unwrap();

        let options = ExportOptions {
            require_verification: true,
            max_report_age_seconds: None,
            allow_warn: true,
        };

        let result = check_export_guard(&mut conn, &case_id, &options);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("No verification report found"));
    }

    #[test]
    fn test_export_guard_allows_no_verification() {
        let temp_dir = TempDir::new().unwrap();
        let (mut conn, case_id) = create_test_db(&temp_dir).unwrap();

        let options = ExportOptions {
            require_verification: false,
            max_report_age_seconds: None,
            allow_warn: true,
        };

        let result = check_export_guard(&mut conn, &case_id, &options);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_export_guard_blocks_fail_status() {
        let temp_dir = TempDir::new().unwrap();
        let (mut conn, case_id) = create_test_db(&temp_dir).unwrap();

        let now = chrono::Utc::now();
        let report = VerificationReport {
            case_id: case_id.clone(),
            tool_version: "1.0.0".to_string(),
            schema_version: "1.0".to_string(),
            started_utc: now.to_rfc3339(),
            finished_utc: now.to_rfc3339(),
            status: VerificationStatus::Fail,
            checks: vec![],
            stats: VerificationStats {
                activity_events_checked: 0,
                packets_checked: 0,
                exhibits_checked: 0,
                read_models_rebuilt: false,
                timeline_events_checked: 0,
                fts_queue_depth: 0,
            },
        };

        insert_verification_report(&mut conn, &case_id, &report).unwrap();

        let options = ExportOptions::default();
        let result = check_export_guard(&mut conn, &case_id, &options);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("Verification failed"));
    }

    #[test]
    fn test_export_guard_allows_warn_by_default() {
        let temp_dir = TempDir::new().unwrap();
        let (mut conn, case_id) = create_test_db(&temp_dir).unwrap();

        let now = chrono::Utc::now();
        let report = VerificationReport {
            case_id: case_id.clone(),
            tool_version: "1.0.0".to_string(),
            schema_version: "1.0".to_string(),
            started_utc: now.to_rfc3339(),
            finished_utc: now.to_rfc3339(),
            status: VerificationStatus::Warn,
            checks: vec![CheckResult {
                name: "test_check".to_string(),
                status: VerificationStatus::Warn,
                message: "Warning".to_string(),
                details_json: None,
                started_utc: now.to_rfc3339(),
                finished_utc: now.to_rfc3339(),
            }],
            stats: VerificationStats {
                activity_events_checked: 0,
                packets_checked: 0,
                exhibits_checked: 0,
                read_models_rebuilt: false,
                timeline_events_checked: 0,
                fts_queue_depth: 0,
            },
        };

        insert_verification_report(&mut conn, &case_id, &report).unwrap();

        let options = ExportOptions::default();
        let result = check_export_guard(&mut conn, &case_id, &options);
        assert!(result.is_ok());
    }

    #[test]
    fn test_export_guard_blocks_warn_when_strict() {
        let temp_dir = TempDir::new().unwrap();
        let (mut conn, case_id) = create_test_db(&temp_dir).unwrap();

        let now = chrono::Utc::now();
        let report = VerificationReport {
            case_id: case_id.clone(),
            tool_version: "1.0.0".to_string(),
            schema_version: "1.0".to_string(),
            started_utc: now.to_rfc3339(),
            finished_utc: now.to_rfc3339(),
            status: VerificationStatus::Warn,
            checks: vec![],
            stats: VerificationStats {
                activity_events_checked: 0,
                packets_checked: 0,
                exhibits_checked: 0,
                read_models_rebuilt: false,
                timeline_events_checked: 0,
                fts_queue_depth: 0,
            },
        };

        insert_verification_report(&mut conn, &case_id, &report).unwrap();

        let options = ExportOptions {
            require_verification: true,
            max_report_age_seconds: None,
            allow_warn: false,
        };
        let result = check_export_guard(&mut conn, &case_id, &options);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("warnings"));
    }

    #[test]
    fn test_export_guard_blocks_old_report() {
        let temp_dir = TempDir::new().unwrap();
        let (mut conn, case_id) = create_test_db(&temp_dir).unwrap();

        let old_time = chrono::Utc::now() - chrono::Duration::seconds(100000);
        let report = VerificationReport {
            case_id: case_id.clone(),
            tool_version: "1.0.0".to_string(),
            schema_version: "1.0".to_string(),
            started_utc: old_time.to_rfc3339(),
            finished_utc: old_time.to_rfc3339(),
            status: VerificationStatus::Pass,
            checks: vec![],
            stats: VerificationStats {
                activity_events_checked: 0,
                packets_checked: 0,
                exhibits_checked: 0,
                read_models_rebuilt: false,
                timeline_events_checked: 0,
                fts_queue_depth: 0,
            },
        };

        insert_verification_report(&mut conn, &case_id, &report).unwrap();

        let options = ExportOptions {
            require_verification: true,
            max_report_age_seconds: Some(60),
            allow_warn: true,
        };
        let result = check_export_guard(&mut conn, &case_id, &options);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("too old"));
    }

    #[test]
    fn test_write_verification_artifacts() {
        let temp_dir = TempDir::new().unwrap();
        let case_id = "test_case_001";

        let now = chrono::Utc::now();
        let report = VerificationReport {
            case_id: case_id.to_string(),
            tool_version: "1.0.0".to_string(),
            schema_version: "1.0".to_string(),
            started_utc: now.to_rfc3339(),
            finished_utc: now.to_rfc3339(),
            status: VerificationStatus::Pass,
            checks: vec![
                CheckResult {
                    name: "db_integrity".to_string(),
                    status: VerificationStatus::Pass,
                    message: "Database integrity check passed".to_string(),
                    details_json: None,
                    started_utc: now.to_rfc3339(),
                    finished_utc: now.to_rfc3339(),
                },
                CheckResult {
                    name: "activity_hash_chain".to_string(),
                    status: VerificationStatus::Pass,
                    message: "Activity hash chain verified".to_string(),
                    details_json: None,
                    started_utc: now.to_rfc3339(),
                    finished_utc: now.to_rfc3339(),
                },
            ],
            stats: VerificationStats {
                activity_events_checked: 10,
                packets_checked: 2,
                exhibits_checked: 5,
                read_models_rebuilt: true,
                timeline_events_checked: 20,
                fts_queue_depth: 0,
            },
        };

        write_verification_artifacts(temp_dir.path(), case_id, Some(&report)).unwrap();

        let json_path = temp_dir.path().join("verification_report.latest.json");
        let summary_path = temp_dir.path().join("verification_summary.txt");

        assert!(json_path.exists());
        assert!(summary_path.exists());

        let json_content = std::fs::read_to_string(&json_path).unwrap();
        let loaded: VerificationReport = serde_json::from_str(&json_content).unwrap();
        assert_eq!(loaded.case_id, case_id);

        let summary = std::fs::read_to_string(&summary_path).unwrap();
        assert!(summary.contains("Overall: Pass"));
        assert!(summary.contains("db_integrity"));
        assert!(summary.contains("activity_hash_chain"));
    }

    #[test]
    fn test_write_missing_verification_artifacts() {
        let temp_dir = TempDir::new().unwrap();
        let case_id = "test_case_001";

        write_verification_artifacts(temp_dir.path(), case_id, None).unwrap();

        let json_path = temp_dir.path().join("verification_report.latest.json");
        let json_content = std::fs::read_to_string(&json_path).unwrap();

        assert!(json_content.contains("MISSING"));

        let summary_path = temp_dir.path().join("verification_summary.txt");
        let summary = std::fs::read_to_string(&summary_path).unwrap();
        assert!(summary.contains("Overall: MISSING"));
    }

    #[test]
    fn test_verification_summary_sorted() {
        let now = chrono::Utc::now();
        let report = VerificationReport {
            case_id: "test".to_string(),
            tool_version: "1.0.0".to_string(),
            schema_version: "1.0".to_string(),
            started_utc: now.to_rfc3339(),
            finished_utc: now.to_rfc3339(),
            status: VerificationStatus::Pass,
            checks: vec![
                CheckResult {
                    name: "zebra".to_string(),
                    status: VerificationStatus::Pass,
                    message: "zebra check".to_string(),
                    details_json: None,
                    started_utc: now.to_rfc3339(),
                    finished_utc: now.to_rfc3339(),
                },
                CheckResult {
                    name: "alpha".to_string(),
                    status: VerificationStatus::Pass,
                    message: "alpha check".to_string(),
                    details_json: None,
                    started_utc: now.to_rfc3339(),
                    finished_utc: now.to_rfc3339(),
                },
                CheckResult {
                    name: "middle".to_string(),
                    status: VerificationStatus::Pass,
                    message: "middle check".to_string(),
                    details_json: None,
                    started_utc: now.to_rfc3339(),
                    finished_utc: now.to_rfc3339(),
                },
            ],
            stats: VerificationStats {
                activity_events_checked: 0,
                packets_checked: 0,
                exhibits_checked: 0,
                read_models_rebuilt: false,
                timeline_events_checked: 0,
                fts_queue_depth: 0,
            },
        };

        let summary = generate_verification_summary(&report);

        let alpha_pos = summary.find("alpha").unwrap();
        let middle_pos = summary.find("middle").unwrap();
        let zebra_pos = summary.find("zebra").unwrap();

        assert!(alpha_pos < middle_pos);
        assert!(middle_pos < zebra_pos);
    }
}
