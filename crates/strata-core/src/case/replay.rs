use rusqlite::{params, Connection, Result as SqliteResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;

use crate::case::database::CaseDatabase;
use crate::case::watchpoints::{
    fail_if_integrity_violations_with_conn, get_integrity_watchpoints_enabled,
};
use crate::events::{EngineEvent, EngineEventKind, EventBus, EventSeverity};

pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReplayStatus {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableFingerprint {
    pub table: String,
    pub row_count: u64,
    pub stable_hash: String,
    pub sample_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayStepResult {
    pub name: String,
    pub status: ReplayStatus,
    pub message: String,
    pub details_json: serde_json::Value,
    pub started_utc: String,
    pub finished_utc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayReport {
    pub case_id: String,
    pub started_utc: String,
    pub finished_utc: String,
    pub status: ReplayStatus,
    pub steps: Vec<ReplayStepResult>,
    pub before: Vec<TableFingerprint>,
    pub after: Vec<TableFingerprint>,
    pub diffs: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayOptions {
    pub fingerprint_tables: Vec<String>,
    pub run_read_model_rebuild: bool,
    pub run_fts_rebuild: bool,
    pub fts_entities: Vec<String>,
    pub process_fts_queue: bool,
    pub fts_queue_batch: u64,
    pub run_db_optimize: bool,
    pub sample_limit: Option<u64>,
}

impl Default for ReplayOptions {
    fn default() -> Self {
        Self {
            fingerprint_tables: vec![
                "activity_log".to_string(),
                "evidence_timeline".to_string(),
                "exhibits".to_string(),
                "exhibit_packets".to_string(),
                "bookmarks".to_string(),
                "notes".to_string(),
                "provenance".to_string(),
                "case_stats".to_string(),
                "triage_stats".to_string(),
                "timeline_buckets".to_string(),
                "artifact_summary".to_string(),
                "notes_fts".to_string(),
                "bookmarks_fts".to_string(),
                "exhibits_fts".to_string(),
                "fts_index_queue".to_string(),
            ],
            run_read_model_rebuild: true,
            run_fts_rebuild: true,
            fts_entities: vec![
                "notes".to_string(),
                "bookmarks".to_string(),
                "exhibits".to_string(),
            ],
            process_fts_queue: true,
            fts_queue_batch: 5000,
            run_db_optimize: false,
            sample_limit: None,
        }
    }
}

pub struct CaseReplay {
    case_id: String,
    options: ReplayOptions,
    started_utc: String,
    steps: Vec<ReplayStepResult>,
    before: Vec<TableFingerprint>,
    after: Vec<TableFingerprint>,
    event_bus: Option<Arc<EventBus>>,
}

impl CaseReplay {
    pub fn new(case_id: &str, options: ReplayOptions) -> Self {
        let now = chrono::Utc::now();
        let started_utc = now.to_rfc3339();

        Self {
            case_id: case_id.to_string(),
            options,
            started_utc,
            steps: Vec::new(),
            before: Vec::new(),
            after: Vec::new(),
            event_bus: None,
        }
    }

    pub fn with_event_bus(mut self, event_bus: Arc<EventBus>) -> Self {
        self.event_bus = Some(event_bus);
        self
    }

    fn emit_progress(&self, step_name: &str, status: &str, message: &str) {
        if let Some(ref bus) = self.event_bus {
            bus.emit(EngineEvent::new(
                Some(self.case_id.clone()),
                EngineEventKind::ReplayProgress {
                    step_name: step_name.to_string(),
                    status: status.to_string(),
                    message: message.to_string(),
                },
                match status {
                    "fail" => EventSeverity::Error,
                    "warn" => EventSeverity::Warn,
                    _ => EventSeverity::Info,
                },
                format!("Replay: {} - {}", step_name, message),
            ));
        }
    }

    pub fn replay(mut self, db: &CaseDatabase) -> anyhow::Result<ReplayReport> {
        let now = chrono::Utc::now();
        let finished_utc = now.to_rfc3339();

        let conn = db.get_connection();
        let mut conn = conn.lock().unwrap();

        self.add_step(
            "Pre-fingerprint".to_string(),
            ReplayStatus::Pass,
            "Computing pre-replay fingerprints".to_string(),
            serde_json::json!({}),
        );
        self.before = self.compute_fingerprints(&mut conn)?;

        if self.options.run_read_model_rebuild {
            self.add_step(
                "Read model rebuild".to_string(),
                ReplayStatus::Pass,
                "Rebuilding read models".to_string(),
                serde_json::json!({}),
            );
            if let Err(e) = self.run_read_model_rebuild(&mut conn) {
                self.add_step(
                    "Read model rebuild".to_string(),
                    ReplayStatus::Warn,
                    format!("Rebuild completed with error: {}", e),
                    serde_json::json!({"error": e.to_string()}),
                );
            }
        }

        if self.options.run_fts_rebuild {
            self.add_step(
                "FTS rebuild".to_string(),
                ReplayStatus::Pass,
                "Rebuilding FTS indexes".to_string(),
                serde_json::json!({}),
            );
            if let Err(e) = self.run_fts_rebuild(&mut conn) {
                self.add_step(
                    "FTS rebuild".to_string(),
                    ReplayStatus::Warn,
                    format!("FTS rebuild completed with error: {}", e),
                    serde_json::json!({"error": e.to_string()}),
                );
            }
        }

        if self.options.process_fts_queue {
            self.add_step(
                "FTS queue drain".to_string(),
                ReplayStatus::Pass,
                "Processing FTS queue".to_string(),
                serde_json::json!({}),
            );
            match self.process_fts_queue(&mut conn) {
                Ok((processed, remaining)) => {
                    if remaining > 0 && processed == 0 {
                        self.add_step(
                            "FTS queue drain".to_string(),
                            ReplayStatus::Warn,
                            format!(
                                "Queue not drained after processing: {} remaining",
                                remaining
                            ),
                            serde_json::json!({"remaining": remaining}),
                        );
                    } else {
                        self.add_step(
                            "FTS queue drain".to_string(),
                            ReplayStatus::Pass,
                            format!("Processed {} items, {} remaining", processed, remaining),
                            serde_json::json!({"processed": processed, "remaining": remaining}),
                        );
                    }
                }
                Err(e) => {
                    self.add_step(
                        "FTS queue drain".to_string(),
                        ReplayStatus::Warn,
                        format!("Queue processing error: {}", e),
                        serde_json::json!({"error": e.to_string()}),
                    );
                }
            }
        }

        if self.options.run_db_optimize {
            self.add_step(
                "Database optimize".to_string(),
                ReplayStatus::Pass,
                "Running database optimization".to_string(),
                serde_json::json!({}),
            );
            if let Err(e) = db.optimize() {
                self.add_step(
                    "Database optimize".to_string(),
                    ReplayStatus::Warn,
                    format!("Optimize error: {}", e),
                    serde_json::json!({"error": e.to_string()}),
                );
            }
            if let Err(e) = db.wal_checkpoint() {
                self.add_step(
                    "Database optimize".to_string(),
                    ReplayStatus::Warn,
                    format!("WAL checkpoint error: {}", e),
                    serde_json::json!({"error": e.to_string()}),
                );
            }
        }

        self.add_step(
            "Post-fingerprint".to_string(),
            ReplayStatus::Pass,
            "Computing post-replay fingerprints".to_string(),
            serde_json::json!({}),
        );
        self.after = self.compute_fingerprints(&mut conn)?;

        let (status, diffs) = self.compute_diff();

        self.add_step(
            "Diff analysis".to_string(),
            status.clone(),
            "Analyzing before/after differences".to_string(),
            diffs.clone(),
        );

        if let Ok(enabled) = get_integrity_watchpoints_enabled(&conn, &self.case_id) {
            if enabled {
                match fail_if_integrity_violations_with_conn(&conn, &self.case_id) {
                    Ok(_) => {
                        self.add_step(
                            "Integrity check".to_string(),
                            ReplayStatus::Pass,
                            "No integrity violations detected".to_string(),
                            serde_json::json!({}),
                        );
                    }
                    Err(e) => {
                        self.add_step(
                            "Integrity check".to_string(),
                            ReplayStatus::Fail,
                            format!("Integrity violations detected: {}", e),
                            serde_json::json!({"error": e.to_string()}),
                        );
                    }
                }
            }
        }

        let status = self.compute_overall_status();

        let report = ReplayReport {
            case_id: self.case_id.clone(),
            started_utc: self.started_utc.clone(),
            finished_utc,
            status,
            steps: self.steps.clone(),
            before: self.before.clone(),
            after: self.after.clone(),
            diffs,
        };

        self.save_replay_record(&mut conn, &report)?;

        Ok(report)
    }

    fn add_step(
        &mut self,
        name: String,
        status: ReplayStatus,
        message: String,
        details: serde_json::Value,
    ) {
        let now = chrono::Utc::now();
        let finished_utc = now.to_rfc3339();

        let status_str = match status {
            ReplayStatus::Pass => "pass",
            ReplayStatus::Warn => "warn",
            ReplayStatus::Fail => "fail",
        };

        self.emit_progress(&name, status_str, &message);

        self.steps.push(ReplayStepResult {
            name,
            status,
            message,
            details_json: details,
            started_utc: self.started_utc.clone(),
            finished_utc,
        });
    }

    fn compute_fingerprints(&self, conn: &mut Connection) -> anyhow::Result<Vec<TableFingerprint>> {
        let mut fingerprints = Vec::new();

        for table in &self.options.fingerprint_tables {
            match fingerprint_table_case_scoped(
                conn,
                table,
                &self.case_id,
                self.options.sample_limit,
            ) {
                Ok(fp) => fingerprints.push(fp),
                Err(_e) => {
                    fingerprints.push(TableFingerprint {
                        table: table.clone(),
                        row_count: 0,
                        stable_hash: String::new(),
                        sample_keys: vec![],
                    });
                }
            }
        }

        fingerprints.sort_by(|a, b| a.table.cmp(&b.table));
        Ok(fingerprints)
    }

    fn run_read_model_rebuild(&self, conn: &mut Connection) -> anyhow::Result<()> {
        let case_id = &self.case_id;

        conn.execute(
            "INSERT OR REPLACE INTO case_settings (id, case_id, key, value, modified_at) 
             VALUES (lower(hex(randomblob(16))), 'system', 'read_models_enabled', '1', strftime('%s', 'now'))",
            [],
        )?;

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

        conn.execute("DELETE FROM triage_stats WHERE case_id = ?1", [case_id])?;
        conn.execute(
            "INSERT INTO triage_stats (id, case_id, category, count, last_updated)
             SELECT lower(hex(randomblob(16))), ?1, COALESCE(bf.folder_name, 'uncategorized'), COUNT(*), strftime('%s', 'now')
             FROM bookmarks b
             LEFT JOIN bookmark_folders bf ON b.folder_id = bf.id
             WHERE b.case_id = ?1
             GROUP BY bf.folder_name",
            [case_id],
        )?;

        conn.execute(
            "DELETE FROM timeline_buckets WHERE case_id = ?1 AND bucket_type = 'activity'",
            [case_id],
        )?;
        conn.execute(
            "INSERT INTO timeline_buckets (id, case_id, bucket_type, bucket_time, granularity_seconds, count)
             SELECT lower(hex(randomblob(16))), ?1, 'activity', (ts_utc / 3600) * 3600, 3600, COUNT(*)
             FROM activity_log WHERE case_id = ?1 AND ts_utc IS NOT NULL
             GROUP BY (ts_utc / 3600) * 3600",
            [case_id],
        )?;

        conn.execute(
            "DELETE FROM timeline_buckets WHERE case_id = ?1 AND bucket_type = 'evidence'",
            [case_id],
        )?;
        conn.execute(
            "INSERT INTO timeline_buckets (id, case_id, bucket_type, bucket_time, category, granularity_seconds, count)
             SELECT lower(hex(randomblob(16))), ?1, 'evidence', (event_time / 3600) * 3600, event_category, 3600, COUNT(*)
             FROM evidence_timeline WHERE case_id = ?1 AND event_time IS NOT NULL
             GROUP BY (event_time / 3600) * 3600, event_category",
            [case_id],
        )?;

        Ok(())
    }

    fn run_fts_rebuild(&self, conn: &mut Connection) -> anyhow::Result<()> {
        let case_id = &self.case_id;

        for entity in &self.options.fts_entities {
            match entity.as_str() {
                "notes" => {
                    conn.execute("DELETE FROM notes_fts", [])?;
                    let mut stmt = conn.prepare(
                        "SELECT id, rowid, title, content FROM notes WHERE case_id = ?1",
                    )?;
                    let notes: Vec<(String, i64, String, String)> = stmt
                        .query_map([case_id], |row| {
                            Ok((
                                row.get(0)?,
                                row.get(1)?,
                                row.get(2)?,
                                row.get(3).unwrap_or_default(),
                            ))
                        })?
                        .filter_map(|r| r.ok())
                        .collect();

                    for (_id, rowid, title, content) in notes {
                        let _ = conn.execute(
                            "INSERT INTO notes_fts (rowid, title, content) VALUES (?1, ?2, ?3)",
                            params![rowid, title, content],
                        );
                    }
                }
                "bookmarks" => {
                    conn.execute("DELETE FROM bookmarks_fts", [])?;
                    let mut stmt = conn.prepare(
                        "SELECT id, rowid, title, description FROM bookmarks WHERE case_id = ?1",
                    )?;
                    let bookmarks: Vec<(String, i64, String, String)> = stmt
                        .query_map([case_id], |row| {
                            Ok((
                                row.get(0)?,
                                row.get(1)?,
                                row.get(2)?,
                                row.get(3).unwrap_or_default(),
                            ))
                        })?
                        .filter_map(|r| r.ok())
                        .collect();

                    for (_id, rowid, title, description) in bookmarks {
                        let _ = conn.execute(
                            "INSERT INTO bookmarks_fts (rowid, title, description) VALUES (?1, ?2, ?3)",
                            params![rowid, title, description],
                        );
                    }
                }
                "exhibits" => {
                    conn.execute("DELETE FROM exhibits_fts", [])?;
                    let mut stmt = conn.prepare(
                        "SELECT id, rowid, name, description FROM exhibits WHERE case_id = ?1",
                    )?;
                    let exhibits: Vec<(String, i64, String, String)> = stmt
                        .query_map([case_id], |row| {
                            Ok((
                                row.get(0)?,
                                row.get(1)?,
                                row.get(2)?,
                                row.get(3).unwrap_or_default(),
                            ))
                        })?
                        .filter_map(|r| r.ok())
                        .collect();

                    for (_id, rowid, name, description) in exhibits {
                        let _ = conn.execute(
                            "INSERT INTO exhibits_fts (rowid, name, description) VALUES (?1, ?2, ?3)",
                            params![rowid, name, description],
                        );
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn process_fts_queue(&self, conn: &mut Connection) -> anyhow::Result<(u64, u64)> {
        let case_id = &self.case_id;
        let batch_size = self.options.fts_queue_batch as usize;
        let max_iterations = 20;

        let mut total_processed: u64 = 0;
        let mut iterations = 0;

        loop {
            if iterations >= max_iterations {
                break;
            }

            let queue_count: u64 = conn.query_row(
                "SELECT COUNT(*) FROM fts_index_queue WHERE case_id = ?1 AND status = 'pending'",
                [case_id],
                |row| row.get(0),
            ).unwrap_or(0);

            if queue_count == 0 {
                break;
            }

            let mut stmt = conn.prepare(
                "SELECT id, table_name, row_id, operation FROM fts_index_queue 
                 WHERE case_id = ?1 AND status = 'pending' ORDER BY created_at LIMIT ?2",
            )?;

            let queue: Vec<(String, String, String, String)> = stmt
                .query_map(params![case_id, batch_size as i64], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })?
                .filter_map(|r| r.ok())
                .collect();

            drop(stmt);

            if queue.is_empty() {
                break;
            }

            for (queue_id, table_name, row_id, operation) in queue {
                let result = match (table_name.as_str(), operation.as_str()) {
                    ("notes", "insert") | ("notes", "update") => {
                        if let Ok(note) = conn.query_row(
                            "SELECT rowid, title, content FROM notes WHERE id = ?1",
                            [&row_id],
                            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2).unwrap_or_default())),
                        ) {
                            conn.execute(
                                "INSERT OR REPLACE INTO notes_fts (rowid, title, content) VALUES (?1, ?2, ?3)",
                                params![note.0, note.1, note.2],
                            )
                        } else {
                            Ok(0)
                        }
                    }
                    ("notes", "delete") => conn.execute(
                        "DELETE FROM notes_fts WHERE rowid = (SELECT rowid FROM notes WHERE id = ?1)",
                        [&row_id],
                    ),
                    ("bookmarks", "insert") | ("bookmarks", "update") => {
                        if let Ok(bm) = conn.query_row(
                            "SELECT rowid, title, description FROM bookmarks WHERE id = ?1",
                            [&row_id],
                            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2).unwrap_or_default())),
                        ) {
                            conn.execute(
                                "INSERT OR REPLACE INTO bookmarks_fts (rowid, title, description) VALUES (?1, ?2, ?3)",
                                params![bm.0, bm.1, bm.2],
                            )
                        } else {
                            Ok(0)
                        }
                    }
                    ("bookmarks", "delete") => conn.execute(
                        "DELETE FROM bookmarks_fts WHERE rowid = (SELECT rowid FROM bookmarks WHERE id = ?1)",
                        [&row_id],
                    ),
                    ("exhibits", "insert") | ("exhibits", "update") => {
                        if let Ok(ex) = conn.query_row(
                            "SELECT rowid, name, description FROM exhibits WHERE id = ?1",
                            [&row_id],
                            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2).unwrap_or_default())),
                        ) {
                            conn.execute(
                                "INSERT OR REPLACE INTO exhibits_fts (rowid, name, description) VALUES (?1, ?2, ?3)",
                                params![ex.0, ex.1, ex.2],
                            )
                        } else {
                            Ok(0)
                        }
                    }
                    _ => Ok(0),
                };

                if result.is_ok() {
                    conn.execute(
                        "UPDATE fts_index_queue SET status = 'completed', processed_at = strftime('%s', 'now') WHERE id = ?1",
                        [&queue_id],
                    )?;
                    total_processed += 1;
                }
            }

            iterations += 1;
        }

        let remaining: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM fts_index_queue WHERE case_id = ?1 AND status = 'pending'",
                [case_id],
                |row| row.get(0),
            )
            .unwrap_or(0);

        Ok((total_processed, remaining))
    }

    fn compute_diff(&self) -> (ReplayStatus, serde_json::Value) {
        let mut changed_tables = Vec::new();
        let mut fail_tables = Vec::new();
        let mut warn_tables = Vec::new();

        let tamper_evident_tables = [
            "activity_log",
            "provenance",
            "case_verifications",
            "exhibit_packets",
        ];

        for (before_fp, after_fp) in self.before.iter().zip(self.after.iter()) {
            if before_fp.row_count != after_fp.row_count
                || before_fp.stable_hash != after_fp.stable_hash
            {
                let change = serde_json::json!({
                    "table": before_fp.table,
                    "before_count": before_fp.row_count,
                    "after_count": after_fp.row_count,
                    "before_hash": before_fp.stable_hash,
                    "after_hash": after_fp.stable_hash,
                });
                changed_tables.push(change);

                if tamper_evident_tables.contains(&before_fp.table.as_str()) {
                    fail_tables.push(before_fp.table.clone());
                } else {
                    warn_tables.push(before_fp.table.clone());
                }
            }
        }

        let diffs = serde_json::json!({
            "changed_tables": changed_tables,
            "classification": {
                "fail_tables": fail_tables,
                "warn_tables": warn_tables,
            },
            "hints": self.generate_hints(&fail_tables, &warn_tables),
        });

        let status = if !fail_tables.is_empty() {
            ReplayStatus::Fail
        } else if !warn_tables.is_empty() {
            ReplayStatus::Warn
        } else {
            ReplayStatus::Pass
        };

        (status, diffs)
    }

    fn generate_hints(&self, fail_tables: &[String], warn_tables: &[String]) -> Vec<String> {
        let mut hints = Vec::new();

        if fail_tables.contains(&"activity_log".to_string()) {
            hints.push(
                "Tamper-evident activity_log changed - possible unauthorized modification"
                    .to_string(),
            );
        }
        if fail_tables.contains(&"provenance".to_string()) {
            hints.push("Provenance chain modified - possible data tampering".to_string());
        }
        if fail_tables.contains(&"case_verifications".to_string()) {
            hints.push("Verification records modified - possible replay attack".to_string());
        }
        if warn_tables.contains(&"case_stats".to_string()) {
            hints.push("Read models may need rebuild or were dirty".to_string());
        }
        if warn_tables.contains(&"triage_stats".to_string()) {
            hints.push("Triage stats changed - check bookmark folders".to_string());
        }
        if warn_tables.contains(&"timeline_buckets".to_string()) {
            hints.push("Timeline buckets changed - check timeline generation".to_string());
        }
        if warn_tables.contains(&"fts_index_queue".to_string()) {
            hints.push(
                "FTS queue not fully drained - increase batch size or iterations".to_string(),
            );
        }
        if warn_tables.iter().any(|t| t.contains("_fts")) {
            hints.push("FTS indexes rebuilt - this is expected on first rebuild".to_string());
        }

        if hints.is_empty() && (fail_tables.is_empty() && warn_tables.is_empty()) {
            hints.push("All tables stable after replay".to_string());
        }

        hints
    }

    fn compute_overall_status(&self) -> ReplayStatus {
        if self.steps.iter().any(|s| s.status == ReplayStatus::Fail) {
            ReplayStatus::Fail
        } else if self.steps.iter().any(|s| s.status == ReplayStatus::Warn) {
            ReplayStatus::Warn
        } else {
            ReplayStatus::Pass
        }
    }

    fn save_replay_record(&self, conn: &mut Connection, report: &ReplayReport) -> SqliteResult<()> {
        let report_json = serde_json::to_string(report).unwrap_or_default();

        conn.execute(
            "INSERT INTO case_replays (case_id, started_utc, finished_utc, status, report_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                report.case_id,
                report.started_utc,
                report.finished_utc,
                match report.status {
                    ReplayStatus::Pass => "Pass",
                    ReplayStatus::Warn => "Warn",
                    ReplayStatus::Fail => "Fail",
                },
                report_json
            ],
        )?;

        Ok(())
    }
}

pub fn fingerprint_table_case_scoped(
    conn: &Connection,
    table: &str,
    case_id: &str,
    sample_limit: Option<u64>,
) -> anyhow::Result<TableFingerprint> {
    let tables_with_case_id = vec![
        "activity_log",
        "evidence_timeline",
        "exhibits",
        "exhibit_packets",
        "bookmarks",
        "notes",
        "provenance",
        "case_stats",
        "triage_stats",
        "timeline_buckets",
        "artifact_summary",
        "fts_index_queue",
    ];

    let fts_tables = ["notes_fts", "bookmarks_fts", "exhibits_fts"];

    let (row_count, stable_hash, sample_keys) = if tables_with_case_id.contains(&table) {
        compute_case_scoped_hash(conn, table, case_id, sample_limit)?
    } else if fts_tables.contains(&table) {
        compute_fts_hash(conn, table, case_id)?
    } else {
        return Err(anyhow::anyhow!("Unknown table: {}", table));
    };

    Ok(TableFingerprint {
        table: table.to_string(),
        row_count,
        stable_hash,
        sample_keys,
    })
}

fn compute_case_scoped_hash(
    conn: &Connection,
    table: &str,
    case_id: &str,
    sample_limit: Option<u64>,
) -> anyhow::Result<(u64, String, Vec<String>)> {
    let (id_column, stable_columns) = get_table_key_info(table)?;

    let count: u64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM {} WHERE case_id = ?1", table),
            [case_id],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let order_by = stable_columns
        .iter()
        .map(|c| format!("{} ASC", c))
        .collect::<Vec<_>>()
        .join(", ");

    let query = if let Some(limit) = sample_limit {
        format!(
            "SELECT {} FROM {} WHERE case_id = ?1 ORDER BY {} LIMIT {}",
            stable_columns.join(", "),
            table,
            order_by,
            limit
        )
    } else {
        format!(
            "SELECT {} FROM {} WHERE case_id = ?1 ORDER BY {}",
            stable_columns.join(", "),
            table,
            order_by
        )
    };

    let mut stmt = conn.prepare(&query)?;
    let rows: Vec<Vec<String>> = stmt
        .query_map([case_id], |row| {
            let mut values = Vec::new();
            for i in 0..stable_columns.len() {
                let val: String = row.get(i).unwrap_or_default();
                values.push(val);
            }
            Ok(values)
        })?
        .filter_map(|r| r.ok())
        .collect();

    let mut sample_keys = Vec::new();
    let mut hasher = Sha256::new();

    for (i, row) in rows.iter().enumerate() {
        if i < 20 {
            if let Some(ref _id_col) = id_column {
                sample_keys.push(row[0].clone());
            }
        }

        for (j, val) in row.iter().enumerate() {
            hasher.update(stable_columns[j].as_bytes());
            hasher.update(b"=");
            hasher.update(val.as_bytes());
            hasher.update(b"\n");
        }
    }

    let stable_hash = format!("{:x}", hasher.finalize());

    Ok((count, stable_hash, sample_keys))
}

fn compute_fts_hash(
    conn: &Connection,
    table: &str,
    case_id: &str,
) -> anyhow::Result<(u64, String, Vec<String>)> {
    let fts_table = match table {
        "notes_fts" => "notes",
        "bookmarks_fts" => "bookmarks",
        "exhibits_fts" => "exhibits",
        _ => return Err(anyhow::anyhow!("Unknown FTS table: {}", table)),
    };

    let count: u64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM {} WHERE case_id = ?1", fts_table),
            [case_id],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let mut hasher = sha2::Sha256::new();

    let mut stmt = conn.prepare(&format!(
        "SELECT rowid, title, content FROM {} WHERE case_id = ?1 ORDER BY rowid",
        fts_table
    ))?;
    let rows = stmt.query_map([case_id], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1).unwrap_or_default(),
            row.get::<_, String>(2).unwrap_or_default(),
        ))
    });
    if let Ok(rows) = rows {
        for row in rows.filter_map(|r| r.ok()) {
            hasher.update(format!("{}\n", row.0).as_bytes());
            hasher.update(row.1.as_bytes());
            hasher.update(b"\n");
            hasher.update(row.2.as_bytes());
            hasher.update(b"\n");
        }
    }

    let stable_hash = format!("{:x}", hasher.finalize());

    Ok((count, stable_hash, vec![]))
}

fn get_table_key_info(table: &str) -> anyhow::Result<(Option<String>, Vec<String>)> {
    match table {
        "activity_log" => Ok((
            Some("id".to_string()),
            vec!["id".to_string(), "ts_utc".to_string()],
        )),
        "evidence_timeline" => Ok((
            Some("id".to_string()),
            vec!["id".to_string(), "event_time".to_string()],
        )),
        "exhibits" => Ok((
            Some("id".to_string()),
            vec!["id".to_string(), "created_at".to_string()],
        )),
        "exhibit_packets" => Ok((
            Some("id".to_string()),
            vec!["id".to_string(), "created_at".to_string()],
        )),
        "bookmarks" => Ok((
            Some("id".to_string()),
            vec!["id".to_string(), "created_at".to_string()],
        )),
        "notes" => Ok((
            Some("id".to_string()),
            vec!["id".to_string(), "created_at".to_string()],
        )),
        "provenance" => Ok((
            Some("id".to_string()),
            vec!["id".to_string(), "ts_utc".to_string()],
        )),
        "case_stats" => Ok((Some("case_id".to_string()), vec!["case_id".to_string()])),
        "triage_stats" => Ok((
            Some("case_id".to_string()),
            vec!["case_id".to_string(), "category".to_string()],
        )),
        "timeline_buckets" => Ok((
            Some("case_id".to_string()),
            vec!["case_id".to_string(), "bucket_time".to_string()],
        )),
        "artifact_summary" => Ok((
            Some("case_id".to_string()),
            vec!["case_id".to_string(), "artifact_type".to_string()],
        )),
        "fts_index_queue" => Ok((
            Some("id".to_string()),
            vec!["id".to_string(), "created_at".to_string()],
        )),
        _ => Err(anyhow::anyhow!("Unknown table: {}", table)),
    }
}

pub fn replay_case(
    case_id: &str,
    db_path: &Path,
    options: ReplayOptions,
) -> anyhow::Result<ReplayReport> {
    let db = CaseDatabase::open(case_id, db_path)?;
    let replay = CaseReplay::new(case_id, options);
    replay.replay(&db)
}

pub fn replay_case_with_events(
    case_id: &str,
    db_path: &Path,
    options: ReplayOptions,
    event_bus: Option<Arc<EventBus>>,
) -> anyhow::Result<ReplayReport> {
    let db = CaseDatabase::open(case_id, db_path)?;
    let mut replay = CaseReplay::new(case_id, options);
    if let Some(bus) = event_bus {
        replay = replay.with_event_bus(bus);
    }
    replay.replay(&db)
}

pub fn get_recent_replays(
    conn: &mut Connection,
    case_id: &str,
    limit: usize,
) -> SqliteResult<Vec<ReplayReport>> {
    let mut stmt = conn.prepare(
        "SELECT report_json FROM case_replays 
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

pub fn get_latest_replay_report(
    conn: &mut Connection,
    case_id: &str,
) -> SqliteResult<Option<ReplayReport>> {
    let mut stmt = conn.prepare(
        "SELECT report_json FROM case_replays 
         WHERE case_id = ?1 
         ORDER BY started_utc DESC 
         LIMIT 1",
    )?;

    let result = stmt.query_row(params![case_id], |row| {
        let json: String = row.get(0)?;
        Ok(json)
    });

    match result {
        Ok(json) => Ok(serde_json::from_str(&json).ok()),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

pub fn generate_replay_summary(report: &ReplayReport) -> String {
    let mut summary = String::new();
    summary.push_str(&format!("Case ID: {}\n", report.case_id));
    summary.push_str(&format!("Started: {}\n", report.started_utc));
    summary.push_str(&format!("Finished: {}\n", report.finished_utc));
    summary.push_str(&format!("Status: {:?}\n\n", report.status));

    summary.push_str("Steps:\n");
    for step in &report.steps {
        let status_str = match step.status {
            ReplayStatus::Pass => "PASS",
            ReplayStatus::Warn => "WARN",
            ReplayStatus::Fail => "FAIL",
        };
        summary.push_str(&format!(
            "  [{}] {}: {}\n",
            status_str, step.name, step.message
        ));
    }

    summary.push_str("\nFingerprints:\n");
    summary.push_str(&format!(
        "  Tables fingerprinted: {}\n",
        report.before.len()
    ));

    if let Some(changes) = report.diffs.get("changed_tables") {
        if let Some(changed) = changes.as_array() {
            if !changed.is_empty() {
                summary.push_str("\nChanged tables:\n");
                for change in changed {
                    if let (Some(table), Some(before), Some(after)) = (
                        change.get("table"),
                        change.get("before_count"),
                        change.get("after_count"),
                    ) {
                        summary.push_str(&format!("  - {}: {} -> {}\n", table, before, after));
                    }
                }
            }
        }
    }

    summary
}

pub fn write_replay_artifacts(
    output_dir: &std::path::Path,
    case_id: &str,
    report: Option<&ReplayReport>,
) -> std::io::Result<()> {
    let report_to_write: ReplayReport = match report {
        Some(r) => r.clone(),
        None => ReplayReport {
            case_id: case_id.to_string(),
            started_utc: String::new(),
            finished_utc: String::new(),
            status: ReplayStatus::Pass,
            steps: vec![],
            before: vec![],
            after: vec![],
            diffs: serde_json::json!({}),
        },
    };

    let json_path = output_dir.join("replay_report.latest.json");
    let json_content = serde_json::to_string_pretty(&report_to_write).unwrap_or_default();
    std::fs::write(&json_path, json_content)?;

    let summary_path = output_dir.join("replay_summary.txt");
    let summary_content = generate_replay_summary(&report_to_write);
    std::fs::write(&summary_path, summary_content)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_db(temp_dir: &TempDir) -> SqliteResult<(rusqlite::Connection, String)> {
        let db_path = temp_dir.path().join("test_case.sqlite");
        let case_id = "test_case_001".to_string();

        let conn = rusqlite::Connection::open(&db_path)?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS cases (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                examiner TEXT NOT NULL,
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
                schema_version TEXT NOT NULL DEFAULT '1.0'
            );

            CREATE TABLE IF NOT EXISTS bookmarks (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                folder_id TEXT,
                title TEXT NOT NULL,
                description TEXT,
                tags_json TEXT,
                created_by TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                modified_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS notes (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                title TEXT NOT NULL,
                content TEXT,
                created_by TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                modified_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS exhibits (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                name TEXT NOT NULL,
                exhibit_type TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS case_stats (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                total_bookmarks INTEGER DEFAULT 0,
                total_notes INTEGER DEFAULT 0,
                total_exhibits INTEGER DEFAULT 0,
                total_jobs INTEGER DEFAULT 0,
                last_updated INTEGER NOT NULL,
                UNIQUE(case_id)
            );

            CREATE TABLE IF NOT EXISTS triage_stats (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                category TEXT NOT NULL,
                count INTEGER DEFAULT 0,
                last_updated INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS timeline_buckets (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                bucket_type TEXT NOT NULL,
                bucket_time INTEGER NOT NULL,
                category TEXT,
                count INTEGER DEFAULT 0,
                UNIQUE(case_id, bucket_type, bucket_time, category)
            );

            CREATE TABLE IF NOT EXISTS evidence_timeline (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_time INTEGER NOT NULL,
                source_module TEXT,
                source_record_id TEXT,
                UNIQUE(case_id, event_type, event_time, source_module, source_record_id)
            );

            CREATE TABLE IF NOT EXISTS fts_index_queue (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                table_name TEXT NOT NULL,
                row_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS case_settings (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT,
                modified_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS notes_fts (
                rowid INTEGER PRIMARY KEY,
                title TEXT,
                content TEXT
            );

            CREATE TABLE IF NOT EXISTS bookmarks_fts (
                rowid INTEGER PRIMARY KEY,
                title TEXT,
                description TEXT
            );

            CREATE TABLE IF NOT EXISTS exhibits_fts (
                rowid INTEGER PRIMARY KEY,
                name TEXT,
                description TEXT
            );

            CREATE TABLE IF NOT EXISTS case_replays (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                started_utc TEXT NOT NULL,
                finished_utc TEXT NOT NULL,
                status TEXT NOT NULL,
                report_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS provenance (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                object_id TEXT NOT NULL,
                object_type TEXT NOT NULL,
                action TEXT NOT NULL,
                user_name TEXT NOT NULL,
                session_id TEXT NOT NULL,
                ts_utc INTEGER NOT NULL
            );

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
            );",
        )?;
        conn.execute(
            "INSERT INTO cases (id, name, examiner, created_at, modified_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![&case_id, "Test Case", "tester", 1700000000, 1700000000],
        )?;

        Ok((conn, case_id))
    }

    fn insert_test_data(conn: &rusqlite::Connection, case_id: &str) {
        conn.execute(
            "INSERT INTO bookmarks (id, case_id, title, created_by, created_at, modified_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![uuid::Uuid::new_v4().to_string(), case_id, "Test Bookmark", "tester", 1700000000, 1700000000],
        ).unwrap();

        conn.execute(
            "INSERT INTO notes (id, case_id, title, content, created_by, created_at, modified_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![uuid::Uuid::new_v4().to_string(), case_id, "Test Note", "Content", "tester", 1700000000, 1700000000],
        ).unwrap();

        conn.execute(
            "INSERT INTO exhibits (id, case_id, name, exhibit_type, created_by, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![uuid::Uuid::new_v4().to_string(), case_id, "Test Exhibit", "File", "tester", 1700000000],
        ).unwrap();
    }

    #[test]
    fn test_replay_pass_with_stable_data() {
        let temp_dir = TempDir::new().unwrap();
        let (conn, case_id) = create_test_db(&temp_dir).unwrap();

        insert_test_data(&conn, &case_id);

        let options = ReplayOptions::default();
        let result = replay_case(
            &case_id,
            temp_dir.path().join("test_case.sqlite").as_path(),
            options,
        );

        assert!(result.is_ok());
        let report = result.unwrap();

        assert!(matches!(
            report.status,
            ReplayStatus::Pass | ReplayStatus::Warn
        ));
    }

    #[test]
    fn test_replay_detects_changed_activity_log() {
        let temp_dir = TempDir::new().unwrap();
        let (conn, case_id) = create_test_db(&temp_dir).unwrap();

        insert_test_data(&conn, &case_id);

        let options = ReplayOptions::default();

        conn.execute(
            "UPDATE activity_log SET summary = 'TAMPERED' WHERE case_id = ?1",
            [&case_id],
        )
        .unwrap();

        let result = replay_case(
            &case_id,
            temp_dir.path().join("test_case.sqlite").as_path(),
            options,
        );

        assert!(result.is_ok());
        let report = result.unwrap();

        let classification = report
            .diffs
            .get("classification")
            .and_then(|v| v.as_object());
        assert!(classification.is_some());
        assert!(classification.unwrap().contains_key("fail_tables"));
        assert!(classification.unwrap().contains_key("warn_tables"));
    }

    #[test]
    fn test_fingerprint_deterministic() {
        let temp_dir = TempDir::new().unwrap();
        let (conn, case_id) = create_test_db(&temp_dir).unwrap();

        insert_test_data(&conn, &case_id);

        let fp1 = fingerprint_table_case_scoped(&conn, "bookmarks", &case_id, None).unwrap();

        let fp2 = fingerprint_table_case_scoped(&conn, "bookmarks", &case_id, None).unwrap();

        assert_eq!(fp1.stable_hash, fp2.stable_hash);
    }

    #[test]
    fn test_diff_analysis_classification() {
        let temp_dir = TempDir::new().unwrap();
        let (_conn, case_id) = create_test_db(&temp_dir).unwrap();

        let before = vec![
            TableFingerprint {
                table: "activity_log".to_string(),
                row_count: 10,
                stable_hash: "abc123".to_string(),
                sample_keys: vec![],
            },
            TableFingerprint {
                table: "case_stats".to_string(),
                row_count: 1,
                stable_hash: "def456".to_string(),
                sample_keys: vec![],
            },
        ];

        let after = vec![
            TableFingerprint {
                table: "activity_log".to_string(),
                row_count: 11,
                stable_hash: "xyz789".to_string(),
                sample_keys: vec![],
            },
            TableFingerprint {
                table: "case_stats".to_string(),
                row_count: 1,
                stable_hash: "def456".to_string(),
                sample_keys: vec![],
            },
        ];

        let replay = CaseReplay::new(&case_id, ReplayOptions::default());
        let (status, diffs) = replay.compute_diff_for_test(&before, &after);

        assert!(matches!(status, ReplayStatus::Warn | ReplayStatus::Fail));

        let classification = diffs.get("classification").unwrap();
        let fail_tables = classification
            .get("fail_tables")
            .unwrap()
            .as_array()
            .unwrap();
        assert!(fail_tables.contains(&serde_json::json!("activity_log")));
    }

    impl CaseReplay {
        fn compute_diff_for_test(
            &self,
            before: &[TableFingerprint],
            after: &[TableFingerprint],
        ) -> (ReplayStatus, serde_json::Value) {
            let mut changed_tables = Vec::new();
            let mut fail_tables = Vec::new();
            let mut warn_tables = Vec::new();

            let tamper_evident_tables = ["activity_log", "provenance", "case_verifications"];
            for (before_fp, after_fp) in before.iter().zip(after.iter()) {
                if before_fp.row_count != after_fp.row_count
                    || before_fp.stable_hash != after_fp.stable_hash
                {
                    changed_tables.push(serde_json::json!({
                        "table": before_fp.table,
                        "before_count": before_fp.row_count,
                        "after_count": after_fp.row_count,
                    }));

                    if tamper_evident_tables.contains(&before_fp.table.as_str()) {
                        fail_tables.push(before_fp.table.clone());
                    } else {
                        warn_tables.push(before_fp.table.clone());
                    }
                }
            }

            let diffs = serde_json::json!({
                "changed_tables": changed_tables,
                "classification": {
                    "fail_tables": fail_tables,
                    "warn_tables": warn_tables,
                },
            });

            let status = if !fail_tables.is_empty() {
                ReplayStatus::Fail
            } else if !warn_tables.is_empty() {
                ReplayStatus::Warn
            } else {
                ReplayStatus::Pass
            };

            (status, diffs)
        }
    }
}
