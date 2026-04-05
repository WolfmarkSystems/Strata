use rusqlite::{params, Connection, Result as SqliteResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::case::replay::{replay_case, write_replay_artifacts, ReplayOptions};
use crate::case::verify::{verify_case, write_verification_artifacts, VerifyOptions};
use crate::case::watchpoints::{
    clear_integrity_violations, enable_integrity_watchpoints, get_integrity_violations_count,
    list_integrity_violations, set_current_actor, IntegrityViolation,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum TriageSessionStatus {
    #[default]
    Running,
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageSessionOptions {
    pub enable_watchpoints: bool,
    pub run_replay: bool,
    pub run_verify: bool,
    pub verify_options: VerifyOptions,
    pub replay_options: ReplayOptions,
    pub fail_on_violations: bool,
    pub allow_verify_warn: bool,
    pub allow_replay_warn: bool,
    pub export_bundle: bool,
    pub bundle_dir: String,
}

impl Default for TriageSessionOptions {
    fn default() -> Self {
        Self {
            enable_watchpoints: true,
            run_replay: true,
            run_verify: true,
            verify_options: VerifyOptions::default(),
            replay_options: ReplayOptions::default(),
            fail_on_violations: true,
            allow_verify_warn: true,
            allow_replay_warn: true,
            export_bundle: true,
            bundle_dir: "exports/defensibility".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageSessionResult {
    pub session_id: i64,
    pub status: TriageSessionStatus,
    pub replay_id: Option<i64>,
    pub verification_id: Option<i64>,
    pub violations_count: u64,
    pub bundle_path: Option<String>,
    pub bundle_hash_sha256: Option<String>,
}

pub struct TriageSessionManager {
    conn: Arc<Mutex<Connection>>,
    case_id: String,
}

impl TriageSessionManager {
    pub fn new(conn: Arc<Mutex<Connection>>, case_id: String) -> Self {
        Self { conn, case_id }
    }

    pub fn start_session(
        &self,
        session_name: Option<&str>,
        opts: TriageSessionOptions,
    ) -> SqliteResult<TriageSessionResult> {
        let conn = self.conn.lock().unwrap();
        let started_utc = chrono::Utc::now().to_rfc3339();
        let options_json = serde_json::to_string(&opts).unwrap_or_default();

        conn.execute(
            "INSERT INTO triage_sessions (case_id, session_name, started_utc, status, options_json, violations_count)
             VALUES (?1, ?2, ?3, 'RUNNING', ?4, 0)",
            params![&self.case_id, session_name, &started_utc, &options_json],
        )?;

        let session_id = conn.last_insert_rowid();
        drop(conn);

        let mut result = TriageSessionResult {
            session_id,
            status: TriageSessionStatus::Running,
            replay_id: None,
            verification_id: None,
            violations_count: 0,
            bundle_path: None,
            bundle_hash_sha256: None,
        };

        if opts.enable_watchpoints {
            let conn = self.conn.lock().unwrap();
            if let Err(e) = enable_integrity_watchpoints(&conn, &self.case_id, true) {
                eprintln!("Warning: Failed to enable watchpoints: {}", e);
            }
            if let Err(e) = clear_integrity_violations(&conn, &self.case_id) {
                eprintln!("Warning: Failed to clear violations: {}", e);
            }
            drop(conn);
        }

        let db_path = PathBuf::new();

        if opts.run_replay {
            let conn = self.conn.lock().unwrap();
            if let Err(e) =
                set_current_actor(&conn, &self.case_id, &format!("triage:{}", session_id))
            {
                eprintln!("Warning: Failed to set actor: {}", e);
            }
            drop(conn);

            let replay_result = replay_case(&self.case_id, &db_path, opts.replay_options.clone());

            let conn = self.conn.lock().unwrap();
            if let Err(e) = clear_current_actor(&conn, &self.case_id) {
                eprintln!("Warning: Failed to clear actor: {}", e);
            }
            drop(conn);

            match replay_result {
                Ok(report) => {
                    let conn = self.conn.lock().unwrap();
                    let report_json = serde_json::to_string(&report).unwrap_or_default();
                    conn.execute(
                        "INSERT INTO case_replays (case_id, started_utc, finished_utc, status, report_json)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![
                            &self.case_id,
                            &report.started_utc,
                            &report.finished_utc,
                            format!("{:?}", report.status),
                            &report_json
                        ],
                    )?;
                    result.replay_id = Some(conn.last_insert_rowid());
                    drop(conn);

                    let status_str = format!("{:?}", report.status);
                    if status_str == "Fail" || (status_str == "Warn" && !opts.allow_replay_warn) {
                        result.status = TriageSessionStatus::Fail;
                    } else if result.status == TriageSessionStatus::Running && status_str == "Warn"
                    {
                        result.status = TriageSessionStatus::Warn;
                    }
                }
                Err(e) => {
                    result.status = TriageSessionStatus::Fail;
                    if should_log_triage_substep_error(&e.to_string()) {
                        eprintln!("Replay failed: {}", e);
                    }
                }
            }
        }

        if opts.run_verify {
            let verify_result = verify_case(&self.case_id, &db_path, opts.verify_options.clone());

            match verify_result {
                Ok(report) => {
                    let conn = self.conn.lock().unwrap();
                    let report_json = serde_json::to_string(&report).unwrap_or_default();
                    conn.execute(
                        "INSERT INTO case_verifications (case_id, started_utc, finished_utc, status, report_json)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![
                            &self.case_id,
                            &report.started_utc,
                            &report.finished_utc,
                            format!("{:?}", report.status),
                            &report_json
                        ],
                    )?;
                    result.verification_id = Some(conn.last_insert_rowid());
                    drop(conn);

                    let status_str = format!("{:?}", report.status);
                    if status_str == "Fail" || (status_str == "Warn" && !opts.allow_verify_warn) {
                        result.status = TriageSessionStatus::Fail;
                    } else if result.status == TriageSessionStatus::Running && status_str == "Warn"
                    {
                        result.status = TriageSessionStatus::Warn;
                    }
                }
                Err(e) => {
                    result.status = TriageSessionStatus::Fail;
                    if should_log_triage_substep_error(&e.to_string()) {
                        eprintln!("Verify failed: {}", e);
                    }
                }
            }
        }

        let conn = self.conn.lock().unwrap();
        result.violations_count = get_integrity_violations_count(&conn, &self.case_id).unwrap_or(0);

        if opts.fail_on_violations && result.violations_count > 0 {
            result.status = TriageSessionStatus::Fail;
        }
        drop(conn);

        if opts.export_bundle {
            match self.create_bundle(&started_utc, &opts, &result) {
                Ok((bundle_path, bundle_hash)) => {
                    result.bundle_path = Some(bundle_path);
                    result.bundle_hash_sha256 = Some(bundle_hash);
                }
                Err(e) => {
                    eprintln!("Warning: Failed to create bundle: {}", e);
                }
            }
        }

        if opts.enable_watchpoints {
            let conn = self.conn.lock().unwrap();
            if let Err(e) = enable_integrity_watchpoints(&conn, &self.case_id, false) {
                eprintln!("Warning: Failed to disable watchpoints: {}", e);
            }
            drop(conn);
        }

        if result.status == TriageSessionStatus::Running {
            result.status = TriageSessionStatus::Pass;
        }

        let conn = self.conn.lock().unwrap();
        let finished_utc = chrono::Utc::now().to_rfc3339();
        let status_str = match result.status {
            TriageSessionStatus::Running => "RUNNING",
            TriageSessionStatus::Pass => "PASS",
            TriageSessionStatus::Warn => "WARN",
            TriageSessionStatus::Fail => "FAIL",
        };

        conn.execute(
            "UPDATE triage_sessions SET finished_utc = ?1, status = ?2, replay_id = ?3, verification_id = ?4, violations_count = ?5, bundle_path = ?6, bundle_hash_sha256 = ?7 WHERE id = ?8",
            params![
                &finished_utc,
                status_str,
                result.replay_id,
                result.verification_id,
                result.violations_count,
                &result.bundle_path,
                &result.bundle_hash_sha256,
                session_id
            ],
        )?;
        drop(conn);

        Ok(result)
    }

    fn create_bundle(
        &self,
        started_utc: &str,
        opts: &TriageSessionOptions,
        result: &TriageSessionResult,
    ) -> anyhow::Result<(String, String)> {
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let bundle_dir = PathBuf::from(&opts.bundle_dir)
            .join(&self.case_id)
            .join(&timestamp);

        std::fs::create_dir_all(&bundle_dir)?;

        let conn = self.conn.lock().unwrap();

        if let Some(verify_id) = result.verification_id {
            let mut stmt =
                conn.prepare("SELECT report_json FROM case_verifications WHERE id = ?1")?;
            let report_json: Option<String> = stmt.query_row([verify_id], |row| row.get(0)).ok();
            drop(stmt);

            if let Some(json) = report_json {
                if let Ok(report) =
                    serde_json::from_str::<crate::case::verify::VerificationReport>(&json)
                {
                    let _ = write_verification_artifacts(&bundle_dir, &self.case_id, Some(&report));
                }
            }
        } else {
            let _ = write_verification_artifacts(&bundle_dir, &self.case_id, None);
        }

        if let Some(replay_id) = result.replay_id {
            let mut stmt = conn.prepare("SELECT report_json FROM case_replays WHERE id = ?1")?;
            let report_json: Option<String> = stmt.query_row([replay_id], |row| row.get(0)).ok();
            drop(stmt);

            if let Some(json) = report_json {
                if let Ok(report) = serde_json::from_str::<crate::case::replay::ReplayReport>(&json)
                {
                    let _ = write_replay_artifacts(&bundle_dir, &self.case_id, Some(&report));
                }
            }
        } else {
            let _ = write_replay_artifacts(&bundle_dir, &self.case_id, None);
        }

        let violations =
            list_integrity_violations(&conn, &self.case_id, Some(started_utc.to_string()), 10000)?;
        drop(conn);

        let violations_path = bundle_dir.join("integrity_violations.json");
        let violations_json = serde_json::to_string_pretty(&violations).unwrap_or_default();
        std::fs::write(&violations_path, &violations_json)?;

        let violations_summary_path = bundle_dir.join("integrity_violations_summary.txt");
        let mut violations_summary = String::new();
        violations_summary.push_str(&format!("Case ID: {}\n", self.case_id));
        violations_summary.push_str(&format!("Session started: {}\n", started_utc));
        violations_summary.push_str(&format!("Total violations: {}\n\n", violations.len()));

        let mut by_table: std::collections::HashMap<String, Vec<&IntegrityViolation>> =
            std::collections::HashMap::new();
        for v in &violations {
            by_table.entry(v.table_name.clone()).or_default().push(v);
        }

        let mut tables: Vec<_> = by_table.keys().collect();
        tables.sort();

        for table in tables {
            let table_violations = &by_table[table];
            violations_summary.push_str(&format!(
                "{}: {} violation(s)\n",
                table,
                table_violations.len()
            ));

            let mut ops: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
            for v in table_violations {
                *ops.entry(v.operation.clone()).or_insert(0) += 1;
            }
            for (op, count) in ops.iter() {
                violations_summary.push_str(&format!("  - {}: {}\n", op, count));
            }
        }

        std::fs::write(&violations_summary_path, &violations_summary)?;

        let conn = self.conn.lock().unwrap();

        let mut case_versions = std::collections::HashMap::new();
        let mut stmt =
            conn.prepare("SELECT key, value FROM case_settings WHERE case_id = 'system'")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows.flatten() {
            case_versions.insert(row.0, row.1);
        }
        drop(stmt);

        let case_versions_path = bundle_dir.join("case_versions.json");
        let case_versions_json = serde_json::to_string_pretty(&case_versions).unwrap_or_default();
        std::fs::write(&case_versions_path, &case_versions_json)?;

        let mut case_settings = std::collections::HashMap::new();
        let mut stmt = conn.prepare("SELECT key, value FROM case_settings WHERE case_id = ?1")?;
        let rows = stmt.query_map([&self.case_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
        })?;
        for row in rows.flatten() {
            case_settings.insert(row.0, row.1.unwrap_or_default());
        }
        drop(stmt);

        let case_settings_path = bundle_dir.join("case_settings.json");
        let case_settings_json = serde_json::to_string_pretty(&case_settings).unwrap_or_default();
        std::fs::write(&case_settings_path, &case_settings_json)?;

        drop(conn);

        let mut manifest: Vec<serde_json::Value> = vec![];

        let files = vec![
            "verification_report.latest.json",
            "verification_summary.txt",
            "replay_report.latest.json",
            "replay_summary.txt",
            "integrity_violations.json",
            "integrity_violations_summary.txt",
            "case_versions.json",
            "case_settings.json",
        ];

        for filename in files {
            let file_path = bundle_dir.join(filename);
            if file_path.exists() {
                let hash = compute_sha256_file(&file_path)?;
                manifest.push(serde_json::json!({
                    "filename": filename,
                    "sha256": hash,
                }));
            }
        }

        let manifest_json = serde_json::to_string_pretty(&manifest).unwrap_or_default();
        let manifest_path = bundle_dir.join("bundle_manifest.json");
        std::fs::write(&manifest_path, &manifest_json)?;

        let manifest_hash = compute_sha256_file(&manifest_path)?;

        let bundle_path_str = bundle_dir.to_string_lossy().to_string();
        Ok((bundle_path_str, manifest_hash))
    }

    pub fn get_session(&self, session_id: i64) -> SqliteResult<Option<TriageSessionResult>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, case_id, session_name, started_utc, finished_utc, status, options_json, 
                    replay_id, verification_id, violations_count, bundle_path, bundle_hash_sha256
             FROM triage_sessions WHERE id = ?1",
        )?;

        let result = stmt.query_row([session_id], |row| {
            let status_str: String = row.get(5)?;
            let status = match status_str.as_str() {
                "PASS" => TriageSessionStatus::Pass,
                "WARN" => TriageSessionStatus::Warn,
                "FAIL" => TriageSessionStatus::Fail,
                _ => TriageSessionStatus::Running,
            };

            Ok(TriageSessionResult {
                session_id: row.get(0)?,
                status,
                replay_id: row.get(7)?,
                verification_id: row.get(8)?,
                violations_count: row.get::<_, i64>(9)? as u64,
                bundle_path: row.get(10)?,
                bundle_hash_sha256: row.get(11)?,
            })
        });

        match result {
            Ok(r) => Ok(Some(r)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn list_sessions(&self, limit: usize) -> SqliteResult<Vec<TriageSessionResult>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, case_id, session_name, started_utc, finished_utc, status, options_json, 
                    replay_id, verification_id, violations_count, bundle_path, bundle_hash_sha256
             FROM triage_sessions WHERE case_id = ?1 ORDER BY started_utc DESC LIMIT ?2",
        )?;

        let sessions = stmt.query_map(params![&self.case_id, limit as i64], |row| {
            let status_str: String = row.get(5)?;
            let status = match status_str.as_str() {
                "PASS" => TriageSessionStatus::Pass,
                "WARN" => TriageSessionStatus::Warn,
                "FAIL" => TriageSessionStatus::Fail,
                _ => TriageSessionStatus::Running,
            };

            Ok(TriageSessionResult {
                session_id: row.get(0)?,
                status,
                replay_id: row.get(7)?,
                verification_id: row.get(8)?,
                violations_count: row.get::<_, i64>(9)? as u64,
                bundle_path: row.get(10)?,
                bundle_hash_sha256: row.get(11)?,
            })
        })?;

        sessions.collect()
    }
}

fn should_log_triage_substep_error(error_text: &str) -> bool {
    let e = error_text.to_ascii_lowercase();
    !e.contains("no such table: case_replays") && !e.contains("no such table: case_verifications")
}

fn compute_sha256_file(path: &std::path::Path) -> SqliteResult<String> {
    let mut file =
        File::open(path).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];

    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn clear_current_actor(conn: &Connection, case_id: &str) -> SqliteResult<()> {
    conn.execute(
        "DELETE FROM case_settings WHERE case_id = ?1 AND key = 'current_actor'",
        [case_id],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_db(
        temp_dir: &TempDir,
    ) -> SqliteResult<(Arc<Mutex<rusqlite::Connection>>, String)> {
        let db_path = temp_dir.path().join("test_case.sqlite");
        let case_id = "test_case_001".to_string();

        let conn = rusqlite::Connection::open(&db_path)?;

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
                schema_version TEXT NOT NULL DEFAULT '1.0'
            );

            CREATE TABLE IF NOT EXISTS case_verifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                started_utc TEXT NOT NULL,
                finished_utc TEXT NOT NULL,
                status TEXT NOT NULL,
                report_json TEXT
            );

            CREATE TABLE IF NOT EXISTS case_replays (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                started_utc TEXT NOT NULL,
                finished_utc TEXT NOT NULL,
                status TEXT NOT NULL,
                report_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS case_settings (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT,
                modified_at INTEGER NOT NULL,
                UNIQUE(case_id, key)
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
            );

            CREATE TABLE IF NOT EXISTS evidence_timeline (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_time INTEGER NOT NULL,
                artifact_id TEXT,
                source_module TEXT,
                source_record_id TEXT,
                UNIQUE(case_id, event_type, event_time, source_module, source_record_id)
            );

            CREATE TABLE IF NOT EXISTS triage_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                session_name TEXT,
                preset_name TEXT,
                started_utc TEXT NOT NULL,
                finished_utc TEXT,
                status TEXT NOT NULL DEFAULT 'RUNNING',
                options_json TEXT NOT NULL,
                replay_id INTEGER,
                verification_id INTEGER,
                violations_count INTEGER NOT NULL DEFAULT 0,
                bundle_path TEXT,
                bundle_hash_sha256 TEXT
            );",
        )?;
        conn.execute(
            "INSERT INTO cases (id, name, examiner, created_at, modified_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![&case_id, "Test Case", "tester", 1700000000, 1700000000],
        )?;

        Ok((Arc::new(Mutex::new(conn)), case_id))
    }

    #[test]
    fn test_happy_path_triage_session() {
        let temp_dir = TempDir::new().unwrap();
        let (conn, case_id) = create_test_db(&temp_dir).unwrap();

        let options = TriageSessionOptions {
            enable_watchpoints: false,
            run_replay: false,
            run_verify: false,
            verify_options: VerifyOptions::default(),
            replay_options: ReplayOptions::default(),
            fail_on_violations: false,
            allow_verify_warn: true,
            allow_replay_warn: true,
            export_bundle: false,
            bundle_dir: "exports/test".to_string(),
        };

        let manager = TriageSessionManager::new(conn, case_id);
        let result = manager
            .start_session(Some("Test Session"), options)
            .unwrap();

        assert_eq!(result.status, TriageSessionStatus::Pass);
        assert_eq!(result.violations_count, 0);
    }

    #[test]
    fn test_triage_session_with_violations_fails() {
        let temp_dir = TempDir::new().unwrap();
        let (conn, case_id) = create_test_db(&temp_dir).unwrap();

        {
            let conn = conn.lock().unwrap();
            conn.execute(
                "INSERT INTO integrity_violations (case_id, occurred_utc, table_name, operation, row_key, reason, details_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![&case_id, "2024-01-01T00:00:00Z", "activity_log", "INSERT", "1", "WATCHPOINT_TRIGGER", "{}"],
            ).unwrap();
        }

        let options = TriageSessionOptions {
            enable_watchpoints: false,
            run_replay: false,
            run_verify: false,
            verify_options: VerifyOptions::default(),
            replay_options: ReplayOptions::default(),
            fail_on_violations: true,
            allow_verify_warn: true,
            allow_replay_warn: true,
            export_bundle: false,
            bundle_dir: "exports/test".to_string(),
        };

        let manager = TriageSessionManager::new(conn, case_id);
        let result = manager.start_session(None, options).unwrap();

        assert_eq!(result.status, TriageSessionStatus::Fail);
        assert_eq!(result.violations_count, 1);
    }

    #[test]
    fn test_triage_session_strict_mode() {
        let temp_dir = TempDir::new().unwrap();
        let (conn, case_id) = create_test_db(&temp_dir).unwrap();

        let options = TriageSessionOptions {
            enable_watchpoints: false,
            run_replay: false,
            run_verify: false,
            verify_options: VerifyOptions::default(),
            replay_options: ReplayOptions::default(),
            fail_on_violations: false,
            allow_verify_warn: false,
            allow_replay_warn: false,
            export_bundle: false,
            bundle_dir: "exports/test".to_string(),
        };

        let manager = TriageSessionManager::new(conn, case_id);
        let result = manager.start_session(None, options).unwrap();

        assert_eq!(result.status, TriageSessionStatus::Pass);
    }

    #[test]
    fn test_list_sessions() {
        let temp_dir = TempDir::new().unwrap();
        let (conn, case_id) = create_test_db(&temp_dir).unwrap();

        let options = TriageSessionOptions::default();

        let manager = TriageSessionManager::new(conn.clone(), case_id.clone());
        manager
            .start_session(Some("Session 1"), options.clone())
            .unwrap();
        manager.start_session(Some("Session 2"), options).unwrap();

        let manager = TriageSessionManager::new(conn, case_id);
        let sessions = manager.list_sessions(10).unwrap();

        assert_eq!(sessions.len(), 2);
    }

    #[test]
    fn test_should_log_triage_substep_error_filters_missing_optional_tables() {
        assert!(!should_log_triage_substep_error(
            "no such table: case_replays"
        ));
        assert!(!should_log_triage_substep_error(
            "no such table: case_verifications"
        ));
        assert!(should_log_triage_substep_error("database is locked"));
    }
}
