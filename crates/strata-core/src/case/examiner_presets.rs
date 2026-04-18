use rusqlite::{params, Connection, Result as SqliteResult};
use serde::{Deserialize, Serialize};

use crate::case::database::CaseDatabase;
use crate::case::replay::ReplayOptions;
use crate::case::triage_session::{
    TriageSessionManager, TriageSessionOptions, TriageSessionResult,
};
use crate::case::verify::VerifyOptions;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExaminerPreset {
    pub name: String,
    pub description: String,
    pub preset_json: serde_json::Value,
    pub locked_keys_json: Vec<String>,
    pub is_default: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresetInfo {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresetDetails {
    pub preset_json: serde_json::Value,
    pub locked_keys_json: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExaminationOptions {
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

impl Default for ExaminationOptions {
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

fn default_strict_preset() -> ExaminerPreset {
    ExaminerPreset {
        name: "Strict Examiner".to_string(),
        description:
            "Maximum rigor: no warnings allowed, all checks enabled, violations cause failure"
                .to_string(),
        preset_json: serde_json::json!({
            "enable_watchpoints": true,
            "run_replay": true,
            "run_verify": true,
            "verify_options": {
                "verify_activity_hash_chain": true,
                "verify_packet_manifests": true,
                "verify_db_integrity": true,
                "verify_read_models_rebuild": true,
                "verify_timeline_idempotency": true,
                "verify_fts_queue_empty": true,
                "sample_limit": null
            },
            "replay_options": {
                "run_read_model_rebuild": true,
                "run_fts_rebuild": true,
                "process_fts_queue": true,
                "run_db_optimize": false,
                "sample_limit": null
            },
            "fail_on_violations": true,
            "allow_verify_warn": false,
            "allow_replay_warn": false,
            "export_bundle": true,
            "bundle_dir": "exports/defensibility"
        }),
        locked_keys_json: vec![
            "fail_on_violations".to_string(),
            "verify_options.require_verification".to_string(),
            "verify_options.verify_fts_queue_empty".to_string(),
        ],
        is_default: false,
    }
}

fn default_standard_preset() -> ExaminerPreset {
    ExaminerPreset {
        name: "Standard Examiner".to_string(),
        description: "Balanced: warnings allowed but logged, violations cause failure, export requires verification".to_string(),
        preset_json: serde_json::json!({
            "enable_watchpoints": true,
            "run_replay": true,
            "run_verify": true,
            "verify_options": {
                "verify_activity_hash_chain": true,
                "verify_packet_manifests": true,
                "verify_db_integrity": true,
                "verify_read_models_rebuild": true,
                "verify_timeline_idempotency": true,
                "verify_fts_queue_empty": false,
                "sample_limit": null
            },
            "replay_options": {
                "run_read_model_rebuild": true,
                "run_fts_rebuild": true,
                "process_fts_queue": true,
                "run_db_optimize": false,
                "sample_limit": null
            },
            "fail_on_violations": true,
            "allow_verify_warn": true,
            "allow_replay_warn": true,
            "export_bundle": true,
            "bundle_dir": "exports/defensibility"
        }),
        locked_keys_json: vec![
            "fail_on_violations".to_string(),
        ],
        is_default: false,
    }
}

fn default_fast_triage_preset() -> ExaminerPreset {
    ExaminerPreset {
        name: "Fast Triage".to_string(),
        description: "Quick assessment: reduced fingerprints, sample limits, faster execution"
            .to_string(),
        preset_json: serde_json::json!({
            "enable_watchpoints": true,
            "run_replay": true,
            "run_verify": true,
            "verify_options": {
                "verify_activity_hash_chain": true,
                "verify_packet_manifests": false,
                "verify_db_integrity": true,
                "verify_read_models_rebuild": false,
                "verify_timeline_idempotency": false,
                "verify_fts_queue_empty": false,
                "sample_limit": 50000
            },
            "replay_options": {
                "run_read_model_rebuild": false,
                "run_fts_rebuild": false,
                "process_fts_queue": false,
                "run_db_optimize": false,
                "sample_limit": 1000
            },
            "fail_on_violations": false,
            "allow_verify_warn": true,
            "allow_replay_warn": true,
            "export_bundle": false,
            "bundle_dir": "exports/defensibility"
        }),
        locked_keys_json: vec![],
        is_default: false,
    }
}

pub fn init_case_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            examiner TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            modified_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS examiner_presets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL,
            preset_json TEXT NOT NULL,
            locked_keys_json TEXT NOT NULL,
            is_default INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS case_settings (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            key TEXT NOT NULL,
            value TEXT,
            modified_at INTEGER NOT NULL,
            UNIQUE(case_id, key)
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
        );

        -- FIX-3: the integrity-violations audit table must exist from
        -- `case init` onward so `strata examine` / watchpoint flows can
        -- record, query, and clear violations without hitting
        -- "no such table" runtime errors on fresh cases.
        CREATE TABLE IF NOT EXISTS integrity_violations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT,
            occurred_utc TEXT,
            timestamp TEXT NOT NULL,
            violation_type TEXT NOT NULL,
            table_name TEXT,
            expected_value TEXT NOT NULL,
            actual_value TEXT NOT NULL,
            affected_path TEXT NOT NULL,
            severity TEXT NOT NULL,
            examiner_notified INTEGER DEFAULT 0,
            acknowledged_by TEXT,
            acknowledgment_timestamp TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_integrity_timestamp
            ON integrity_violations(timestamp);
        CREATE INDEX IF NOT EXISTS idx_integrity_type
            ON integrity_violations(violation_type);
        CREATE INDEX IF NOT EXISTS idx_integrity_severity
            ON integrity_violations(severity);
        CREATE INDEX IF NOT EXISTS idx_integrity_violations_case_time
            ON integrity_violations(case_id, occurred_utc);
        CREATE INDEX IF NOT EXISTS idx_integrity_violations_case_table
            ON integrity_violations(case_id, table_name);
        "#,
    )?;
    init_default_presets(conn)
}

#[cfg(test)]
mod fix3_integrity_violations_tests {
    use super::*;
    use rusqlite::Connection;

    fn count_table(conn: &Connection, table: &str) -> i64 {
        conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='{}'",
                table
            ),
            [],
            |r| r.get(0),
        )
        .unwrap_or(0)
    }

    #[test]
    fn fresh_case_init_creates_integrity_violations_table() {
        let conn = Connection::open_in_memory().expect("open");
        init_case_schema(&conn).expect("init");
        assert_eq!(count_table(&conn, "integrity_violations"), 1);
    }

    #[test]
    fn second_init_is_idempotent() {
        let conn = Connection::open_in_memory().expect("open");
        init_case_schema(&conn).expect("init1");
        init_case_schema(&conn).expect("init2");
        assert_eq!(count_table(&conn, "integrity_violations"), 1);
    }

    #[test]
    fn can_insert_and_select_violation_after_init() {
        let conn = Connection::open_in_memory().expect("open");
        init_case_schema(&conn).expect("init");
        conn.execute(
            "INSERT INTO integrity_violations \
             (case_id, timestamp, violation_type, expected_value, actual_value, affected_path, severity) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params!["c1", "2026-04-17T00:00:00Z", "HashMismatch", "aaa", "bbb", "/x", "High"],
        )
        .expect("insert");
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM integrity_violations", [], |r| r.get(0))
            .expect("q");
        assert_eq!(n, 1);
    }
}

pub fn init_default_presets(conn: &Connection) -> SqliteResult<()> {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM examiner_presets", [], |row| {
        row.get(0)
    })?;

    if count > 0 {
        return Ok(());
    }

    let defaults = vec![
        default_strict_preset(),
        default_standard_preset(),
        default_fast_triage_preset(),
    ];

    for preset in defaults {
        conn.execute(
            "INSERT INTO examiner_presets (name, description, preset_json, locked_keys_json, is_default)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                preset.name,
                preset.description,
                serde_json::to_string(&preset.preset_json).unwrap_or_default(),
                serde_json::to_string(&preset.locked_keys_json).unwrap_or_default(),
                preset.is_default as i32,
            ],
        )?;
    }

    Ok(())
}

pub fn list_examiner_presets(conn: &Connection) -> SqliteResult<Vec<PresetInfo>> {
    let mut stmt = conn.prepare("SELECT name, description FROM examiner_presets ORDER BY name")?;
    let presets = stmt.query_map([], |row| {
        Ok(PresetInfo {
            name: row.get(0)?,
            description: row.get(1)?,
        })
    })?;

    presets.collect()
}

pub fn get_examiner_preset(conn: &Connection, name: &str) -> SqliteResult<Option<PresetDetails>> {
    let result = conn.query_row(
        "SELECT preset_json, locked_keys_json FROM examiner_presets WHERE name = ?1",
        [name],
        |row| {
            let preset_json: String = row.get(0)?;
            let locked_keys_json: String = row.get(1)?;
            Ok((preset_json, locked_keys_json))
        },
    );

    match result {
        Ok((preset_json, locked_keys_json)) => {
            let preset: serde_json::Value = serde_json::from_str(&preset_json)
                .unwrap_or(serde_json::Value::Object(Default::default()));
            let locked: Vec<String> = serde_json::from_str(&locked_keys_json).unwrap_or_default();
            Ok(Some(PresetDetails {
                preset_json: preset,
                locked_keys_json: locked,
            }))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

pub fn resolve_examination_options(
    preset: &PresetDetails,
    overrides_json: Option<&serde_json::Value>,
) -> ExaminationOptions {
    let mut options = ExaminationOptions::default();

    if let Some(preset_obj) = preset.preset_json.as_object() {
        if let Some(v) = preset_obj
            .get("enable_watchpoints")
            .and_then(|v| v.as_bool())
        {
            options.enable_watchpoints = v;
        }
        if let Some(v) = preset_obj.get("run_replay").and_then(|v| v.as_bool()) {
            options.run_replay = v;
        }
        if let Some(v) = preset_obj.get("run_verify").and_then(|v| v.as_bool()) {
            options.run_verify = v;
        }
        if let Some(v) = preset_obj
            .get("fail_on_violations")
            .and_then(|v| v.as_bool())
        {
            options.fail_on_violations = v;
        }
        if let Some(v) = preset_obj
            .get("allow_verify_warn")
            .and_then(|v| v.as_bool())
        {
            options.allow_verify_warn = v;
        }
        if let Some(v) = preset_obj
            .get("allow_replay_warn")
            .and_then(|v| v.as_bool())
        {
            options.allow_replay_warn = v;
        }
        if let Some(v) = preset_obj.get("export_bundle").and_then(|v| v.as_bool()) {
            options.export_bundle = v;
        }
        if let Some(v) = preset_obj.get("bundle_dir").and_then(|v| v.as_str()) {
            options.bundle_dir = v.to_string();
        }

        if let Some(verify_obj) = preset_obj.get("verify_options").and_then(|v| v.as_object()) {
            options.verify_options = parse_verify_options(verify_obj);
        }

        if let Some(replay_obj) = preset_obj.get("replay_options").and_then(|v| v.as_object()) {
            options.replay_options = parse_replay_options(replay_obj);
        }
    }

    if let Some(overrides) = overrides_json {
        if let Some(overrides_obj) = overrides.as_object() {
            for (key, value) in overrides_obj {
                if preset.locked_keys_json.contains(key) {
                    continue;
                }

                match key.as_str() {
                    "enable_watchpoints" => {
                        if let Some(v) = value.as_bool() {
                            options.enable_watchpoints = v;
                        }
                    }
                    "run_replay" => {
                        if let Some(v) = value.as_bool() {
                            options.run_replay = v;
                        }
                    }
                    "run_verify" => {
                        if let Some(v) = value.as_bool() {
                            options.run_verify = v;
                        }
                    }
                    "fail_on_violations" => {
                        if let Some(v) = value.as_bool() {
                            options.fail_on_violations = v;
                        }
                    }
                    "allow_verify_warn" => {
                        if let Some(v) = value.as_bool() {
                            options.allow_verify_warn = v;
                        }
                    }
                    "allow_replay_warn" => {
                        if let Some(v) = value.as_bool() {
                            options.allow_replay_warn = v;
                        }
                    }
                    "export_bundle" => {
                        if let Some(v) = value.as_bool() {
                            options.export_bundle = v;
                        }
                    }
                    "bundle_dir" => {
                        if let Some(v) = value.as_str() {
                            options.bundle_dir = v.to_string();
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    options
}

fn parse_verify_options(obj: &serde_json::Map<String, serde_json::Value>) -> VerifyOptions {
    VerifyOptions {
        verify_activity_hash_chain: obj
            .get("verify_activity_hash_chain")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        verify_packet_manifests: obj
            .get("verify_packet_manifests")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        verify_db_integrity: obj
            .get("verify_db_integrity")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        verify_read_models_rebuild: obj
            .get("verify_read_models_rebuild")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        verify_timeline_idempotency: obj
            .get("verify_timeline_idempotency")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        verify_fts_queue_empty: obj
            .get("verify_fts_queue_empty")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        sample_limit: obj.get("sample_limit").and_then(|v| v.as_u64()),
    }
}

fn parse_replay_options(obj: &serde_json::Map<String, serde_json::Value>) -> ReplayOptions {
    ReplayOptions {
        fingerprint_tables: ReplayOptions::default().fingerprint_tables,
        run_read_model_rebuild: obj
            .get("run_read_model_rebuild")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        run_fts_rebuild: obj
            .get("run_fts_rebuild")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        fts_entities: ReplayOptions::default().fts_entities,
        process_fts_queue: obj
            .get("process_fts_queue")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        fts_queue_batch: obj
            .get("fts_queue_batch")
            .and_then(|v| v.as_u64())
            .unwrap_or(5000),
        run_db_optimize: obj
            .get("run_db_optimize")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        sample_limit: obj.get("sample_limit").and_then(|v| v.as_u64()),
    }
}

pub fn start_examination(
    db: &CaseDatabase,
    case_id: &str,
    preset_name: &str,
    overrides_json: Option<serde_json::Value>,
) -> anyhow::Result<TriageSessionResult> {
    let conn = db.get_connection();
    let conn = conn.lock().unwrap();

    let preset = get_examiner_preset(&conn, preset_name)?;
    let preset = match preset {
        Some(p) => p,
        None => anyhow::bail!("Preset not found: {}", preset_name),
    };

    let options = resolve_examination_options(&preset, overrides_json.as_ref());

    let triage_options = TriageSessionOptions {
        enable_watchpoints: options.enable_watchpoints,
        run_replay: options.run_replay,
        run_verify: options.run_verify,
        verify_options: options.verify_options.clone(),
        replay_options: options.replay_options.clone(),
        fail_on_violations: options.fail_on_violations,
        allow_verify_warn: options.allow_verify_warn,
        allow_replay_warn: options.allow_replay_warn,
        export_bundle: options.export_bundle,
        bundle_dir: options.bundle_dir.clone(),
    };

    drop(conn);

    let conn_arc = db.get_connection();
    let manager = TriageSessionManager::new(conn_arc, case_id.to_string());
    let result = manager.start_session(
        Some(&format!("Examination: {}", preset_name)),
        triage_options,
    )?;

    let conn = db.get_connection();
    let conn = conn.lock().unwrap();
    let final_options_json = serde_json::json!({
        "preset_name": preset_name,
        "options": options,
        "overrides_applied": overrides_json,
    });

    conn.execute(
        "UPDATE triage_sessions SET preset_name = ?1, options_json = ?2 WHERE id = ?3",
        params![
            preset_name,
            serde_json::to_string(&final_options_json).unwrap_or_default(),
            result.session_id
        ],
    )?;

    Ok(result)
}

pub fn get_auto_start_preset(conn: &Connection, case_id: &str) -> SqliteResult<Option<String>> {
    let result = conn.query_row(
        "SELECT value FROM case_settings WHERE case_id = ?1 AND key = 'auto_start_examination_preset'",
        [case_id],
        |row| row.get(0),
    );

    match result {
        Ok(val) => Ok(Some(val)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

pub fn set_auto_start_preset(
    conn: &Connection,
    case_id: &str,
    preset: Option<&str>,
) -> SqliteResult<()> {
    if let Some(preset_name) = preset {
        conn.execute(
            "INSERT OR REPLACE INTO case_settings (id, case_id, key, value, modified_at)
             VALUES (?1, ?2, 'auto_start_examination_preset', ?3, strftime('%s', 'now'))",
            params![uuid::Uuid::new_v4().to_string(), case_id, preset_name],
        )?;
    } else {
        conn.execute(
            "DELETE FROM case_settings WHERE case_id = ?1 AND key = 'auto_start_examination_preset'",
            [case_id],
        )?;
    }
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

            CREATE TABLE IF NOT EXISTS examiner_presets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT NOT NULL,
                preset_json TEXT NOT NULL,
                locked_keys_json TEXT NOT NULL,
                is_default INTEGER NOT NULL DEFAULT 0
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
            );

            CREATE TABLE IF NOT EXISTS case_settings (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT,
                modified_at INTEGER NOT NULL,
                UNIQUE(case_id, key)
            );",
        )?;
        conn.execute(
            "INSERT INTO cases (id, name, examiner, created_at, modified_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![&case_id, "Test Case", "tester", 1700000000, 1700000000],
        )?;

        Ok((conn, case_id))
    }

    #[test]
    fn test_init_default_presets() {
        let temp_dir = TempDir::new().unwrap();
        let (conn, _) = create_test_db(&temp_dir).unwrap();

        init_default_presets(&conn).unwrap();

        let presets = list_examiner_presets(&conn).unwrap();
        assert_eq!(presets.len(), 3);
        assert!(presets.iter().any(|p| p.name == "Strict Examiner"));
        assert!(presets.iter().any(|p| p.name == "Standard Examiner"));
        assert!(presets.iter().any(|p| p.name == "Fast Triage"));
    }

    #[test]
    fn test_locked_key_enforcement() {
        let temp_dir = TempDir::new().unwrap();
        let (conn, _) = create_test_db(&temp_dir).unwrap();

        init_default_presets(&conn).unwrap();

        let preset = get_examiner_preset(&conn, "Strict Examiner")
            .unwrap()
            .unwrap();
        assert!(preset
            .locked_keys_json
            .contains(&"fail_on_violations".to_string()));

        let overrides = serde_json::json!({
            "fail_on_violations": false,
            "allow_verify_warn": true
        });

        let options = resolve_examination_options(&preset, Some(&overrides));

        assert!(options.fail_on_violations);
        assert!(options.allow_verify_warn);
    }

    #[test]
    fn test_auto_preset_setting() {
        let temp_dir = TempDir::new().unwrap();
        let (conn, case_id) = create_test_db(&temp_dir).unwrap();

        let before = get_auto_start_preset(&conn, &case_id).unwrap();
        assert!(before.is_none());

        set_auto_start_preset(&conn, &case_id, Some("Strict Examiner")).unwrap();

        let after = get_auto_start_preset(&conn, &case_id).unwrap();
        assert_eq!(after, Some("Strict Examiner".to_string()));

        set_auto_start_preset(&conn, &case_id, None).unwrap();

        let final_check = get_auto_start_preset(&conn, &case_id).unwrap();
        assert!(final_check.is_none());
    }
}
