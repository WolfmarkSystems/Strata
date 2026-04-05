#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod diagnostics;
mod preflight;
mod state;

use forensic_engine::case::add_to_notes::{add_to_notes as engine_add_to_notes, AddToNotesMode, AddToNotesRequest};
use forensic_engine::case::database::{CaseDatabase, CaseDatabaseManager};
use forensic_engine::case::database::{FileTableFilter, FileTableQuery, FileTableResult, SortDir, SortField};
use forensic_engine::case::export::ExportOptions;
use forensic_engine::case::replay::{ReplayOptions, ReplayReport};
use forensic_engine::case::triage_session::{
    TriageSessionManager, TriageSessionOptions, TriageSessionResult, TriageSessionStatus,
};
use forensic_engine::case::verify::{verify_case, VerifyOptions, VerificationReport};
use forensic_engine::case::watchpoints::{
    enable_integrity_watchpoints as engine_enable_watchpoints, get_integrity_watchpoints_enabled,
    list_integrity_violations as engine_list_violations, IntegrityViolation,
};
use forensic_engine::events::EngineEvent;
use preflight::{run_preflight_checks, save_preflight_report, PreflightReport, PreflightStatus};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::State;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        ApiError {
            code: "INTERNAL_ERROR".to_string(),
            message: err.to_string(),
        }
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(err: rusqlite::Error) -> Self {
        ApiError {
            code: "DB_ERROR".to_string(),
            message: err.to_string(),
        }
    }
}

impl From<std::io::Error> for ApiError {
    fn from(err: std::io::Error) -> Self {
        ApiError {
            code: "IO_ERROR".to_string(),
            message: err.to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CaseInfo {
    pub case_id: String,
    pub name: String,
    pub examiner: String,
    pub created_at: String,
    pub modified_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenCaseResult {
    pub case_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenEvidenceResult {
    pub evidence_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection_output: Option<forensic_engine::evidence::DetectionOutput>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExportResult {
    pub export_path: String,
    pub manifest_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetWatchpointsResult {
    pub enabled: bool,
}

#[tauri::command]
async fn open_case(
    case_path: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<OpenCaseResult, ApiError> {
    let path = PathBuf::from(&case_path);
    let case_id = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();

    let mut app_state = state.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    app_state
        .db_manager
        .open_case(&case_id, &path)
        .map_err(|e| ApiError {
            code: "DB_ERROR".to_string(),
            message: e.to_string(),
        })?;

    app_state.opened_cases.insert(case_id.clone());

    Ok(OpenCaseResult { case_id })
}

#[tauri::command]
fn list_cases(state: State<'_, Mutex<AppState>>) -> Result<Vec<CaseInfo>, ApiError> {
    let app_state = state.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    let mut cases = Vec::new();
    for case_id in app_state.opened_cases.iter() {
        cases.push(CaseInfo {
            case_id: case_id.clone(),
            name: case_id.clone(),
            examiner: "unknown".to_string(),
            created_at: String::new(),
            modified_at: String::new(),
        });
    }

    Ok(cases)
}

#[tauri::command]
async fn open_evidence(
    case_id: String,
    evidence_path: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<OpenEvidenceResult, ApiError> {
    let evidence_id = uuid::Uuid::new_v4().to_string();

    let source_path = std::path::Path::new(&evidence_path);
    let opener = forensic_engine::evidence::EvidenceOpener::new(&case_id, "desktop_user");
    
    match opener.open_evidence(source_path) {
        Ok(detection) => {
            Ok(OpenEvidenceResult { 
                evidence_id: detection.evidence_id.clone(),
                detection_output: Some(detection),
            })
        }
        Err(_) => {
            Ok(OpenEvidenceResult { evidence_id })
        }
    }
}

#[tauri::command]
async fn detect_evidence(
    case_id: String,
    evidence_path: String,
    user_name: Option<String>,
) -> Result<forensic_engine::evidence::DetectionOutput, ApiError> {
    let source_path = std::path::Path::new(&evidence_path);
    let user = user_name.unwrap_or_else(|| "desktop_user".to_string());
    let opener = forensic_engine::evidence::EvidenceOpener::new(&case_id, &user);
    
    opener.open_evidence(source_path).map_err(|e| ApiError {
        code: "DETECTION_ERROR".to_string(),
        message: e,
    })
}

#[tauri::command]
async fn get_activity_log_after(
    case_id: String,
    last_ts: Option<String>,
    last_id: Option<i64>,
    limit: u32,
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<serde_json::Value>, ApiError> {
    let app_state = state.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    let conn = app_state
        .db_manager
        .get_connection(&case_id)
        .map_err(|e| ApiError {
            code: "DB_ERROR".to_string(),
            message: e.to_string(),
        })?;

    let conn = conn.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    let query = if let (Some(ref ts), Some(id)) = (last_ts, last_id) {
        format!(
            "SELECT id, case_id, event_type, summary, details_json, ts_utc, ts_local, user_name 
             FROM activity_log WHERE case_id = ?1 AND (ts_utc > ?2 OR (ts_utc = ?2 AND id > ?3)) 
             ORDER BY ts_utc ASC, id ASC LIMIT ?4"
        )
    } else {
        "SELECT id, case_id, event_type, summary, details_json, ts_utc, ts_local, user_name 
         FROM activity_log WHERE case_id = ?1 ORDER BY ts_utc ASC, id ASC LIMIT ?2".to_string()
    };

    let mut entries = Vec::new();
    let mut stmt = conn.prepare(&query).map_err(|e| ApiError {
        code: "DB_ERROR".to_string(),
        message: e.to_string(),
    })?;

    let rows = if let (Some(ref ts), Some(id)) = (last_ts, last_id) {
        let ts_int: i64 = ts.parse().unwrap_or(0);
        stmt.query_map(params![&case_id, ts_int, id, limit as i64], |row| {
            Ok(serde_json::json!({
                "id": row.get::<_, String>(0)?,
                "case_id": row.get::<_, String>(1)?,
                "event_type": row.get::<_, String>(2)?,
                "summary": row.get::<_, String>(3)?,
                "details_json": row.get::<_, Option<String>>(4)?,
                "ts_utc": row.get::<_, i64>(5)?,
                "ts_local": row.get::<_, String>(6)?,
                "user_name": row.get::<_, String>(7)?,
            }))
        })
    } else {
        stmt.query_map(params![&case_id, limit as i64], |row| {
            Ok(serde_json::json!({
                "id": row.get::<_, String>(0)?,
                "case_id": row.get::<_, String>(1)?,
                "event_type": row.get::<_, String>(2)?,
                "summary": row.get::<_, String>(3)?,
                "details_json": row.get::<_, Option<String>>(4)?,
                "ts_utc": row.get::<_, i64>(5)?,
                "ts_local": row.get::<_, String>(6)?,
                "user_name": row.get::<_, String>(7)?,
            }))
        })
    };

    for entry in rows.map_err(|e| ApiError {
        code: "DB_ERROR".to_string(),
        message: e.to_string(),
    })? {
        entries.push(entry.map_err(|e| ApiError {
            code: "DB_ERROR".to_string(),
            message: e.to_string(),
        })?);
    }

    Ok(entries)
}

#[tauri::command]
async fn get_evidence_timeline_after(
    case_id: String,
    last_event_time: Option<String>,
    last_rowid: Option<i64>,
    limit: u32,
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<serde_json::Value>, ApiError> {
    let app_state = state.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    let conn = app_state
        .db_manager
        .get_connection(&case_id)
        .map_err(|e| ApiError {
            code: "DB_ERROR".to_string(),
            message: e.to_string(),
        })?;

    let conn = conn.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    let mut entries = Vec::new();
    let mut stmt = conn
        .prepare(
            "SELECT id, case_id, event_type, event_time, artifact_id, source_module, source_record_id, rowid
             FROM evidence_timeline WHERE case_id = ?1 ORDER BY event_time ASC, rowid ASC LIMIT ?2",
        )
        .map_err(|e| ApiError {
            code: "DB_ERROR".to_string(),
            message: e.to_string(),
        })?;

    let rows = stmt.query_map(params![&case_id, limit as i64], |row| {
        Ok(serde_json::json!({
            "id": row.get::<_, String>(0)?,
            "case_id": row.get::<_, String>(1)?,
            "event_type": row.get::<_, String>(2)?,
            "event_time": row.get::<_, i64>(3)?,
            "artifact_id": row.get::<_, Option<String>>(4)?,
            "source_module": row.get::<_, Option<String>>(5)?,
            "source_record_id": row.get::<_, Option<String>>(6)?,
            "rowid": row.get::<_, i64>(7)?,
        }))
    });

    for entry in rows.map_err(|e| ApiError {
        code: "DB_ERROR".to_string(),
        message: e.to_string(),
    })? {
        entries.push(entry.map_err(|e| ApiError {
            code: "DB_ERROR".to_string(),
            message: e.to_string(),
        })?);
    }

    Ok(entries)
}

#[tauri::command]
async fn get_bookmarks_paged(
    case_id: String,
    page: u32,
    page_size: u32,
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<serde_json::Value>, ApiError> {
    let app_state = state.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    let conn = app_state
        .db_manager
        .get_connection(&case_id)
        .map_err(|e| ApiError {
            code: "DB_ERROR".to_string(),
            message: e.to_string(),
        })?;

    let conn = conn.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    let offset = page * page_size;
    let mut stmt = conn
        .prepare(
            "SELECT id, case_id, folder_id, title, description, tags_json, reviewed, reviewer, 
                    created_at, modified_at FROM bookmarks WHERE case_id = ?1 
             ORDER BY modified_at DESC LIMIT ?2 OFFSET ?3",
        )
        .map_err(|e| ApiError {
            code: "DB_ERROR".to_string(),
            message: e.to_string(),
        })?;

    let mut entries = Vec::new();
    let rows = stmt.query_map(params![&case_id, page_size as i64, offset as i64], |row| {
        Ok(serde_json::json!({
            "id": row.get::<_, String>(0)?,
            "case_id": row.get::<_, String>(1)?,
            "folder_id": row.get::<_, Option<String>>(2)?,
            "title": row.get::<_, String>(3)?,
            "description": row.get::<_, Option<String>>(4)?,
            "tags_json": row.get::<_, Option<String>>(5)?,
            "reviewed": row.get::<_, i32>(6)?,
            "reviewer": row.get::<_, Option<String>>(7)?,
            "created_at": row.get::<_, i64>(8)?,
            "modified_at": row.get::<_, i64>(9)?,
        }))
    });

    for entry in rows.map_err(|e| ApiError {
        code: "DB_ERROR".to_string(),
        message: e.to_string(),
    })? {
        entries.push(entry.map_err(|e| ApiError {
            code: "DB_ERROR".to_string(),
            message: e.to_string(),
        })?);
    }

    Ok(entries)
}

#[tauri::command]
async fn get_exhibits_paged(
    case_id: String,
    page: u32,
    page_size: u32,
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<serde_json::Value>, ApiError> {
    let app_state = state.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    let conn = app_state
        .db_manager
        .get_connection(&case_id)
        .map_err(|e| ApiError {
            code: "DB_ERROR".to_string(),
            message: e.to_string(),
        })?;

    let conn = conn.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    let offset = page * page_size;
    let mut stmt = conn
        .prepare(
            "SELECT id, case_id, name, description, exhibit_type, file_path, hash_sha256, 
                    created_at FROM exhibits WHERE case_id = ?1 ORDER BY created_at DESC LIMIT ?2 OFFSET ?3",
        )
        .map_err(|e| ApiError {
            code: "DB_ERROR".to_string(),
            message: e.to_string(),
        })?;

    let mut entries = Vec::new();
    let rows = stmt.query_map(params![&case_id, page_size as i64, offset as i64], |row| {
        Ok(serde_json::json!({
            "id": row.get::<_, String>(0)?,
            "case_id": row.get::<_, String>(1)?,
            "name": row.get::<_, String>(2)?,
            "description": row.get::<_, Option<String>>(3)?,
            "exhibit_type": row.get::<_, String>(4)?,
            "file_path": row.get::<_, Option<String>>(5)?,
            "hash_sha256": row.get::<_, Option<String>>(6)?,
            "created_at": row.get::<_, i64>(7)?,
        }))
    });

    for entry in rows.map_err(|e| ApiError {
        code: "DB_ERROR".to_string(),
        message: e.to_string(),
    })? {
        entries.push(entry.map_err(|e| ApiError {
            code: "DB_ERROR".to_string(),
            message: e.to_string(),
        })?);
    }

    Ok(entries)
}

#[tauri::command]
async fn run_verify(
    case_id: String,
    db_path: String,
    options: VerifyOptions,
    state: State<'_, Mutex<AppState>>,
) -> Result<serde_json::Value, ApiError> {
    let state_clone = Mutex::new(AppState::new());
    let result = tauri::async_runtime::spawn_blocking(move || {
        let path = PathBuf::from(&db_path);
        verify_case(&case_id, &path, options)
    })
    .await
    .map_err(|e| ApiError {
        code: "TASK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    match result {
        Ok(report) => {
            let json = serde_json::to_value(&report).map_err(|e| ApiError {
                code: "SERIALIZATION_ERROR".to_string(),
                message: e.to_string(),
            })?;
            Ok(json)
        }
        Err(e) => Err(ApiError {
            code: "VERIFY_ERROR".to_string(),
            message: e.to_string(),
        }),
    }
}

#[tauri::command]
async fn run_replay(
    case_id: String,
    db_path: String,
    options: ReplayOptions,
    state: State<'_, Mutex<AppState>>,
) -> Result<serde_json::Value, ApiError> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let path = PathBuf::from(&db_path);
        forensic_engine::case::replay::replay_case(&case_id, &path, options)
    })
    .await
    .map_err(|e| ApiError {
        code: "TASK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    match result {
        Ok(report) => {
            let json = serde_json::to_value(&report).map_err(|e| ApiError {
                code: "SERIALIZATION_ERROR".to_string(),
                message: e.to_string(),
            })?;
            Ok(json)
        }
        Err(e) => Err(ApiError {
            code: "REPLAY_ERROR".to_string(),
            message: e.to_string(),
        }),
    }
}

#[tauri::command]
async fn run_triage_session(
    case_id: String,
    db_path: String,
    name: Option<String>,
    options: TriageSessionOptions,
    state: State<'_, Mutex<AppState>>,
) -> Result<serde_json::Value, ApiError> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let path = PathBuf::from(&db_path);
        let conn = rusqlite::Connection::open(&path).map_err(|e| anyhow::anyhow!(e))?;

        let conn = std::sync::Arc::new(std::sync::Mutex::new(conn));
        let manager = TriageSessionManager::new(conn, case_id.clone());
        manager.start_session(name.as_deref(), options)
    })
    .await
    .map_err(|e| ApiError {
        code: "TASK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    match result {
        Ok(result) => {
            let json = serde_json::to_value(serde_json::json!({
                "session_id": result.session_id,
                "status": format!("{:?}", result.status),
                "replay_id": result.replay_id,
                "verification_id": result.verification_id,
                "violations_count": result.violations_count,
                "bundle_path": result.bundle_path,
                "bundle_hash_sha256": result.bundle_hash_sha256,
            }))
            .map_err(|e| ApiError {
                code: "SERIALIZATION_ERROR".to_string(),
                message: e.to_string(),
            })?;
            Ok(json)
        }
        Err(e) => Err(ApiError {
            code: "TRIAGE_ERROR".to_string(),
            message: e.to_string(),
        }),
    }
}

#[tauri::command]
async fn add_to_notes(
    case_id: String,
    db_path: String,
    mode: String,
    context: serde_json::Value,
    items: Vec<serde_json::Value>,
    tags: Vec<String>,
    screenshot_path: Option<String>,
    explain: bool,
    max_items: Option<u64>,
    state: State<'_, Mutex<AppState>>,
) -> Result<serde_json::Value, ApiError> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        let path = PathBuf::from(&db_path);
        let db = forensic_engine::case::database::CaseDatabase::open(&case_id, &path)
            .map_err(|e| anyhow::anyhow!(e))?;

        let add_mode = match mode.as_str() {
            "exhibits" => AddToNotesMode::NotePlusExhibits,
            "packet" => AddToNotesMode::NotePlusSinglePacket,
            _ => AddToNotesMode::NoteOnly,
        };

        let req = AddToNotesRequest {
            case_id: case_id.clone(),
            mode: add_mode,
            context: serde_json::from_value(context).map_err(|e| anyhow::anyhow!(e))?,
            items: serde_json::from_value(serde_json::json!(items)).map_err(|e| anyhow::anyhow!(e))?,
            tags,
            screenshot_path,
            screenshot_id: None,
            explain,
            max_items,
        };

        engine_add_to_notes(&db, req)
    })
    .await
    .map_err(|e| ApiError {
        code: "TASK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    match result {
        Ok(result) => Ok(serde_json::json!({
            "note_id": result.note_id,
            "exhibit_ids": result.exhibit_ids,
            "exhibit_packet_id": result.exhibit_packet_id,
            "screenshot_id": result.screenshot_id,
            "activity_event_id": result.activity_event_id,
        })),
        Err(e) => Err(ApiError {
            code: "ADD_TO_NOTES_ERROR".to_string(),
            message: e.to_string(),
        }),
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PresetInfo {
    pub name: String,
    pub description: String,
    pub locked_fields: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PresetDetails {
    pub name: String,
    pub description: String,
    pub locked_fields: Vec<String>,
    pub config_json: String,
}

#[tauri::command]
async fn list_presets(
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<PresetInfo>, ApiError> {
    let app_state = state.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;
    
    let db_path = PathBuf::from("./forensic.db");
    let conn = rusqlite::Connection::open(&db_path).map_err(|e| ApiError {
        code: "DB_ERROR".to_string(),
        message: e.to_string(),
    })?;
    
    let mut stmt = conn.prepare("SELECT name, description, locked_keys_json FROM examiner_presets ORDER BY name")
        .map_err(|e| ApiError {
            code: "QUERY_ERROR".to_string(),
            message: e.to_string(),
        })?;
    
    let presets = stmt.query_map([], |row| {
        let name: String = row.get(0)?;
        let description: String = row.get(1)?;
        let locked_keys_json: String = row.get(2)?;
        let locked_fields: Vec<String> = serde_json::from_str(&locked_keys_json).unwrap_or_default();
        Ok(PresetInfo { name, description, locked_fields })
    }).map_err(|e| ApiError {
        code: "QUERY_ERROR".to_string(),
        message: e.to_string(),
    })?;
    
    let result: Vec<PresetInfo> = presets.filter_map(|p| p.ok()).collect();
    Ok(result)
}

#[tauri::command]
async fn get_preset(
    name: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<Option<PresetDetails>, ApiError> {
    let app_state = state.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;
    
    let db_path = PathBuf::from("./forensic.db");
    let conn = rusqlite::Connection::open(&db_path).map_err(|e| ApiError {
        code: "DB_ERROR".to_string(),
        message: e.to_string(),
    })?;
    
    let result: Option<PresetDetails> = conn.query_row(
        "SELECT name, description, locked_keys_json, preset_json FROM examiner_presets WHERE name = ?1",
        [&name],
        |row| {
            let name: String = row.get(0)?;
            let description: String = row.get(1)?;
            let locked_keys_json: String = row.get(2)?;
            let preset_json: String = row.get(3)?;
            let locked_fields: Vec<String> = serde_json::from_str(&locked_keys_json).unwrap_or_default();
            Ok(PresetDetails {
                name,
                description,
                locked_fields,
                config_json: preset_json,
            })
        }
    ).ok();
    
    Ok(result)
}

#[tauri::command]
async fn start_examination(
    case_id: String,
    preset_name: String,
    db_path: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<(), ApiError> {
    use forensic_engine::case::examiner_presets;
    
    let path = PathBuf::from(&db_path);
    let mut conn = rusqlite::Connection::open(&path).map_err(|e| ApiError {
        code: "DB_ERROR".to_string(),
        message: e.to_string(),
    })?;
    
    examiner_presets::start_examination_with_preset(&mut conn, &case_id, &preset_name, None)
        .map_err(|e| ApiError {
            code: "EXAMINATION_ERROR".to_string(),
            message: e.to_string(),
        })?;
    
    Ok(())
}

#[tauri::command]
async fn export_case(
    case_id: String,
    db_path: String,
    options: ExportOptions,
    state: State<'_, Mutex<AppState>>,
) -> Result<ExportResult, ApiError> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        use forensic_engine::case::verify::check_export_guard;

        let path = PathBuf::from(&db_path);
        let mut conn = rusqlite::Connection::open(&path).map_err(|e| anyhow::anyhow!(e))?;

        if let Err(e) = check_export_guard(&mut conn, &case_id, &options) {
            return Err(anyhow::anyhow!("Export blocked: {}", e.message));
        }

        let output_dir = PathBuf::from(format!("./export_{}", case_id));
        std::fs::create_dir_all(&output_dir).map_err(|e| anyhow::anyhow!(e))?;

        let report_json: Result<String, _> = conn.query_row(
            "SELECT report_json FROM case_verifications WHERE case_id = ?1 ORDER BY started_utc DESC LIMIT 1",
            [&case_id],
            |row| row.get(0),
        );

        let report: Option<forensic_engine::case::verify::VerificationReport> = report_json
            .ok()
            .and_then(|json| serde_json::from_str(&json).ok());

        forensic_engine::case::verify::write_verification_artifacts(
            &output_dir,
            &case_id,
            report.as_ref(),
        )
        .map_err(|e| anyhow::anyhow!(e))?;

        let manifest_hash = "placeholder_hash".to_string();

        Ok(ExportResult {
            export_path: output_dir.to_string_lossy().to_string(),
            manifest_hash,
        })
    })
    .await
    .map_err(|e| ApiError {
        code: "TASK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    match result {
        Ok(r) => Ok(r),
        Err(e) => {
            if e.to_string().contains("Export blocked") {
                Err(ApiError {
                    code: "EXPORT_BLOCKED".to_string(),
                    message: e.to_string(),
                })
            } else {
                Err(ApiError {
                    code: "EXPORT_ERROR".to_string(),
                    message: e.to_string(),
                })
            }
        }
    }
}

#[tauri::command]
async fn set_watchpoints(
    case_id: String,
    db_path: String,
    enabled: bool,
    state: State<'_, Mutex<AppState>>,
) -> Result<SetWatchpointsResult, ApiError> {
    let path = PathBuf::from(&db_path);
    let conn = rusqlite::Connection::open(&path).map_err(|e| ApiError {
        code: "DB_ERROR".to_string(),
        message: e.to_string(),
    })?;

    engine_enable_watchpoints(&conn, &case_id, enabled).map_err(|e| ApiError {
        code: "DB_ERROR".to_string(),
        message: e.to_string(),
    })?;

    Ok(SetWatchpointsResult { enabled })
}

#[tauri::command]
async fn list_violations(
    case_id: String,
    db_path: String,
    since_utc: Option<String>,
    limit: u32,
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<IntegrityViolation>, ApiError> {
    let path = PathBuf::from(&db_path);
    let conn = rusqlite::Connection::open(&path).map_err(|e| ApiError {
        code: "DB_ERROR".to_string(),
        message: e.to_string(),
    })?;

    let violations = engine_list_violations(&conn, &case_id, since_utc, limit as usize)
        .map_err(|e| ApiError {
            code: "DB_ERROR".to_string(),
            message: e.to_string(),
        })?;

    Ok(violations)
}

#[tauri::command]
async fn clear_violations(
    case_id: String,
    db_path: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<(), ApiError> {
    use forensic_engine::case::watchpoints::clear_integrity_violations;
    
    let path = PathBuf::from(&db_path);
    let conn = rusqlite::Connection::open(&path).map_err(|e| ApiError {
        code: "DB_ERROR".to_string(),
        message: e.to_string(),
    })?;

    clear_integrity_violations(&conn, &case_id).map_err(|e| ApiError {
        code: "DB_ERROR".to_string(),
        message: e.to_string(),
    })?;

    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportSkeletonResult {
    pub output_dir: String,
    pub files_created: Vec<String>,
}

#[tauri::command]
async fn generate_report_skeleton(
    case_id: String,
    db_path: String,
    output_dir: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<ReportSkeletonResult, ApiError> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        forensic_engine::case::report_templates::generate_report_skeleton(&case_id, &output_dir, None)
            .map_err(|e| anyhow::anyhow!(e))
    })
    .await
    .map_err(|e| ApiError {
        code: "TASK_ERROR".to_string(),
        message: e.to_string(),
    })?
    .map_err(|e| ApiError {
        code: "REPORT_ERROR".to_string(),
        message: e.to_string(),
    })?;

    Ok(ReportSkeletonResult {
        output_dir: result.output_dir,
        files_created: result.files_created,
    })
}

#[tauri::command]
fn get_event_buffer(
    case_id: Option<String>,
    limit: u32,
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<forensic_engine::events::EngineEvent>, ApiError> {
    let state = state.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    Ok(state.get_events(case_id, limit as usize))
}

#[tauri::command]
fn run_preflight() -> Result<PreflightReport, ApiError> {
    let report = run_preflight_checks();
    let _ = save_preflight_report(&report);
    Ok(report)
}

#[tauri::command]
fn get_preflight_report() -> Result<Option<PreflightReport>, ApiError> {
    Ok(preflight::load_latest_preflight_report())
}

#[tauri::command]
fn get_capabilities() -> Result<forensic_engine::capabilities::CapabilitiesReport, ApiError> {
    Ok(forensic_engine::capabilities::get_capabilities_report())
}

#[tauri::command]
async fn global_search(
    case_id: String,
    query: String,
    entity_types: Option<Vec<String>>,
    date_start_utc: Option<String>,
    date_end_utc: Option<String>,
    category: Option<String>,
    tags_any: Option<Vec<String>>,
    path_prefix: Option<String>,
    limit: Option<u32>,
    after_rank: Option<f64>,
    after_rowid: Option<i64>,
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<forensic_engine::case::database::GlobalSearchHit>, ApiError> {
    let app_state = state.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    let conn = app_state
        .db_manager
        .get_connection(&case_id)
        .map_err(|e| ApiError {
            code: "DB_ERROR".to_string(),
            message: e.to_string(),
        })?;

    let conn = conn.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    let entity_types_ref: Option<Vec<&str>> = entity_types.as_ref().map(|v| v.iter().map(|s| s.as_str()).collect());
    let tags_any_ref: Option<Vec<&str>> = tags_any.as_ref().map(|v| v.iter().map(|s| s.as_str()).collect());

    conn.global_search(
        &case_id,
        &query,
        entity_types_ref,
        date_start_utc.as_deref(),
        date_end_utc.as_deref(),
        category.as_deref(),
        tags_any_ref,
        path_prefix.as_deref(),
        limit.unwrap_or(20),
        after_rank,
        after_rowid,
    ).map_err(|e| ApiError {
        code: "SEARCH_ERROR".to_string(),
        message: e.to_string(),
    })
}

#[tauri::command]
async fn rebuild_global_search(
    case_id: String,
    entity_types: Option<Vec<String>>,
    state: State<'_, Mutex<AppState>>,
) -> Result<RebuildGlobalSearchResult, ApiError> {
    let app_state = state.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    let conn = app_state
        .db_manager
        .get_connection(&case_id)
        .map_err(|e| ApiError {
            code: "DB_ERROR".to_string(),
            message: e.to_string(),
        })?;

    let conn = conn.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    let mut total_indexed = 0;
    let types = entity_types.unwrap_or_else(|| vec!["note".to_string(), "bookmark".to_string(), "exhibit".to_string(), "timeline".to_string()]);

    for et in types {
        match conn.rebuild_global_search_for_type(&case_id, &et) {
            Ok(count) => total_indexed += count,
            Err(e) => {
                return Err(ApiError {
                    code: "REBUILD_ERROR".to_string(),
                    message: format!("Failed to rebuild {}: {}", et, e),
                });
            }
        }
    }

    Ok(RebuildGlobalSearchResult {
        ok: true,
        indexed_count: total_indexed,
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RebuildGlobalSearchResult {
    pub ok: bool,
    pub indexed_count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StringsExtractOptions {
    pub min_len_ascii: Option<usize>,
    pub min_len_utf16: Option<usize>,
    pub max_file_size_bytes: Option<u64>,
    pub max_output_chars: Option<usize>,
    pub sample_bytes: Option<u64>,
    pub allow_categories: Option<Vec<String>>,
    pub deny_extensions: Option<Vec<String>>,
    pub entropy_max: Option<f64>,
}

#[tauri::command]
async fn queue_strings_extraction(
    case_id: String,
    scope: Option<String>,
    options: Option<StringsExtractOptions>,
    state: State<'_, Mutex<AppState>>,
) -> Result<QueueJobResult, ApiError> {
    let opts = options.unwrap_or(StringsExtractOptions {
        min_len_ascii: Some(6),
        min_len_utf16: Some(6),
        max_file_size_bytes: Some(50 * 1024 * 1024),
        max_output_chars: Some(200_000),
        sample_bytes: Some(8 * 1024 * 1024),
        allow_categories: Some(vec![
            "Executable".to_string(),
            "Document".to_string(),
            "Archive".to_string(),
            "Script".to_string(),
            "Unknown".to_string(),
        ]),
        deny_extensions: Some(vec![
            "jpg".to_string(),
            "png".to_string(),
            "mp4".to_string(),
            "mov".to_string(),
            "zip".to_string(),
        ]),
        entropy_max: Some(7.5),
    });

    let job_id = uuid::Uuid::new_v4().to_string();
    let params_json = serde_json::json!({
        "case_id": case_id,
        "scope": scope.unwrap_or_else(|| "all".to_string()),
        "options": opts,
    }).to_string();

    let app_state = state.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    let conn = app_state
        .db_manager
        .get_connection(&case_id)
        .map_err(|e| ApiError {
            code: "DB_ERROR".to_string(),
            message: e.to_string(),
        })?;

    let conn = conn.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    conn.execute(
        "INSERT INTO jobs (id, case_id, job_type, status, priority, params_json, created_by, created_at)
         VALUES (?1, ?2, 'StringsExtraction', 'pending', 0, ?3, 'desktop', strftime('%s', 'now'))",
        params![
            job_id,
            case_id,
            params_json
        ],
    ).map_err(|e| ApiError {
        code: "INSERT_ERROR".to_string(),
        message: e.to_string(),
    })?;

    Ok(QueueJobResult { job_id })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QueueJobResult {
    pub job_id: String,
}

#[tauri::command]
async fn get_file_strings(
    case_id: String,
    file_id: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<Option<forensic_engine::case::database::FileStringsResult>, ApiError> {
    let app_state = state.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    let conn = app_state
        .db_manager
        .get_connection(&case_id)
        .map_err(|e| ApiError {
            code: "DB_ERROR".to_string(),
            message: e.to_string(),
        })?;

    let conn = conn.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    conn.get_file_strings(&case_id, &file_id)
        .map_err(|e| ApiError {
            code: "DB_ERROR".to_string(),
            message: e.to_string(),
        })
}

#[tauri::command]
async fn add_ioc_rule(
    name: String,
    rule_type: String,
    severity: String,
    pattern: String,
    hash_type: Option<String>,
    tags: Vec<String>,
    state: State<'_, Mutex<AppState>>,
) -> Result<i64, ApiError> {
    let scope_json = "{}".to_string();
    let tags_str = tags.join(",");

    let mut app_state = state.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    if let Some(conn) = app_state.db_manager.databases.values().next() {
        let conn = conn.lock().map_err(|e| ApiError {
            code: "LOCK_ERROR".to_string(),
            message: e.to_string(),
        })?;

        conn.insert_ioc_rule(
            &name,
            &rule_type,
            &severity,
            &pattern,
            hash_type.as_deref(),
            &tags_str,
            &scope_json,
        ).map_err(|e| ApiError {
            code: "INSERT_ERROR".to_string(),
            message: e.to_string(),
        })
    } else {
        Err(ApiError {
            code: "NO_DATABASE".to_string(),
            message: "No database available".to_string(),
        })
    }
}

#[tauri::command]
async fn list_ioc_rules(
    enabled_only: Option<bool>,
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<forensic_engine::case::database::IocRuleRow>, ApiError> {
    let app_state = state.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    if let Some(conn) = app_state.db_manager.databases.values().next() {
        let conn = conn.lock().map_err(|e| ApiError {
            code: "LOCK_ERROR".to_string(),
            message: e.to_string(),
        })?;

        conn.list_ioc_rules(enabled_only.unwrap_or(false))
            .map_err(|e| ApiError {
                code: "QUERY_ERROR".to_string(),
                message: e.to_string(),
            })
    } else {
        Err(ApiError {
            code: "NO_DATABASE".to_string(),
            message: "No database available".to_string(),
        })
    }
}

#[tauri::command]
async fn list_ioc_hits(
    case_id: String,
    limit: Option<usize>,
    since: Option<String>,
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<forensic_engine::case::database::IocHitRow>, ApiError> {
    let app_state = state.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    let conn = app_state
        .db_manager
        .get_connection(&case_id)
        .map_err(|e| ApiError {
            code: "DB_ERROR".to_string(),
            message: e.to_string(),
        })?;

    let conn = conn.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    conn.list_ioc_hits(&case_id, limit.unwrap_or(100), since.as_deref())
        .map_err(|e| ApiError {
            code: "QUERY_ERROR".to_string(),
            message: e.to_string(),
        })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IocScanOptions {
    pub include_files: bool,
    pub include_strings: bool,
    pub include_timeline: bool,
    pub severities: Option<Vec<String>>,
    pub rule_names: Option<Vec<String>>,
    pub max_hits: Option<u64>,
    pub emit_exhibits: bool,
    pub emit_timeline_events: bool,
}

#[tauri::command]
async fn queue_ioc_scan(
    case_id: String,
    options: Option<IocScanOptions>,
    state: State<'_, Mutex<AppState>>,
) -> Result<QueueJobResult, ApiError> {
    let opts = options.unwrap_or(IocScanOptions {
        include_files: true,
        include_strings: true,
        include_timeline: true,
        severities: None,
        rule_names: None,
        max_hits: Some(100000),
        emit_exhibits: true,
        emit_timeline_events: true,
    });

    let job_id = uuid::Uuid::new_v4().to_string();
    let params_json = serde_json::json!({
        "case_id": case_id,
        "options": opts,
    }).to_string();

    let app_state = state.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    let conn = app_state
        .db_manager
        .get_connection(&case_id)
        .map_err(|e| ApiError {
            code: "DB_ERROR".to_string(),
            message: e.to_string(),
        })?;

    let conn = conn.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    conn.execute(
        "INSERT INTO jobs (id, case_id, job_type, status, priority, params_json, created_by, created_at)
         VALUES (?1, ?2, 'IocScan', 'pending', 0, ?3, 'desktop', strftime('%s', 'now'))",
        params![
            job_id,
            case_id,
            params_json
        ],
    ).map_err(|e| ApiError {
        code: "INSERT_ERROR".to_string(),
        message: e.to_string(),
    })?;

    Ok(QueueJobResult { job_id })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CarveOptions {
    pub chunk_size: Option<u64>,
    pub overlap: Option<u64>,
    pub max_hits: Option<usize>,
    pub output_dir: Option<String>,
    pub allow_signatures: Option<Vec<String>>,
    pub max_size_override: Option<u64>,
}

#[tauri::command]
async fn queue_carving(
    case_id: String,
    evidence_id: String,
    volume_id: Option<String>,
    options: Option<CarveOptions>,
    state: State<'_, Mutex<AppState>>,
) -> Result<QueueJobResult, ApiError> {
    let opts = options.unwrap_or(CarveOptions {
        chunk_size: Some(1024 * 1024),
        overlap: Some(64),
        max_hits: Some(5000),
        output_dir: Some("carved".to_string()),
        allow_signatures: None,
        max_size_override: None,
    });

    let job_id = uuid::Uuid::new_v4().to_string();
    let params_json = serde_json::json!({
        "case_id": case_id,
        "evidence_id": evidence_id,
        "volume_id": volume_id,
        "options": opts,
    }).to_string();

    let app_state = state.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    let conn = app_state
        .db_manager
        .get_connection(&case_id)
        .map_err(|e| ApiError {
            code: "DB_ERROR".to_string(),
            message: e.to_string(),
        })?;

    let conn = conn.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    conn.execute(
        "INSERT INTO jobs (id, case_id, job_type, status, priority, params_json, created_by, created_at)
         VALUES (?1, ?2, 'CarvingScan', 'pending', 0, ?3, 'desktop', strftime('%s', 'now'))",
        params![
            job_id,
            case_id,
            params_json
        ],
    ).map_err(|e| ApiError {
        code: "INSERT_ERROR".to_string(),
        message: e.to_string(),
    })?;

    Ok(QueueJobResult { job_id })
}

#[tauri::command]
async fn list_carved_files(
    case_id: String,
    limit: Option<usize>,
    since: Option<String>,
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<forensic_engine::case::database::CarvedFileRow>, ApiError> {
    let app_state = state.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    let conn = app_state
        .db_manager
        .get_connection(&case_id)
        .map_err(|e| ApiError {
            code: "DB_ERROR".to_string(),
            message: e.to_string(),
        })?;

    let conn = conn.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    conn.list_carved_files(&case_id, limit.unwrap_or(100), since.as_deref())
        .map_err(|e| ApiError {
            code: "QUERY_ERROR".to_string(),
            message: e.to_string(),
        })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegionSetResult {
    pub regions: Vec<RegionInfo>,
    pub total_bytes: u64,
    pub region_count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegionInfo {
    pub start: u64,
    pub end: u64,
    pub length: u64,
    pub source: String,
}

#[tauri::command]
async fn list_unallocated_regions(
    case_id: String,
    volume_id: String,
    coalesce_gap: Option<u64>,
    state: State<'_, Mutex<AppState>>,
) -> Result<RegionSetResult, ApiError> {
    let gap = coalesce_gap.unwrap_or(1024 * 1024);
    
    let _app_state = state.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    Ok(RegionSetResult {
        regions: Vec::new(),
        total_bytes: 0,
        region_count: 0,
    })
}

#[tauri::command]
async fn file_table_query(
    case_id: String,
    db_path: String,
    source_types: Option<Vec<String>>,
    sort_field: String,
    sort_dir: String,
    limit: u32,
    cursor_json: Option<String>,
    name_contains: Option<String>,
    ext_filter: Option<Vec<String>>,
    category_filter: Option<Vec<String>>,
    min_size: Option<u64>,
    max_size: Option<u64>,
    state: State<'_, Mutex<AppState>>,
) -> Result<FileTableResult, ApiError> {
    let _app_state = state.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    let sort = match sort_field.as_str() {
        "path" => SortField::Path,
        "size" => SortField::Size,
        "modified" => SortField::ModifiedUtc,
        "created" => SortField::CreatedUtc,
        "entropy" => SortField::Entropy,
        "category" => SortField::Category,
        "score" => SortField::Score,
        "ext" | "extension" => SortField::Extension,
        _ => SortField::Name,
    };

    let dir = match sort_dir.as_str() {
        "desc" => SortDir::Desc,
        _ => SortDir::Asc,
    };

    let filter = FileTableFilter {
        case_id: case_id.clone(),
        source_types,
        path_prefix: None,
        name_contains,
        ext_in: ext_filter,
        category_in: category_filter,
        min_size,
        max_size,
        date_start_utc: None,
        date_end_utc: None,
        min_entropy: None,
        max_entropy: None,
        hash_sha256: None,
        tags_any: None,
        score_min: None,
    };

    let query = FileTableQuery {
        filter,
        sort_field: sort,
        sort_dir: dir,
        limit,
        cursor: None,
    };

    let db = CaseDatabase::open(&case_id, &PathBuf::from(&db_path))
        .map_err(|e| ApiError {
            code: "DB_ERROR".to_string(),
            message: e.to_string(),
        })?;

    db.get_file_table_rows(&query)
        .map_err(|e| ApiError {
            code: "QUERY_ERROR".to_string(),
            message: e.to_string(),
        })
}

#[tauri::command]
async fn file_table_preview(
    case_id: String,
    db_path: String,
    row_id: i64,
    source_type: String,
    source_id: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<serde_json::Value, ApiError> {
    let _app_state = state.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    let db = CaseDatabase::open(&case_id, &PathBuf::from(&db_path))
        .map_err(|e| ApiError {
            code: "DB_ERROR".to_string(),
            message: e.to_string(),
        })?;

    match source_type.as_str() {
        "fs" => {
            let files = db.get_mft_entries_paged(&case_id, Some(1), None, Some(source_id.clone()))
                .map_err(|e| ApiError {
                    code: "QUERY_ERROR".to_string(),
                    message: e.to_string(),
                })?;
            if let Some(entry) = files.first() {
                return Ok(serde_json::json!({
                    "type": "filesystem",
                    "source_id": source_id,
                    "path": entry.full_path,
                    "mft_sequence": entry.mft_sequence,
                    "mft_record": entry.mft_record_number,
                    "flags": entry.flags,
                    "size_bytes": entry.data_size,
                }));
            }
        }
        "carved" => {
            let carved = db.get_carved_file_by_id(&source_id)
                .map_err(|e| ApiError {
                    code: "QUERY_ERROR".to_string(),
                    message: e.to_string(),
                })?;
            if let Some(c) = carved {
                return Ok(serde_json::json!({
                    "type": "carved",
                    "source_id": source_id,
                    "file_offset": c.file_offset,
                    "size_bytes": c.size_bytes,
                    "entropy": c.entropy,
                    "signature": c.signature,
                }));
            }
        }
        "ioc" => {
            let hits = db.get_ioc_hits_paged(&case_id, Some(1), None, Some(source_id.clone()))
                .map_err(|e| ApiError {
                    code: "QUERY_ERROR".to_string(),
                    message: e.to_string(),
                })?;
            if let Some(hit) = hits.first() {
                return Ok(serde_json::json!({
                    "type": "ioc_hit",
                    "source_id": source_id,
                    "rule_name": hit.rule_name,
                    "matched_field": hit.matched_field,
                    "matched_value": hit.matched_value,
                    "severity": hit.severity,
                }));
            }
        }
        _ => {}
    }

    Ok(serde_json::json!({
        "type": "unknown",
        "message": "Preview not available for this source type"
    }))
}

#[tauri::command]
async fn rebuild_file_table(
    case_id: String,
    db_path: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<String, ApiError> {
    let _app_state = state.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    let db = CaseDatabase::open(&case_id, &PathBuf::from(&db_path))
        .map_err(|e| ApiError {
            code: "DB_ERROR".to_string(),
            message: e.to_string(),
        })?;

    db.clear_file_table(&case_id)
        .map_err(|e| ApiError {
            code: "DB_ERROR".to_string(),
            message: e.to_string(),
        })?;

    Ok(format!("File table cleared for case {}", case_id))
}

#[tauri::command]
async fn rebuild_scores(
    case_id: String,
    db_path: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<ScoreUpdateResult, ApiError> {
    let _app_state = state.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    let db = CaseDatabase::open(&case_id, &PathBuf::from(&db_path))
        .map_err(|e| ApiError {
            code: "DB_ERROR".to_string(),
            message: e.to_string(),
        })?;

    let updated = db.recompute_scores(&case_id, None)
        .map_err(|e| ApiError {
            code: "SCORE_ERROR".to_string(),
            message: e.to_string(),
        })?;

    Ok(ScoreUpdateResult { updated })
}

#[derive(serde::Serialize)]
struct ScoreUpdateResult {
    updated: u64,
}

#[tauri::command]
async fn explain_score(
    case_id: String,
    db_path: String,
    row_id: i64,
    state: State<'_, Mutex<AppState>>,
) -> Result<ScoreExplainResult, ApiError> {
    let _app_state = state.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    let db = CaseDatabase::open(&case_id, &PathBuf::from(&db_path))
        .map_err(|e| ApiError {
            code: "DB_ERROR".to_string(),
            message: e.to_string(),
        })?;

    let result = db.explain_file_table_score(&case_id, row_id)
        .map_err(|e| ApiError {
            code: "SCORE_ERROR".to_string(),
            message: e.to_string(),
        })?;

    Ok(ScoreExplainResult {
        score: result.score,
        signals: result.signals.into_iter().map(|s| ScoreSignalResult {
            key: s.key,
            points: s.points,
            evidence: s.evidence,
        }).collect(),
    })
}

#[derive(serde::Serialize)]
struct ScoreExplainResult {
    score: f64,
    signals: Vec<ScoreSignalResult>,
}

#[derive(serde::Serialize)]
struct ScoreSignalResult {
    key: String,
    points: f64,
    evidence: String,
}

#[tauri::command]
fn generate_diagnostics_bundle(
    output_dir: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<diagnostics::DiagnosticsBundle, ApiError> {
    let state = state.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;

    diagnostics::generate_diagnostics_bundle(&output_dir, &state)
        .map_err(|e| ApiError {
            code: "DIAGNOSTICS_ERROR".to_string(),
            message: e.to_string(),
        })
}

#[tauri::command]
fn install_webview2() -> Result<String, ApiError> {
    #[cfg(target_os = "windows")]
    {
        diagnostics::webview2::download_and_install_evergreen()
            .map_err(|e| ApiError {
                code: "WEBVIEW2_INSTALL_ERROR".to_string(),
                message: e.to_string(),
            })
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err(ApiError {
            code: "NOT_SUPPORTED".to_string(),
            message: "WebView2 installation only supported on Windows".to_string(),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkerStatus {
    pub queued: i64,
    pub running: i64,
    pub last_status: String,
}

#[tauri::command]
async fn worker_run_once(
    case_id: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<(), ApiError> {
    use forensic_engine::context::EngineContext;
    
    let _ctx = EngineContext::with_case(&case_id);
    Ok(())
}

#[tauri::command]
async fn worker_start_loop(
    case_id: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<(), ApiError> {
    let mut app_state = state.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;
    
    if app_state.worker_loop_running.load(Ordering::SeqCst) {
        return Err(ApiError {
            code: "ALREADY_RUNNING".to_string(),
            message: "Worker loop is already running".to_string(),
        });
    }
    
    app_state.worker_loop_running.store(true, Ordering::SeqCst);
    Ok(())
}

#[tauri::command]
async fn worker_stop_loop(
    state: State<'_, Mutex<AppState>>,
) -> Result<(), ApiError> {
    let mut app_state = state.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;
    
    app_state.worker_loop_running.store(false, Ordering::SeqCst);
    Ok(())
}

#[tauri::command]
async fn worker_status(
    state: State<'_, Mutex<AppState>>,
) -> Result<WorkerStatus, ApiError> {
    let app_state = state.lock().map_err(|e| ApiError {
        code: "LOCK_ERROR".to_string(),
        message: e.to_string(),
    })?;
    
    let running = app_state.worker_loop_running.load(Ordering::SeqCst);
    
    Ok(WorkerStatus {
        queued: 0,
        running: if running { 1 } else { 0 },
        last_status: if running { "running" } else { "stopped" }.to_string(),
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let safe_mode = args.iter().any(|a| a == "--safe-mode");

    if safe_mode {
        run_safe_mode();
        return;
    }

    let report = run_preflight_checks();
    let _ = save_preflight_report(&report);

    if report.overall_status == PreflightStatus::Fail {
        eprintln!("Preflight checks failed. Launching safe mode...");
        run_safe_mode();
        return;
    }

    if report.overall_status == PreflightStatus::Warn {
        eprintln!("Preflight warnings detected. Proceeding with caution...");
    }

    tauri::Builder::default()
        .manage(Mutex::new(AppState::new()))
        .setup(|app| {
            let app_handle = app.handle().clone();
            let state = app.state::<Mutex<AppState>>();
            
            let event_bus = {
                let state = state.lock().unwrap();
                state.event_bus.clone()
            };
            
            std::thread::spawn(move || {
                let mut rx = event_bus.subscribe();
                loop {
                    if let Ok(event) = rx.blocking_recv() {
                        let _ = app_handle.emit_all("engine_event", &event);
                    }
                    if event_bus.is_closed() {
                        break;
                    }
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            open_case,
            list_cases,
            open_evidence,
            detect_evidence,
            get_activity_log_after,
            get_evidence_timeline_after,
            get_bookmarks_paged,
            get_exhibits_paged,
            run_verify,
            run_replay,
            run_triage_session,
            add_to_notes,
            export_case,
            set_watchpoints,
            list_violations,
            clear_violations,
            get_event_buffer,
            run_preflight,
            get_preflight_report,
            generate_diagnostics_bundle,
            install_webview2,
            get_capabilities,
            global_search,
            rebuild_global_search,
            queue_strings_extraction,
            get_file_strings,
            add_ioc_rule,
            list_ioc_rules,
            list_ioc_hits,
            queue_ioc_scan,
            queue_carving,
            list_carved_files,
            list_unallocated_regions,
            file_table_query,
            file_table_preview,
            rebuild_file_table,
            rebuild_scores,
            explain_score,
            list_presets,
            get_preset,
            start_examination,
            generate_report_skeleton,
            worker_run_once,
            worker_start_loop,
            worker_stop_loop,
            worker_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn run_safe_mode() {
    println!("=== Forensic Suite Safe Mode ===");
    println!();
    
    if let Some(report) = preflight::load_latest_preflight_report() {
        println!("Latest Preflight Report:");
        println!("Overall Status: {:?}", report.overall_status);
        println!();
        
        for result in &report.results {
            println!("[{:?}] {}", result.status, result.name);
            println!("  {}", result.message);
        }
    } else {
        println!("No preflight report available.");
    }
    
    println!();
    println!("Diagnostics: forensic_desktop generate-diagnostics --output <dir>");
    println!("CLI Help: forensic_cli --help");
    println!();
    
    if let Some(app_dir) = preflight::system::get_app_data_dir() {
        println!("Log directory: {}", app_dir.display());
    }
}
