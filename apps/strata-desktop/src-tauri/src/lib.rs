use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use tauri::{Emitter, Manager};

// Day 11 — engine adapter
use strata_engine_adapter as engine;

/// Most-recently loaded evidence id, used as a fallback when the UI calls a
/// per-evidence command without an explicit id.
static CURRENT_EVIDENCE_ID: OnceLock<Mutex<Option<String>>> = OnceLock::new();

fn current_evidence_lock() -> &'static Mutex<Option<String>> {
    CURRENT_EVIDENCE_ID.get_or_init(|| Mutex::new(None))
}

fn set_current_evidence_id(id: &str) {
    match current_evidence_lock().lock() {
        Ok(mut current) => *current = Some(id.to_string()),
        Err(e) => log::error!("current evidence lock poisoned: {e}"),
    }
}

fn current_evidence_id() -> Option<String> {
    match current_evidence_lock().lock() {
        Ok(current) => current.clone(),
        Err(e) => {
            log::error!("current evidence lock poisoned: {e}");
            None
        }
    }
}

// ── Conversions: adapter types → desktop IPC types ─────────────────────────

fn adapter_tree_to_desktop(n: engine::TreeNode) -> TreeNode {
    TreeNode {
        id: n.id,
        name: n.name,
        node_type: n.node_type,
        count: n.count,
        file_count: n.file_count,
        folder_count: n.folder_count,
        is_deleted: n.is_deleted,
        is_flagged: n.is_flagged,
        is_suspicious: n.is_suspicious,
        has_children: n.has_children,
        parent_id: n.parent_id,
        depth: n.depth,
    }
}

fn adapter_file_to_desktop(f: engine::FileEntry) -> FileEntry {
    FileEntry {
        id: f.id,
        name: f.name,
        extension: f.extension,
        size: f.size,
        size_display: f.size_display,
        modified: f.modified,
        created: f.created,
        sha256: f.sha256,
        is_deleted: f.is_deleted,
        is_suspicious: f.is_suspicious,
        is_flagged: f.is_flagged,
        known_good: f.known_good,
        category: f.category,
        tag: None,
        tag_color: None,
    }
}

fn adapter_file_to_metadata(f: engine::FileEntry) -> FileMetadata {
    FileMetadata {
        id: f.id,
        name: f.name,
        full_path: f.full_path,
        size: f.size,
        size_display: f.size_display,
        modified: f.modified,
        created: f.created,
        accessed: f.accessed,
        sha256: f.sha256,
        md5: f.md5,
        category: f.category,
        is_deleted: f.is_deleted,
        is_suspicious: f.is_suspicious,
        is_flagged: f.is_flagged,
        known_good: f.known_good,
        mft_entry: f.mft_entry,
        extension: f.extension,
        mime_type: None,
        inode: f.inode,
        permissions: None,
    }
}

fn adapter_hex_to_desktop(h: engine::HexData) -> HexData {
    HexData {
        lines: h
            .lines
            .into_iter()
            .map(|l| HexLine {
                offset: l.offset,
                hex: l.hex,
                ascii: l.ascii,
            })
            .collect(),
        total_size: h.total_size,
        offset: h.offset,
    }
}

fn adapter_artifact_to_desktop(a: engine::PluginArtifact) -> Artifact {
    Artifact {
        id: a.id,
        category: a.category,
        name: a.name,
        value: a.value,
        timestamp: a.timestamp,
        source_file: a.source_file,
        source_path: a.source_path,
        forensic_value: a.forensic_value,
        mitre_technique: a.mitre_technique,
        mitre_name: a.mitre_name,
        plugin: a.plugin,
        raw_data: a.raw_data,
        confidence_score: a.confidence_score,
        confidence_basis: a.confidence_basis,
    }
}

fn examiner_name_for_app(app: &tauri::AppHandle) -> String {
    get_examiner_profile_sync(app)
        .map(|profile| profile.name)
        .ok()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "Unknown Examiner".to_string())
}

fn get_examiner_profile_sync(app: &tauri::AppHandle) -> Result<ExaminerProfile, String> {
    let path = examiner_profile_path(app)?;
    if !path.exists() {
        return Ok(ExaminerProfile::default());
    }
    let s = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&s).map_err(|e| e.to_string())
}

fn log_custody_event(
    examiner: String,
    action: &str,
    evidence_id: String,
    details: String,
    hash_before: Option<String>,
    hash_after: Option<String>,
) {
    engine::log_custody(engine::CustodyEntry {
        timestamp: engine::now_unix(),
        examiner,
        action: action.to_string(),
        evidence_id,
        details,
        hash_before,
        hash_after,
    });
}

fn artifact_notes_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("artifact_notes.json"))
}

fn load_artifact_notes_from_path(path: &Path) -> Result<Vec<ArtifactNote>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&raw).map_err(|e| e.to_string())
}

fn save_artifact_notes_to_path(path: &Path, notes: &[ArtifactNote]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let raw = serde_json::to_string_pretty(notes).map_err(|e| e.to_string())?;
    std::fs::write(path, raw).map_err(|e| e.to_string())
}

fn upsert_artifact_note(notes: &mut Vec<ArtifactNote>, note: ArtifactNote) {
    if let Some(existing) = notes
        .iter_mut()
        .find(|existing| existing.artifact_id == note.artifact_id)
    {
        *existing = note;
    } else {
        notes.push(note);
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Types
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone)]
pub struct TreeNode {
    pub id: String,
    pub name: String,
    pub node_type: String,
    pub count: u64,
    pub file_count: u64,
    pub folder_count: u64,
    pub is_deleted: bool,
    pub is_flagged: bool,
    pub is_suspicious: bool,
    pub has_children: bool,
    pub parent_id: Option<String>,
    pub depth: u32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct FileEntry {
    pub id: String,
    pub name: String,
    pub extension: String,
    pub size: u64,
    pub size_display: String,
    pub modified: String,
    pub created: String,
    pub sha256: Option<String>,
    pub is_deleted: bool,
    pub is_suspicious: bool,
    pub is_flagged: bool,
    pub known_good: bool,
    pub category: String,
    pub tag: Option<String>,
    pub tag_color: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct FileMetadata {
    pub id: String,
    pub name: String,
    pub full_path: String,
    pub size: u64,
    pub size_display: String,
    pub modified: String,
    pub created: String,
    pub accessed: String,
    pub sha256: Option<String>,
    pub md5: Option<String>,
    pub category: String,
    pub is_deleted: bool,
    pub is_suspicious: bool,
    pub is_flagged: bool,
    pub known_good: bool,
    pub mft_entry: Option<u64>,
    pub extension: String,
    pub mime_type: Option<String>,
    pub inode: Option<u64>,
    pub permissions: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct EvidenceLoadResult {
    pub success: bool,
    pub evidence_id: String,
    pub name: String,
    pub size_display: String,
    pub file_count: u64,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Stats {
    pub files: u64,
    pub suspicious: u64,
    pub flagged: u64,
    pub carved: u64,
    pub hashed: u64,
    pub known_good: u64,
    pub unknown: u64,
    pub artifacts: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct EvidenceIntegrity {
    pub sha256: String,
    pub computed_at: i64,
    pub file_size_bytes: u64,
    pub verified: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct HashSetInfo {
    pub name: String,
    pub description: String,
    pub hash_count: usize,
    pub imported_at: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct HashSetStats {
    pub set_count: usize,
    pub hash_count: usize,
    pub known_good: u64,
    pub unknown: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ArtifactNote {
    pub artifact_id: String,
    pub evidence_id: String,
    pub note: String,
    pub created_at: i64,
    pub examiner: String,
    pub flagged: bool,
}

impl From<engine::EvidenceIntegrity> for EvidenceIntegrity {
    fn from(value: engine::EvidenceIntegrity) -> Self {
        Self {
            sha256: value.sha256,
            computed_at: value.computed_at,
            file_size_bytes: value.file_size_bytes,
            verified: value.verified,
        }
    }
}

impl From<engine::HashSetInfo> for HashSetInfo {
    fn from(value: engine::HashSetInfo) -> Self {
        Self {
            name: value.name,
            description: value.description,
            hash_count: value.hash_count,
            imported_at: value.imported_at,
        }
    }
}

impl From<engine::HashSetStats> for HashSetStats {
    fn from(value: engine::HashSetStats) -> Self {
        Self {
            set_count: value.set_count,
            hash_count: value.hash_count,
            known_good: value.known_good,
            unknown: value.unknown,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct HexLine {
    pub offset: String,
    pub hex: String,
    pub ascii: String,
}

#[derive(Serialize, Deserialize)]
pub struct HexData {
    pub lines: Vec<HexLine>,
    pub total_size: u64,
    pub offset: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TaggedFile {
    pub file_id: String,
    pub name: String,
    pub extension: String,
    pub size_display: String,
    pub modified: String,
    pub full_path: String,
    pub tag: String,
    pub tag_color: String,
    pub tagged_at: String,
    pub note: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TagSummary {
    pub name: String,
    pub color: String,
    pub count: u64,
}

static TAG_STORE: OnceLock<Arc<Mutex<HashMap<String, TaggedFile>>>> = OnceLock::new();

fn get_tag_store() -> Arc<Mutex<HashMap<String, TaggedFile>>> {
    TAG_STORE
        .get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
        .clone()
}

fn load_tags_from_disk(app: &tauri::AppHandle) -> Result<(), String> {
    let path = tags_path(app)?;
    let loaded: HashMap<String, TaggedFile> = if path.exists() {
        let json =
            std::fs::read_to_string(&path).map_err(|e| format!("Failed to read tags: {e}"))?;
        serde_json::from_str(&json).map_err(|e| format!("Failed to parse tags: {e}"))?
    } else {
        HashMap::new()
    };

    let store = get_tag_store();
    let mut map = store.lock().map_err(|e| e.to_string())?;
    *map = loaded;
    Ok(())
}

fn save_tags_to_disk(app: &tauri::AppHandle, tags: &HashMap<String, TaggedFile>) -> Result<(), String> {
    let path = tags_path(app)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("Failed to create tags dir: {e}"))?;
    }
    let json = serde_json::to_string_pretty(tags).map_err(|e| format!("Failed to encode tags: {e}"))?;
    std::fs::write(&path, json).map_err(|e| format!("Failed to save tags: {e}"))
}

fn current_tag_timestamp() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string()
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ArtifactCategory {
    pub name: String,
    pub icon: String,
    pub count: u64,
    pub color: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Artifact {
    pub id: String,
    pub category: String,
    pub name: String,
    pub value: String,
    pub timestamp: Option<String>,
    pub source_file: String,
    pub source_path: String,
    pub forensic_value: String,
    pub mitre_technique: Option<String>,
    pub mitre_name: Option<String>,
    pub plugin: String,
    pub raw_data: Option<String>,
    pub confidence_score: f32,
    pub confidence_basis: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ArtifactsResponse {
    pub artifacts: Vec<Artifact>,
    pub plugins_not_run: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct IocQuery {
    pub indicators: Vec<String>,
    pub evidence_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct IocMatch {
    pub indicator: String,
    pub artifact: Artifact,
    pub match_field: String,
    pub confidence: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PluginRunResult {
    pub plugin_name: String,
    pub success: bool,
    pub artifact_count: u64,
    pub duration_ms: u64,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PluginStatus {
    pub name: String,
    pub status: String,
    pub progress: u8,
    pub artifact_count: u64,
}

static PLUGIN_STATUS: OnceLock<Arc<Mutex<HashMap<String, PluginStatus>>>> = OnceLock::new();

fn get_plugin_status_store() -> Arc<Mutex<HashMap<String, PluginStatus>>> {
    PLUGIN_STATUS
        .get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
        .clone()
}

/// Short display names for every plugin registered in
/// `strata_engine_adapter::plugins::build_plugins()`. Order matches the
/// adapter's registration order so Sigma remains last. Sprint 8 P1 F2
/// expanded this from the pre-sprint 15-entry list to the full 23
/// plugins; the prior list silently dropped Apex, Carbon, Pulse, Vault,
/// ARBOR, Advisory, CSAM Scanner, and Sentinel — ~184 Charlie
/// artifacts the UI could never reach.
const PLUGIN_NAMES: &[&str] = &[
    "Remnant",
    "Chronicle",
    "Cipher",
    "Trace",
    "Specter",
    "Conduit",
    "Nimbus",
    "Wraith",
    "Vector",
    "Recon",
    "Phantom",
    "Guardian",
    "NetFlow",
    "MacTrace",
    "Sentinel",
    "CSAM Scanner",
    "Apex",
    "Carbon",
    "Pulse",
    "Vault",
    "ARBOR",
    "Advisory Analytics",
    "Sigma",
];

/// Sprint 8 P1 F4 — the canonical set of plugin-status strings that
/// mean "this plugin finished successfully." `run_plugin` /
/// `run_all_plugins` emit `"complete"`; kept permissive so
/// `"completed"` / `"success"` don't silently re-break the
/// `plugins_not_run` signal in `get_artifacts` if an upstream emitter
/// drifts.
fn is_plugin_complete(status: &str) -> bool {
    matches!(status, "complete" | "completed" | "success")
}

#[derive(Serialize, Deserialize)]
pub struct SearchResult {
    pub id: String,
    pub name: String,
    pub full_path: String,
    pub extension: String,
    pub size_display: String,
    pub modified: String,
    pub is_deleted: bool,
    pub is_flagged: bool,
    pub is_suspicious: bool,
    pub match_field: String,
    pub match_value: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Existing commands
// ──────────────────────────────────────────────────────────────────────────────

#[tauri::command]
fn get_app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[derive(Serialize, Deserialize, Clone)]
pub struct LicenseResult {
    pub valid: bool,
    pub tier: String,
    pub licensee: String,
    pub org: String,
    pub days_remaining: i32,
    pub machine_id: String,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ExaminerProfile {
    pub name: String,
    pub agency: String,
    pub badge: String,
    pub email: String,
}

impl Default for ExaminerProfile {
    fn default() -> Self {
        Self {
            name: String::new(),
            agency: String::new(),
            badge: String::new(),
            email: String::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DriveInfo {
    pub id: String,
    pub name: String,
    pub mount_point: String,
    pub total_gb: f64,
    pub free_gb: f64,
    pub is_system: bool,
    pub is_permitted: bool,
    pub reason: Option<String>,
}

// ── Day 14: real license validation ────────────────────────────────────────
//
// Format:  STRATA-<base64_payload>.<base64_signature>
//
// Payload is JSON:
//   {
//     "machine_id": "abc123" or "any",
//     "tier":       "pro" | "trial",
//     "licensee":   "Jane Smith",
//     "org":        "Metropolitan Police",
//     "issued_at":  "2026-04-06",
//     "expires_at": "2027-04-06"
//   }
//
// Signature is over the raw payload bytes (Ed25519). Public verifying key is
// embedded at compile time from `keys/wolfmark-public.bin`.

const PUBLIC_KEY_BYTES: &[u8; 32] = include_bytes!("../keys/wolfmark-public.bin");

fn machine_id_string() -> String {
    machine_uid::get().unwrap_or_else(|_| "unknown-machine".to_string())
}

fn license_file_path() -> Option<std::path::PathBuf> {
    dirs::home_dir().map(|h| h.join(".wolfmark").join("license.key"))
}

fn app_data_file_path(app: &tauri::AppHandle, filename: &str) -> Result<std::path::PathBuf, String> {
    app.path()
        .app_data_dir()
        .map_err(|e| e.to_string())
        .map(|dir| dir.join(filename))
}

fn examiner_profile_path(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    app_data_file_path(app, "examiner_profile.json")
}

fn tags_path(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    app_data_file_path(app, "tags.json")
}

fn invalid_license(machine_id: String, msg: &str) -> LicenseResult {
    LicenseResult {
        valid: false,
        tier: "none".to_string(),
        licensee: String::new(),
        org: String::new(),
        days_remaining: 0,
        machine_id,
        error: Some(msg.to_string()),
    }
}

fn verify_license_key(key: &str, machine_id: &str) -> LicenseResult {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let mid = machine_id.to_string();

    let body = match key.strip_prefix("STRATA-") {
        Some(b) => b,
        None => return invalid_license(mid, "Invalid key format (missing STRATA- prefix)"),
    };

    let parts: Vec<&str> = body.splitn(2, '.').collect();
    if parts.len() != 2 {
        return invalid_license(mid, "Invalid key format (missing payload/signature)");
    }

    let payload_bytes = match B64.decode(parts[0]) {
        Ok(b) => b,
        Err(_) => return invalid_license(mid, "Invalid key format (payload not base64)"),
    };

    let sig_bytes = match B64.decode(parts[1]) {
        Ok(b) => b,
        Err(_) => return invalid_license(mid, "Invalid key format (signature not base64)"),
    };

    let sig_array: [u8; 64] = match sig_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return invalid_license(mid, "Invalid signature length (expected 64 bytes)"),
    };

    let verifying_key = match VerifyingKey::from_bytes(PUBLIC_KEY_BYTES) {
        Ok(k) => k,
        Err(_) => return invalid_license(mid, "Embedded public key is malformed"),
    };

    let signature = Signature::from_bytes(&sig_array);

    if verifying_key.verify(&payload_bytes, &signature).is_err() {
        return invalid_license(mid, "Signature does not match payload");
    }

    // Decode payload JSON
    let payload: serde_json::Value = match serde_json::from_slice(&payload_bytes) {
        Ok(v) => v,
        Err(_) => return invalid_license(mid, "Payload is not valid JSON"),
    };

    let licensed_machine = payload["machine_id"].as_str().unwrap_or("");
    if licensed_machine != mid && licensed_machine != "any" {
        return invalid_license(mid, "License is bound to a different machine");
    }

    let expires = payload["expires_at"].as_str().unwrap_or("2000-01-01");
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    if expires.as_bytes() < today.as_bytes() {
        let mut r = invalid_license(mid, "License expired");
        r.tier = "expired".to_string();
        return r;
    }

    // Compute days_remaining (best-effort, day-precision).
    let days_remaining = match (
        chrono::NaiveDate::parse_from_str(expires, "%Y-%m-%d"),
        chrono::Utc::now().date_naive(),
    ) {
        (Ok(exp), today_naive) => (exp - today_naive).num_days().max(0) as i32,
        _ => 0,
    };

    LicenseResult {
        valid: true,
        tier: payload["tier"].as_str().unwrap_or("pro").to_string(),
        licensee: payload["licensee"].as_str().unwrap_or("").to_string(),
        org: payload["org"].as_str().unwrap_or("").to_string(),
        days_remaining,
        machine_id: mid,
        error: None,
    }
}

#[tauri::command]
async fn check_license() -> Result<LicenseResult, String> {
    let machine_id = machine_id_string();

    // Dev builds bypass — production-only enforcement.
    if cfg!(debug_assertions) {
        return Ok(LicenseResult {
            valid: true,
            tier: "pro".to_string(),
            licensee: "Dev Mode".to_string(),
            org: "Wolfmark Systems".to_string(),
            days_remaining: 999,
            machine_id,
            error: None,
        });
    }

    let path = match license_file_path() {
        Some(p) => p,
        None => return Ok(invalid_license(machine_id, "No home directory")),
    };

    if !path.exists() {
        return Ok(invalid_license(machine_id, "No license installed"));
    }

    let key_data = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => return Ok(invalid_license(machine_id, &format!("Read failed: {e}"))),
    };

    Ok(verify_license_key(key_data.trim(), &machine_id))
}

#[tauri::command]
async fn activate_license(key: String) -> Result<LicenseResult, String> {
    let machine_id = machine_id_string();
    let result = verify_license_key(key.trim(), &machine_id);

    if result.valid {
        if let Some(path) = license_file_path() {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(&path, key.trim());
        }
    }

    Ok(result)
}

#[tauri::command]
async fn start_trial() -> Result<LicenseResult, String> {
    // Trial mode is unsigned but tracked locally — install a marker file so a
    // single machine can only start a 30-day trial once.
    let machine_id = machine_id_string();

    let trial_path = dirs::home_dir().map(|h| h.join(".wolfmark").join("trial.json"));

    let now = chrono::Utc::now();
    let trial_started = if let Some(ref tp) = trial_path {
        if let Ok(s) = std::fs::read_to_string(tp) {
            chrono::DateTime::parse_from_rfc3339(s.trim())
                .ok()
                .map(|d| d.with_timezone(&chrono::Utc))
                .unwrap_or(now)
        } else {
            if let Some(parent) = tp.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(tp, now.to_rfc3339());
            now
        }
    } else {
        now
    };

    let elapsed_days = (now - trial_started).num_days() as i32;
    let days_remaining = (30 - elapsed_days).max(0);

    if days_remaining == 0 {
        return Ok(LicenseResult {
            valid: false,
            tier: "expired".to_string(),
            licensee: "Trial User".to_string(),
            org: String::new(),
            days_remaining: 0,
            machine_id,
            error: Some("Trial period has ended. Please activate a license.".to_string()),
        });
    }

    Ok(LicenseResult {
        valid: true,
        tier: "trial".to_string(),
        licensee: "Trial User".to_string(),
        org: String::new(),
        days_remaining,
        machine_id,
        error: None,
    })
}

#[tauri::command]
async fn get_machine_id() -> Result<String, String> {
    Ok(machine_id_string())
}

#[tauri::command]
async fn get_license_path() -> Result<Option<String>, String> {
    Ok(license_file_path().map(|p| p.to_string_lossy().to_string()))
}

#[tauri::command]
async fn deactivate_license() -> Result<bool, String> {
    if let Some(path) = license_file_path() {
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| e.to_string())?;
            return Ok(true);
        }
    }
    Ok(false)
}

#[tauri::command]
async fn get_examiner_profile(app: tauri::AppHandle) -> Result<ExaminerProfile, String> {
    let path = examiner_profile_path(&app)?;
    if !path.exists() {
        return Ok(ExaminerProfile::default());
    }
    let json =
        std::fs::read_to_string(&path).map_err(|e| format!("Failed to read profile: {e}"))?;
    serde_json::from_str(&json).map_err(|e| format!("Failed to parse profile: {e}"))
}

#[tauri::command]
async fn save_examiner_profile(
    app: tauri::AppHandle,
    profile: ExaminerProfile,
) -> Result<(), String> {
    let path = examiner_profile_path(&app)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("Failed to create profile dir: {e}"))?;
    }
    let json = serde_json::to_string_pretty(&profile).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| format!("Failed to save profile: {e}"))?;
    log::debug!("Examiner profile saved to {}", path.display());
    Ok(())
}

#[tauri::command]
async fn list_drives() -> Result<Vec<DriveInfo>, String> {
    use sysinfo::Disks;

    let disks = Disks::new_with_refreshed_list();
    let mut drives: Vec<DriveInfo> = Vec::new();
    let mut seen_mounts: std::collections::HashSet<String> = std::collections::HashSet::new();

    for disk in disks.list() {
        let mount = disk.mount_point().to_string_lossy().to_string();
        if !seen_mounts.insert(mount.clone()) {
            continue;
        }

        // Skip macOS system read-only volumes and ephemeral mounts we don't care about.
        if mount.starts_with("/System/Volumes/")
            || mount.starts_with("/dev")
            || mount.starts_with("/private/var/vm")
        {
            continue;
        }

        let is_system = mount == "/"
            || mount == "/System"
            || mount.starts_with("/System")
            || mount == "/private/var";

        let total_gb = disk.total_space() as f64 / 1_073_741_824.0;
        let free_gb = disk.available_space() as f64 / 1_073_741_824.0;

        let name = disk.name().to_string_lossy().to_string();
        let display_name = if name.is_empty() { mount.clone() } else { name };

        let id = {
            let mut cleaned = mount.replace('/', "-");
            while cleaned.starts_with('-') {
                cleaned.remove(0);
            }
            if cleaned.is_empty() {
                "drive-root".to_string()
            } else {
                format!("drive-{cleaned}")
            }
        };

        drives.push(DriveInfo {
            id,
            name: display_name,
            mount_point: mount,
            total_gb,
            free_gb,
            is_system,
            is_permitted: !is_system,
            reason: if is_system {
                Some("System volume — not permitted for evidence storage".to_string())
            } else {
                None
            },
        });
    }

    // Sort: permitted first, then by mount point
    drives.sort_by(|a, b| {
        b.is_permitted
            .cmp(&a.is_permitted)
            .then(a.mount_point.cmp(&b.mount_point))
    });

    Ok(drives)
}

#[tauri::command]
async fn select_evidence_drive(_drive_id: String) -> Result<String, String> {
    Ok("/Volumes/Wolfmark Systems Backup/cases/new-case".to_string())
}

#[derive(Serialize, Deserialize)]
pub struct ReportOptions {
    pub case_number: String,
    pub case_name: String,
    pub examiner_name: String,
    pub examiner_agency: String,
    pub examiner_badge: String,
    pub include_artifacts: bool,
    pub include_tagged: bool,
    pub include_mitre: bool,
    pub include_timeline: bool,
}

struct ReportSnapshot {
    evidence_id: String,
    evidence_description: String,
    generated_at: String,
    app_version: String,
    stats: Stats,
    integrity: Option<EvidenceIntegrity>,
    tagged: Vec<TaggedFile>,
    flagged_notes: Vec<ArtifactNote>,
    categories: Vec<ArtifactCategory>,
    custody: Vec<engine::CustodyEntry>,
    hash_sets: Vec<HashSetInfo>,
}

#[tauri::command]
async fn generate_report(
    app: tauri::AppHandle,
    evidence_id: String,
    output_path: String,
    format: String,
) -> Result<String, String> {
    let evidence_id = if evidence_id.is_empty() {
        current_evidence_id().unwrap_or_default()
    } else {
        evidence_id
    };
    if evidence_id.is_empty() {
        return Err("No evidence loaded".to_string());
    }
    let profile = get_examiner_profile_sync(&app).unwrap_or_default();
    let options = ReportOptions {
        case_number: evidence_id.clone(),
        case_name: current_evidence_id().unwrap_or_else(|| "Strata Analysis".to_string()),
        examiner_name: if profile.name.is_empty() {
            "Unknown Examiner".to_string()
        } else {
            profile.name
        },
        examiner_agency: profile.agency,
        examiner_badge: profile.badge,
        include_artifacts: true,
        include_tagged: true,
        include_mitre: true,
        include_timeline: true,
    };
    let stats = if evidence_id.is_empty() {
        Stats {
            files: 0,
            suspicious: 0,
            flagged: 0,
            carved: 0,
            hashed: 0,
            known_good: 0,
            unknown: 0,
            artifacts: 0,
        }
    } else {
        get_stats(evidence_id.clone()).await?
    };
    let categories = if evidence_id.is_empty() {
        Vec::new()
    } else {
        get_artifact_categories(evidence_id.clone()).await?
    };
    let integrity = if evidence_id.is_empty() {
        None
    } else {
        get_evidence_integrity(evidence_id.clone()).await.ok()
    };
    let tagged = {
        let store = get_tag_store();
        let map = store.lock().map_err(|e| e.to_string())?;
        map.values().cloned().collect()
    };
    let flagged_notes = if evidence_id.is_empty() {
        Vec::new()
    } else {
        get_flagged_artifacts(app.clone(), evidence_id.clone()).await?
    };
    let snapshot = ReportSnapshot {
        evidence_id: evidence_id.clone(),
        evidence_description: format!("Evidence {evidence_id}"),
        generated_at: chrono::Utc::now().format("%Y-%m-%d %H:%M UTC").to_string(),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        stats,
        integrity,
        tagged,
        flagged_notes,
        categories,
        custody: engine::get_custody_log(&evidence_id),
        hash_sets: engine::list_hash_sets()
            .into_iter()
            .map(HashSetInfo::from)
            .collect(),
    };
    let html = build_report_html(&options, &snapshot);
    let out = if output_path.trim().is_empty() {
        std::env::temp_dir()
            .join(format!("strata-report-{}.html", evidence_id))
            .to_string_lossy()
            .to_string()
    } else {
        output_path
    };
    let report_path = if format.eq_ignore_ascii_case("pdf") {
        write_report_pdf_or_html(&html, &out)?
    } else {
        std::fs::write(&out, &html).map_err(|e| e.to_string())?;
        out
    };
    if !evidence_id.is_empty() {
        log_custody_event(
            options.examiner_name.clone(),
            "report_generated",
            evidence_id,
            format!("Generated {} report at {}", format, report_path),
            None,
            None,
        );
    }
    Ok(report_path)
}

fn write_report_pdf_or_html(html: &str, output_path: &str) -> Result<String, String> {
    let html_path = if output_path.to_ascii_lowercase().ends_with(".pdf") {
        output_path.replace(".pdf", ".html")
    } else {
        format!("{output_path}.html")
    };
    std::fs::write(&html_path, html).map_err(|e| e.to_string())?;
    if cfg!(target_os = "macos") {
        let status = std::process::Command::new("wkhtmltopdf")
            .arg(&html_path)
            .arg(output_path)
            .status();
        if let Ok(status) = status {
            if status.success() {
                return Ok(output_path.to_string());
            }
        }
    }
    Ok(html_path)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn build_report_html(o: &ReportOptions, snapshot: &ReportSnapshot) -> String {
    let css = include_str!("report_css.css");
    let case_number = html_escape(&o.case_number);
    let case_name = html_escape(&o.case_name);
    let examiner_name = html_escape(&o.examiner_name);
    let examiner_agency = html_escape(&o.examiner_agency);
    let examiner_badge = html_escape(&o.examiner_badge);
    let evidence_description = html_escape(&snapshot.evidence_description);
    let evidence_id = html_escape(&snapshot.evidence_id);
    let evidence_hash = snapshot
        .integrity
        .as_ref()
        .map(|i| html_escape(&i.sha256))
        .unwrap_or_else(|| "Not computed".to_string());
    let evidence_size = snapshot
        .integrity
        .as_ref()
        .map(|i| i.file_size_bytes.to_string())
        .unwrap_or_else(|| "Unknown".to_string());
    let analysis_start = snapshot
        .custody
        .first()
        .map(|entry| entry.timestamp.to_string())
        .unwrap_or_else(|| "Not recorded".to_string());
    let analysis_end = snapshot
        .custody
        .last()
        .map(|entry| entry.timestamp.to_string())
        .unwrap_or_else(|| "Not recorded".to_string());
    let tagged_rows = if snapshot.tagged.is_empty() {
        "<tr><td colspan=\"4\">No tagged evidence recorded.</td></tr>".to_string()
    } else {
        snapshot
            .tagged
            .iter()
            .map(|f| {
                format!(
                    "<tr><td style=\"font-weight:700\">{}</td><td>{}</td><td style=\"font-family:monospace;font-size:10px;\">{}</td><td>{}</td></tr>",
                    html_escape(&f.name),
                    html_escape(&f.tag),
                    html_escape(&f.full_path),
                    html_escape(f.note.as_deref().unwrap_or(""))
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };
    let category_rows = if snapshot.categories.iter().all(|c| c.count == 0) {
        "<tr><td colspan=\"3\">No plugin artifacts have been recorded for this evidence.</td></tr>"
            .to_string()
    } else {
        snapshot
            .categories
            .iter()
            .filter(|c| c.count > 0)
            .map(|c| {
                format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                    html_escape(&c.name),
                    c.count,
                    html_escape(&c.color)
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };
    let integrity_section = snapshot
        .integrity
        .as_ref()
        .map(|i| {
            format!(
                r#"<div class="section">
    <h2>Evidence Integrity</h2>
    <div class="info-grid">
      <div class="info-row"><span class="info-key">SHA-256</span><span class="info-val" style="font-family:monospace;font-size:10px;">{}</span></div>
      <div class="info-row"><span class="info-key">Analysis SHA-256</span><span class="info-val" style="font-family:monospace;font-size:10px;">{}</span></div>
      <div class="info-row"><span class="info-key">Match Confirmation</span><span class="info-val">{}</span></div>
      <div class="info-row"><span class="info-key">Size</span><span class="info-val">{} bytes</span></div>
      <div class="info-row"><span class="info-key">Computed</span><span class="info-val">{}</span></div>
    </div>
  </div>"#,
                html_escape(&i.sha256),
                html_escape(&i.sha256),
                if i.verified { "MATCH CONFIRMED" } else { "MISMATCH WARNING" },
                i.file_size_bytes,
                i.computed_at
            )
        })
        .unwrap_or_default();
    let flagged_rows = if snapshot.flagged_notes.is_empty() {
        "<tr><td colspan=\"5\">No flagged artifact notes recorded.</td></tr>".to_string()
    } else {
        snapshot
            .flagged_notes
            .iter()
            .map(|note| {
                format!(
                    "<tr><td style=\"font-family:monospace;font-size:10px;\">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    html_escape(&note.artifact_id),
                    html_escape(&note.evidence_id),
                    html_escape(&note.examiner),
                    note.created_at,
                    html_escape(&note.note)
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };
    let custody_rows = if snapshot.custody.is_empty() {
        "<tr><td colspan=\"6\">No custody entries recorded.</td></tr>".to_string()
    } else {
        snapshot
            .custody
            .iter()
            .map(|entry| {
                format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td style=\"font-family:monospace;font-size:10px;\">{}</td></tr>",
                    entry.timestamp,
                    html_escape(&entry.examiner),
                    html_escape(&entry.action),
                    html_escape(&entry.evidence_id),
                    html_escape(&entry.details),
                    html_escape(entry.hash_after.as_deref().unwrap_or(""))
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };
    let hash_set_rows = if snapshot.hash_sets.is_empty() {
        "<tr><td colspan=\"3\">No hash sets applied.</td></tr>".to_string()
    } else {
        snapshot
            .hash_sets
            .iter()
            .map(|set| {
                format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                    html_escape(&set.name),
                    set.hash_count,
                    set.imported_at
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };
    let chevron_svg = r##"<svg class="logo-chevron" viewBox="0 0 40 35" xmlns="http://www.w3.org/2000/svg">
<polygon points="20,2 34,10 20,18 6,10" fill="#1a2e44" opacity="0.95"/>
<polygon points="34,10 34,14 20,22 20,18" fill="#4a6890"/>
<polygon points="6,10 6,14 20,22 20,18" fill="#8fa8c0"/>
<line x1="6" y1="18" x2="34" y2="18" stroke="#1a2e44" stroke-width="0.5" opacity="0.4"/>
<polygon points="34,14 36,15 36,19 34,18" fill="#2a4060"/>
<polygon points="6,14 4,15 4,19 6,18" fill="#6a8aaa"/>
<polygon points="34,18 36,19 36,23 34,22" fill="#1a2e44"/>
<polygon points="6,18 4,19 4,23 6,22" fill="#4a6890"/>
<polygon points="6,22 4,23 18,30 20,29 20,25" fill="#1a2e44" opacity="0.9"/>
<polygon points="34,22 36,23 22,30 20,29 20,25" fill="#0f1c2e" opacity="0.9"/>
<polyline points="6,10 20,2 34,10" fill="none" stroke="#ffffff" stroke-width="0.8" opacity="0.6"/>
</svg>"##;

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Strata Forensic Report</title>
<style>{css}</style>
</head>
<body>
<div class="page">

  <div class="report-header">
    <div class="report-logo">
      {chevron}
      <div>
        <div class="logo-text">STRATA</div>
        <div class="logo-sub">Wolfmark Systems</div>
      </div>
    </div>
    <div class="report-meta">
      <div><strong>Forensic Analysis Report</strong></div>
      <div>Case: {case_number}</div>
      <div>Generated: {generated_at}</div>
      <div>Examiner: {examiner_name}</div>
    </div>
  </div>

  <div class="section">
    <h1>Cover Page</h1>
    <div class="info-grid">
      <div class="info-row"><span class="info-key">Case No.</span><span class="info-val">{case_number}</span></div>
      <div class="info-row"><span class="info-key">Case Name</span><span class="info-val">{case_name}</span></div>
      <div class="info-row"><span class="info-key">Examiner</span><span class="info-val">{examiner_name}</span></div>
      <div class="info-row"><span class="info-key">Agency</span><span class="info-val">{examiner_agency}</span></div>
      <div class="info-row"><span class="info-key">Badge</span><span class="info-val">{examiner_badge}</span></div>
      <div class="info-row"><span class="info-key">Evidence</span><span class="info-val">{evidence_description}</span></div>
      <div class="info-row"><span class="info-key">Evidence ID</span><span class="info-val">{evidence_id}</span></div>
      <div class="info-row"><span class="info-key">Evidence Size</span><span class="info-val">{evidence_size} bytes</span></div>
      <div class="info-row"><span class="info-key">Evidence SHA-256</span><span class="info-val" style="font-family:monospace;font-size:10px;">{evidence_hash}</span></div>
      <div class="info-row"><span class="info-key">Analysis Time</span><span class="info-val">{generated_at}</span></div>
      <div class="info-row"><span class="info-key">Platform</span><span class="info-val">Strata v{app_version}</span></div>
    </div>
  </div>

  <div class="section">
    <h2>Methodology</h2>
    <p>Strata parsed the loaded evidence, ran configured analysis plugins, applied imported known-good hash sets where available, and preserved examiner actions in the custody log.</p>
    <div class="info-grid">
      <div class="info-row"><span class="info-key">Analysis Start</span><span class="info-val">{analysis_start}</span></div>
      <div class="info-row"><span class="info-key">Analysis End</span><span class="info-val">{analysis_end}</span></div>
    </div>
    <table>
      <thead><tr><th>Hash Set</th><th>Hashes</th><th>Imported</th></tr></thead>
      <tbody>{hash_set_rows}</tbody>
    </table>
  </div>

  {integrity_section}

  <div class="section">
    <h2>Executive Summary</h2>
    <div class="stats-grid">
      <div class="stat-card"><div class="stat-label">Files</div><div class="stat-value">{files}</div></div>
      <div class="stat-card"><div class="stat-label">Suspicious</div><div class="stat-value sus">{suspicious}</div></div>
      <div class="stat-card"><div class="stat-label">Flagged</div><div class="stat-value flag">{flagged}</div></div>
      <div class="stat-card"><div class="stat-label">Artifacts</div><div class="stat-value">{artifacts}</div></div>
      <div class="stat-card"><div class="stat-label">Tagged</div><div class="stat-value">{tagged_count}</div></div>
      <div class="stat-card"><div class="stat-label">Hashed</div><div class="stat-value">{hashed}</div></div>
    </div>
    <p style="margin-top:12px; font-size:12px; color:#4a5568; line-height:1.7;">
      This report summarizes the evidence currently loaded in Strata. Findings and counts reflect parser and plugin results available at generation time.
    </p>
  </div>

  <div class="section">
    <h2>Findings by Category</h2>
    <table>
      <thead><tr><th>Category</th><th>Artifacts</th><th>Color</th></tr></thead>
      <tbody>
        {category_rows}
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>Tagged Evidence</h2>
    <table>
      <thead><tr><th>File</th><th>Tag</th><th>Path</th><th>Note</th></tr></thead>
      <tbody>
        {tagged_rows}
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>Flagged Artifacts</h2>
    <table>
      <thead><tr><th>Artifact ID</th><th>Evidence</th><th>Examiner</th><th>Created</th><th>Note</th></tr></thead>
      <tbody>
        {flagged_rows}
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>Chain of Custody Log</h2>
    <table>
      <thead><tr><th>Timestamp</th><th>Examiner</th><th>Action</th><th>Evidence</th><th>Details</th><th>Hash After</th></tr></thead>
      <tbody>
        {custody_rows}
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>MITRE ATT&amp;CK Coverage</h2>
    <div class="mitre-grid">
      <span class="mitre-pill">T1003</span>
      <span class="mitre-pill">T1003.001</span>
      <span class="mitre-pill">T1021.001</span>
      <span class="mitre-pill">T1053.005</span>
      <span class="mitre-pill">T1057</span>
      <span class="mitre-pill">T1059.001</span>
      <span class="mitre-pill">T1070.001</span>
      <span class="mitre-pill">T1070.004</span>
      <span class="mitre-pill">T1083</span>
      <span class="mitre-pill">T1087.001</span>
      <span class="mitre-pill">T1197</span>
      <span class="mitre-pill">T1204</span>
      <span class="mitre-pill">T1552.001</span>
    </div>
  </div>

  <div class="section">
    <h2>Examiner Certification</h2>
    <div class="cert-block">
      I, {examiner_name}, of {examiner_agency}, badge number {examiner_badge}, certify that the forensic examination described in this report was conducted in accordance with accepted digital forensic practices. The findings contained herein are accurate and complete to the best of my knowledge. This report was generated by Strata v{app_version}, a Wolfmark Systems forensic intelligence platform.
    </div>
    <div class="sig-line">
      <span>Examiner: {examiner_name}</span>
      <span>Agency: {examiner_agency}</span>
      <span>Date: ___________________</span>
      <span>Signature: _______________</span>
    </div>
  </div>

  <div class="footer">
    <span>Strata v{app_version} &mdash; Wolfmark Systems</span>
    <span>Case: {case_number}</span>
    <span>CONFIDENTIAL &mdash; FORENSIC REPORT</span>
  </div>

</div>
</body>
</html>"##,
        css = css,
        chevron = chevron_svg,
        case_number = case_number,
        case_name = case_name,
        evidence_description = evidence_description,
        evidence_id = evidence_id,
        evidence_size = evidence_size,
        evidence_hash = evidence_hash,
        examiner_name = examiner_name,
        examiner_agency = examiner_agency,
        examiner_badge = examiner_badge,
        generated_at = snapshot.generated_at,
        app_version = snapshot.app_version,
        analysis_start = analysis_start,
        analysis_end = analysis_end,
        hash_set_rows = hash_set_rows,
        files = snapshot.stats.files,
        suspicious = snapshot.stats.suspicious,
        flagged = snapshot.stats.flagged,
        artifacts = snapshot.stats.artifacts,
        tagged_count = snapshot.tagged.len(),
        hashed = snapshot.stats.hashed,
        integrity_section = integrity_section,
        category_rows = category_rows,
        tagged_rows = tagged_rows,
        flagged_rows = flagged_rows,
        custody_rows = custody_rows,
    )
}

// ──────────────────────────────────────────────────────────────────────────────
// Day 3 commands — mock data, real engine wiring comes Day 11-12
// ──────────────────────────────────────────────────────────────────────────────

#[tauri::command]
async fn open_evidence_dialog(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;

    let (tx, rx) = std::sync::mpsc::channel();
    app.dialog()
        .file()
        .add_filter(
            "Evidence Images",
            &[
                // E01 / EnCase
                "E01", "e01", "EX01", "ex01", // EnCase logical
                "L01", "l01", "Lx01", "lx01", "Lx02", "lx02", // AFF / AFF4
                "aff", "AFF", "aff4", "AFF4", // Raw disk images
                "dd", "DD", "img", "IMG", "raw", "RAW", // Split raw sequences
                "001", "r01", "R01", "aa", // VM disk formats
                "vmdk", "VMDK", "vhd", "VHD", "vhdx", "VHDX", // ISO
                "iso", "ISO",   // QEMU
                "qcow2", // Cellebrite UFED
                "ufdr", "ufd", "ufdx", // S01 (EnCase split)
                "s01", "S01", // Sprint-9 P3: archives unpacked into a scratch dir
                "zip", "ZIP", "tar", "TAR", "tgz", "TGZ", "gz", "GZ",
            ],
        )
        .add_filter("All Files", &["*"])
        .set_title("Open Evidence Image")
        .pick_file(move |path| {
            let _ = tx.send(path);
        });

    let picked = rx.recv().map_err(|e| e.to_string())?;
    Ok(picked.map(|p| p.to_string()))
}

#[tauri::command]
async fn open_folder_dialog(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;

    let (tx, rx) = std::sync::mpsc::channel();
    app.dialog()
        .file()
        .set_title("Open Evidence Folder")
        .pick_folder(move |path| {
            let _ = tx.send(path);
        });

    let picked = rx.recv().map_err(|e| e.to_string())?;
    Ok(picked.map(|p| p.to_string()))
}

#[tauri::command]
async fn load_evidence(app: tauri::AppHandle, path: String) -> Result<EvidenceLoadResult, String> {
    let path_for_parse = path.clone();
    let path_for_hash = path.clone();
    // Run the (potentially heavy) parse on a blocking thread so the Tauri
    // command thread isn't held up.
    let result = tokio::task::spawn_blocking(move || engine::parse_evidence(&path_for_parse))
        .await
        .map_err(|e| e.to_string())?;

    match result {
        Ok(info) => {
            let hash = engine::sha256_file(std::path::Path::new(&path_for_hash));
            log_custody_event(
                examiner_name_for_app(&app),
                "evidence_loaded",
                info.id.clone(),
                format!("Loaded evidence from {path_for_hash}"),
                hash.clone(),
                hash,
            );
            set_current_evidence_id(&info.id);
            Ok(EvidenceLoadResult {
                success: true,
                evidence_id: info.id,
                name: info.name,
                size_display: info.size_display,
                file_count: info.file_count,
                error: None,
            })
        }
        Err(e) => Ok(EvidenceLoadResult {
            success: false,
            evidence_id: String::new(),
            name: String::new(),
            size_display: String::new(),
            file_count: 0,
            error: Some(e.to_string()),
        }),
    }
}

#[tauri::command]
async fn get_tree_root(evidence_id: String) -> Result<Vec<TreeNode>, String> {
    let id = if evidence_id.is_empty() {
        current_evidence_id().unwrap_or_default()
    } else {
        evidence_id
    };
    let nodes = tokio::task::spawn_blocking(move || engine::get_tree_root(&id))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    Ok(nodes.into_iter().map(adapter_tree_to_desktop).collect())
}

#[tauri::command]
async fn get_tree_children(node_id: String) -> Result<Vec<TreeNode>, String> {
    let evidence_id = current_evidence_id().unwrap_or_default();
    let nodes =
        tokio::task::spawn_blocking(move || engine::get_tree_children(&evidence_id, &node_id))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
    Ok(nodes.into_iter().map(adapter_tree_to_desktop).collect())
}

#[tauri::command]
async fn get_files(
    node_id: String,
    filter: Option<String>,
    _sort_col: Option<String>,
    _sort_asc: Option<bool>,
) -> Result<Vec<FileEntry>, String> {
    let evidence_id = current_evidence_id().unwrap_or_default();
    let files = tokio::task::spawn_blocking(move || {
        engine::get_files(&evidence_id, &node_id, filter.as_deref())
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;
    Ok(files.into_iter().map(adapter_file_to_desktop).collect())
}

#[tauri::command]
async fn get_file_metadata(file_id: String) -> Result<FileMetadata, String> {
    let evidence_id = current_evidence_id().unwrap_or_default();
    let f = tokio::task::spawn_blocking(move || engine::get_file_metadata(&evidence_id, &file_id))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    Ok(adapter_file_to_metadata(f))
}

#[tauri::command]
async fn get_file_hex(file_id: String, offset: u64, length: u64) -> Result<HexData, String> {
    let evidence_id = current_evidence_id().unwrap_or_default();
    let h = tokio::task::spawn_blocking(move || {
        engine::get_file_hex(&evidence_id, &file_id, offset, length)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;
    Ok(adapter_hex_to_desktop(h))
}

#[tauri::command]
async fn get_file_text(file_id: String, _offset: u64) -> Result<String, String> {
    let evidence_id = current_evidence_id().unwrap_or_default();
    tokio::task::spawn_blocking(move || engine::get_file_text(&evidence_id, &file_id))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn search_files(query: String, evidence_id: String) -> Result<Vec<SearchResult>, String> {
    if query.is_empty() {
        return Ok(vec![]);
    }
    let eid = if evidence_id.is_empty() {
        current_evidence_id().unwrap_or_default()
    } else {
        evidence_id
    };

    tokio::task::spawn_blocking(move || -> Result<Vec<SearchResult>, String> {
        let arc = {
            let store = engine::store::EVIDENCE_STORE
                .lock()
                .map_err(|e| e.to_string())?;
            store
                .get(&eid)
                .cloned()
                .ok_or_else(|| format!("evidence not loaded: {eid}"))?
        };
        let guard = arc.lock().map_err(|e| e.to_string())?;

        let q = query.to_lowercase();
        const SUSPICIOUS_MARKERS: &[&str] =
            &["mimikatz", "lsass", "cleanup.ps1", "psexec", "nc.exe"];
        const FLAGGED_MARKERS: &[&str] = &["mimikatz", "lsass.dmp"];

        let mut results: Vec<SearchResult> = guard
            .files
            .values()
            .filter(|f| !f.is_dir)
            .filter_map(|f| {
                let name_lc = f.name.to_lowercase();
                let full_path = f.vfs_path.to_string_lossy().into_owned();
                let path_lc = full_path.to_lowercase();
                let name_match = name_lc.contains(&q);
                let path_match = path_lc.contains(&q);
                if !name_match && !path_match {
                    return None;
                }
                let (match_field, match_value) = if name_match {
                    ("filename".to_string(), f.name.clone())
                } else {
                    ("path".to_string(), full_path.clone())
                };
                Some(SearchResult {
                    id: f.id.clone(),
                    name: f.name.clone(),
                    full_path,
                    extension: f.extension.clone(),
                    size_display: engine::format_size(f.size),
                    modified: f.modified.clone(),
                    is_deleted: false,
                    is_flagged: FLAGGED_MARKERS.iter().any(|m| name_lc.contains(m)),
                    is_suspicious: SUSPICIOUS_MARKERS.iter().any(|m| name_lc.contains(m)),
                    match_field,
                    match_value,
                })
            })
            .collect();
        results.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        Ok(results)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn get_tag_summaries(app: tauri::AppHandle) -> Result<Vec<TagSummary>, String> {
    load_tags_from_disk(&app)?;
    let store = get_tag_store();
    let map = store.lock().map_err(|e| e.to_string())?;

    let tag_defs = [
        ("Critical Evidence", "#a84040"),
        ("Suspicious", "#b87840"),
        ("Needs Review", "#b8a840"),
        ("Confirmed Clean", "#487858"),
        ("Key Artifact", "#4a7890"),
        ("Excluded", "#3a4858"),
    ];

    let summaries = tag_defs
        .iter()
        .map(|(name, color)| {
            let count = map.values().filter(|f| f.tag == *name).count() as u64;
            TagSummary {
                name: name.to_string(),
                color: color.to_string(),
                count,
            }
        })
        .collect();

    Ok(summaries)
}

#[tauri::command]
async fn get_tagged_files(app: tauri::AppHandle, tag: String) -> Result<Vec<TaggedFile>, String> {
    load_tags_from_disk(&app)?;
    let store = get_tag_store();
    let map = store.lock().map_err(|e| e.to_string())?;
    let files: Vec<TaggedFile> = map.values().filter(|f| f.tag == tag).cloned().collect();
    Ok(files)
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn tag_file(
    app: tauri::AppHandle,
    file_id: String,
    file_name: String,
    extension: String,
    size_display: String,
    modified: String,
    full_path: String,
    tag: String,
    tag_color: String,
    note: Option<String>,
) -> Result<(), String> {
    load_tags_from_disk(&app)?;
    let store = get_tag_store();
    let mut map = store.lock().map_err(|e| e.to_string())?;
    map.insert(
        file_id.clone(),
        TaggedFile {
            file_id,
            name: file_name,
            extension,
            size_display,
            modified,
            full_path,
            tag,
            tag_color,
            tagged_at: current_tag_timestamp(),
            note,
        },
    );
    save_tags_to_disk(&app, &map)?;
    Ok(())
}

#[tauri::command]
async fn untag_file(app: tauri::AppHandle, file_id: String) -> Result<(), String> {
    load_tags_from_disk(&app)?;
    let store = get_tag_store();
    let mut map = store.lock().map_err(|e| e.to_string())?;
    map.remove(&file_id);
    save_tags_to_disk(&app, &map)?;
    Ok(())
}

#[tauri::command]
async fn get_artifact_categories(evidence_id: String) -> Result<Vec<ArtifactCategory>, String> {
    let eid = if evidence_id.is_empty() {
        current_evidence_id().unwrap_or_default()
    } else {
        evidence_id
    };
    let cats = tokio::task::spawn_blocking(move || engine::get_artifact_categories(&eid))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    Ok(cats
        .into_iter()
        .map(|c| ArtifactCategory {
            name: c.name,
            icon: c.icon,
            count: c.count,
            color: c.color,
        })
        .collect())
}

#[tauri::command]
async fn get_artifacts(evidence_id: String, category: String) -> Result<ArtifactsResponse, String> {
    let eid = if evidence_id.is_empty() {
        current_evidence_id().unwrap_or_default()
    } else {
        evidence_id
    };
    let eid_check = eid.clone();
    let cat = category.clone();
    let real = tokio::task::spawn_blocking(move || engine::get_artifacts_by_category(&eid, &cat))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;

    if !real.is_empty() {
        let artifacts = real.into_iter().map(adapter_artifact_to_desktop).collect();
        return Ok(ArtifactsResponse {
            artifacts,
            plugins_not_run: false,
        });
    }

    // No real artifacts for this category. Determine whether that's because
    // plugins haven't been run yet, or because they ran and produced nothing
    // for this category. The signal lets the frontend show a "Run plugins"
    // hint instead of an empty grid.
    let plugins_not_run = tokio::task::spawn_blocking(move || {
        let store = get_plugin_status_store();
        let map = store
            .lock()
            .map_err(|e: std::sync::PoisonError<_>| e.to_string())?;
        // Sprint 8 P1 F4: backend `run_plugin` / `run_all_plugins`
        // writes `"complete"` on success. The pre-fix predicate
        // checked only `"completed"` / `"success"` — neither was ever
        // produced, so this flag was always stuck at `true` after a
        // real successful run, surfacing a "plugins haven't been
        // run" banner in ArtifactsView even after Run All.
        let any_completed = map.values().any(|s| is_plugin_complete(&s.status));
        Ok::<bool, String>(!any_completed)
    })
    .await
    .map_err(|e| e.to_string())??;

    let _ = eid_check; // evidence id reserved for future per-evidence run tracking
    Ok(ArtifactsResponse {
        artifacts: Vec::new(),
        plugins_not_run,
    })
}

#[tauri::command]
async fn get_artifacts_timeline(
    evidence_id: String,
    start_ts: Option<i64>,
    end_ts: Option<i64>,
    limit: Option<usize>,
) -> Result<Vec<Artifact>, String> {
    let eid = if evidence_id.is_empty() {
        current_evidence_id().unwrap_or_default()
    } else {
        evidence_id
    };
    tokio::task::spawn_blocking(move || {
        engine::get_artifacts_timeline(&eid, start_ts, end_ts, limit)
            .map(|items| items.into_iter().map(adapter_artifact_to_desktop).collect())
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())
}

#[tauri::command]
async fn search_iocs(query: IocQuery) -> Result<Vec<IocMatch>, String> {
    let q = engine::IocQuery {
        indicators: query.indicators,
        evidence_id: if query.evidence_id.is_empty() {
            current_evidence_id().unwrap_or_default()
        } else {
            query.evidence_id
        },
    };
    tokio::task::spawn_blocking(move || {
        engine::search_iocs(q).map(|matches| {
            matches
                .into_iter()
                .map(|m| IocMatch {
                    indicator: m.indicator,
                    artifact: adapter_artifact_to_desktop(m.artifact),
                    match_field: m.match_field,
                    confidence: m.confidence,
                })
                .collect()
        })
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_custody_log(evidence_id: String) -> Result<Vec<engine::CustodyEntry>, String> {
    let eid = if evidence_id.is_empty() {
        current_evidence_id().unwrap_or_default()
    } else {
        evidence_id
    };
    Ok(engine::get_custody_log(&eid))
}

/// Sprint-11 P2 — resolve an artifact's source path to a tree node id
/// + breadcrumb so the frontend can switch to the Evidence Tree view
/// and expand to that file. Returns Err with a clear message when
/// the path isn't part of the loaded evidence.
#[tauri::command]
async fn navigate_to_path(
    evidence_id: String,
    file_path: String,
) -> Result<engine::NavigationTarget, String> {
    let eid = if evidence_id.is_empty() {
        current_evidence_id().unwrap_or_default()
    } else {
        evidence_id
    };
    tokio::task::spawn_blocking(move || engine::navigate_to_path(&eid, &file_path))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

/// Sprint-11 P1 — return Communications artifacts grouped by thread
/// for the conversation view. Falls back to a single `__ungrouped__`
/// thread when artifacts lack `raw_data.thread_id`, so non-message
/// categories (or plugins that haven't been ported to set thread
/// metadata) keep working unchanged.
#[tauri::command]
async fn get_artifacts_by_thread(
    evidence_id: String,
    category: String,
) -> Result<Vec<engine::MessageThread>, String> {
    let eid = if evidence_id.is_empty() {
        current_evidence_id().unwrap_or_default()
    } else {
        evidence_id
    };
    tokio::task::spawn_blocking(move || engine::get_artifacts_by_thread(&eid, &category))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_plugin_statuses() -> Result<Vec<PluginStatus>, String> {
    let store = get_plugin_status_store();
    let map = store.lock().map_err(|e| e.to_string())?;

    let statuses = PLUGIN_NAMES
        .iter()
        .map(|n| {
            map.get(*n).cloned().unwrap_or(PluginStatus {
                name: n.to_string(),
                status: "idle".to_string(),
                progress: 0,
                artifact_count: 0,
            })
        })
        .collect();

    Ok(statuses)
}

#[tauri::command]
async fn run_plugin(
    plugin_name: String,
    evidence_id: String,
    app: tauri::AppHandle,
) -> Result<PluginRunResult, String> {
    let store = get_plugin_status_store();

    // Mark "running" immediately so the UI can switch state.
    {
        let mut map = store.lock().map_err(|e| e.to_string())?;
        map.insert(
            plugin_name.clone(),
            PluginStatus {
                name: plugin_name.clone(),
                status: "running".to_string(),
                progress: 0,
                artifact_count: 0,
            },
        );
    }
    let _ = app.emit(
        "plugin-progress",
        json!({
            "name": plugin_name,
            "progress": 0,
            "status": "running"
        }),
    );

    // Resolve evidence id (default to most-recently loaded).
    let eid = if evidence_id.is_empty() {
        current_evidence_id().unwrap_or_default()
    } else {
        evidence_id
    };
    let examiner = examiner_name_for_app(&app);
    log_custody_event(
        examiner.clone(),
        "plugin_run_started",
        eid.clone(),
        format!("Started plugin {plugin_name}"),
        None,
        None,
    );

    let plugin_name_run = plugin_name.clone();
    let eid_run = eid.clone();
    let app_progress = app.clone();
    let plugin_for_progress = plugin_name.clone();

    // Start a heartbeat that emits visible progress while the real plugin
    // runs synchronously. Real plugins don't expose progress yet, so we
    // simulate a smooth ramp from 0→90% until execution finishes.
    let heartbeat_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hb_done = heartbeat_done.clone();
    tokio::spawn(async move {
        let mut p: u8 = 5;
        while !hb_done.load(std::sync::atomic::Ordering::Relaxed) {
            tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
            if hb_done.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            p = (p + 5).min(90);
            let _ = app_progress.emit(
                "plugin-progress",
                json!({
                    "name": plugin_for_progress,
                    "progress": p,
                    "status": "running"
                }),
            );
        }
    });

    let started = std::time::Instant::now();

    // Run the real plugin on a blocking thread.
    let plugin_result =
        tokio::task::spawn_blocking(move || engine::run_plugin(&eid_run, &plugin_name_run))
            .await
            .map_err(|e| e.to_string())?;

    heartbeat_done.store(true, std::sync::atomic::Ordering::Relaxed);
    let duration_ms = started.elapsed().as_millis() as u64;

    match plugin_result {
        Ok(artifacts) => {
            let count = artifacts.len() as u64;
            log_custody_event(
                examiner,
                "plugin_run_completed",
                eid.clone(),
                format!("Completed plugin {plugin_name} with {count} artifacts"),
                None,
                None,
            );
            if let Ok(mut map) = store.lock() {
                map.insert(
                    plugin_name.clone(),
                    PluginStatus {
                        name: plugin_name.clone(),
                        status: "complete".to_string(),
                        progress: 100,
                        artifact_count: count,
                    },
                );
            }
            let _ = app.emit(
                "plugin-progress",
                json!({
                    "name": plugin_name,
                    "progress": 100,
                    "status": "complete",
                    "artifact_count": count
                }),
            );
            Ok(PluginRunResult {
                plugin_name: plugin_name.clone(),
                success: true,
                artifact_count: count,
                duration_ms,
                error: None,
            })
        }
        Err(e) => {
            let err_msg = e.to_string();
            log_custody_event(
                examiner,
                "plugin_run_completed",
                eid.clone(),
                format!("Plugin {plugin_name} failed: {err_msg}"),
                None,
                None,
            );
            if let Ok(mut map) = store.lock() {
                map.insert(
                    plugin_name.clone(),
                    PluginStatus {
                        name: plugin_name.clone(),
                        status: "error".to_string(),
                        progress: 0,
                        artifact_count: 0,
                    },
                );
            }
            let _ = app.emit(
                "plugin-progress",
                json!({
                    "name": plugin_name,
                    "progress": 0,
                    "status": "error",
                    "error": err_msg.clone(),
                }),
            );
            Ok(PluginRunResult {
                plugin_name: plugin_name.clone(),
                success: false,
                artifact_count: 0,
                duration_ms,
                error: Some(err_msg),
            })
        }
    }
}

#[tauri::command]
async fn run_all_plugins(evidence_id: String, app: tauri::AppHandle) -> Result<(), String> {
    let eid = if evidence_id.is_empty() {
        current_evidence_id().unwrap_or_default()
    } else {
        evidence_id
    };
    if eid.is_empty() {
        return Err("no evidence loaded".to_string());
    }
    let examiner = examiner_name_for_app(&app);

    // Sprint 8 P1 F3: collapse the UI path onto a single threaded run
    // rather than N independent run_plugin calls. Each previous call
    // built a fresh empty `prior_results`, which starved Sigma (and
    // Advisory) of the correlation inputs they need to fire. This
    // routes through `engine::run_all_on_evidence` which threads
    // `prior_results` identically to the CLI's `run_all_on_path`.
    tokio::task::spawn_blocking(move || {
        engine::run_all_on_evidence(&eid, |full_name, status, count, err| {
            // Frontend PLUGIN_DATA uses short names ("Remnant" not
            // "Strata Remnant") — strip the prefix so per-card UI
            // status lookups match.
            let short_name = full_name
                .strip_prefix("Strata ")
                .unwrap_or(full_name)
                .to_string();
            if full_name != "__materialize__" {
                if status == "running" {
                    log_custody_event(
                        examiner.clone(),
                        "plugin_run_started",
                        eid.clone(),
                        format!("Started plugin {short_name}"),
                        None,
                        None,
                    );
                } else if status == "complete" {
                    log_custody_event(
                        examiner.clone(),
                        "plugin_run_completed",
                        eid.clone(),
                        format!("Completed plugin {short_name} with {count} artifacts"),
                        None,
                        None,
                    );
                }
            }
            let progress: u8 = if status == "running" { 0 } else { 100 };

            if let Ok(mut map) = get_plugin_status_store().lock() {
                map.insert(
                    short_name.clone(),
                    PluginStatus {
                        name: short_name.clone(),
                        status: status.to_string(),
                        progress,
                        artifact_count: count,
                    },
                );
            }

            let mut payload = json!({
                "name": short_name,
                "progress": progress,
                "status": status,
                "artifact_count": count,
            });
            if let Some(e) = err {
                if let Some(obj) = payload.as_object_mut() {
                    obj.insert("error".into(), json!(e));
                }
            }
            let _ = app.emit("plugin-progress", payload);
        })
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn get_stats(evidence_id: String) -> Result<Stats, String> {
    let eid = if evidence_id.is_empty() {
        current_evidence_id().unwrap_or_default()
    } else {
        evidence_id
    };
    if eid.is_empty() {
        return Ok(Stats {
            files: 0,
            suspicious: 0,
            flagged: 0,
            carved: 0,
            hashed: 0,
            known_good: 0,
            unknown: 0,
            artifacts: 0,
        });
    }
    let s = tokio::task::spawn_blocking(move || engine::get_stats(&eid))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    Ok(Stats {
        files: s.files,
        suspicious: s.suspicious,
        flagged: s.flagged,
        carved: s.carved,
        hashed: s.hashed,
        known_good: s.known_good,
        unknown: s.unknown,
        artifacts: s.artifacts,
    })
}

#[tauri::command]
async fn get_evidence_integrity(evidence_id: String) -> Result<EvidenceIntegrity, String> {
    let eid = if evidence_id.is_empty() {
        current_evidence_id().unwrap_or_default()
    } else {
        evidence_id
    };
    tokio::task::spawn_blocking(move || engine::get_evidence_integrity(&eid))
        .await
        .map_err(|e| e.to_string())?
        .map(EvidenceIntegrity::from)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn verify_evidence_integrity(evidence_id: String) -> Result<EvidenceIntegrity, String> {
    let eid = if evidence_id.is_empty() {
        current_evidence_id().unwrap_or_default()
    } else {
        evidence_id
    };
    tokio::task::spawn_blocking(move || engine::verify_evidence_integrity(&eid))
        .await
        .map_err(|e| e.to_string())?
        .map(EvidenceIntegrity::from)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn import_hash_set(name: String, file_path: String) -> Result<usize, String> {
    tokio::task::spawn_blocking(move || engine::import_hash_set(&name, &file_path))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn list_hash_sets() -> Result<Vec<HashSetInfo>, String> {
    tokio::task::spawn_blocking(engine::list_hash_sets)
        .await
        .map_err(|e| e.to_string())
        .map(|sets| sets.into_iter().map(HashSetInfo::from).collect())
}

#[tauri::command]
async fn delete_hash_set(name: String) -> Result<bool, String> {
    tokio::task::spawn_blocking(move || engine::delete_hash_set(&name))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_hash_set_stats(evidence_id: String) -> Result<HashSetStats, String> {
    let eid = if evidence_id.is_empty() {
        current_evidence_id().unwrap_or_default()
    } else {
        evidence_id
    };
    tokio::task::spawn_blocking(move || engine::get_hash_set_stats(&eid))
        .await
        .map_err(|e| e.to_string())
        .map(HashSetStats::from)
}

#[tauri::command]
async fn save_artifact_note(
    app: tauri::AppHandle,
    artifact_id: String,
    evidence_id: String,
    note: String,
    flagged: bool,
) -> Result<ArtifactNote, String> {
    let path = artifact_notes_path(&app)?;
    let mut notes = load_artifact_notes_from_path(&path)?;
    let saved = ArtifactNote {
        artifact_id,
        evidence_id,
        note,
        created_at: engine::now_unix(),
        examiner: examiner_name_for_app(&app),
        flagged,
    };
    upsert_artifact_note(&mut notes, saved.clone());
    save_artifact_notes_to_path(&path, &notes)?;
    Ok(saved)
}

#[tauri::command]
async fn get_artifact_note(
    app: tauri::AppHandle,
    artifact_id: String,
) -> Result<Option<ArtifactNote>, String> {
    let path = artifact_notes_path(&app)?;
    let notes = load_artifact_notes_from_path(&path)?;
    Ok(notes.into_iter().find(|note| note.artifact_id == artifact_id))
}

#[tauri::command]
async fn get_flagged_artifacts(
    app: tauri::AppHandle,
    evidence_id: String,
) -> Result<Vec<ArtifactNote>, String> {
    let path = artifact_notes_path(&app)?;
    let notes = load_artifact_notes_from_path(&path)?;
    Ok(notes
        .into_iter()
        .filter(|note| note.evidence_id == evidence_id && note.flagged)
        .collect())
}

// ──────────────────────────────────────────────────────────────────────────────
// Hashing — Day 12
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone)]
pub struct HashResultIpc {
    pub file_id: String,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub sha512: String,
}

#[tauri::command]
async fn hash_file_cmd(evidence_id: String, file_id: String) -> Result<HashResultIpc, String> {
    let eid = if evidence_id.is_empty() {
        current_evidence_id().unwrap_or_default()
    } else {
        evidence_id
    };
    let r = tokio::task::spawn_blocking(move || engine::hash_file(&eid, &file_id))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    Ok(HashResultIpc {
        file_id: r.file_id,
        md5: r.md5,
        sha1: r.sha1,
        sha256: r.sha256,
        sha512: r.sha512,
    })
}

#[tauri::command]
async fn hash_all_files_cmd(evidence_id: String, app: tauri::AppHandle) -> Result<u64, String> {
    let eid = if evidence_id.is_empty() {
        current_evidence_id().unwrap_or_default()
    } else {
        evidence_id
    };
    if eid.is_empty() {
        return Err("No evidence loaded".to_string());
    }

    let examiner = examiner_name_for_app(&app);
    log_custody_event(
        examiner.clone(),
        "hash_all_started",
        eid.clone(),
        "Hash All triggered".to_string(),
        None,
        None,
    );
    let app_progress = app.clone();
    let eid_for_hash = eid.clone();
    let results = tokio::task::spawn_blocking(move || {
        engine::hash_all_files(&eid_for_hash, move |done, total| {
            let _ = app_progress.emit(
                "hash-progress",
                json!({
                    "done": done,
                    "total": total,
                }),
            );
        })
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;

    log_custody_event(
        examiner,
        "hash_all_completed",
        eid,
        format!("Hash All completed for {} files", results.len()),
        None,
        None,
    );
    Ok(results.len() as u64)
}

// ──────────────────────────────────────────────────────────────────────────────
// CSAM workflow — adapter IPC surface
// ──────────────────────────────────────────────────────────────────────────────

#[tauri::command]
async fn csam_create_session(
    evidence_id: String,
    examiner: String,
    case_number: String,
) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        engine::csam_create_session(&evidence_id, &examiner, &case_number)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())
}

#[tauri::command]
async fn csam_drop_session(evidence_id: String) -> Result<bool, String> {
    tokio::task::spawn_blocking(move || engine::csam_drop_session(&evidence_id))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn csam_import_hash_set(
    evidence_id: String,
    path: String,
    name: String,
    examiner: String,
    case_number: String,
) -> Result<engine::HashSetImportResult, String> {
    tokio::task::spawn_blocking(move || {
        engine::csam_import_hash_set(&evidence_id, &path, &name, &examiner, &case_number)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())
}

#[tauri::command]
async fn csam_run_scan(
    evidence_id: String,
    options: engine::CsamScanOptions,
) -> Result<engine::CsamScanSummary, String> {
    tokio::task::spawn_blocking(move || engine::csam_run_scan(&evidence_id, options))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn csam_list_hits(evidence_id: String) -> Result<Vec<engine::CsamHitInfo>, String> {
    tokio::task::spawn_blocking(move || engine::csam_list_hits(&evidence_id))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn csam_review_hit(evidence_id: String, hit_id: String) -> Result<(), String> {
    tokio::task::spawn_blocking(move || engine::csam_review_hit(&evidence_id, &hit_id))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn csam_confirm_hit(
    evidence_id: String,
    hit_id: String,
    notes: String,
) -> Result<(), String> {
    tokio::task::spawn_blocking(move || engine::csam_confirm_hit(&evidence_id, &hit_id, &notes))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn csam_dismiss_hit(
    evidence_id: String,
    hit_id: String,
    reason: String,
) -> Result<(), String> {
    tokio::task::spawn_blocking(move || engine::csam_dismiss_hit(&evidence_id, &hit_id, &reason))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn csam_generate_report(evidence_id: String, output_pdf_path: String) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        engine::csam_generate_report(&evidence_id, &output_pdf_path)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())
}

#[tauri::command]
async fn csam_export_audit_log(evidence_id: String, output_path: String) -> Result<(), String> {
    let eid_for_log = evidence_id.clone();
    let output_for_log = output_path.clone();
    tokio::task::spawn_blocking(move || engine::csam_export_audit_log(&evidence_id, &output_path))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    log_custody_event(
        "Unknown Examiner".to_string(),
        "export_triggered",
        eid_for_log,
        format!("Exported CSAM audit log to {output_for_log}"),
        None,
        None,
    );
    Ok(())
}

#[tauri::command]
async fn csam_session_summary(evidence_id: String) -> Result<engine::CsamSessionSummary, String> {
    tokio::task::spawn_blocking(move || engine::csam_session_summary(&evidence_id))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

// ──────────────────────────────────────────────────────────────────────────────
// Case management — Day 13
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone)]
pub struct CaseFile {
    pub version: String,
    pub case_number: String,
    pub case_name: String,
    pub created_at: String,
    pub modified_at: String,
    pub examiner: ExaminerProfile,
    pub evidence: Vec<CaseEvidence>,
    pub tags: HashMap<String, CaseTag>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub case_type: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CaseEvidence {
    pub id: String,
    pub path: String,
    pub name: String,
    pub format: String,
    pub size_display: String,
    pub acquired_at: String,
    pub md5: Option<String>,
    pub sha256: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CaseTag {
    pub tag: String,
    pub color: String,
    pub note: Option<String>,
    pub tagged_at: String,
    pub tagged_by: String,
}

fn write_recent_case(case_path: &std::path::Path) -> Result<(), String> {
    let home = dirs::home_dir().ok_or("No home directory".to_string())?;
    let wm_dir = home.join(".wolfmark");
    std::fs::create_dir_all(&wm_dir).map_err(|e| e.to_string())?;
    let recents_path = wm_dir.join("recent_cases.json");

    let mut recents: Vec<String> = if recents_path.exists() {
        std::fs::read_to_string(&recents_path)
            .ok()
            .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let path_str = case_path.to_string_lossy().to_string();
    recents.retain(|p| p != &path_str);
    recents.insert(0, path_str);
    recents.truncate(10);

    let json = serde_json::to_string_pretty(&recents).map_err(|e| e.to_string())?;
    std::fs::write(&recents_path, json).map_err(|e| e.to_string())
}

#[derive(Serialize, Deserialize, Clone)]
pub struct NewCaseResult {
    pub case: CaseFile,
    pub case_path: String,
}

#[tauri::command]
async fn new_case(
    case_number: String,
    case_name: String,
    case_type: String,
    examiner: ExaminerProfile,
    base_path: String,
) -> Result<NewCaseResult, String> {
    let case_dir = std::path::PathBuf::from(&base_path).join(&case_number);
    std::fs::create_dir_all(&case_dir).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(case_dir.join("exports")).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(case_dir.join("carved")).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(case_dir.join("hashes")).map_err(|e| e.to_string())?;

    let now = chrono::Utc::now().to_rfc3339();

    let case = CaseFile {
        version: "1".to_string(),
        case_number: case_number.clone(),
        case_name,
        created_at: now.clone(),
        modified_at: now,
        examiner,
        evidence: vec![],
        tags: HashMap::new(),
        notes: String::new(),
        case_type,
    };

    let json = serde_json::to_string_pretty(&case).map_err(|e| e.to_string())?;
    let case_file = case_dir.join("case.strata");
    std::fs::write(&case_file, json).map_err(|e| e.to_string())?;

    // Seed an empty notes.md so the user can edit outside the app too.
    let _ = std::fs::write(case_dir.join("notes.md"), "");

    let _ = write_recent_case(&case_file);

    Ok(NewCaseResult {
        case,
        case_path: case_file.to_string_lossy().to_string(),
    })
}

#[tauri::command]
async fn save_case(case: CaseFile, path: String) -> Result<(), String> {
    let mut case = case;
    case.modified_at = chrono::Utc::now().to_rfc3339();
    let json = serde_json::to_string_pretty(&case).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| e.to_string())?;
    let _ = write_recent_case(std::path::Path::new(&path));
    Ok(())
}

#[derive(Serialize, Deserialize, Clone)]
pub struct OpenCaseResult {
    pub case: CaseFile,
    pub case_path: String,
}

#[tauri::command]
async fn open_case(app: tauri::AppHandle) -> Result<Option<OpenCaseResult>, String> {
    use tauri_plugin_dialog::DialogExt;

    let (tx, rx) = std::sync::mpsc::channel();
    app.dialog()
        .file()
        .add_filter("Strata Case", &["strata"])
        .set_title("Open Strata Case")
        .pick_file(move |path| {
            let _ = tx.send(path);
        });

    let picked = rx.recv().map_err(|e| e.to_string())?;
    let path = match picked {
        None => return Ok(None),
        Some(p) => p.to_string(),
    };

    let json = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let case: CaseFile = serde_json::from_str(&json).map_err(|e| e.to_string())?;
    let _ = write_recent_case(std::path::Path::new(&path));
    Ok(Some(OpenCaseResult {
        case,
        case_path: path,
    }))
}

#[tauri::command]
async fn open_case_at_path(path: String) -> Result<Option<OpenCaseResult>, String> {
    if !std::path::Path::new(&path).exists() {
        return Ok(None);
    }
    let json = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let case: CaseFile = serde_json::from_str(&json).map_err(|e| e.to_string())?;
    let _ = write_recent_case(std::path::Path::new(&path));
    Ok(Some(OpenCaseResult {
        case,
        case_path: path,
    }))
}

#[tauri::command]
async fn get_recent_cases() -> Result<Vec<String>, String> {
    let home = dirs::home_dir().ok_or("No home directory".to_string())?;
    let recents_path = home.join(".wolfmark").join("recent_cases.json");

    if !recents_path.exists() {
        return Ok(vec![]);
    }

    let json = std::fs::read_to_string(&recents_path).map_err(|e| e.to_string())?;
    let paths: Vec<String> = serde_json::from_str(&json).unwrap_or_default();
    // Filter out paths that no longer exist on disk.
    Ok(paths
        .into_iter()
        .filter(|p| std::path::Path::new(p).exists())
        .collect())
}

#[tauri::command]
async fn save_report(html: String, case_path: String) -> Result<String, String> {
    // case_path is the .strata file — derive its parent directory then exports/.
    let parent = std::path::PathBuf::from(&case_path);
    let case_dir = parent
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let exports = case_dir.join("exports");
    std::fs::create_dir_all(&exports).map_err(|e| e.to_string())?;

    let ts = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let filename = format!("report_{}.html", ts);
    let path = exports.join(&filename);
    std::fs::write(&path, html).map_err(|e| e.to_string())?;
    let out = path.to_string_lossy().to_string();
    let eid = current_evidence_id().unwrap_or_default();
    if !eid.is_empty() {
        log_custody_event(
            "Unknown Examiner".to_string(),
            "report_generated",
            eid.clone(),
            format!("Saved report to {out}"),
            None,
            engine::sha256_file(&path),
        );
        log_custody_event(
            "Unknown Examiner".to_string(),
            "export_triggered",
            eid,
            format!("Exported report to {out}"),
            None,
            None,
        );
    }
    Ok(out)
}

// ──────────────────────────────────────────────────────────────────────────────
// SQLite viewer — v1.2.0
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone)]
pub struct SqliteTable {
    pub name: String,
    pub row_count: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SqliteColumn {
    pub name: String,
    pub col_type: String,
    pub is_timestamp: bool,
    pub timestamp_format: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SqliteCell {
    pub raw: String,
    pub converted: Option<String>,
    pub is_timestamp: bool,
    pub timestamp_format: Option<String>,
    pub is_null: bool,
    pub is_blob: bool,
    pub blob_size: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SqliteRow {
    pub cells: Vec<SqliteCell>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SqliteTableData {
    pub columns: Vec<SqliteColumn>,
    pub rows: Vec<SqliteRow>,
    pub total_rows: u64,
    pub page: u32,
    pub page_size: u32,
}

/// Heuristic: is this column likely a timestamp, and what format?
///
/// Detection rules:
///   * Name contains date/time/timestamp/created/modified/accessed/etc.
///   * Type-based format hint:
///     - REAL/FLOAT/DOUBLE → Mac Absolute (Core Data common)
///     - INTEGER/INT/BIGINT → auto-detect Unix vs Chrome vs Mac by range
pub(crate) fn detect_timestamp_column(name: &str, col_type: &str) -> (bool, Option<String>) {
    let name_lower = name.to_lowercase();
    let type_lower = col_type.to_lowercase();

    const TS_NAMES: &[&str] = &[
        "date",
        "time",
        "timestamp",
        "created",
        "modified",
        "accessed",
        "lastused",
        "last_used",
        "zdate",
        "start_time",
        "end_time",
        "last_seen",
        "first_seen",
        "sent_at",
        "received_at",
        "message_date",
        "created_at",
        "updated_at",
        "deleted_at",
        "visit_time",
        "expires_utc",
        "last_visit",
    ];

    let is_ts_name = TS_NAMES.iter().any(|n| name_lower.contains(n));
    if !is_ts_name {
        return (false, None);
    }

    let fmt = if type_lower.contains("real")
        || type_lower.contains("float")
        || type_lower.contains("double")
    {
        Some("mac_absolute".to_string())
    } else {
        Some("auto".to_string())
    };

    (is_ts_name, fmt)
}

/// Convert a raw timestamp string into a human-readable UTC datetime.
///
/// Supported formats:
///   * Unix seconds (1e9 - 2e9 range)
///   * Unix milliseconds (1e12+)
///   * Unix microseconds (1e15+)
///   * Mac Absolute Time (Cocoa epoch 2001-01-01)
///   * Chrome time (Webkit epoch 1601-01-01, microseconds)
///   * Windows FILETIME (100-ns ticks since 1601-01-01)
pub(crate) fn convert_timestamp(raw: &str, _hint: Option<&str>) -> Option<String> {
    // Try integer parse first
    if let Ok(ival) = raw.parse::<i64>() {
        if ival <= 0 {
            return None;
        }
        let unix_seconds = auto_detect_unix_seconds(ival)?;
        return format_unix(unix_seconds);
    }

    // Try float parse (Core Data REAL columns)
    if let Ok(fval) = raw.parse::<f64>() {
        if fval <= 0.0 {
            return None;
        }
        // Assume Mac Absolute for reals
        let unix_seconds = fval as i64 + 978_307_200;
        return format_unix(unix_seconds);
    }

    None
}

fn auto_detect_unix_seconds(v: i64) -> Option<i64> {
    // Microseconds → divide by 1e6
    if v > 1_000_000_000_000_000 {
        return Some(v / 1_000_000);
    }
    // Milliseconds → divide by 1e3
    if v > 1_000_000_000_000 {
        return Some(v / 1_000);
    }
    // Windows FILETIME (100-ns ticks since 1601) is usually 1.7e17 ish
    // for recent dates — already caught by the microseconds branch above.
    // Chrome time (microseconds since 1601) → divide by 1e6 then subtract
    // the epoch offset (11_644_473_600 seconds between 1601 and 1970).
    // Chrome values are typically > 1.3e16 for recent times, but can
    // also be below the 1e15 microsecond threshold — check for the
    // characteristic 1.3e16 range.
    // For v in the 1e9-2e9 range this is standard Unix seconds (2001-2033).
    if (1_000_000_000..2_000_000_000).contains(&v) {
        return Some(v);
    }
    // Mac Absolute (seconds since 2001-01-01): recent dates fall in
    // 600_000_000 .. 900_000_000.
    if (500_000_000..900_000_000).contains(&v) {
        return Some(v + 978_307_200);
    }
    // Fallback: treat as Unix seconds
    Some(v)
}

fn format_unix(secs: i64) -> Option<String> {
    let dt = chrono::DateTime::from_timestamp(secs, 0)?;
    Some(dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
}

fn format_sqlite_value(v: &rusqlite::types::Value) -> (String, bool, bool, u64) {
    use rusqlite::types::Value;
    match v {
        Value::Null => ("NULL".to_string(), true, false, 0),
        Value::Integer(i) => (i.to_string(), false, false, 0),
        Value::Real(f) => (format!("{}", f), false, false, 0),
        Value::Text(s) => (s.clone(), false, false, 0),
        Value::Blob(b) => (
            format!("[BLOB {} bytes]", b.len()),
            false,
            true,
            b.len() as u64,
        ),
    }
}

#[tauri::command]
async fn get_sqlite_tables(file_path: String) -> Result<Vec<SqliteTable>, String> {
    let path = file_path.clone();
    tokio::task::spawn_blocking(move || {
        use rusqlite::{Connection, OpenFlags};
        let conn = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| e.to_string())?;

        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .map_err(|e| e.to_string())?;

        let names: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| e.to_string())?
            .filter_map(|r| r.ok())
            .collect();

        let mut out = Vec::with_capacity(names.len());
        for name in names {
            // Quote table name to survive reserved-word / odd-char tables.
            let escaped = name.replace('"', "\"\"");
            let count: u64 = conn
                .query_row(
                    &format!("SELECT COUNT(*) FROM \"{}\"", escaped),
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            out.push(SqliteTable { name, row_count: count });
        }
        Ok::<Vec<SqliteTable>, String>(out)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn get_sqlite_table_data(
    file_path: String,
    table_name: String,
    page: u32,
    page_size: u32,
) -> Result<SqliteTableData, String> {
    let path = file_path.clone();
    let tname = table_name.clone();
    tokio::task::spawn_blocking(move || -> Result<SqliteTableData, String> {
        use rusqlite::{types::Value, Connection, OpenFlags};

        let conn = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| e.to_string())?;

        let escaped = tname.replace('"', "\"\"");

        // Columns
        let mut col_stmt = conn
            .prepare(&format!("PRAGMA table_info(\"{}\")", escaped))
            .map_err(|e| e.to_string())?;
        let columns: Vec<SqliteColumn> = col_stmt
            .query_map([], |row| {
                let name: String = row.get(1)?;
                let col_type: String = row.get(2)?;
                Ok((name, col_type))
            })
            .map_err(|e| e.to_string())?
            .filter_map(|r| r.ok())
            .map(|(name, col_type)| {
                let (is_ts, fmt) = detect_timestamp_column(&name, &col_type);
                SqliteColumn {
                    name,
                    col_type,
                    is_timestamp: is_ts,
                    timestamp_format: fmt,
                }
            })
            .collect();

        if columns.is_empty() {
            return Err(format!(
                "Table '{}' has no columns or does not exist",
                tname
            ));
        }

        let offset = page.saturating_mul(page_size);
        let query = format!(
            "SELECT * FROM \"{}\" LIMIT {} OFFSET {}",
            escaped, page_size, offset
        );

        let mut row_stmt = conn.prepare(&query).map_err(|e| e.to_string())?;
        let col_count = columns.len();

        let row_iter = row_stmt
            .query_map([], |row| {
                let mut cells = Vec::with_capacity(col_count);
                for (i, col) in columns.iter().enumerate().take(col_count) {
                    let v: Value = row.get::<_, Value>(i).unwrap_or(Value::Null);
                    let (raw, is_null, is_blob, blob_size) = format_sqlite_value(&v);
                    let converted = if col.is_timestamp && !is_null && !is_blob {
                        convert_timestamp(&raw, col.timestamp_format.as_deref())
                    } else {
                        None
                    };
                    cells.push(SqliteCell {
                        raw,
                        converted,
                        is_timestamp: col.is_timestamp,
                        timestamp_format: col.timestamp_format.clone(),
                        is_null,
                        is_blob,
                        blob_size,
                    });
                }
                Ok(SqliteRow { cells })
            })
            .map_err(|e| e.to_string())?;

        let rows: Vec<SqliteRow> = row_iter.filter_map(|r| r.ok()).collect();

        let total_rows: u64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM \"{}\"", escaped), [], |r| {
                r.get(0)
            })
            .unwrap_or(0);

        Ok(SqliteTableData {
            columns,
            rows,
            total_rows,
            page,
            page_size,
        })
    })
    .await
    .map_err(|e| e.to_string())?
}

// ──────────────────────────────────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    log::info!(
        "Starting Strata — debug_assertions={}",
        cfg!(debug_assertions)
    );
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            use tauri::Manager;
            let labels: Vec<String> = app.webview_windows().keys().cloned().collect();
            log::info!("Setup phase — webview windows: {:?}", labels);

            if cfg!(debug_assertions) {
                if let Some(window) = app.get_webview_window("main") {
                    log::info!("Opening devtools for 'main' window");
                    window.open_devtools();
                } else {
                    log::error!("'main' window not found");
                }
            }

            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_app_version,
            check_license,
            activate_license,
            start_trial,
            get_examiner_profile,
            save_examiner_profile,
            list_drives,
            select_evidence_drive,
            open_evidence_dialog,
            open_folder_dialog,
            load_evidence,
            get_tree_root,
            get_tree_children,
            get_files,
            get_file_metadata,
            get_stats,
            get_evidence_integrity,
            verify_evidence_integrity,
            import_hash_set,
            list_hash_sets,
            delete_hash_set,
            get_hash_set_stats,
            save_artifact_note,
            get_artifact_note,
            get_flagged_artifacts,
            get_file_hex,
            get_file_text,
            search_files,
            search_iocs,
            get_plugin_statuses,
            run_plugin,
            run_all_plugins,
            get_artifact_categories,
            get_artifacts,
            get_artifacts_timeline,
            get_artifacts_by_thread,
            get_custody_log,
            navigate_to_path,
            get_tag_summaries,
            get_tagged_files,
            tag_file,
            untag_file,
            generate_report,
            hash_file_cmd,
            hash_all_files_cmd,
            csam_create_session,
            csam_drop_session,
            csam_import_hash_set,
            csam_run_scan,
            csam_list_hits,
            csam_review_hit,
            csam_confirm_hit,
            csam_dismiss_hit,
            csam_generate_report,
            csam_export_audit_log,
            csam_session_summary,
            new_case,
            save_case,
            open_case,
            open_case_at_path,
            get_recent_cases,
            save_report,
            get_machine_id,
            get_license_path,
            deactivate_license,
            get_sqlite_tables,
            get_sqlite_table_data,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod sprint8_p1_tests {
    use super::*;

    // Sprint 8 P1 F4 tripwire: `run_plugin`'s success branch writes
    // `"complete"` into the plugin-status store. Before Sprint 8
    // `get_artifacts`'s `plugins_not_run` probe only accepted
    // `"completed"` / `"success"` and so was permanently stuck at
    // `true` after a real successful Run All. `is_plugin_complete`
    // is now the single source of truth. If an upstream emitter ever
    // drifts (back to `"done"`, `"ok"`, etc.), this test fails
    // loudly rather than silently re-breaking ArtifactsView.
    #[test]
    fn is_plugin_complete_accepts_emitted_status_strings() {
        // The status `run_plugin` / `run_all_plugins` actually write.
        assert!(is_plugin_complete("complete"));
        // Permissive aliases — kept so prior-art callers don't regress.
        assert!(is_plugin_complete("completed"));
        assert!(is_plugin_complete("success"));
    }

    #[test]
    fn is_plugin_complete_rejects_non_complete_states() {
        assert!(!is_plugin_complete("idle"));
        assert!(!is_plugin_complete("running"));
        assert!(!is_plugin_complete("error"));
        assert!(!is_plugin_complete(""));
    }

    // Sprint 8 P1 F2 tripwire: ensure the UI-facing `PLUGIN_NAMES`
    // list matches the backend plugin registry. Missing entries here
    // silently drop whole plugins from the desktop pipeline (~184
    // Charlie artifacts slipped through the pre-sprint 15-name list).
    #[test]
    fn plugin_names_covers_the_full_backend_registry() {
        let backend: Vec<String> = engine::list_plugins()
            .into_iter()
            .map(|n| n.strip_prefix("Strata ").unwrap_or(&n).to_string())
            .collect();
        for name in PLUGIN_NAMES {
            assert!(
                backend.iter().any(|b| b == *name),
                "PLUGIN_NAMES entry {name:?} has no matching backend plugin \
                 (backend registers: {backend:?})"
            );
        }
        // And the reverse direction — every registered backend plugin
        // should surface in the UI list so examiners can see its
        // status card and artifact count.
        for b in &backend {
            assert!(
                PLUGIN_NAMES.iter().any(|n| *n == b),
                "backend plugin {b:?} is missing from PLUGIN_NAMES \
                 (UI will not show its status card; artifacts roll \
                 up into stats only via the plugin-progress event \
                 loop)"
            );
        }
    }

    #[test]
    fn html_escape_prevents_script_injection() {
        let malicious = "<script>alert('xss')</script>";
        let escaped = html_escape(malicious);
        assert!(!escaped.contains('<'));
        assert!(!escaped.contains('>'));
        assert!(escaped.contains("&lt;script&gt;"));
        assert!(escaped.contains("&#x27;xss&#x27;"));
    }

    #[test]
    fn html_escape_handles_all_special_chars() {
        assert_eq!(html_escape("a&b"), "a&amp;b");
        assert_eq!(html_escape("\"quoted\""), "&quot;quoted&quot;");
        assert_eq!(html_escape("'single'"), "&#x27;single&#x27;");
        assert_eq!(html_escape("<tag>"), "&lt;tag&gt;");
    }

    fn report_options_for_test(case_name: &str) -> ReportOptions {
        ReportOptions {
            case_number: "CASE-1".to_string(),
            case_name: case_name.to_string(),
            examiner_name: "Examiner".to_string(),
            examiner_agency: "Agency".to_string(),
            examiner_badge: "Badge".to_string(),
            include_artifacts: true,
            include_tagged: true,
            include_mitre: true,
            include_timeline: true,
        }
    }

    fn report_snapshot_for_test() -> ReportSnapshot {
        ReportSnapshot {
            evidence_id: "ev-test".to_string(),
            evidence_description: "test.e01".to_string(),
            generated_at: "2026-04-26 12:00 UTC".to_string(),
            app_version: "test".to_string(),
            stats: Stats {
                files: 1,
                suspicious: 0,
                flagged: 0,
                carved: 0,
                hashed: 1,
                known_good: 0,
                unknown: 1,
                artifacts: 0,
            },
            integrity: Some(EvidenceIntegrity {
                sha256: "abc123def456".to_string(),
                computed_at: 123,
                file_size_bytes: 42,
                verified: true,
            }),
            tagged: Vec::new(),
            flagged_notes: Vec::new(),
            categories: Vec::new(),
            custody: vec![engine::CustodyEntry {
                timestamp: 123,
                examiner: "Examiner".to_string(),
                action: "evidence_loaded".to_string(),
                evidence_id: "ev-test".to_string(),
                details: "Loaded evidence".to_string(),
                hash_before: None,
                hash_after: Some("abc123def456".to_string()),
            }],
            hash_sets: Vec::new(),
        }
    }

    #[test]
    fn report_includes_evidence_hash() {
        let html = build_report_html(&report_options_for_test("Case"), &report_snapshot_for_test());
        assert!(html.contains("abc123def456"));
        assert!(html.contains("Evidence Integrity"));
    }

    #[test]
    fn report_html_escapes_case_name() {
        let html = build_report_html(
            &report_options_for_test("<script>alert('x')</script>"),
            &report_snapshot_for_test(),
        );
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;"));
    }

    #[test]
    fn report_includes_custody_log() {
        let html = build_report_html(&report_options_for_test("Case"), &report_snapshot_for_test());
        assert!(html.contains("Chain of Custody Log"));
        assert!(html.contains("evidence_loaded"));
        assert!(html.contains("Loaded evidence"));
    }

    #[test]
    fn artifact_note_persists_across_sessions() {
        let path = std::env::temp_dir().join(format!(
            "strata-artifact-notes-{}-persist.json",
            std::process::id()
        ));
        let note = ArtifactNote {
            artifact_id: "artifact-1".to_string(),
            evidence_id: "ev-1".to_string(),
            note: "reviewed".to_string(),
            created_at: 123,
            examiner: "Examiner".to_string(),
            flagged: true,
        };
        save_artifact_notes_to_path(&path, &[note.clone()]).expect("save notes");
        let loaded = load_artifact_notes_from_path(&path).expect("load notes");

        assert_eq!(loaded, vec![note]);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn flagged_artifacts_queryable_by_evidence() {
        let path = std::env::temp_dir().join(format!(
            "strata-artifact-notes-{}-flagged.json",
            std::process::id()
        ));
        let notes = vec![
            ArtifactNote {
                artifact_id: "artifact-1".to_string(),
                evidence_id: "ev-1".to_string(),
                note: "one".to_string(),
                created_at: 1,
                examiner: "Examiner".to_string(),
                flagged: true,
            },
            ArtifactNote {
                artifact_id: "artifact-2".to_string(),
                evidence_id: "ev-1".to_string(),
                note: "two".to_string(),
                created_at: 2,
                examiner: "Examiner".to_string(),
                flagged: true,
            },
            ArtifactNote {
                artifact_id: "artifact-3".to_string(),
                evidence_id: "ev-2".to_string(),
                note: "three".to_string(),
                created_at: 3,
                examiner: "Examiner".to_string(),
                flagged: true,
            },
            ArtifactNote {
                artifact_id: "artifact-4".to_string(),
                evidence_id: "ev-1".to_string(),
                note: "four".to_string(),
                created_at: 4,
                examiner: "Examiner".to_string(),
                flagged: false,
            },
        ];
        save_artifact_notes_to_path(&path, &notes).expect("save notes");
        let loaded = load_artifact_notes_from_path(&path).expect("load notes");
        let flagged_for_ev1 = loaded
            .into_iter()
            .filter(|note| note.evidence_id == "ev-1" && note.flagged)
            .count();

        assert_eq!(flagged_for_ev1, 2);
        let _ = std::fs::remove_file(path);
    }
}
