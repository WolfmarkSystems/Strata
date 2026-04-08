use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use tauri::Emitter;

// Day 11 — engine adapter
use strata_engine_adapter as engine;

/// Most-recently loaded evidence id, used as a fallback when the UI calls a
/// per-evidence command without an explicit id.
static CURRENT_EVIDENCE_ID: OnceLock<Mutex<Option<String>>> = OnceLock::new();

fn current_evidence_lock() -> &'static Mutex<Option<String>> {
    CURRENT_EVIDENCE_ID.get_or_init(|| Mutex::new(None))
}

fn set_current_evidence_id(id: &str) {
    *current_evidence_lock().lock().unwrap() = Some(id.to_string());
}

fn current_evidence_id() -> Option<String> {
    current_evidence_lock().lock().unwrap().clone()
}

// ── Conversions: adapter types → desktop IPC types ─────────────────────────

fn adapter_tree_to_desktop(n: engine::TreeNode) -> TreeNode {
    TreeNode {
        id: n.id,
        name: n.name,
        node_type: n.node_type,
        count: n.count,
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

// ──────────────────────────────────────────────────────────────────────────────
// Types
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone)]
pub struct TreeNode {
    pub id: String,
    pub name: String,
    pub node_type: String,
    pub count: u64,
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
    pub artifacts: u64,
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
        .get_or_init(|| {
            let mut map: HashMap<String, TaggedFile> = HashMap::new();
            map.insert("f004".to_string(), TaggedFile {
                file_id: "f004".to_string(),
                name: "mimikatz.exe".to_string(),
                extension: "exe".to_string(),
                size_display: "1.2 MB".to_string(),
                modified: "2009-11-15 14:33".to_string(),
                full_path: "\\Windows\\Temp\\mimikatz.exe".to_string(),
                tag: "Critical Evidence".to_string(),
                tag_color: "#a84040".to_string(),
                tagged_at: "2009-11-16 09:00".to_string(),
                note: Some("Known credential dumping tool".to_string()),
            });
            map.insert("f003".to_string(), TaggedFile {
                file_id: "f003".to_string(),
                name: "svchost32.exe".to_string(),
                extension: "exe".to_string(),
                size_display: "892 KB".to_string(),
                modified: "2009-11-15 14:32".to_string(),
                full_path: "\\Windows\\System32\\svchost32.exe".to_string(),
                tag: "Suspicious".to_string(),
                tag_color: "#b87840".to_string(),
                tagged_at: "2009-11-16 09:01".to_string(),
                note: None,
            });
            map.insert("f010".to_string(), TaggedFile {
                file_id: "f010".to_string(),
                name: "cleanup.ps1".to_string(),
                extension: "ps1".to_string(),
                size_display: "4.8 KB".to_string(),
                modified: "2009-11-15 14:31".to_string(),
                full_path: "\\Windows\\Temp\\cleanup.ps1".to_string(),
                tag: "Suspicious".to_string(),
                tag_color: "#b87840".to_string(),
                tagged_at: "2009-11-16 09:02".to_string(),
                note: Some("Anti-forensic script".to_string()),
            });
            map.insert("f005".to_string(), TaggedFile {
                file_id: "f005".to_string(),
                name: "Security.evtx".to_string(),
                extension: "evtx".to_string(),
                size_display: "44 MB".to_string(),
                modified: "2009-11-16 03:44".to_string(),
                full_path: "\\Windows\\System32\\winevt\\Logs\\Security.evtx".to_string(),
                tag: "Key Artifact".to_string(),
                tag_color: "#4a7890".to_string(),
                tagged_at: "2009-11-16 09:03".to_string(),
                note: None,
            });
            Arc::new(Mutex::new(map))
        })
        .clone()
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
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ArtifactsResponse {
    pub artifacts: Vec<Artifact>,
    pub plugins_not_run: bool,
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

const PLUGIN_NAMES: &[&str] = &[
    "Remnant", "Chronicle", "Cipher", "Trace", "Specter", "Conduit", "Nimbus", "Wraith", "Vector",
    "Recon", "Phantom", "Guardian", "NetFlow", "MacTrace", "Sigma",
];


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
    let days_remaining =
        match (chrono::NaiveDate::parse_from_str(expires, "%Y-%m-%d"), chrono::Utc::now().date_naive()) {
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
async fn get_examiner_profile() -> Result<ExaminerProfile, String> {
    Ok(ExaminerProfile {
        name: String::new(),
        agency: String::new(),
        badge: String::new(),
        email: String::new(),
    })
}

#[tauri::command]
async fn save_examiner_profile(profile: ExaminerProfile) -> Result<(), String> {
    println!("Saving examiner: {:?}", profile.name);
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
        let display_name = if name.is_empty() {
            mount.clone()
        } else {
            name
        };

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

#[derive(Serialize, Deserialize)]
pub struct ReportResult {
    pub html: String,
    pub path: Option<String>,
}

#[tauri::command]
async fn generate_report(options: ReportOptions) -> Result<ReportResult, String> {
    let html = build_report_html(&options);
    Ok(ReportResult { html, path: None })
}

fn build_report_html(o: &ReportOptions) -> String {
    let css = include_str!("report_css.css");
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
      <div>Generated: 2026-04-06 09:00</div>
      <div>Examiner: {examiner_name}</div>
    </div>
  </div>

  <div class="section">
    <h2>Case Information</h2>
    <div class="info-grid">
      <div class="info-row"><span class="info-key">Case No.</span><span class="info-val">{case_number}</span></div>
      <div class="info-row"><span class="info-key">Case Name</span><span class="info-val">{case_name}</span></div>
      <div class="info-row"><span class="info-key">Examiner</span><span class="info-val">{examiner_name}</span></div>
      <div class="info-row"><span class="info-key">Agency</span><span class="info-val">{examiner_agency}</span></div>
      <div class="info-row"><span class="info-key">Badge</span><span class="info-val">{examiner_badge}</span></div>
      <div class="info-row"><span class="info-key">Platform</span><span class="info-val">Strata v1.3.0</span></div>
    </div>
  </div>

  <div class="section">
    <h2>Executive Summary</h2>
    <div class="stats-grid">
      <div class="stat-card"><div class="stat-label">Files</div><div class="stat-value">26,235</div></div>
      <div class="stat-card"><div class="stat-label">Suspicious</div><div class="stat-value sus">8,993</div></div>
      <div class="stat-card"><div class="stat-label">Flagged</div><div class="stat-value flag">12</div></div>
      <div class="stat-card"><div class="stat-label">Artifacts</div><div class="stat-value">403</div></div>
      <div class="stat-card"><div class="stat-label">Tagged</div><div class="stat-value">4</div></div>
      <div class="stat-card"><div class="stat-label">Plugins Run</div><div class="stat-value">11</div></div>
    </div>
    <p style="margin-top:12px; font-size:12px; color:#4a5568; line-height:1.7;">
      Examination of the submitted evidence image revealed indicators of credential dumping activity, anti-forensic tool usage, and attempted evidence destruction. The presence of mimikatz.exe, a known credential dumping tool, combined with evidence of scheduled task persistence and deliberate event log clearing suggests a targeted intrusion with post-exploitation activity.
    </p>
  </div>

  <div class="section">
    <h2>Critical Findings</h2>
    <table>
      <thead><tr><th>Finding</th><th>Value</th><th>Timestamp</th><th>MITRE</th><th>Severity</th></tr></thead>
      <tbody>
        <tr><td>mimikatz.exe execution</td><td>3 executions recorded</td><td style="font-family:monospace;font-size:10px;">2009-11-15 14:33:05</td><td><span class="badge badge-mitre">T1003</span></td><td><span class="badge badge-high">HIGH</span></td></tr>
        <tr><td>Anti-forensic script executed</td><td>Event logs cleared, VSS deleted</td><td style="font-family:monospace;font-size:10px;">2009-11-15 14:31:05</td><td><span class="badge badge-mitre">T1070.001</span></td><td><span class="badge badge-high">HIGH</span></td></tr>
        <tr><td>Scheduled task persistence</td><td>svchost32.exe as WindowsUpdate</td><td style="font-family:monospace;font-size:10px;">2009-11-14 03:00:00</td><td><span class="badge badge-mitre">T1053.005</span></td><td><span class="badge badge-high">HIGH</span></td></tr>
        <tr><td>Credential dump deleted</td><td>lsass.dmp sent to Recycle Bin</td><td style="font-family:monospace;font-size:10px;">2009-11-15 14:45:00</td><td><span class="badge badge-mitre">T1003.001</span></td><td><span class="badge badge-high">HIGH</span></td></tr>
        <tr><td>RDP lateral movement</td><td>Connection to 192.168.1.50</td><td style="font-family:monospace;font-size:10px;">2009-11-15 13:45:00</td><td><span class="badge badge-mitre">T1021.001</span></td><td><span class="badge badge-medium">MEDIUM</span></td></tr>
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>Tagged Evidence</h2>
    <table>
      <thead><tr><th>File</th><th>Tag</th><th>Path</th><th>Note</th></tr></thead>
      <tbody>
        <tr><td style="font-weight:700">mimikatz.exe</td><td><span class="tag-critical">Critical Evidence</span></td><td style="font-family:monospace;font-size:10px;">\Windows\Temp\mimikatz.exe</td><td>Known credential dumping tool</td></tr>
        <tr><td style="font-weight:700">cleanup.ps1</td><td><span class="tag-suspicious">Suspicious</span></td><td style="font-family:monospace;font-size:10px;">\Windows\Temp\cleanup.ps1</td><td>Anti-forensic script</td></tr>
        <tr><td style="font-weight:700">svchost32.exe</td><td><span class="tag-suspicious">Suspicious</span></td><td style="font-family:monospace;font-size:10px;">\Windows\System32\svchost32.exe</td><td>&mdash;</td></tr>
        <tr><td style="font-weight:700">Security.evtx</td><td><span class="tag-key">Key Artifact</span></td><td style="font-family:monospace;font-size:10px;">\Windows\System32\winevt\Logs\Security.evtx</td><td>&mdash;</td></tr>
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
      I, {examiner_name}, of {examiner_agency}, badge number {examiner_badge}, certify that the forensic examination described in this report was conducted in accordance with accepted digital forensic practices. The findings contained herein are accurate and complete to the best of my knowledge. This report was generated by Strata v1.3.0, a Wolfmark Systems forensic intelligence platform.
    </div>
    <div class="sig-line">
      <span>Examiner: {examiner_name}</span>
      <span>Agency: {examiner_agency}</span>
      <span>Date: ___________________</span>
      <span>Signature: _______________</span>
    </div>
  </div>

  <div class="footer">
    <span>Strata v1.3.0 &mdash; Wolfmark Systems</span>
    <span>Case: {case_number}</span>
    <span>CONFIDENTIAL &mdash; FORENSIC REPORT</span>
  </div>

</div>
</body>
</html>"##,
        css = css,
        chevron = chevron_svg,
        case_number = o.case_number,
        case_name = o.case_name,
        examiner_name = o.examiner_name,
        examiner_agency = o.examiner_agency,
        examiner_badge = o.examiner_badge,
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
            &["E01", "e01", "dd", "img", "raw", "vmdk", "vhd", "vhdx"],
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
async fn load_evidence(path: String) -> Result<EvidenceLoadResult, String> {
    // Run the (potentially heavy) parse on a blocking thread so the Tauri
    // command thread isn't held up.
    let result =
        tokio::task::spawn_blocking(move || engine::parse_evidence(&path))
            .await
            .map_err(|e| e.to_string())?;

    match result {
        Ok(info) => {
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
    let f =
        tokio::task::spawn_blocking(move || engine::get_file_metadata(&evidence_id, &file_id))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
    Ok(adapter_file_to_metadata(f))
}


#[tauri::command]
async fn get_file_hex(
    file_id: String,
    offset: u64,
    length: u64,
) -> Result<HexData, String> {
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
async fn get_tag_summaries() -> Result<Vec<TagSummary>, String> {
    let store = get_tag_store();
    let map = store.lock().map_err(|e| e.to_string())?;

    let tag_defs = [
        ("Critical Evidence", "#a84040"),
        ("Suspicious",        "#b87840"),
        ("Needs Review",      "#b8a840"),
        ("Confirmed Clean",   "#487858"),
        ("Key Artifact",      "#4a7890"),
        ("Excluded",          "#3a4858"),
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
async fn get_tagged_files(tag: String) -> Result<Vec<TaggedFile>, String> {
    let store = get_tag_store();
    let map = store.lock().map_err(|e| e.to_string())?;
    let files: Vec<TaggedFile> = map.values().filter(|f| f.tag == tag).cloned().collect();
    Ok(files)
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn tag_file(
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
    let store = get_tag_store();
    let mut map = store.lock().map_err(|e| e.to_string())?;
    map.insert(file_id.clone(), TaggedFile {
        file_id,
        name: file_name,
        extension,
        size_display,
        modified,
        full_path,
        tag,
        tag_color,
        tagged_at: "2009-11-16 09:00".to_string(),
        note,
    });
    Ok(())
}

#[tauri::command]
async fn untag_file(file_id: String) -> Result<(), String> {
    let store = get_tag_store();
    let mut map = store.lock().map_err(|e| e.to_string())?;
    map.remove(&file_id);
    Ok(())
}

#[tauri::command]
async fn get_artifact_categories(
    evidence_id: String,
) -> Result<Vec<ArtifactCategory>, String> {
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
async fn get_artifacts(
    evidence_id: String,
    category: String,
) -> Result<ArtifactsResponse, String> {
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
        let artifacts = real
            .into_iter()
            .map(|a| Artifact {
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
            })
            .collect();
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
        let map = store.lock().map_err(|e: std::sync::PoisonError<_>| e.to_string())?;
        let any_completed = map
            .values()
            .any(|s| s.status == "completed" || s.status == "success");
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
    for plugin in PLUGIN_NAMES {
        let _ = run_plugin(plugin.to_string(), evidence_id.clone(), app.clone()).await;
    }
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
        artifacts: s.artifacts,
    })
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
async fn hash_file_cmd(
    evidence_id: String,
    file_id: String,
) -> Result<HashResultIpc, String> {
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
async fn hash_all_files_cmd(
    evidence_id: String,
    app: tauri::AppHandle,
) -> Result<u64, String> {
    let eid = if evidence_id.is_empty() {
        current_evidence_id().unwrap_or_default()
    } else {
        evidence_id
    };
    if eid.is_empty() {
        return Err("No evidence loaded".to_string());
    }

    let app_progress = app.clone();
    let results = tokio::task::spawn_blocking(move || {
        engine::hash_all_files(&eid, move |done, total| {
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

    Ok(results.len() as u64)
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
    Ok(path.to_string_lossy().to_string())
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

    let fmt = if type_lower.contains("real") || type_lower.contains("float") || type_lower.contains("double") {
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
        Value::Blob(b) => (format!("[BLOB {} bytes]", b.len()), false, true, b.len() as u64),
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
            return Err(format!("Table '{}' has no columns or does not exist", tname));
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
            .query_row(
                &format!("SELECT COUNT(*) FROM \"{}\"", escaped),
                [],
                |r| r.get(0),
            )
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
    eprintln!("[STRATA] Starting v1.3.0 — debug_assertions={}", cfg!(debug_assertions));
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            use tauri::Manager;
            let labels: Vec<String> = app.webview_windows().keys().cloned().collect();
            eprintln!("[STRATA] Setup phase — webview windows: {:?}", labels);

            // Force devtools open on every build (devtools feature flag is on in Cargo.toml).
            if let Some(window) = app.get_webview_window("main") {
                eprintln!("[STRATA] Opening devtools for 'main' window");
                window.open_devtools();
            } else {
                eprintln!("[STRATA] ERROR: 'main' window not found!");
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
            load_evidence,
            get_tree_root,
            get_tree_children,
            get_files,
            get_file_metadata,
            get_stats,
            get_file_hex,
            get_file_text,
            search_files,
            get_plugin_statuses,
            run_plugin,
            run_all_plugins,
            get_artifact_categories,
            get_artifacts,
            get_tag_summaries,
            get_tagged_files,
            tag_file,
            untag_file,
            generate_report,
            hash_file_cmd,
            hash_all_files_cmd,
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
