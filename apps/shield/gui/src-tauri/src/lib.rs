use rayon::prelude::*;
use std::{
    collections::{HashMap, HashSet},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use tauri::{Emitter, Manager};
use tracing::{error, info, warn};

mod kb_bridge_client;

fn write_log(msg: &str) {
    // Print to console immediately
    println!("[LOG] {}", msg);

    // Also write to file - use absolute path
    let log_path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("forensic_suite.log");

    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        let _ = writeln!(
            file,
            "[{}] {}",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
            msg
        );
    }
}

fn count_tree_nodes(tree: &TreeNode) -> usize {
    let mut count = 1; // Count self
    for child in &tree.children {
        count += count_tree_nodes(child);
    }
    count
}

fn build_hex_dump(data: &[u8]) -> String {
    let mut out = String::new();
    for (line, chunk) in data.chunks(16).enumerate() {
        let offset = line * 16;
        let mut hex_part = String::new();
        let mut ascii_part = String::new();

        for (i, b) in chunk.iter().enumerate() {
            if i == 8 {
                hex_part.push(' ');
            }
            hex_part.push_str(&format!("{:02X} ", b));
            let ch = *b as char;
            if ch.is_ascii_graphic() || ch == ' ' {
                ascii_part.push(ch);
            } else {
                ascii_part.push('.');
            }
        }

        while hex_part.len() < 49 {
            hex_part.push(' ');
        }
        out.push_str(&format!("{:08X}  {} |{}|\n", offset, hex_part, ascii_part));
    }
    out
}

fn extract_ascii_strings(data: &[u8], min_len: usize, max_items: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut current: Vec<u8> = Vec::new();

    for b in data {
        if b.is_ascii_graphic() || *b == b' ' || *b == b'\t' {
            current.push(*b);
        } else {
            if current.len() >= min_len {
                out.push(String::from_utf8_lossy(&current).to_string());
                if out.len() >= max_items {
                    return out;
                }
            }
            current.clear();
        }
    }

    if current.len() >= min_len && out.len() < max_items {
        out.push(String::from_utf8_lossy(&current).to_string());
    }

    out
}

use forensic_engine::{
    container::open_evidence_container,
    context::EngineContext,
    disk::detect_image_format,
    events::{EngineEventKind, EventSeverity},
    evidence::{
        build_filtered_tree, ArtifactNote, ArtifactTag, EvidenceAnalyzer, SearchResult,
        SearchResultType, TreeNode,
    },
    hashing::{hash_and_categorize_parallel, hash_bytes, FileCategory, FileHashResult},
    hashset::{HashCategory, SqliteHashSetManager},
    parser::ParserRegistry,
    plugin::{get_default_plugin_dir, PluginInfo, PluginManager},
    report::export::ExportFormat,
    report::generator::ReportGenerator,
    timeline::TimelineEntry,
    virtualization::{MountManager, VirtualFileSystem, VolumeInfo},
};
use kb_bridge_client::{KbBridgeClient, KbBridgeHealth, KbSearchResponse};

#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[tauri::command]
fn kb_bridge_health() -> Result<KbBridgeHealth, String> {
    KbBridgeClient::from_env()
        .and_then(|client| client.health())
        .map_err(|err| err.to_string())
}

#[tauri::command]
fn search_kb_bridge(query: String, limit: Option<usize>) -> Result<KbSearchResponse, String> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Err("KB bridge query cannot be empty".to_string());
    }

    KbBridgeClient::from_env()
        .and_then(|client| client.search(trimmed, limit.unwrap_or(6)))
        .map_err(|err| err.to_string())
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MountResult {
    pub format: String,
    pub description: String,
    pub total_size: u64,
    pub volumes: Vec<VolumeInfo>,
    pub is_compressed: bool,
    pub is_encrypted: bool,
}

#[tauri::command]
fn mount_evidence(path: String) -> Result<MountResult, String> {
    let root_path = PathBuf::from(&path);

    if !root_path.exists() {
        return Err(format!("Path does not exist: {}", path));
    }

    let format_info =
        detect_image_format(&root_path).map_err(|e| format!("Failed to detect format: {}", e))?;

    let mount_result =
        MountManager::mount(&root_path).map_err(|e| format!("Failed to mount: {}", e))?;

    write_log(&format!(
        "[CRITICAL] mount_evidence: found {} volumes",
        mount_result.volumes.len()
    ));
    for vol in &mount_result.volumes {
        write_log(&format!(
            "[CRITICAL] mount_evidence: volume {} - filesystem: {:?}, size: {}",
            vol.volume_index, vol.filesystem, vol.size
        ));
    }

    Ok(MountResult {
        format: mount_result.format.as_str().to_string(),
        description: format_info.description,
        total_size: mount_result.total_size,
        volumes: mount_result.volumes,
        is_compressed: format_info.is_compressed,
        is_encrypted: format_info.is_encrypted,
    })
}

#[tauri::command]
fn detect_evidence_format(path: String) -> Result<serde_json::Value, String> {
    let root_path = PathBuf::from(&path);

    if !root_path.exists() {
        return Err(format!("Path does not exist: {}", path));
    }

    let format_info =
        detect_image_format(&root_path).map_err(|e| format!("Failed to detect format: {}", e))?;

    Ok(serde_json::json!({
        "format": format_info.format.as_str(),
        "description": format_info.description,
        "isCompressed": format_info.is_compressed,
        "isEncrypted": format_info.is_encrypted,
        "totalSize": format_info.total_size,
        "segmentCount": format_info.segment_count,
    }))
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VolumeEntryRow {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified_time: Option<i64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HashMatchSampleRow {
    pub path: String,
    pub sha256: String,
    pub category: String,
    pub size: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HashVfsFilesResult {
    pub total_files: usize,
    pub hashed_files: usize,
    pub known_good_matches: usize,
    pub known_bad_matches: usize,
    pub unmatched: usize,
    pub nsrl_count: usize,
    pub custom_bad_count: usize,
    pub sample_matches: Vec<HashMatchSampleRow>,
}

#[tauri::command]
fn capabilities() -> serde_json::Value {
    serde_json::json!({
        "name": "Strata Shield",
        "version": env!("CARGO_PKG_VERSION"),
        "commands": {
            "kb_bridge_health": true,
            "mount_evidence": true,
            "detect_evidence_format": true,
            "enumerate_volume": true,
            "read_vfs_file": true,
            "load_hashsets": true,
            "load_nsrl_database": true,
            "hash_vfs_files": true,
            "get_timeline_rows": true,
            "get_email_rows": true,
            "get_registry_rows": true
        }
    })
}

#[tauri::command]
fn enumerate_volume(
    evidence_path: String,
    volume_index: Option<usize>,
) -> Result<Vec<VolumeEntryRow>, String> {
    let root_path = PathBuf::from(&evidence_path);
    if !root_path.exists() {
        return Err(format!("Evidence path does not exist: {}", evidence_path));
    }

    let source = open_evidence_container(root_path.as_path())
        .map_err(|e| format!("Failed to open evidence source: {:?}", e))?;
    let vfs = source
        .vfs_ref()
        .ok_or_else(|| "No virtual filesystem available for evidence source".to_string())?;

    let volumes = vfs.get_volumes();
    if volumes.is_empty() {
        return Ok(Vec::new());
    }

    let target_volume = volume_index.unwrap_or(volumes[0].volume_index);
    let entries = vfs
        .enumerate_volume(target_volume)
        .map_err(|e| format!("Failed to enumerate volume {}: {:?}", target_volume, e))?;

    Ok(entries
        .into_iter()
        .map(|entry| VolumeEntryRow {
            name: entry.name,
            path: normalize_virtual_path(entry.path.as_path()),
            is_dir: entry.is_dir,
            size: entry.size,
            modified_time: entry.modified.map(|m| m.timestamp()),
        })
        .collect())
}

#[tauri::command]
async fn read_vfs_file(
    evidence_path: String,
    artifact_path: String,
    max_bytes: Option<usize>,
) -> Result<serde_json::Value, String> {
    let preview = read_artifact_preview(evidence_path, artifact_path, max_bytes).await?;
    let hex_dump = preview
        .get("hexDump")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let bytes_read = preview
        .get("bytesRead")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let content_utf8 = hex_dump
        .lines()
        .map(|line| line.split('|').nth(1).unwrap_or("").trim())
        .collect::<Vec<_>>()
        .join(" ");

    Ok(serde_json::json!({
        "artifactPath": preview.get("artifactPath").cloned().unwrap_or(serde_json::json!("")),
        "bytesRead": bytes_read,
        "totalBytes": preview.get("totalBytes").cloned().unwrap_or(serde_json::json!(0)),
        "truncated": preview.get("truncated").cloned().unwrap_or(serde_json::json!(false)),
        "hexDump": hex_dump,
        "contentUtf8": content_utf8,
        "strings": preview.get("strings").cloned().unwrap_or(serde_json::json!([]))
    }))
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TreeLoadResult {
    pub tree: TreeNode,
    pub categorization_summary: HashMap<String, usize>,
    pub total_files: usize,
    pub total_hashed: usize,
    pub container_type: String,
    pub hashset_stats: HashSetLoadResult,
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct HashSetLoadResult {
    pub nsrl_count: usize,
    pub custom_bad_count: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Artifact {
    pub artifact_type: String,
    pub name: String,
    pub path: String,
    pub description: String,
    pub timestamp: Option<i64>,
    pub created_time: Option<i64>,
    pub modified_time: Option<i64>,
    pub accessed_time: Option<i64>,
    pub mft_changed_time: Option<i64>,
    pub size: Option<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuiltEmailRow {
    pub id: String,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub date: Option<i64>,
    pub attachments: u32,
    pub source: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuiltRegistryRow {
    pub id: String,
    pub key: String,
    pub value: String,
    pub data: String,
    pub last_write: Option<i64>,
    pub source: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuiltMediaRow {
    pub id: String,
    pub name: String,
    pub path: String,
    pub media_type: String,
    pub size: u64,
    pub modified_time: Option<i64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuiltTimelineRow {
    pub id: String,
    pub timestamp: Option<i64>,
    pub event_type: String,
    pub source: String,
    pub description: String,
}

#[derive(Default)]
struct SpecializedViewCache {
    email_rows: std::sync::Mutex<Vec<BuiltEmailRow>>,
    registry_rows: std::sync::Mutex<Vec<BuiltRegistryRow>>,
    media_rows: std::sync::Mutex<Vec<BuiltMediaRow>>,
    timeline_rows: std::sync::Mutex<Vec<BuiltTimelineRow>>,
    active_source: std::sync::Mutex<Option<String>>,
}

fn normalize_virtual_path(path: &std::path::Path) -> String {
    let mut text = path.to_string_lossy().replace('\\', "/");
    if text.is_empty() {
        return "/".to_string();
    }
    if !text.starts_with('/') {
        text.insert(0, '/');
    }
    while text.contains("//") {
        text = text.replace("//", "/");
    }
    while text.len() > 1 && text.ends_with('/') {
        text.pop();
    }
    text.to_ascii_lowercase()
}

fn default_virtual_file_category(path: &Path) -> FileCategory {
    let filename = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    match filename.as_str() {
        "pagefile.sys" | "hiberfil.sys" | "swapfile.sys" | "$mft" | "$bitmap" | "$boot"
        | "thumbs.db" | "desktop.ini" | "ntuser.dat" | "ntuser.ini" => FileCategory::OSArtifact,
        _ => FileCategory::Unknown,
    }
}

fn normalize_virtual_path_text(raw: &str) -> String {
    let mut text = raw.replace('\\', "/");
    if text.is_empty() {
        return "/".to_string();
    }
    if !text.starts_with('/') {
        text.insert(0, '/');
    }
    while text.contains("//") {
        text = text.replace("//", "/");
    }
    while text.len() > 1 && text.ends_with('/') {
        text.pop();
    }
    text.to_ascii_lowercase()
}

fn strip_volume_prefix(path: &str) -> &str {
    if let Some(rest) = path.strip_prefix("/vol") {
        let digits = rest.chars().take_while(|c| c.is_ascii_digit()).count();
        if digits > 0 {
            let after = &rest[digits..];
            return after.trim_start_matches('/');
        }
    }
    path.trim_start_matches('/')
}

fn media_type_from_path(path_lower: &str) -> Option<&'static str> {
    if [
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".heic", ".raw",
    ]
    .iter()
    .any(|ext| path_lower.ends_with(ext))
    {
        return Some("image");
    }
    if [
        ".mp4", ".mov", ".avi", ".mkv", ".wmv", ".flv", ".m4v", ".3gp",
    ]
    .iter()
    .any(|ext| path_lower.ends_with(ext))
    {
        return Some("video");
    }
    if [".mp3", ".wav", ".flac", ".aac", ".m4a", ".ogg", ".wma"]
        .iter()
        .any(|ext| path_lower.ends_with(ext))
    {
        return Some("audio");
    }
    None
}

fn looks_like_email_artifact(path_lower: &str) -> bool {
    [".pst", ".ost", ".eml", ".msg", ".mbox", ".dbx", ".oft"]
        .iter()
        .any(|ext| path_lower.ends_with(ext))
        || path_lower.contains("outlook")
        || path_lower.contains("mail")
        || path_lower.contains("thunderbird")
}

fn looks_like_registry_artifact(path_lower: &str) -> bool {
    let name = path_lower.rsplit('/').next().unwrap_or(path_lower);
    matches!(
        name,
        "ntuser.dat"
            | "usrclass.dat"
            | "sam"
            | "security"
            | "software"
            | "system"
            | "amcache.hve"
            | "bcd"
    ) || path_lower.ends_with(".reg")
        || path_lower.contains("registry")
}

fn reset_specialized_view_cache(cache: &Arc<SpecializedViewCache>, source: &str) {
    if let Ok(mut rows) = cache.email_rows.lock() {
        rows.clear();
    }
    if let Ok(mut rows) = cache.registry_rows.lock() {
        rows.clear();
    }
    if let Ok(mut rows) = cache.media_rows.lock() {
        rows.clear();
    }
    if let Ok(mut rows) = cache.timeline_rows.lock() {
        rows.clear();
    }
    if let Ok(mut active) = cache.active_source.lock() {
        *active = Some(source.to_string());
    }
}

fn build_specialized_views_background(
    source_path: PathBuf,
    cache: Arc<SpecializedViewCache>,
    event_bus: Arc<forensic_engine::events::EventBus>,
    case_id: Option<String>,
) {
    let source_string = source_path.to_string_lossy().to_string();
    reset_specialized_view_cache(&cache, &source_string);

    let start_job = |job_type: &str, message: &str| {
        event_bus.emit_simple(
            case_id.clone(),
            EngineEventKind::JobStatus {
                job_id: format!("{}_builder", job_type),
                job_type: format!("{}_builder", job_type),
                status: "started".to_string(),
            },
            EventSeverity::Info,
            message,
        );
        event_bus.emit_simple(
            case_id.clone(),
            EngineEventKind::JobProgress {
                job_id: format!("{}_builder", job_type),
                job_type: format!("{}_builder", job_type),
                progress: 1.0,
                message: message.to_string(),
            },
            EventSeverity::Info,
            message,
        );
    };

    start_job("timeline", "Building timeline dataset");
    start_job("email", "Building email dataset");
    start_job("registry", "Building registry dataset");
    start_job("media", "Building media dataset");

    let source = match open_evidence_container(&source_path) {
        Ok(source) => source,
        Err(e) => {
            let msg = format!("Failed to open evidence for specialized builders: {:?}", e);
            error!("{}", msg);
            for jt in ["timeline", "email", "registry", "media"] {
                event_bus.emit_simple(
                    case_id.clone(),
                    EngineEventKind::JobStatus {
                        job_id: format!("{}_builder", jt),
                        job_type: format!("{}_builder", jt),
                        status: "failed".to_string(),
                    },
                    EventSeverity::Error,
                    &msg,
                );
            }
            return;
        }
    };

    let Some(vfs) = source.vfs_ref() else {
        let msg = "No VFS available for specialized builders".to_string();
        warn!("{}", msg);
        for jt in ["timeline", "email", "registry", "media"] {
            event_bus.emit_simple(
                case_id.clone(),
                EngineEventKind::JobStatus {
                    job_id: format!("{}_builder", jt),
                    job_type: format!("{}_builder", jt),
                    status: "failed".to_string(),
                },
                EventSeverity::Warn,
                &msg,
            );
        }
        return;
    };

    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    for volume in vfs.get_volumes() {
        if let Ok(vol_entries) = vfs.enumerate_volume(volume.volume_index) {
            for entry in vol_entries {
                if entry.is_dir {
                    continue;
                }
                let key = normalize_virtual_path(entry.path.as_path());
                if seen.insert(key) {
                    entries.push(entry);
                }
            }
        }
    }

    let total = entries.len().max(1);
    let mut email_rows = Vec::new();
    let mut registry_rows = Vec::new();
    let mut media_rows = Vec::new();
    let mut timeline_rows = Vec::new();

    for (idx, entry) in entries.into_iter().enumerate() {
        let path = normalize_virtual_path(entry.path.as_path());
        let path_lower = path.to_ascii_lowercase();
        let ts = entry.modified.map(|m| m.timestamp());

        if timeline_rows.len() < 60_000 {
            timeline_rows.push(BuiltTimelineRow {
                id: format!("fs:{}:{}", idx, path),
                timestamp: ts,
                event_type: "Filesystem".to_string(),
                source: path.clone(),
                description: format!("File observed: {} ({} bytes)", entry.name, entry.size),
            });
        }

        if looks_like_email_artifact(&path_lower) {
            email_rows.push(BuiltEmailRow {
                id: format!("email:{}:{}", idx, path),
                from: "—".to_string(),
                to: "—".to_string(),
                subject: entry.name.clone(),
                date: ts,
                attachments: 0,
                source: path.clone(),
            });
        }

        if looks_like_registry_artifact(&path_lower) {
            registry_rows.push(BuiltRegistryRow {
                id: format!("registry:{}:{}", idx, path),
                key: path.clone(),
                value: entry.name.clone(),
                data: format!("{} bytes", entry.size),
                last_write: ts,
                source: "filesystem".to_string(),
            });
        }

        if let Some(media_type) = media_type_from_path(&path_lower) {
            media_rows.push(BuiltMediaRow {
                id: format!("media:{}:{}", idx, path),
                name: entry.name.clone(),
                path: path.clone(),
                media_type: media_type.to_string(),
                size: entry.size,
                modified_time: ts,
            });
        }

        if idx == 0 || (idx + 1) % 2000 == 0 || idx + 1 == total {
            let progress = ((idx + 1) as f32 / total as f32) * 100.0;
            for jt in ["timeline", "email", "registry", "media"] {
                event_bus.emit_simple(
                    case_id.clone(),
                    EngineEventKind::JobProgress {
                        job_id: format!("{}_builder", jt),
                        job_type: format!("{}_builder", jt),
                        progress,
                        message: format!("Scanning files {}/{}", idx + 1, total),
                    },
                    EventSeverity::Info,
                    "Building specialized datasets",
                );
            }
        }
    }

    timeline_rows.sort_by(|a, b| b.timestamp.unwrap_or(0).cmp(&a.timestamp.unwrap_or(0)));
    email_rows.sort_by(|a, b| b.date.unwrap_or(0).cmp(&a.date.unwrap_or(0)));
    registry_rows.sort_by(|a, b| b.last_write.unwrap_or(0).cmp(&a.last_write.unwrap_or(0)));
    media_rows.sort_by(|a, b| {
        b.modified_time
            .unwrap_or(0)
            .cmp(&a.modified_time.unwrap_or(0))
    });

    timeline_rows.truncate(25_000);
    email_rows.truncate(10_000);
    registry_rows.truncate(10_000);
    media_rows.truncate(20_000);

    if let Ok(mut rows) = cache.timeline_rows.lock() {
        *rows = timeline_rows;
    }
    if let Ok(mut rows) = cache.email_rows.lock() {
        *rows = email_rows;
    }
    if let Ok(mut rows) = cache.registry_rows.lock() {
        *rows = registry_rows;
    }
    if let Ok(mut rows) = cache.media_rows.lock() {
        *rows = media_rows;
    }

    let complete_job = |job_type: &str, count: usize| {
        event_bus.emit_simple(
            case_id.clone(),
            EngineEventKind::JobProgress {
                job_id: format!("{}_builder", job_type),
                job_type: format!("{}_builder", job_type),
                progress: 100.0,
                message: format!("{} rows ready", count),
            },
            EventSeverity::Info,
            "Specialized dataset complete",
        );
        event_bus.emit_simple(
            case_id.clone(),
            EngineEventKind::JobStatus {
                job_id: format!("{}_builder", job_type),
                job_type: format!("{}_builder", job_type),
                status: "completed".to_string(),
            },
            EventSeverity::Info,
            "Specialized dataset complete",
        );
    };

    let timeline_count = cache.timeline_rows.lock().map(|v| v.len()).unwrap_or(0);
    let email_count = cache.email_rows.lock().map(|v| v.len()).unwrap_or(0);
    let registry_count = cache.registry_rows.lock().map(|v| v.len()).unwrap_or(0);
    let media_count = cache.media_rows.lock().map(|v| v.len()).unwrap_or(0);

    complete_job("timeline", timeline_count);
    complete_job("email", email_count);
    complete_job("registry", registry_count);
    complete_job("media", media_count);
}

fn resolve_vfs_preview_path(
    vfs: &dyn VirtualFileSystem,
    evidence_path: &str,
    artifact_path: &str,
) -> Result<PathBuf, String> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let mut push_candidate = |candidate: String| {
        let normalized = normalize_virtual_path_text(&candidate);
        if seen.insert(normalized) {
            candidates.push(PathBuf::from(candidate));
        }
    };

    push_candidate(artifact_path.to_string());
    push_candidate(artifact_path.replace('\\', "/"));
    push_candidate(normalize_virtual_path_text(artifact_path));

    let artifact_norm = normalize_virtual_path_text(artifact_path);
    if !artifact_norm.starts_with("/vol") {
        push_candidate(format!("/vol0/{}", artifact_norm.trim_start_matches('/')));
    }

    let evidence_norm = evidence_path.replace('\\', "/").to_ascii_lowercase();
    let artifact_slashes = artifact_path.replace('\\', "/");
    let artifact_slashes_lower = artifact_slashes.to_ascii_lowercase();
    if artifact_slashes_lower.starts_with(&evidence_norm) {
        let stripped = artifact_slashes[evidence_norm.len()..].trim_start_matches('/');
        if !stripped.is_empty() {
            push_candidate(format!("/{}", stripped));
            if !stripped.to_ascii_lowercase().starts_with("vol") {
                push_candidate(format!("/vol0/{}", stripped));
            }
        }
    }

    for candidate in &candidates {
        if vfs.file_metadata(candidate.as_path()).is_ok() {
            return Ok(candidate.clone());
        }
    }

    let target_norm = normalize_virtual_path_text(artifact_path);
    let target_without_vol = strip_volume_prefix(&target_norm).to_string();
    for volume in vfs.get_volumes() {
        if let Ok(entries) = vfs.enumerate_volume(volume.volume_index) {
            for entry in entries {
                let entry_norm = normalize_virtual_path(entry.path.as_path());
                if entry_norm == target_norm {
                    return Ok(entry.path);
                }
                if !target_without_vol.is_empty() {
                    let entry_without_vol = strip_volume_prefix(&entry_norm);
                    if entry_without_vol == target_without_vol
                        || entry_without_vol.ends_with(&target_without_vol)
                    {
                        return Ok(entry.path);
                    }
                }
            }
        }
    }

    Err(format!(
        "Failed to resolve VFS artifact path from '{}'",
        artifact_path
    ))
}

fn hash_vfs_files_internal(
    vfs: &dyn VirtualFileSystem,
    manager: &SqliteHashSetManager,
    event_bus: Arc<forensic_engine::events::EventBus>,
    case_id: Option<String>,
    job_id: &str,
    progress_start: f32,
    progress_end: f32,
) -> (Vec<FileHashResult>, usize) {
    const MAX_HASH_FILE_BYTES: u64 = 256 * 1024 * 1024;
    let hashsets_loaded = manager.is_loaded();

    write_log("[CRITICAL] hash_vfs_files: start");
    let mut deduped = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let volumes = vfs.get_volumes();
    for volume in &volumes {
        match vfs.enumerate_volume(volume.volume_index) {
            Ok(entries) => {
                for entry in entries {
                    if entry.is_dir {
                        continue;
                    }
                    let key = normalize_virtual_path(entry.path.as_path());
                    if seen.insert(key) {
                        deduped.push(entry);
                    }
                }
            }
            Err(e) => {
                warn!(
                    "Failed to enumerate volume {} for hashing: {:?}",
                    volume.volume_index, e
                );
            }
        }
    }

    let total_candidates = deduped.len();
    let progress_emit_every = (total_candidates / 120).max(100);
    write_log(&format!(
        "[CRITICAL] hash_vfs_files: discovered {} candidate files",
        total_candidates
    ));

    event_bus.emit_simple(
        case_id.clone(),
        EngineEventKind::JobProgress {
            job_id: job_id.to_string(),
            job_type: "file_hashing".to_string(),
            progress: progress_start,
            message: format!("Discovered {} virtual files to hash", total_candidates),
        },
        EventSeverity::Info,
        "Preparing virtual file hashing",
    );

    if total_candidates == 0 {
        event_bus.emit_simple(
            case_id.clone(),
            EngineEventKind::JobProgress {
                job_id: job_id.to_string(),
                job_type: "file_hashing".to_string(),
                progress: progress_end,
                message: "No virtual files discovered".to_string(),
            },
            EventSeverity::Info,
            "Virtual file hashing skipped",
        );
        return (Vec::new(), 0);
    }

    if let Some(first) = deduped.first() {
        write_log(&format!(
            "[CRITICAL] hash_vfs_files: first file {} ({} bytes)",
            first.path.display(),
            first.size
        ));
    }

    if hashsets_loaded {
        let mut results = Vec::with_capacity(total_candidates);
        for (i, entry) in deduped.into_iter().enumerate() {
            if entry.size > MAX_HASH_FILE_BYTES {
                warn!(
                    "Skipping oversized virtual file {} ({} bytes)",
                    entry.path.display(),
                    entry.size
                );
            } else {
                match vfs.open_file(entry.path.as_path()) {
                    Ok(data) => {
                        let hashes = hash_bytes(&data);
                        if let Some(sha256) = hashes.sha256 {
                            let mut file_result = FileHashResult::new(
                                entry.path.clone(),
                                sha256,
                                entry.size,
                                entry.modified,
                            )
                            .with_additional_hashes(hashes.md5, hashes.sha1);
                            file_result.category = Some(manager.categorize_with_path(&file_result));
                            results.push(file_result);
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Failed to read virtual file {} for hashing: {:?}",
                            entry.path.display(),
                            e
                        );
                    }
                }
            }

            if i == 0 || ((i + 1) % progress_emit_every == 0) || i + 1 == total_candidates {
                let ratio = (i + 1) as f32 / total_candidates as f32;
                let progress = progress_start + ratio * (progress_end - progress_start);
                event_bus.emit_simple(
                    case_id.clone(),
                    EngineEventKind::JobProgress {
                        job_id: job_id.to_string(),
                        job_type: "file_hashing".to_string(),
                        progress,
                        message: format!("Hashed {}/{} virtual files", i + 1, total_candidates),
                    },
                    EventSeverity::Info,
                    "Hashing virtual files",
                );
            }

            if (i + 1) % 5000 == 0 {
                write_log(&format!(
                    "[CRITICAL] hash_vfs_files: processed {}/{} candidates",
                    i + 1,
                    total_candidates
                ));
            }
        }
        write_log(&format!(
            "[CRITICAL] hash_vfs_files: complete (hashed {})",
            results.len()
        ));
        return (results, total_candidates);
    }

    let processed = AtomicUsize::new(0);
    let results: Vec<FileHashResult> = deduped
        .into_par_iter()
        .filter_map(|entry| {
            let maybe_result = if entry.size > MAX_HASH_FILE_BYTES {
                warn!(
                    "Skipping oversized virtual file {} ({} bytes)",
                    entry.path.display(),
                    entry.size
                );
                None
            } else {
                match vfs.open_file(entry.path.as_path()) {
                    Ok(data) => {
                        let hashes = hash_bytes(&data);
                        hashes.sha256.map(|sha256| {
                            let mut file_result = FileHashResult::new(
                                entry.path.clone(),
                                sha256,
                                entry.size,
                                entry.modified,
                            )
                            .with_additional_hashes(hashes.md5, hashes.sha1);
                            file_result.category =
                                Some(default_virtual_file_category(entry.path.as_path()));
                            file_result
                        })
                    }
                    Err(e) => {
                        warn!(
                            "Failed to read virtual file {} for hashing: {:?}",
                            entry.path.display(),
                            e
                        );
                        None
                    }
                }
            };

            let done = processed.fetch_add(1, Ordering::Relaxed) + 1;
            if done == 1 || (done % progress_emit_every == 0) || done == total_candidates {
                let ratio = done as f32 / total_candidates as f32;
                let progress = progress_start + ratio * (progress_end - progress_start);
                event_bus.emit_simple(
                    case_id.clone(),
                    EngineEventKind::JobProgress {
                        job_id: job_id.to_string(),
                        job_type: "file_hashing".to_string(),
                        progress,
                        message: format!("Hashed {}/{} virtual files", done, total_candidates),
                    },
                    EventSeverity::Info,
                    "Hashing virtual files",
                );
            }
            if done % 5000 == 0 {
                write_log(&format!(
                    "[CRITICAL] hash_vfs_files: processed {}/{} candidates",
                    done, total_candidates
                ));
            }

            maybe_result
        })
        .collect();

    write_log(&format!(
        "[CRITICAL] hash_vfs_files: complete (hashed {})",
        results.len()
    ));
    (results, total_candidates)
}

fn collect_files_recursively(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("Failed to read dir: {}", e))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files_recursively(path.as_path(), files)?;
        } else if path.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

fn run_hashing_job_background(
    root_path: PathBuf,
    is_file: bool,
    is_directory: bool,
    nsrl_path: Option<String>,
    custom_bad_path: Option<String>,
    event_bus: Arc<forensic_engine::events::EventBus>,
    case_id: Option<String>,
    job_id: String,
) {
    let case_id_for_error = case_id.clone();
    let job_id_for_error = job_id.clone();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        event_bus.emit_simple(
            case_id.clone(),
            EngineEventKind::JobProgress {
                job_id: job_id.clone(),
                job_type: "file_hashing".to_string(),
                progress: 2.0,
                message: "Background hashing started".to_string(),
            },
            EventSeverity::Info,
            "Background hashing started",
        );

        let manager = SqliteHashSetManager::new().map_err(|e| {
            format!(
                "Failed to create hashset manager for background hashing: {}",
                e
            )
        })?;

        if let Some(nsrl) = nsrl_path {
            let nsrl_path = PathBuf::from(nsrl);
            if nsrl_path.exists() {
                let _ = manager.load_nsrl_sqlite(&nsrl_path);
            }
        }

        if let Some(custom) = custom_bad_path {
            let custom_path = PathBuf::from(custom);
            if custom_path.exists() {
                let _ = manager.load_custom_hashset(&custom_path, HashCategory::KnownBad);
            }
        }

        let (total_hashed, total_files) = if is_directory {
            let mut file_paths = Vec::new();
            collect_files_recursively(root_path.as_path(), &mut file_paths)?;
            let total_files = file_paths.len();

            event_bus.emit_simple(
                case_id.clone(),
                EngineEventKind::JobProgress {
                    job_id: job_id.clone(),
                    job_type: "file_hashing".to_string(),
                    progress: 5.0,
                    message: format!("Discovered {} files for background hashing", total_files),
                },
                EventSeverity::Info,
                "Discovered files for background hashing",
            );

            let results = if total_files > 0 {
                hash_and_categorize_parallel(
                    file_paths,
                    &manager,
                    event_bus.clone(),
                    case_id.clone(),
                    &job_id,
                )
            } else {
                Vec::new()
            };
            (results.len(), total_files)
        } else if is_file {
            let source = open_evidence_container(root_path.as_path()).map_err(|e| {
                format!("Failed to reopen evidence for background hashing: {:?}", e)
            })?;
            if let Some(vfs) = source.vfs_ref() {
                let (results, total_files) = hash_vfs_files_internal(
                    vfs,
                    &manager,
                    event_bus.clone(),
                    case_id.clone(),
                    &job_id,
                    8.0,
                    99.0,
                );
                (results.len(), total_files)
            } else {
                (0, 0)
            }
        } else {
            (0, 0)
        };

        event_bus.emit_simple(
            case_id.clone(),
            EngineEventKind::JobProgress {
                job_id: job_id.clone(),
                job_type: "file_hashing".to_string(),
                progress: 100.0,
                message: format!(
                    "Background hashing complete: {}/{} files",
                    total_hashed, total_files
                ),
            },
            EventSeverity::Info,
            "Background hashing complete",
        );

        event_bus.emit_simple(
            case_id,
            EngineEventKind::JobStatus {
                job_id,
                job_type: "file_hashing".to_string(),
                status: "completed".to_string(),
            },
            EventSeverity::Info,
            "Background hashing complete",
        );

        Ok::<(), String>(())
    }));

    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            error!("{}", err);
            event_bus.emit_simple(
                case_id_for_error.clone(),
                EngineEventKind::JobStatus {
                    job_id: job_id_for_error.clone(),
                    job_type: "file_hashing".to_string(),
                    status: "failed".to_string(),
                },
                EventSeverity::Error,
                &err,
            );
        }
        Err(_) => {
            let msg = "PANIC in background hashing job".to_string();
            error!("{}", msg);
            event_bus.emit_simple(
                case_id_for_error,
                EngineEventKind::JobStatus {
                    job_id: job_id_for_error,
                    job_type: "file_hashing".to_string(),
                    status: "failed".to_string(),
                },
                EventSeverity::Error,
                &msg,
            );
        }
    }
}

#[tauri::command]
async fn load_evidence_and_build_tree(
    path: String,
    nsrl_path: Option<String>,
    custom_bad_path: Option<String>,
    run_artifact_parsers: bool,
    state: tauri::State<'_, Arc<EngineContext>>,
    cache: tauri::State<'_, Arc<SpecializedViewCache>>,
) -> Result<serde_json::Value, String> {
    write_log(&format!(
        "[CRITICAL] load_evidence_and_build_tree START - path: {}",
        path
    ));
    write_log("[CRITICAL] triage pipeline marker: 2026-03-18-progress-v3");
    info!("load_evidence_and_build_tree called with path: {}", path);

    let root_path = PathBuf::from(&path);
    if let Ok(mut slot) = state.active_evidence_path.lock() {
        *slot = Some(root_path.clone());
    }

    write_log("[CRITICAL] Checking if path exists...");
    if !root_path.exists() {
        error!("Path does not exist: {}", path);
        write_log("[CRITICAL] Path does not exist!");
        return Err(format!("Path does not exist: {}", path));
    }

    write_log("[CRITICAL] Checking if file or directory...");
    let is_file = root_path.is_file();
    let is_directory = root_path.is_dir();
    write_log(&format!(
        "[CRITICAL] is_file = {}, is_directory = {}",
        is_file, is_directory
    ));

    // Initialize event bus for logging
    let event_bus = state.event_bus.clone();
    let case_id = state.case_id.clone();
    let load_job_id = "image_loading";
    let hash_job_id = "triage_hashing";

    event_bus.emit_simple(
        case_id.clone(),
        EngineEventKind::JobStatus {
            job_id: load_job_id.to_string(),
            job_type: "image_loading".to_string(),
            status: "started".to_string(),
        },
        EventSeverity::Info,
        "Starting image load",
    );
    event_bus.emit_simple(
        case_id.clone(),
        EngineEventKind::JobProgress {
            job_id: load_job_id.to_string(),
            job_type: "image_loading".to_string(),
            progress: 1.0,
            message: "Opening evidence container".to_string(),
        },
        EventSeverity::Info,
        "Starting image load",
    );

    // ======== FULL LOADING PATH FOR ALL FILES ========
    info!("Step 1: Opening evidence container with full processing...");
    write_log("[CRITICAL] Step 1: Opening evidence container...");

    // Use the FULL evidence container opening (not simple mode!)
    let evidence_source_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        open_evidence_container(&root_path)
    }));

    let evidence_source = match evidence_source_result {
        Ok(Ok(source)) => {
            info!("Evidence container opened: {:?}", source.container_type);
            write_log(&format!(
                "[CRITICAL] Evidence container opened: {:?}",
                source.container_type
            ));
            source
        }
        Ok(Err(e)) => {
            error!("Failed to open evidence container: {:?}", e);
            write_log(&format!("[CRITICAL] Error opening container: {:?}", e));
            return Err(format!("Failed to open evidence container: {:?}", e));
        }
        Err(panic_val) => {
            let msg = if let Some(s) = panic_val.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_val.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic".to_string()
            };
            error!("PANIC opening evidence container: {}", msg);
            write_log(&format!("[CRITICAL] PANIC opening container: {}", msg));
            return Err(format!("PANIC opening evidence container: {}", msg));
        }
    };

    let container_type = evidence_source.container_type.as_str().to_string();
    info!("Container type: {}", container_type);
    write_log(&format!("[CRITICAL] Container type: {}", container_type));
    event_bus.emit_simple(
        case_id.clone(),
        EngineEventKind::JobProgress {
            job_id: load_job_id.to_string(),
            job_type: "image_loading".to_string(),
            progress: 8.0,
            message: format!("Container opened: {}", container_type),
        },
        EventSeverity::Info,
        "Evidence container opened",
    );

    // Debug: Get volumes from VFS (panic-safe so malformed images do not crash GUI flow)
    if let Some(vfs) = evidence_source.vfs_ref() {
        let volumes_result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| vfs.get_volumes()));
        match volumes_result {
            Ok(volumes) => {
                let debug_msg = format!("[GUI] VFS has {} volumes\n", volumes.len());
                let _ = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open("D:\\forensic-suite\\target\\debug\\vfs_debug.log")
                    .and_then(|mut f| {
                        let _ = std::io::Write::write_all(&mut f, debug_msg.as_bytes());
                        Ok(f)
                    });
                for vol in &volumes {
                    let vol_msg = format!(
                        "[GUI] Volume {}: filesystem={:?}, size={}\n",
                        vol.volume_index, vol.filesystem, vol.size
                    );
                    let _ = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open("D:\\forensic-suite\\target\\debug\\vfs_debug.log")
                        .and_then(|mut f| {
                            let _ = std::io::Write::write_all(&mut f, vol_msg.as_bytes());
                            Ok(f)
                        });
                }
            }
            Err(panic_val) => {
                let msg = if let Some(s) = panic_val.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic_val.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "Unknown panic".to_string()
                };
                warn!("[GUI] get_volumes panic-suppressed: {}", msg);
                write_log(&format!("[CRITICAL] get_volumes panic-suppressed: {}", msg));
            }
        }
    }

    // Step 2: Create lightweight hashset manager for immediate tree build.
    // Full hashset loading + hashing now run in the background job.
    info!("Step 2: Preparing quick tree build...");
    write_log("[CRITICAL] Step 2: Preparing quick tree build...");
    event_bus.emit_simple(
        case_id.clone(),
        EngineEventKind::JobProgress {
            job_id: load_job_id.to_string(),
            job_type: "image_loading".to_string(),
            progress: 12.0,
            message: "Preparing tree for immediate browsing".to_string(),
        },
        EventSeverity::Info,
        "Preparing quick tree build",
    );
    let manager = SqliteHashSetManager::new().map_err(|e| {
        error!("Failed to create hashset manager: {:?}", e);
        format!("Failed to create hashset manager: {}", e)
    })?;

    let hash_results: Vec<FileHashResult> = Vec::new();
    let total_files = 0usize;
    let total_hashed = 0usize;
    let categorization_summary: HashMap<String, usize> = HashMap::new();
    let hashset_stats = HashSetLoadResult::default();

    // Step 5: Build tree using build_filtered_tree (full path with VFS)
    info!("Step 5: Building tree structure with real VFS...");
    write_log("[CRITICAL] Step 5: Building tree with VFS...");
    event_bus.emit_simple(
        case_id.clone(),
        EngineEventKind::JobProgress {
            job_id: load_job_id.to_string(),
            job_type: "image_loading".to_string(),
            progress: 92.0,
            message: "Building evidence tree".to_string(),
        },
        EventSeverity::Info,
        "Building evidence tree",
    );
    let tree: TreeNode = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let vfs_ref = evidence_source.vfs_ref();
        build_filtered_tree(&root_path, &hash_results, &manager, vfs_ref)
    }))
    .unwrap_or_else(|panic_val| {
        let msg = if let Some(s) = panic_val.downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = panic_val.downcast_ref::<String>() {
            s.clone()
        } else {
            "Unknown panic".to_string()
        };
        error!("PANIC in tree building: {}", msg);
        write_log(&format!("[CRITICAL] PANIC in tree building: {}", msg));
        Ok(TreeNode::new_dir(
            root_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| root_path.display().to_string()),
            root_path.clone(),
        ))
    })
    .unwrap_or_else(|e| {
        error!("ERROR in tree building: {:?}", e);
        write_log(&format!("[CRITICAL] ERROR in tree building: {:?}", e));
        TreeNode::new_dir(
            root_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| root_path.display().to_string()),
            root_path.clone(),
        )
    });

    info!("Tree built successfully");
    write_log("[CRITICAL] Tree built successfully");
    event_bus.emit_simple(
        case_id.clone(),
        EngineEventKind::JobProgress {
            job_id: load_job_id.to_string(),
            job_type: "image_loading".to_string(),
            progress: 98.0,
            message: "Finalizing results".to_string(),
        },
        EventSeverity::Info,
        "Finalizing triage results",
    );

    // Step 6: Start search indexing in background thread - don't block UI!
    // The tree can be returned immediately - search indexing runs async
    {
        let tree_clone = tree.clone();
        let timeline_path = std::env::temp_dir().join("forensic_timeline.db");
        let case_id_clone = case_id.clone();
        let event_bus_clone = event_bus.clone();

        std::thread::spawn(move || {
            let start = std::time::Instant::now();
            let node_count = count_tree_nodes(&tree_clone);
            info!(
                "[BG] Starting background search indexing for {} nodes...",
                node_count
            );
            write_log(&format!(
                "[CRITICAL] Starting background search indexing for {} nodes...",
                node_count
            ));

            match EvidenceAnalyzer::new(&timeline_path) {
                Ok(bg_analyzer) => {
                    match bg_analyzer.index_tree_for_search(&tree_clone) {
                        Ok(_) => {
                            let elapsed = start.elapsed();
                            info!(
                                "[BG] Search indexing complete in {:.2}s",
                                elapsed.as_secs_f64()
                            );
                            write_log(&format!(
                                "[CRITICAL] Search indexing complete in {:.2}s",
                                elapsed.as_secs_f64()
                            ));

                            // Update state analyzer with the one that has indexed data
                            // This requires a channel or mutex to update state
                            event_bus_clone.emit_simple(
                                case_id_clone.clone(),
                                EngineEventKind::JobStatus {
                                    job_id: "search_indexing".to_string(),
                                    job_type: "search_indexing".to_string(),
                                    status: "completed".to_string(),
                                },
                                EventSeverity::Info,
                                &format!(
                                    "Search indexing complete: {} nodes in {:.2}s",
                                    node_count,
                                    elapsed.as_secs_f64()
                                ),
                            );
                        }
                        Err(e) => {
                            warn!("[BG] Search indexing failed: {}", e);
                            write_log(&format!("[CRITICAL] Search indexing failed: {}", e));
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "[BG] Failed to create analyzer for background indexing: {}",
                        e
                    );
                    write_log(&format!("[CRITICAL] Failed to create analyzer: {}", e));
                }
            }
        });
    }

    // Count tree nodes to verify actual evidence was found
    let tree_node_count = count_tree_nodes(&tree);
    let has_real_data = tree_node_count > 1; // More than just root node
    let child_count = tree.children.len();

    // Determine appropriate status based on actual results
    let (final_status, final_message, final_severity) = if has_real_data {
        (
            "completed".to_string(),
            "Image loaded with evidence tree".to_string(),
            EventSeverity::Info,
        )
    } else {
        // No real evidence data found - this is a failure condition
        let warn_msg = format!(
            "Enumeration returned no data: container={}, tree_nodes={}, child_volumes={}. Filesystem may not be supported or image is empty.",
            container_type, tree_node_count, child_count
        );
        warn!("[CRITICAL] {}", warn_msg);
        write_log(&format!("[CRITICAL] EMPTY ENUMERATION: {}", warn_msg));
        ("partial".to_string(), warn_msg, EventSeverity::Warn)
    };

    let result = TreeLoadResult {
        tree: tree.clone(),
        categorization_summary,
        total_files,
        total_hashed,
        container_type,
        hashset_stats,
    };

    info!("Result created, serializing to JSON...");
    write_log(&format!(
        "[CRITICAL] Serializing to JSON... (status={})",
        final_status
    ));

    // Only start background hashing if we have real data
    if has_real_data {
        let root_path_bg = root_path.clone();
        let event_bus_bg = event_bus.clone();
        let case_id_bg = case_id.clone();
        let job_id_bg = hash_job_id.to_string();
        let nsrl_bg = nsrl_path.clone();
        let custom_bg = custom_bad_path.clone();
        std::thread::spawn(move || {
            run_hashing_job_background(
                root_path_bg,
                is_file,
                is_directory,
                nsrl_bg,
                custom_bg,
                event_bus_bg,
                case_id_bg,
                job_id_bg,
            );
        });
    }

    // Start specialized view builders (media/timeline/registry/email) in background.
    // Only run if we have real data to analyze
    if has_real_data {
        let root_path_bg = root_path.clone();
        let event_bus_bg = event_bus.clone();
        let case_id_bg = case_id.clone();
        let cache_bg = cache.inner().clone();
        std::thread::spawn(move || {
            build_specialized_views_background(root_path_bg, cache_bg, event_bus_bg, case_id_bg);
        });
    }

    event_bus.emit_simple(
        case_id.clone(),
        EngineEventKind::JobProgress {
            job_id: load_job_id.to_string(),
            job_type: "image_loading".to_string(),
            progress: 100.0,
            message: if has_real_data {
                "Image loaded. Hashing continues in Active Jobs.".to_string()
            } else {
                format!(
                    "Container opened but enumeration returned no data. Tree nodes: {}",
                    tree_node_count
                )
            },
        },
        final_severity.clone(),
        &final_message,
    );
    event_bus.emit_simple(
        case_id.clone(),
        EngineEventKind::JobStatus {
            job_id: load_job_id.to_string(),
            job_type: "image_loading".to_string(),
            status: final_status,
        },
        final_severity,
        &final_message,
    );

    // Run artifact parsers in background if requested
    // Only run if we actually have data to analyze
    if run_artifact_parsers && has_real_data {
        info!("Starting background artifact analysis...");
        write_log("[CRITICAL] Starting background analysis...");
        let timeline_path = std::env::temp_dir().join("forensic_timeline.db");

        let mut analyzer = EvidenceAnalyzer::new(&timeline_path)
            .map_err(|e| format!("Failed to create analyzer: {}", e))?;

        let event_bus_clone = event_bus.clone();
        let case_id_clone = case_id.clone();
        let root_path_for_vfs = root_path.clone();

        std::thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                match open_evidence_container(&root_path_for_vfs) {
                    Ok(source) => {
                        if let Some(vfs) = source.vfs_ref() {
                            let _ = analyzer.analyze(
                                &root_path_for_vfs,
                                Some(vfs),
                                &event_bus_clone.clone(),
                                case_id_clone.clone(),
                            );
                        } else {
                            let _ = analyzer.analyze(
                                &root_path_for_vfs,
                                None,
                                &event_bus_clone.clone(),
                                case_id_clone.clone(),
                            );
                        }
                    }
                    Err(e) => {
                        error!("Failed to open evidence for artifact analysis: {:?}", e);
                    }
                }
            }));

            if let Err(panic_val) = result {
                let msg = if let Some(s) = panic_val.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic_val.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "Unknown panic".to_string()
                };
                error!("PANIC in background analysis: {}", msg);
            }
        });
    }

    write_log("[CRITICAL] About to return JSON...");
    write_log(&format!(
        "[CRITICAL] Result has tree children: {:?}",
        result.tree.children.len()
    ));
    info!("Returning result to frontend");

    // JSON serialization with crash protection
    let json_value = serde_json::to_value(&result).map_err(|e| format!("JSON error: {}", e))?;

    let json_str = serde_json::to_string_pretty(&json_value).unwrap_or_default();
    write_log(&format!(
        "[CRITICAL] JSON result (first 500 chars): {}",
        &json_str[..json_str.len().min(500)]
    ));
    write_log("[CRITICAL] SUCCESS - returning to frontend");
    Ok(json_value)
}

#[tauri::command]
async fn load_hashsets(
    nsrl_path: Option<String>,
    custom_bad_path: Option<String>,
    state: tauri::State<'_, Arc<EngineContext>>,
) -> Result<HashSetLoadResult, String> {
    let event_bus = state.event_bus.clone();

    let manager = SqliteHashSetManager::new()
        .map_err(|e| format!("Failed to create hashset manager: {}", e))?;

    let mut result = HashSetLoadResult::default();

    if let Some(nsrl) = nsrl_path {
        let nsrl_path = PathBuf::from(&nsrl);
        if nsrl_path.exists() {
            match manager.load_nsrl_sqlite(&nsrl_path) {
                Ok(count) => {
                    result.nsrl_count = count;
                    event_bus.emit_simple(
                        None,
                        EngineEventKind::System {
                            subsystem: "hashset".to_string(),
                        },
                        EventSeverity::Info,
                        &format!("Loaded {} NSRL hashes", count),
                    );
                }
                Err(e) => {
                    return Err(format!("Failed to load NSRL: {}", e));
                }
            }
        }
    }

    if let Some(custom) = custom_bad_path {
        let custom_path = PathBuf::from(&custom);
        if custom_path.exists() {
            match manager.load_custom_hashset(&custom_path, HashCategory::KnownBad) {
                Ok(count) => {
                    result.custom_bad_count = count;
                    event_bus.emit_simple(
                        None,
                        EngineEventKind::System {
                            subsystem: "hashset".to_string(),
                        },
                        EventSeverity::Info,
                        &format!("Loaded {} custom bad hashes", count),
                    );
                }
                Err(e) => {
                    return Err(format!("Failed to load custom hashset: {}", e));
                }
            }
        }
    }

    Ok(result)
}

#[tauri::command]
async fn load_nsrl_database(
    nsrl_path: String,
    state: tauri::State<'_, Arc<EngineContext>>,
) -> Result<HashSetLoadResult, String> {
    load_hashsets(Some(nsrl_path), None, state).await
}

#[tauri::command]
async fn hash_vfs_files(
    evidence_path: String,
    nsrl_path: Option<String>,
    custom_bad_path: Option<String>,
    state: tauri::State<'_, Arc<EngineContext>>,
) -> Result<HashVfsFilesResult, String> {
    let root_path = PathBuf::from(&evidence_path);
    if !root_path.exists() {
        return Err(format!("Evidence path does not exist: {}", evidence_path));
    }

    let manager = SqliteHashSetManager::new()
        .map_err(|e| format!("Failed to create hashset manager: {}", e))?;
    let mut load_result = HashSetLoadResult::default();

    if let Some(nsrl) = nsrl_path {
        let nsrl_file = PathBuf::from(&nsrl);
        if nsrl_file.exists() {
            load_result.nsrl_count = manager
                .load_nsrl_sqlite(&nsrl_file)
                .map_err(|e| format!("Failed to load NSRL: {}", e))?;
        }
    }

    if let Some(custom_bad) = custom_bad_path {
        let bad_file = PathBuf::from(&custom_bad);
        if bad_file.exists() {
            load_result.custom_bad_count = manager
                .load_custom_hashset(&bad_file, HashCategory::KnownBad)
                .map_err(|e| format!("Failed to load custom bad hashset: {}", e))?;
        }
    }

    let source = open_evidence_container(root_path.as_path())
        .map_err(|e| format!("Failed to open evidence source: {:?}", e))?;
    let vfs = source
        .vfs_ref()
        .ok_or_else(|| "No virtual filesystem available for evidence source".to_string())?;

    let (results, total_files) = hash_vfs_files_internal(
        vfs,
        &manager,
        state.event_bus.clone(),
        state.case_id.clone(),
        "hash_vfs_files",
        0.0,
        100.0,
    );

    let mut known_good_matches = 0usize;
    let mut known_bad_matches = 0usize;
    let mut unmatched = 0usize;

    for result in &results {
        match result.category.unwrap_or(FileCategory::Unknown) {
            FileCategory::KnownGood => known_good_matches += 1,
            FileCategory::KnownBad => known_bad_matches += 1,
            _ => unmatched += 1,
        }
    }

    let sample_matches = results
        .iter()
        .take(250)
        .map(|result| HashMatchSampleRow {
            path: normalize_virtual_path(result.path.as_path()),
            sha256: result.sha256.clone(),
            category: result.category.unwrap_or(FileCategory::Unknown).to_string(),
            size: result.size,
        })
        .collect::<Vec<_>>();

    Ok(HashVfsFilesResult {
        total_files,
        hashed_files: results.len(),
        known_good_matches,
        known_bad_matches,
        unmatched,
        nsrl_count: load_result.nsrl_count,
        custom_bad_count: load_result.custom_bad_count,
        sample_matches,
    })
}

#[tauri::command]
async fn get_initial_timeline(
    limit: Option<usize>,
    state: tauri::State<'_, Arc<EngineContext>>,
) -> Result<Vec<TimelineEntry>, String> {
    let has_active_evidence = {
        let lock = state
            .active_evidence_path
            .lock()
            .map_err(|e| format!("Failed to read active evidence path: {}", e))?;
        lock.is_some()
    };

    if !has_active_evidence {
        return Ok(Vec::new());
    }

    let timeline_path = std::env::temp_dir().join("forensic_timeline.db");
    if !timeline_path.exists() {
        return Ok(Vec::new());
    }

    let analyzer = EvidenceAnalyzer::new(&timeline_path)
        .map_err(|e| format!("Failed to create analyzer: {}", e))?;
    let entries: Vec<TimelineEntry> = analyzer
        .get_initial_timeline(limit.unwrap_or(1000))
        .map_err(|e| format!("Failed to get timeline: {}", e))?;
    Ok(entries
        .into_iter()
        .filter(|entry| entry.timestamp.map(|ts| ts > 0).unwrap_or(false))
        .collect())
}

#[tauri::command]
fn start_specialized_view_builders(
    path: String,
    state: tauri::State<'_, Arc<EngineContext>>,
    cache: tauri::State<'_, Arc<SpecializedViewCache>>,
) -> Result<String, String> {
    let root_path = PathBuf::from(&path);
    if !root_path.exists() {
        return Err(format!("Path does not exist: {}", path));
    }

    let event_bus = state.event_bus.clone();
    let case_id = state.case_id.clone();
    let cache_arc = cache.inner().clone();

    std::thread::spawn(move || {
        build_specialized_views_background(root_path, cache_arc, event_bus, case_id);
    });

    Ok("started".to_string())
}

#[tauri::command]
fn get_built_email_rows(
    limit: Option<usize>,
    cache: tauri::State<'_, Arc<SpecializedViewCache>>,
) -> Result<Vec<BuiltEmailRow>, String> {
    let rows = cache
        .email_rows
        .lock()
        .map_err(|e| format!("Failed to read email rows: {}", e))?;
    let max = limit.unwrap_or(rows.len());
    Ok(rows.iter().take(max).cloned().collect())
}

#[tauri::command]
fn get_built_registry_rows(
    limit: Option<usize>,
    cache: tauri::State<'_, Arc<SpecializedViewCache>>,
) -> Result<Vec<BuiltRegistryRow>, String> {
    let rows = cache
        .registry_rows
        .lock()
        .map_err(|e| format!("Failed to read registry rows: {}", e))?;
    let max = limit.unwrap_or(rows.len());
    Ok(rows.iter().take(max).cloned().collect())
}

#[tauri::command]
fn get_built_media_rows(
    limit: Option<usize>,
    cache: tauri::State<'_, Arc<SpecializedViewCache>>,
) -> Result<Vec<BuiltMediaRow>, String> {
    let rows = cache
        .media_rows
        .lock()
        .map_err(|e| format!("Failed to read media rows: {}", e))?;
    let max = limit.unwrap_or(rows.len());
    Ok(rows.iter().take(max).cloned().collect())
}

#[tauri::command]
fn get_built_timeline_rows(
    limit: Option<usize>,
    cache: tauri::State<'_, Arc<SpecializedViewCache>>,
) -> Result<Vec<BuiltTimelineRow>, String> {
    let rows = cache
        .timeline_rows
        .lock()
        .map_err(|e| format!("Failed to read timeline rows: {}", e))?;
    let max = limit.unwrap_or(rows.len());
    Ok(rows.iter().take(max).cloned().collect())
}

#[tauri::command]
fn get_timeline_rows(
    limit: Option<usize>,
    cache: tauri::State<'_, Arc<SpecializedViewCache>>,
) -> Result<Vec<BuiltTimelineRow>, String> {
    get_built_timeline_rows(limit, cache)
}

#[tauri::command]
fn get_email_rows(
    limit: Option<usize>,
    cache: tauri::State<'_, Arc<SpecializedViewCache>>,
) -> Result<Vec<BuiltEmailRow>, String> {
    get_built_email_rows(limit, cache)
}

#[tauri::command]
fn get_registry_rows(
    limit: Option<usize>,
    cache: tauri::State<'_, Arc<SpecializedViewCache>>,
) -> Result<Vec<BuiltRegistryRow>, String> {
    get_built_registry_rows(limit, cache)
}

#[tauri::command]
async fn read_artifact_preview(
    evidence_path: String,
    artifact_path: String,
    max_bytes: Option<usize>,
) -> Result<serde_json::Value, String> {
    const MAX_SAFE_FILE_BYTES: u64 = 64 * 1024 * 1024; // Avoid huge in-memory reads for previews
    const DEFAULT_PREVIEW_BYTES: usize = 64 * 1024;
    const MAX_PREVIEW_BYTES: usize = 256 * 1024;

    let root_path = PathBuf::from(&evidence_path);
    if !root_path.exists() {
        return Err(format!("Evidence path does not exist: {}", evidence_path));
    }

    let source = open_evidence_container(root_path.as_path())
        .map_err(|e| format!("Failed to open evidence source: {:?}", e))?;
    let vfs = source
        .vfs_ref()
        .ok_or_else(|| "No virtual filesystem available for evidence source".to_string())?;

    let artifact = resolve_vfs_preview_path(vfs, &evidence_path, &artifact_path)?;
    let meta = vfs.file_metadata(artifact.as_path()).map_err(|e| {
        format!(
            "Failed to read metadata for {} (resolved as {}): {:?}",
            artifact_path,
            artifact.display(),
            e
        )
    })?;

    if meta.is_dir {
        return Err("Selected item is a directory".to_string());
    }
    if meta.size > MAX_SAFE_FILE_BYTES {
        return Err(format!(
            "Preview disabled for files larger than {} MB",
            MAX_SAFE_FILE_BYTES / (1024 * 1024)
        ));
    }

    let data = vfs.open_file(artifact.as_path()).map_err(|e| {
        format!(
            "Failed to read file {} (resolved as {}): {:?}",
            artifact_path,
            artifact.display(),
            e
        )
    })?;

    let requested = max_bytes
        .unwrap_or(DEFAULT_PREVIEW_BYTES)
        .min(MAX_PREVIEW_BYTES);
    let preview_len = data.len().min(requested);
    let preview = &data[..preview_len];
    let truncated = data.len() > preview_len;

    let hex_dump = build_hex_dump(preview);
    let strings = extract_ascii_strings(preview, 4, 400);

    Ok(serde_json::json!({
        "artifactPath": artifact_path,
        "bytesRead": preview_len,
        "totalBytes": data.len(),
        "truncated": truncated,
        "hexDump": hex_dump,
        "strings": strings
    }))
}

#[tauri::command]
async fn acquire_live_memory(_output_path: Option<String>) -> Result<String, String> {
    Err("Live memory acquisition requires physical driver load. Currently disabled in Phase 8 architecture.".to_string())
}

#[tauri::command]
async fn generate_report(
    case_id: String,
    format: String,
    output_dir: Option<String>,
    state: tauri::State<'_, Arc<EngineContext>>,
) -> Result<String, String> {
    let event_bus = state.event_bus.clone();
    let case_id_for_event = case_id.clone();

    event_bus.emit_simple(
        Some(case_id_for_event.clone()),
        EngineEventKind::ExportProgress {
            phase: "starting".to_string(),
            progress: 0.0,
            message: "Starting report generation...".to_string(),
        },
        EventSeverity::Info,
        "Report generation started",
    );

    let output_path = output_dir.unwrap_or_else(|| {
        std::env::temp_dir()
            .join("forensic_reports")
            .to_string_lossy()
            .to_string()
    });
    let output_dir_path = std::path::Path::new(&output_path);

    let _timeline_path = std::env::temp_dir().join("forensic_timeline.db");

    let _export_format = match format.to_lowercase().as_str() {
        "json" => ExportFormat::JSON,
        "html" => ExportFormat::HTML,
        "csv" => ExportFormat::CSV,
        "xml" => ExportFormat::XML,
        "markdown" => ExportFormat::Markdown,
        _ => ExportFormat::HTML,
    };

    let generator = ReportGenerator::new();

    event_bus.emit_simple(
        Some(case_id_for_event.clone()),
        EngineEventKind::ExportProgress {
            phase: "generating".to_string(),
            progress: 50.0,
            message: "Generating report bundle...".to_string(),
        },
        EventSeverity::Info,
        "Generating report",
    );

    let result_html = generator
        .generate_html_report(&case_id, &[])
        .map_err(|e| format!("Failed to generate report: {}", e))?;

    let result_path = output_dir_path.join("report.html");
    std::fs::write(&result_path, result_html).map_err(|e| e.to_string())?;

    event_bus.emit_simple(
        Some(case_id_for_event),
        EngineEventKind::ExportProgress {
            phase: "completed".to_string(),
            progress: 100.0,
            message: format!("Report saved to: {}", result_path.display()),
        },
        EventSeverity::Info,
        "Report generation complete",
    );

    Ok(result_path.to_string_lossy().to_string())
}

#[tauri::command]
async fn export_jsonl_timeline(
    case_id: String,
    output_path: Option<String>,
    state: tauri::State<'_, Arc<EngineContext>>,
) -> Result<String, String> {
    let event_bus = state.event_bus.clone();
    let case_id_for_event = case_id.clone();

    event_bus.emit_simple(
        Some(case_id_for_event.clone()),
        EngineEventKind::ExportProgress {
            phase: "starting".to_string(),
            progress: 0.0,
            message: "Starting JSONL timeline export...".to_string(),
        },
        EventSeverity::Info,
        "JSONL export started",
    );

    let timeline_path = std::env::temp_dir().join("forensic_timeline.db");

    if !timeline_path.exists() {
        return Err("Timeline database not found. Run artifact analysis first.".to_string());
    }

    let output = output_path.unwrap_or_else(|| {
        std::env::temp_dir()
            .join(format!("timeline_{}.jsonl", case_id))
            .to_string_lossy()
            .to_string()
    });
    let output_path_buf = std::path::Path::new(&output);

    let count =
        forensic_engine::report::jsonl::export_timeline_jsonl(&timeline_path, output_path_buf)
            .map_err(|e| format!("Failed to export timeline: {}", e))?;

    event_bus.emit_simple(
        Some(case_id_for_event),
        EngineEventKind::ExportProgress {
            phase: "completed".to_string(),
            progress: 100.0,
            message: format!("Exported {} timeline entries to JSONL", count),
        },
        EventSeverity::Info,
        "JSONL export complete",
    );

    Ok(format!("{}:{}:{}", output, count, "entries"))
}

#[tauri::command]
fn list_plugins(plugin_dir: Option<String>) -> Vec<PluginInfo> {
    let dir = plugin_dir
        .map(PathBuf::from)
        .unwrap_or_else(get_default_plugin_dir);

    let manager = PluginManager::new(&dir);
    manager.plugin_infos()
}

#[tauri::command]
fn load_plugin(
    path: String,
    state: tauri::State<'_, Arc<EngineContext>>,
) -> Result<PluginInfo, String> {
    let event_bus = state.event_bus.clone();
    let plugin_path = std::path::Path::new(&path);

    let loaded = PluginManager::load_plugin(plugin_path)
        .map_err(|e| format!("Failed to load plugin: {}", e))?;

    let info = loaded.info.clone();

    event_bus.emit_simple(
        None,
        EngineEventKind::PluginLoaded {
            name: info.name.clone(),
            version: info.version.clone(),
        },
        EventSeverity::Info,
        &format!("Loaded plugin: {} v{}", info.name, info.version),
    );

    Ok(info)
}

#[tauri::command]
fn global_search(
    query: String,
    result_types: Option<Vec<String>>,
    state: tauri::State<'_, Arc<EngineContext>>,
) -> Result<Vec<SearchResult>, String> {
    let types = result_types.map(|v| {
        v.iter()
            .filter_map(|t| match t.as_str() {
                "TreeNode" => Some(SearchResultType::TreeNode),
                "TimelineEntry" => Some(SearchResultType::TimelineEntry),
                "CarvedFile" => Some(SearchResultType::CarvedFile),
                "MemoryArtifact" => Some(SearchResultType::MemoryArtifact),
                "BrowserHistory" => Some(SearchResultType::BrowserHistory),
                "Note" => Some(SearchResultType::Note),
                "YaraHit" => Some(SearchResultType::YaraHit),
                "Tag" => Some(SearchResultType::Tag),
                _ => None,
            })
            .collect()
    });

    let analyzer = state.analyzer.lock().map_err(|e| e.to_string())?;
    match analyzer.as_ref() {
        Some(a) => a.global_search(&query, types),
        None => Err("Analyzer not initialized".to_string()),
    }
}

#[tauri::command]
fn get_artifacts_for_path(
    path: String,
    state: tauri::State<'_, Arc<EngineContext>>,
) -> Result<Vec<Artifact>, String> {
    let evidence_path = {
        let lock = state
            .active_evidence_path
            .lock()
            .map_err(|e| format!("Failed to read active evidence path: {}", e))?;
        lock.clone()
            .ok_or_else(|| "No active evidence loaded".to_string())?
    };

    let source = open_evidence_container(evidence_path.as_path())
        .map_err(|e| format!("Failed to open evidence source: {:?}", e))?;
    let vfs = source
        .vfs_ref()
        .ok_or_else(|| "No virtual filesystem available for loaded evidence".to_string())?;

    let requested = if path.starts_with('/') {
        PathBuf::from(&path)
    } else {
        PathBuf::from(normalize_virtual_path(Path::new(&path)))
    };
    let requested_norm = normalize_virtual_path(requested.as_path());
    let mut out: Vec<Artifact> = Vec::new();

    if let Ok(meta) = vfs.file_metadata(requested.as_path()) {
        out.push(Artifact {
            artifact_type: "filesystem".to_string(),
            name: meta.name.clone(),
            path: requested_norm.clone(),
            description: if meta.is_dir {
                "Directory metadata".to_string()
            } else {
                format!("File metadata ({} bytes)", meta.size)
            },
            timestamp: meta.modified.map(|m| m.timestamp()),
            created_time: None,
            modified_time: meta.modified.map(|m| m.timestamp_millis()),
            accessed_time: None,
            mft_changed_time: None,
            size: Some(meta.size),
        });

        if !meta.is_dir {
            let data = vfs.open_file(requested.as_path()).unwrap_or_default();
            if !data.is_empty() {
                let mut registry = ParserRegistry::new();
                registry.register_default_parsers();
                let path_lower = requested_norm.to_lowercase();
                for parser in registry.parsers() {
                    let matches_target = parser.target_patterns().iter().any(|pattern| {
                        let p = pattern.to_lowercase();
                        let needle = p.trim_start_matches('*');
                        !needle.is_empty() && path_lower.contains(needle)
                    });
                    if !matches_target {
                        continue;
                    }

                    if let Ok(parsed) = parser.parse_file(requested.as_path(), &data) {
                        for artifact in parsed {
                            out.push(Artifact {
                                artifact_type: artifact.artifact_type.clone(),
                                name: artifact.artifact_type,
                                path: artifact.source_path,
                                description: artifact.description,
                                timestamp: artifact.timestamp,
                                created_time: None,
                                modified_time: None,
                                accessed_time: None,
                                mft_changed_time: None,
                                size: Some(meta.size),
                            });
                        }
                    }
                }
            }
        }
    }

    if let Ok(analyzer) = state.analyzer.lock() {
        if let Some(a) = analyzer.as_ref() {
            let search_types = Some(vec![
                SearchResultType::TimelineEntry,
                SearchResultType::BrowserHistory,
                SearchResultType::CarvedFile,
                SearchResultType::MemoryArtifact,
                SearchResultType::YaraHit,
                SearchResultType::TreeNode,
            ]);
            if let Ok(search_hits) = a.global_search(&requested_norm, search_types) {
                for hit in search_hits {
                    out.push(Artifact {
                        artifact_type: format!("{:?}", hit.result_type),
                        name: hit.name,
                        path: hit.path,
                        description: hit.description,
                        timestamp: hit.timestamp,
                        created_time: None,
                        modified_time: None,
                        accessed_time: None,
                        mft_changed_time: None,
                        size: None,
                    });
                }
            }
        }
    }

    let mut seen = HashSet::new();
    out.retain(|a| {
        let key = format!(
            "{}|{}|{}|{}|{:?}",
            a.artifact_type, a.name, a.path, a.description, a.timestamp
        );
        seen.insert(key)
    });

    Ok(out)
}

#[tauri::command]
fn get_all_tags(state: tauri::State<'_, Arc<EngineContext>>) -> Result<Vec<ArtifactTag>, String> {
    let analyzer = state.analyzer.lock().map_err(|e| e.to_string())?;
    match analyzer.as_ref() {
        Some(a) => a.get_all_tags(),
        None => Err("Analyzer not initialized".to_string()),
    }
}

#[tauri::command]
fn create_tag(
    name: String,
    color: String,
    state: tauri::State<'_, Arc<EngineContext>>,
) -> Result<ArtifactTag, String> {
    let analyzer = state.analyzer.lock().map_err(|e| e.to_string())?;
    match analyzer.as_ref() {
        Some(a) => a.create_tag(name, color),
        None => Err("Analyzer not initialized".to_string()),
    }
}

#[tauri::command]
fn add_tag(
    artifact_path: String,
    tag_id: i64,
    state: tauri::State<'_, Arc<EngineContext>>,
) -> Result<(), String> {
    let analyzer = state.analyzer.lock().map_err(|e| e.to_string())?;
    match analyzer.as_ref() {
        Some(a) => a.add_tag_to_artifact(&artifact_path, tag_id),
        None => Err("Analyzer not initialized".to_string()),
    }
}

#[tauri::command]
fn remove_tag(
    artifact_path: String,
    tag_id: i64,
    state: tauri::State<'_, Arc<EngineContext>>,
) -> Result<(), String> {
    let analyzer = state.analyzer.lock().map_err(|e| e.to_string())?;
    match analyzer.as_ref() {
        Some(a) => a.remove_tag_from_artifact(&artifact_path, tag_id),
        None => Err("Analyzer not initialized".to_string()),
    }
}

#[tauri::command]
fn get_tags_for_artifact(
    artifact_path: String,
    state: tauri::State<'_, Arc<EngineContext>>,
) -> Result<Vec<ArtifactTag>, String> {
    let analyzer = state.analyzer.lock().map_err(|e| e.to_string())?;
    match analyzer.as_ref() {
        Some(a) => a.get_tags_for_artifact(&artifact_path),
        None => Err("Analyzer not initialized".to_string()),
    }
}

#[tauri::command]
fn get_tag_counts(
    state: tauri::State<'_, Arc<EngineContext>>,
) -> Result<HashMap<String, usize>, String> {
    let analyzer = state.analyzer.lock().map_err(|e| e.to_string())?;
    match analyzer.as_ref() {
        Some(a) => a.get_tag_counts(),
        None => Err("Analyzer not initialized".to_string()),
    }
}

#[tauri::command]
fn add_note(
    artifact_path: String,
    content: String,
    author: String,
    state: tauri::State<'_, Arc<EngineContext>>,
) -> Result<ArtifactNote, String> {
    let analyzer = state.analyzer.lock().map_err(|e| e.to_string())?;
    match analyzer.as_ref() {
        Some(a) => a.add_note(artifact_path, content, author),
        None => Err("Analyzer not initialized".to_string()),
    }
}

#[tauri::command]
fn update_note(
    note_id: i64,
    content: String,
    state: tauri::State<'_, Arc<EngineContext>>,
) -> Result<(), String> {
    let analyzer = state.analyzer.lock().map_err(|e| e.to_string())?;
    match analyzer.as_ref() {
        Some(a) => a.update_note(note_id, content),
        None => Err("Analyzer not initialized".to_string()),
    }
}

#[tauri::command]
fn delete_note(note_id: i64, state: tauri::State<'_, Arc<EngineContext>>) -> Result<(), String> {
    let analyzer = state.analyzer.lock().map_err(|e| e.to_string())?;
    match analyzer.as_ref() {
        Some(a) => a.delete_note(note_id),
        None => Err("Analyzer not initialized".to_string()),
    }
}

#[tauri::command]
fn get_notes_for_artifact(
    artifact_path: String,
    state: tauri::State<'_, Arc<EngineContext>>,
) -> Result<Vec<ArtifactNote>, String> {
    let analyzer = state.analyzer.lock().map_err(|e| e.to_string())?;
    match analyzer.as_ref() {
        Some(a) => a.get_notes_for_artifact(&artifact_path),
        None => Err("Analyzer not initialized".to_string()),
    }
}

#[tauri::command]
fn get_all_notes(state: tauri::State<'_, Arc<EngineContext>>) -> Result<Vec<ArtifactNote>, String> {
    let analyzer = state.analyzer.lock().map_err(|e| e.to_string())?;
    match analyzer.as_ref() {
        Some(a) => a.get_all_notes(),
        None => Err("Analyzer not initialized".to_string()),
    }
}

#[tauri::command]
fn export_artifact(
    source_path: String,
    destination_dir: String,
    include_metadata: bool,
    verify_hash: bool,
    state: tauri::State<'_, Arc<EngineContext>>,
) -> Result<String, String> {
    let analyzer = state.analyzer.lock().map_err(|e| e.to_string())?;
    match analyzer.as_ref() {
        Some(a) => a.export_artifact(
            &source_path,
            std::path::Path::new(&destination_dir),
            include_metadata,
            verify_hash,
        ),
        None => Err("Analyzer not initialized".to_string()),
    }
}

#[tauri::command]
fn export_tagged_items(
    tag_id: i64,
    destination_dir: String,
    include_metadata: bool,
    verify_hash: bool,
    state: tauri::State<'_, Arc<EngineContext>>,
) -> Result<usize, String> {
    let analyzer = state.analyzer.lock().map_err(|e| e.to_string())?;
    match analyzer.as_ref() {
        Some(a) => a.export_tagged_artifacts(
            tag_id,
            std::path::Path::new(&destination_dir),
            include_metadata,
            verify_hash,
        ),
        None => Err("Analyzer not initialized".to_string()),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    forensic_engine::init_tracing_and_panic_hook();

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    log::info!("Strata Shield GUI starting...");
    info!("Strata Shield GUI starting with crash protection...");

    let ctx = Arc::new(EngineContext::new());
    let specialized_cache = Arc::new(SpecializedViewCache::default());

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_strata_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_process::init())
        .manage(ctx)
        .manage(specialized_cache)
        .setup(|app| {
            log::info!("Application setup complete");
            let window = app.get_webview_window("main").unwrap();
            window.set_title("Strata Shield").ok();

            // Bridge engine events to frontend events.
            let app_handle = app.handle().clone();
            let ctx = app.state::<Arc<EngineContext>>().inner().clone();
            std::thread::spawn(move || {
                let mut rx = ctx.event_bus.subscribe();
                while let Ok(event) = rx.blocking_recv() {
                    match event.kind {
                        EngineEventKind::JobProgress {
                            job_id,
                            job_type,
                            progress,
                            message,
                        } => {
                            let payload = serde_json::json!({
                                "job_id": job_id,
                                "job_type": job_type,
                                "status": "running",
                                "progress": progress,
                                "message": message,
                            });
                            let _ = app_handle.emit("job-progress", payload);
                        }
                        EngineEventKind::JobStatus {
                            job_id,
                            job_type,
                            status,
                        } => {
                            let progress = if status.eq_ignore_ascii_case("completed") {
                                100.0
                            } else {
                                0.0
                            };
                            let payload = serde_json::json!({
                                "job_id": job_id,
                                "job_type": job_type,
                                "status": status,
                                "progress": progress,
                                "message": "",
                            });
                            let _ = app_handle.emit("job-progress", payload);
                        }
                        _ => {}
                    }
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            greet,
            capabilities,
            kb_bridge_health,
            search_kb_bridge,
            load_evidence_and_build_tree,
            load_hashsets,
            load_nsrl_database,
            hash_vfs_files,
            get_initial_timeline,
            start_specialized_view_builders,
            get_built_email_rows,
            get_built_registry_rows,
            get_built_media_rows,
            get_built_timeline_rows,
            get_email_rows,
            get_registry_rows,
            get_timeline_rows,
            acquire_live_memory,
            generate_report,
            export_jsonl_timeline,
            list_plugins,
            load_plugin,
            global_search,
            get_artifacts_for_path,
            get_all_tags,
            create_tag,
            add_tag,
            remove_tag,
            get_tags_for_artifact,
            get_tag_counts,
            add_note,
            update_note,
            delete_note,
            get_notes_for_artifact,
            get_all_notes,
            export_artifact,
            export_tagged_items,
            mount_evidence,
            detect_evidence_format,
            enumerate_volume,
            read_artifact_preview,
            read_vfs_file,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
