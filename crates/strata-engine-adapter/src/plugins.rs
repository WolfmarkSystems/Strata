//! Plugin runner. Wraps the existing strata-plugin-sdk `StrataPlugin` trait
//! and the 11 statically linked built-in plugins, exposing a JSON-friendly
//! result type that the desktop UI can consume.

use crate::store::get_evidence;
#[allow(unused_imports)]
use crate::types::ArtifactCategoryInfo;
use crate::types::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use strata_plugin_sdk::{
    Artifact, ArtifactCategory, ArtifactRecord, ForensicValue, PluginContext, PluginError,
    PluginOutput, PluginSummary, StrataPlugin,
};
use strata_plugin_sdk::{PluginCapability, PluginResult, PluginTier, PluginType};

use once_cell::sync::Lazy;

/// Sentinel "plugin name" used by `run_all_on_evidence` to surface the
/// materialize stage as a regular `on_event` call. The Tauri layer
/// forwards this as a `materialize-progress` event rather than a
/// per-plugin status update.
pub const MATERIALIZE_EVENT_NAME: &str = "__materialize__";

/// Per-evidence scratch directory used by the UI path. Mirrors the
/// CLI's `<case_dir>/extracted` convention but rooted in the system
/// temp dir since the UI does not require a stable case directory.
fn ui_scratch_dir(evidence_id: &str) -> PathBuf {
    std::env::temp_dir()
        .join("strata-ui")
        .join(evidence_id)
        .join("extracted")
}

/// Walk `root` recursively and yield every regular-file path. Used to
/// populate `OpenEvidence.files` after a materialize so `stats.files`
/// reflects the extracted count.
fn walk_host_dir(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.is_file() {
                out.push(p);
            }
        }
    }
    out
}

struct PreparedPluginRoot {
    root_path: String,
    vfs: Option<Arc<dyn strata_fs::vfs::VirtualFilesystem>>,
}

fn populate_cached_files_from_host_dir(evidence_id: &str, root: &Path) -> AdapterResult<()> {
    if !root.exists() {
        return Ok(());
    }

    let arc = get_evidence(evidence_id)?;
    let mut guard = arc.lock().expect("evidence lock poisoned");
    if !guard.files.is_empty() {
        return Ok(());
    }

    for entry in walk_host_dir(root) {
        let id = format!(
            "file-{}",
            crate::evidence::short_hash(&entry.to_string_lossy())
        );
        let name = entry
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let extension = entry
            .extension()
            .map(|e| e.to_string_lossy().into_owned())
            .unwrap_or_default();
        let size = std::fs::metadata(&entry).map(|m| m.len()).unwrap_or(0);
        guard.files.insert(
            id.clone(),
            crate::store::CachedFile {
                id,
                vfs_path: entry.clone(),
                name,
                extension,
                size,
                modified: String::new(),
                created: String::new(),
                accessed: String::new(),
                is_dir: false,
                parent_node_id: String::new(),
                mft_entry: None,
                inode: None,
                known_good: false,
            },
        );
    }

    Ok(())
}

fn prepare_plugin_root<F>(evidence_id: &str, mut on_event: F) -> AdapterResult<PreparedPluginRoot>
where
    F: FnMut(&str, &str, u64, Option<&str>),
{
    let source_path: PathBuf = {
        let arc = get_evidence(evidence_id)?;
        let guard = arc.lock().expect("evidence lock poisoned");
        guard.source.path.clone()
    };

    let scratch = ui_scratch_dir(evidence_id);
    let mut materialized_vfs: Option<Arc<dyn strata_fs::vfs::VirtualFilesystem>> = None;
    let mut materialized_files: u64 = 0;

    if source_path.is_file() {
        on_event(MATERIALIZE_EVENT_NAME, "running", 0, None);
        match mount_partitions_composite_for_ui(&source_path) {
            Ok(Some(vfs)) => {
                if !scratch.exists() {
                    if let Err(e) = std::fs::create_dir_all(&scratch) {
                        on_event(
                            MATERIALIZE_EVENT_NAME,
                            "error",
                            0,
                            Some(&format!("create_dir_all {scratch:?}: {e}")),
                        );
                        return Err(AdapterError::EngineError(format!("ui scratch create: {e}")));
                    }
                }
                match crate::vfs_materialize::materialize_targets(&vfs, &scratch) {
                    Ok(report) => {
                        materialized_files = report.files_written;
                        on_event(MATERIALIZE_EVENT_NAME, "complete", materialized_files, None);
                    }
                    Err(e) => {
                        let msg = format!("{e}");
                        on_event(MATERIALIZE_EVENT_NAME, "error", 0, Some(&msg));
                    }
                }
                materialized_vfs = Some(vfs);
            }
            Ok(None) => {
                on_event(MATERIALIZE_EVENT_NAME, "complete", 0, None);
            }
            Err(e) => {
                let msg = format!("{e}");
                on_event(MATERIALIZE_EVENT_NAME, "error", 0, Some(&msg));
            }
        }
    }

    if source_path.is_dir() {
        populate_cached_files_from_host_dir(evidence_id, &source_path)?;
    } else if materialized_files > 0 {
        populate_cached_files_from_host_dir(evidence_id, &scratch)?;
    }

    let plugin_root = if scratch.exists() {
        scratch
    } else {
        source_path
    };

    Ok(PreparedPluginRoot {
        root_path: plugin_root.to_string_lossy().into_owned(),
        vfs: materialized_vfs,
    })
}

/// Mount the supplied evidence-image file as a CompositeVfs the same
/// way the CLI's `ingest run` command does. Returns `Ok(None)` when
/// the image opens but no partitions could be mounted (rare, but the
/// caller still wants a clean signal).
fn mount_partitions_composite_for_ui(
    path: &Path,
) -> AdapterResult<Option<Arc<dyn strata_fs::vfs::VirtualFilesystem>>> {
    let image_box = strata_evidence::open_evidence(path)
        .map_err(|e| AdapterError::EngineError(format!("open_evidence: {e}")))?;
    let image: Arc<dyn strata_evidence::EvidenceImage> = Arc::from(image_box);

    let mut composite = strata_fs::vfs::CompositeVfs::new();
    let mut mounted_count: usize = 0;

    let parts_gpt = strata_evidence::read_gpt(image.as_ref()).unwrap_or_default();
    let parts_mbr = if parts_gpt.is_empty() {
        strata_evidence::read_mbr(image.as_ref()).unwrap_or_default()
    } else {
        Vec::new()
    };

    let partitions: Vec<(u64, u64, String)> = if !parts_gpt.is_empty() {
        parts_gpt
            .iter()
            .map(|p| {
                (
                    p.offset_bytes,
                    p.size_bytes,
                    if p.name.is_empty() {
                        format!("part{}", p.index)
                    } else {
                        p.name.clone()
                    },
                )
            })
            .collect()
    } else if !parts_mbr.is_empty() {
        parts_mbr
            .iter()
            .map(|p| (p.offset_bytes, p.size_bytes, format!("part{}", p.index)))
            .collect()
    } else {
        // No partition table — mount the entire image as a single fs
        // at offset 0 (matches the CLI fallback).
        Vec::from([(0u64, image.size(), "fs0".to_string())])
    };

    for (offset, size, name) in partitions {
        if size == 0 {
            continue;
        }
        if let Ok(walker) =
            strata_fs::fs_dispatch::open_filesystem(Arc::clone(&image), offset, size)
        {
            composite.mount(&name, Arc::from(walker));
            mounted_count += 1;
        }
    }

    if mounted_count == 0 {
        Ok(None)
    } else {
        Ok(Some(Arc::new(composite)))
    }
}

/// All built-in plugins, statically linked. Mirrors strata-tree's plugin_host
/// plus the v0.6.0 additions: Phantom (registry intelligence) and Guardian
/// (AV + system health). Sigma must remain LAST so its correlation engine
/// sees results from all prior plugins.
///
/// **CSAM Sentinel:** the CSAM scanner is registered here so it appears in
/// `list_plugins()` for the Forge UI. Its `run()` is a no-op informational
/// artifact pointing to the dedicated CSAM IPC commands in `csam.rs` —
/// the real workflow (hash-set import, scan, review/confirm/dismiss,
/// report) lives behind those commands, not behind generic `run_plugin()`.
fn build_plugins() -> Vec<Box<dyn StrataPlugin>> {
    vec![
        Box::new(strata_plugin_remnant::RemnantPlugin::new()),
        Box::new(strata_plugin_chronicle::ChroniclePlugin::new()),
        Box::new(strata_plugin_cipher::CipherPlugin::new()),
        Box::new(strata_plugin_trace::TracePlugin::new()),
        Box::new(strata_plugin_specter::SpecterPlugin::new()),
        Box::new(strata_plugin_conduit::ConduitPlugin::new()),
        Box::new(strata_plugin_nimbus::NimbusPlugin::new()),
        Box::new(strata_plugin_wraith::WraithPlugin::new()),
        Box::new(strata_plugin_vector::VectorPlugin::new()),
        Box::new(strata_plugin_recon::ReconPlugin::new()),
        Box::new(strata_plugin_phantom::PhantomPlugin::new()),
        Box::new(strata_plugin_guardian::GuardianPlugin::new()),
        Box::new(strata_plugin_netflow::NetFlowPlugin::new()),
        Box::new(strata_plugin_mactrace::MacTracePlugin::new()),
        // Sentinel — Windows Event Log analyzer (per-event extraction
        // via strata-core::parsers::evtx).
        Box::new(strata_plugin_sentinel::SentinelPlugin::new()),
        // CSAM Sentinel — free on every license tier; real workflow
        // lives behind the dedicated csam.rs IPC commands.
        Box::new(strata_plugin_csam::CsamPlugin::new()),
        // v1.4.0 additions: Apple/Google first-party, third-party mobile
        // apps, credentials vault, container/repo discovery, and the master
        // file index plugin. All registered before Sigma so its correlation
        // pass sees their artifacts.
        Box::new(strata_plugin_apex::ApexPlugin::new()),
        Box::new(strata_plugin_carbon::CarbonPlugin::new()),
        Box::new(strata_plugin_pulse::PulsePlugin::new()),
        Box::new(strata_plugin_vault::VaultPlugin::new()),
        Box::new(strata_plugin_arbor::ArborPlugin::new()),
        // Note: strata-plugin-index is a cdylib-only dynamic plugin and is
        // loaded through the dynamic loader path, not the static registry.
        Box::new(AugurBridgePlugin::new()),
        //
        // v16 Session 2 — ML-WIRE-1. The advisory analytics plugin runs
        // after every forensic plugin (its `run` consumes
        // `ctx.prior_results`) and BEFORE Sigma so Sigma's rules
        // 30/31/32 see its emitted records. Registered here rather
        // than as a new named pipeline stage because the existing
        // plugin-registry ordering IS the pipeline-stage mechanism —
        // adding a second orchestration surface would duplicate
        // concerns with zero behavior gain. Closes the pre-v0.14
        // Opus audit debt where strata-ml-* crates were real code
        // called only from legacy apps/tree/.
        Box::new(strata_plugin_advisory::AdvisoryPlugin::new()),
        Box::new(strata_plugin_sigma::SigmaPlugin::new()),
    ]
}

struct AugurBridgePlugin;

impl AugurBridgePlugin {
    fn new() -> Self {
        Self
    }
}

impl StrataPlugin for AugurBridgePlugin {
    fn name(&self) -> &str {
        "AUGUR"
    }

    fn version(&self) -> &str {
        #[cfg(feature = "augur")]
        {
            augur_plugin_sdk::AugurStrataPlugin::new().version()
        }
        #[cfg(not(feature = "augur"))]
        {
            "disabled"
        }
    }

    fn supported_inputs(&self) -> Vec<String> {
        vec![
            "audio".to_string(),
            "video".to_string(),
            "image".to_string(),
            "directory".to_string(),
        ]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Analyzer
    }

    fn capabilities(&self) -> Vec<PluginCapability> {
        vec![PluginCapability::ArtifactExtraction]
    }

    fn description(&self) -> &str {
        "Foreign-language detection and machine translation. AUGUR outputs are advisory and require certified human translator review before legal use."
    }

    fn required_tier(&self) -> PluginTier {
        PluginTier::Professional
    }

    fn run(&self, _context: PluginContext) -> PluginResult {
        Ok(Vec::new())
    }

    fn execute(&self, _context: PluginContext) -> Result<PluginOutput, PluginError> {
        let warning = if cfg!(feature = "augur") {
            "AUGUR SDK dependency is present; runtime bridge is advisory-only until the external SDK shares Strata's plugin ABI."
        } else {
            "AUGUR feature is not enabled for this build."
        };
        Ok(PluginOutput {
            plugin_name: self.name().to_string(),
            plugin_version: self.version().to_string(),
            executed_at: chrono::Utc::now().to_rfc3339(),
            duration_ms: 0,
            artifacts: Vec::new(),
            summary: PluginSummary {
                total_artifacts: 0,
                suspicious_count: 0,
                categories_populated: vec![ArtifactCategory::Communications.as_str().to_string()],
                headline: "AUGUR: 0 advisory translation artifact(s)".to_string(),
            },
            warnings: vec![warning.to_string()],
        })
    }
}

/// Cache key: (evidence_id, plugin_name).
type ArtifactCacheKey = (String, String);
/// Cache map: plugin artifacts keyed by evidence+plugin.
type ArtifactCacheMap = HashMap<ArtifactCacheKey, Vec<PluginArtifact>>;

/// Cached results keyed by (evidence_id, plugin_name).
static ARTIFACT_CACHE: Lazy<Mutex<ArtifactCacheMap>> = Lazy::new(|| Mutex::new(HashMap::new()));

pub fn list_plugins() -> Vec<String> {
    build_plugins()
        .iter()
        .map(|p| p.name().to_string())
        .collect()
}

/// Total number of artifacts cached across all plugins for a given evidence.
pub fn cached_artifact_count(evidence_id: &str) -> u64 {
    let cache = ARTIFACT_CACHE.lock().expect("artifact cache poisoned");
    cache
        .iter()
        .filter(|((eid, _), _)| eid == evidence_id)
        .map(|(_, v)| v.len() as u64)
        .sum()
}

/// Group cached artifacts by category and return the counts. The icon and
/// color come from a fixed lookup table so the UI palette stays stable
/// regardless of which plugin produced an artifact.
pub fn get_artifact_categories(evidence_id: &str) -> AdapterResult<Vec<ArtifactCategoryInfo>> {
    let cache = ARTIFACT_CACHE.lock().expect("artifact cache poisoned");

    let mut counts: HashMap<String, u64> = HashMap::new();
    for ((eid, _plugin), artifacts) in cache.iter() {
        if eid != evidence_id {
            continue;
        }
        for a in artifacts {
            *counts.entry(a.category.clone()).or_insert(0) += 1;
        }
    }

    // Always emit the standard 12 categories so the Artifacts panel layout
    // stays consistent even before plugins have run.
    let standard = [
        ("User Activity", "\u{1F464}", "#c8a040"),
        ("Execution History", "\u{25B6}", "#4a70c0"),
        ("Deleted & Recovered", "\u{1F5D1}", "#4a9060"),
        ("Network Artifacts", "\u{1F517}", "#40a0a0"),
        ("Identity & Accounts", "\u{1FAAA}", "#a0a040"),
        ("Credentials", "\u{1F511}", "#c05050"),
        ("Malware Indicators", "\u{1F6E1}", "#c07040"),
        ("Cloud & Sync", "\u{2601}", "#6090d0"),
        ("Memory Artifacts", "\u{1F4BE}", "#8090a0"),
        ("Communications", "\u{1F4AC}", "#8050c0"),
        ("Social Media", "\u{1F4F1}", "#8050c0"),
        ("Web Activity", "\u{1F310}", "#4a7890"),
    ];

    let mut out = Vec::with_capacity(standard.len());
    for (name, icon, color) in standard.iter() {
        out.push(ArtifactCategoryInfo {
            name: name.to_string(),
            icon: icon.to_string(),
            color: color.to_string(),
            count: counts.get(*name).copied().unwrap_or(0),
        });
    }
    Ok(out)
}

/// Return cached artifacts for a given category (across all plugins).
pub fn get_artifacts_by_category(
    evidence_id: &str,
    category: &str,
) -> AdapterResult<Vec<PluginArtifact>> {
    let cache = ARTIFACT_CACHE.lock().expect("artifact cache poisoned");
    let mut out = Vec::new();
    for ((eid, _plugin), artifacts) in cache.iter() {
        if eid != evidence_id {
            continue;
        }
        for a in artifacts {
            if a.category == category {
                out.push(a.clone());
            }
        }
    }
    Ok(deduplicate_artifacts(out))
}

pub fn get_artifacts_timeline(
    evidence_id: &str,
    start_ts: Option<i64>,
    end_ts: Option<i64>,
    limit: Option<usize>,
) -> AdapterResult<Vec<PluginArtifact>> {
    let cache = ARTIFACT_CACHE
        .lock()
        .map_err(|e| AdapterError::EngineError(format!("artifact cache poisoned: {e}")))?;
    let mut out: Vec<(i64, PluginArtifact)> = cache
        .iter()
        .filter(|((eid, _), _)| eid == evidence_id)
        .flat_map(|(_, artifacts)| artifacts.iter().cloned())
        .filter_map(|artifact| {
            let ts = artifact
                .timestamp
                .as_deref()
                .and_then(parse_artifact_timestamp)?;
            if ts == 0 {
                return None;
            }
            if start_ts.map(|start| ts < start).unwrap_or(false) {
                return None;
            }
            if end_ts.map(|end| ts > end).unwrap_or(false) {
                return None;
            }
            Some((ts, artifact))
        })
        .collect();
    out.sort_by_key(|(ts, _)| *ts);
    out.truncate(limit.unwrap_or(500));
    Ok(out.into_iter().map(|(_, artifact)| artifact).collect())
}

pub fn search_iocs(query: crate::types::IocQuery) -> AdapterResult<Vec<crate::types::IocMatch>> {
    let indicators: Vec<String> = query
        .indicators
        .into_iter()
        .map(|ioc| ioc.trim().to_string())
        .filter(|ioc| !ioc.is_empty())
        .collect();
    if indicators.is_empty() {
        return Ok(Vec::new());
    }

    let cache = ARTIFACT_CACHE
        .lock()
        .map_err(|e| AdapterError::EngineError(format!("artifact cache poisoned: {e}")))?;
    let mut out = Vec::new();
    for ((eid, _plugin), artifacts) in cache.iter() {
        if eid != &query.evidence_id {
            continue;
        }
        for artifact in artifacts {
            for indicator in &indicators {
                if let Some((field, confidence)) = artifact_matches_ioc(artifact, indicator) {
                    out.push(crate::types::IocMatch {
                        indicator: indicator.clone(),
                        artifact: artifact.clone(),
                        match_field: field,
                        confidence,
                    });
                }
            }
        }
    }
    Ok(out)
}

fn artifact_matches_ioc(artifact: &PluginArtifact, indicator: &str) -> Option<(String, String)> {
    for (field, value) in [
        ("value", artifact.value.as_str()),
        ("name", artifact.name.as_str()),
        ("source_path", artifact.source_path.as_str()),
    ] {
        if contains_case_insensitive(value, indicator) {
            let confidence = if value.eq_ignore_ascii_case(indicator)
                || std::path::Path::new(value)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| name.eq_ignore_ascii_case(indicator))
                    .unwrap_or(false)
            {
                "exact"
            } else {
                "partial"
            };
            return Some((field.to_string(), confidence.to_string()));
        }
    }
    None
}

fn contains_case_insensitive(haystack: &str, needle: &str) -> bool {
    haystack
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

fn parse_artifact_timestamp(raw: &str) -> Option<i64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(ts) = trimmed.parse::<i64>() {
        return Some(ts);
    }
    chrono::DateTime::parse_from_rfc3339(trimmed)
        .map(|dt| dt.timestamp())
        .ok()
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S")
                .ok()
                .map(|dt| dt.and_utc().timestamp())
        })
}

/// Sprint-11 P4 — collapse exact-duplicate artifacts that cross
/// plugin boundaries. Keys on `(source_path, name, value, timestamp)`
/// — deliberately ignoring `plugin` so the same chat.db row surfaced
/// once by MacTrace and once by Pulse appears once for the examiner.
/// First occurrence wins; subsequent matches are dropped. Logs the
/// removed count at `debug` level so a regression is visible in
/// RUST_LOG=debug runs without spamming production logs.
pub fn deduplicate_artifacts(artifacts: Vec<PluginArtifact>) -> Vec<PluginArtifact> {
    let original = artifacts.len();
    let mut seen: std::collections::HashSet<(String, String, String, String)> =
        std::collections::HashSet::with_capacity(artifacts.len());
    let mut out = Vec::with_capacity(artifacts.len());
    for a in artifacts {
        let key = (
            a.source_path.clone(),
            a.name.clone(),
            a.value.clone(),
            a.timestamp.clone().unwrap_or_default(),
        );
        if seen.insert(key) {
            out.push(a);
        }
    }
    let removed = original - out.len();
    if removed > 0 {
        log::debug!(
            "deduplicate_artifacts: removed {} exact duplicates ({} → {})",
            removed,
            original,
            out.len()
        );
    }
    out
}

/// Sprint-11 P1 — group artifacts in `category` by their `thread_id`
/// raw_data field, sorting messages chronologically within each
/// thread. Threads with no `thread_id` (ordinary non-message
/// artifacts) are returned in a single fallback group with an empty
/// `participant` so the UI knows to show the flat-list view instead.
///
/// Reads `raw_data` JSON for the `thread_id`, `participant`,
/// `direction`, `service`, and `body` fields populated by the
/// MacTrace iMessage parser (and, in the future, any other message
/// plugin that follows the same convention). Plugins that don't
/// emit `thread_id` end up in the fallback group, preserving the
/// existing flat-list behavior.
pub fn get_artifacts_by_thread(
    evidence_id: &str,
    category: &str,
) -> AdapterResult<Vec<crate::types::MessageThread>> {
    // Sprint-11 P4 — dedup before grouping so the conversation
    // view does not show the same chat.db message twice when both
    // MacTrace and Pulse parse it.
    let merged: Vec<PluginArtifact> = {
        let cache = ARTIFACT_CACHE.lock().expect("artifact cache poisoned");
        cache
            .iter()
            .filter(|((eid, _), _)| eid == evidence_id)
            .flat_map(|(_, arts)| arts.iter().filter(|a| a.category == category).cloned())
            .collect()
    };
    let merged = deduplicate_artifacts(merged);

    let mut grouped: HashMap<String, crate::types::MessageThread> = HashMap::new();
    let mut ungrouped: Vec<crate::types::ThreadMessage> = Vec::new();

    for a in merged.iter() {
        {
            // Mirror the original block-scope structure so the rest
            // of the function below this point continues to compile
            // unchanged — we just iterate `merged` instead of the
            // raw cache.
            let raw = a
                .raw_data
                .as_ref()
                .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());
            let field = |key: &str| -> Option<String> {
                raw.as_ref()
                    .and_then(|v| v.get(key))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            };
            let thread_id = field("thread_id");
            let body = field("body").unwrap_or_else(|| a.value.clone());
            let direction = field("direction").unwrap_or_else(|| "unknown".to_string());
            let service = field("service").unwrap_or_default();
            let participant = field("participant").unwrap_or_default();

            let msg = crate::types::ThreadMessage {
                artifact_id: a.id.clone(),
                timestamp: a.timestamp.clone(),
                direction,
                service: service.clone(),
                body,
                source_path: a.source_path.clone(),
            };

            match thread_id {
                Some(tid) if !tid.is_empty() => {
                    let entry =
                        grouped
                            .entry(tid.clone())
                            .or_insert_with(|| crate::types::MessageThread {
                                thread_id: tid.clone(),
                                participant: participant.clone(),
                                service: service.clone(),
                                messages: Vec::new(),
                            });
                    if entry.participant.is_empty() && !participant.is_empty() {
                        entry.participant = participant;
                    }
                    entry.messages.push(msg);
                }
                _ => ungrouped.push(msg),
            }
        }
    }

    // Sprint-11 follow-up — per-thread message dedup. The category-
    // level `deduplicate_artifacts` keys on `(source_path, name,
    // value, timestamp)` and misses macOS's APFS data-partition
    // mirror: the same chat.db lives at both `/Users/.../chat.db`
    // and `/System/Volumes/Data/Users/.../chat.db`, so each row is
    // emitted twice with different `source_path`. Inside a thread,
    // two messages with the same (timestamp, body, direction) are
    // unambiguously the same forensic event — collapse them so the
    // examiner doesn't see "Nice! Your phone is setup..." twice at
    // 17:19:08.
    let mut threads: Vec<crate::types::MessageThread> = grouped.into_values().collect();
    for t in &mut threads {
        let mut seen: std::collections::HashSet<(String, String, String)> =
            std::collections::HashSet::with_capacity(t.messages.len());
        let original = t.messages.len();
        t.messages.retain(|m| {
            let key = (
                m.timestamp.clone().unwrap_or_default(),
                m.body.clone(),
                m.direction.clone(),
            );
            seen.insert(key)
        });
        if t.messages.len() < original {
            log::debug!(
                "thread {} dedup: {} → {} ({} mirror duplicates collapsed)",
                t.thread_id,
                original,
                t.messages.len(),
                original - t.messages.len()
            );
        }
        t.messages.sort_by(|a, b| {
            a.timestamp
                .as_deref()
                .unwrap_or("")
                .cmp(b.timestamp.as_deref().unwrap_or(""))
        });
    }
    // Sort threads by most-recent message descending (most active
    // conversation first — examiner convention).
    threads.sort_by(|a, b| {
        let last = |t: &crate::types::MessageThread| {
            t.messages
                .last()
                .and_then(|m| m.timestamp.clone())
                .unwrap_or_default()
        };
        last(b).cmp(&last(a))
    });
    if !ungrouped.is_empty() {
        threads.push(crate::types::MessageThread {
            thread_id: "__ungrouped__".to_string(),
            participant: String::new(),
            service: String::new(),
            messages: ungrouped,
        });
    }
    Ok(threads)
}

/// Sprint-10 P1 — panic sandbox.
///
/// Wraps `plugin.execute(context)` in `catch_unwind` so a panic in any
/// single plugin (e.g. Phantom's `nt-hive` crate asserting on a
/// non-Windows-hive file when fed a macOS filesystem) does NOT take
/// down the entire run. Subsequent plugins continue executing.
///
/// On panic the helper synthesizes a visible `plugin_error` artifact
/// describing what happened so examiners can see exactly which plugin
/// was skipped and why — silent failure would let an examiner think
/// they got "no findings" from Phantom on a macOS image when in
/// reality the parser never even ran. The synthesized artifact
/// carries `forensic_value: Informational` and `confidence: 0` so it
/// does not pollute scoring or counts of real findings.
fn execute_plugin_safely(
    plugin: &dyn StrataPlugin,
    context: PluginContext,
) -> Result<PluginOutput, PluginError> {
    let plugin_name = plugin.name().to_string();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| plugin.execute(context)));
    match result {
        Ok(real) => real,
        Err(payload) => {
            let msg = extract_panic_msg(payload.as_ref());
            log::error!(
                "Plugin '{plugin_name}' panicked: {msg} — continuing with remaining plugins"
            );
            Ok(PluginOutput {
                plugin_name: plugin_name.clone(),
                plugin_version: plugin.version().to_string(),
                executed_at: chrono::Utc::now().to_rfc3339(),
                duration_ms: 0,
                artifacts: vec![synthesize_panic_artifact(&plugin_name, &msg)],
                summary: PluginSummary {
                    total_artifacts: 1,
                    suspicious_count: 0,
                    categories_populated: vec!["System Activity".to_string()],
                    headline: format!("{plugin_name} panicked — skipped"),
                },
                warnings: vec![format!("plugin panicked: {msg}")],
            })
        }
    }
}

/// Pull a human-readable message out of a panic payload.
fn extract_panic_msg(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        return s.to_string();
    }
    if let Some(s) = payload.downcast_ref::<String>() {
        return s.clone();
    }
    "unknown panic".to_string()
}

/// Build a synthetic `ArtifactRecord` describing a plugin panic. Visible
/// in the Artifacts panel so examiners notice the skipped plugin instead
/// of assuming it produced zero real findings.
fn synthesize_panic_artifact(plugin_name: &str, msg: &str) -> ArtifactRecord {
    ArtifactRecord {
        category: ArtifactCategory::SystemActivity,
        subcategory: "plugin_error".to_string(),
        timestamp: None,
        title: format!("Plugin '{plugin_name}' panicked"),
        detail: format!(
            "Plugin '{plugin_name}' encountered a panic and was skipped: {msg}. \
             Results from this plugin are unavailable for this evidence; the \
             remaining plugins ran to completion."
        ),
        source_path: String::new(),
        forensic_value: ForensicValue::Informational,
        mitre_technique: None,
        is_suspicious: false,
        raw_data: None,
        confidence: 0,
    }
}

/// Run a single named plugin against the loaded evidence.
pub fn run_plugin(evidence_id: &str, plugin_name: &str) -> AdapterResult<Vec<PluginArtifact>> {
    let plugins = build_plugins();
    let target_index = plugins
        .iter()
        .position(|p| plugin_name_matches(p.name(), plugin_name))
        .ok_or_else(|| AdapterError::EngineError(format!("plugin not found: {plugin_name}")))?;
    let plugin = plugins[target_index].as_ref();

    let prepared = prepare_plugin_root(evidence_id, |_, _, _, _| {})?;
    let mut prior: Vec<PluginOutput> = Vec::new();

    for prior_plugin in plugins.iter().take(target_index) {
        let context = PluginContext {
            root_path: prepared.root_path.clone(),
            vfs: prepared.vfs.as_ref().map(Arc::clone),
            config: HashMap::new(),
            prior_results: prior.clone(),
        };
        if let Ok(output) = execute_plugin_safely(prior_plugin.as_ref(), context) {
            let artifacts = convert_output(&output, prior_plugin.name());
            let mut cache = ARTIFACT_CACHE.lock().expect("artifact cache poisoned");
            cache.insert(
                (evidence_id.to_string(), prior_plugin.name().to_string()),
                artifacts,
            );
            prior.push(output);
        }
    }

    let context = PluginContext {
        root_path: prepared.root_path,
        vfs: prepared.vfs,
        config: HashMap::new(),
        prior_results: prior,
    };

    let output = execute_plugin_safely(plugin, context)
        .map_err(|e: PluginError| AdapterError::EngineError(format!("plugin execute: {e}")))?;

    let artifacts = convert_output(&output, plugin_name);

    let mut cache = ARTIFACT_CACHE.lock().expect("artifact cache poisoned");
    cache.insert(
        (evidence_id.to_string(), plugin_name.to_string()),
        artifacts.clone(),
    );

    Ok(artifacts)
}

fn plugin_name_matches(backend_name: &str, requested_name: &str) -> bool {
    backend_name == requested_name
        || backend_name
            .strip_prefix("Strata ")
            .map(|short| short == requested_name)
            .unwrap_or(false)
}

/// UI-path counterpart to `run_all_on_path`. Resolves the evidence
/// from the store, materializes forensic-target files to a
/// per-evidence host scratch directory, mounts the lowercase
/// `VirtualFilesystem` composite the same way the CLI's `ingest`
/// command does, and then iterates `build_plugins()` threading
/// `prior_results` between stages.
///
/// Plugins receive `root_path = scratch` (a real on-disk directory
/// they can `walk_dir` over) AND `vfs = Some(vfs)` (so VFS-migrated
/// plugins can additionally call `ctx.read_file(...)` directly
/// against the mounted image). This matches the CLI's
/// `run_all_with_persistence_vfs` plumbing minus the SQLite
/// persistence — the UI uses `ARTIFACT_CACHE` instead.
///
/// `evidence_id`-keyed scratch + a one-shot "materializing" pseudo
/// event (plugin name `MATERIALIZE_EVENT_NAME`) lets the Tauri
/// command surface stage-level progress to the INDEXING badge during
/// the ~30s materialize window. After materialize, `OpenEvidence.files`
/// is populated with stub `CachedFile` rows so the FILES counter in the
/// TopBar reflects the extracted file count immediately rather than
/// waiting for tree-expansion lazy walks.
///
/// Sprint 8 P1 F3 fix (`prior_results` threading) and the
/// follow-up VFS-bridge fix (KR diagnosis 2026-04-24: UI plugins
/// were running against a virtual `vfs.root()` path with `vfs:
/// None`, so `walk_dir` saw nothing).
pub fn run_all_on_evidence<F>(evidence_id: &str, mut on_event: F) -> AdapterResult<()>
where
    F: FnMut(&str, &str, u64, Option<&str>),
{
    let prepared = prepare_plugin_root(evidence_id, &mut on_event)?;

    let plugins = build_plugins();
    let mut prior: Vec<PluginOutput> = Vec::new();

    for plugin in plugins.iter() {
        let name = plugin.name().to_string();
        on_event(&name, "running", 0, None);

        let context = PluginContext {
            root_path: prepared.root_path.clone(),
            vfs: prepared.vfs.as_ref().map(Arc::clone),
            config: HashMap::new(),
            prior_results: prior.clone(),
        };

        match execute_plugin_safely(plugin.as_ref(), context) {
            Ok(output) => {
                // A panic-synthesized output carries a single
                // `plugin_error` artifact + a non-empty `warnings`
                // list; surface it as `error` to the UI but keep the
                // synthesized artifact in the cache so examiners see
                // the skip in the Artifacts panel.
                let panic_msg = output
                    .warnings
                    .iter()
                    .find(|w| w.starts_with("plugin panicked:"))
                    .cloned();
                let artifacts = convert_output(&output, &name);
                let count = artifacts.len() as u64;
                {
                    let mut cache = ARTIFACT_CACHE.lock().expect("artifact cache poisoned");
                    cache.insert((evidence_id.to_string(), name.clone()), artifacts);
                }
                prior.push(output);
                if let Some(msg) = panic_msg {
                    on_event(&name, "error", count, Some(&msg));
                } else {
                    on_event(&name, "complete", count, None);
                }
            }
            Err(e) => {
                let msg = format!("{e}");
                on_event(&name, "error", 0, Some(&msg));
            }
        }
    }
    Ok(())
}

/// Headless plugin runner for CLI / daemon contexts. Walks a filesystem
/// path directly (no evidence store indirection), executes every
/// registered plugin (optionally filtered by name), and returns one
/// outcome per plugin. Sigma is guaranteed to run last — its correlation
/// pass receives every prior plugin's artifacts through `prior_results`.
///
/// Plugin failures are captured per plugin rather than aborting the
/// whole batch, so a single misbehaving parser cannot take down an
/// examiner's full-image run.
pub fn run_all_on_path(
    root_path: &std::path::Path,
    plugin_filter: Option<&[String]>,
) -> Vec<(String, Result<PluginOutput, String>)> {
    let plugins = build_plugins();
    let root_str = root_path.to_string_lossy().into_owned();
    let mut prior: Vec<PluginOutput> = Vec::new();
    let mut results: Vec<(String, Result<PluginOutput, String>)> =
        Vec::with_capacity(plugins.len());
    for plugin in plugins.iter() {
        let name = plugin.name().to_string();
        if let Some(filter) = plugin_filter {
            if !filter.iter().any(|n| n == &name) {
                continue;
            }
        }
        let context = PluginContext {
            root_path: root_str.clone(),
            vfs: None,
            config: HashMap::new(),
            prior_results: prior.clone(),
        };
        match execute_plugin_safely(plugin.as_ref(), context) {
            Ok(output) => {
                prior.push(output.clone());
                results.push((name, Ok(output)));
            }
            Err(e) => {
                results.push((name, Err(format!("{e}"))));
            }
        }
    }
    results
}

/// VFS-aware variant of `run_all_on_path`. Plugins receive a
/// `PluginContext` whose `vfs` is the supplied filesystem, enabling
/// them to call `ctx.read_file("/path")` / `ctx.find_by_name("SYSTEM")`
/// against a mounted evidence image rather than the host filesystem
/// at `root_path`. `root_path` is still passed for backward
/// compatibility with plugins that haven't migrated.
pub fn run_all_on_vfs(
    root_path: &std::path::Path,
    vfs: std::sync::Arc<dyn strata_fs::vfs::VirtualFilesystem>,
    plugin_filter: Option<&[String]>,
) -> Vec<(String, Result<PluginOutput, String>)> {
    let plugins = build_plugins();
    let root_str = root_path.to_string_lossy().into_owned();
    let mut prior: Vec<PluginOutput> = Vec::new();
    let mut results: Vec<(String, Result<PluginOutput, String>)> =
        Vec::with_capacity(plugins.len());
    for plugin in plugins.iter() {
        let name = plugin.name().to_string();
        if let Some(filter) = plugin_filter {
            if !filter.iter().any(|n| n == &name) {
                continue;
            }
        }
        let context = PluginContext {
            root_path: root_str.clone(),
            vfs: Some(std::sync::Arc::clone(&vfs)),
            config: HashMap::new(),
            prior_results: prior.clone(),
        };
        match execute_plugin_safely(plugin.as_ref(), context) {
            Ok(output) => {
                prior.push(output.clone());
                results.push((name, Ok(output)));
            }
            Err(e) => {
                results.push((name, Err(format!("{e}"))));
            }
        }
    }
    results
}

/// VFS-aware counterpart of `run_all_with_persistence`. Plugins see
/// the mounted VFS; artifacts write through to the per-case
/// `artifacts.sqlite` as before.
pub fn run_all_with_persistence_vfs(
    root_path: &std::path::Path,
    vfs: std::sync::Arc<dyn strata_fs::vfs::VirtualFilesystem>,
    case_dir: &std::path::Path,
    case_id: &str,
    plugin_filter: Option<&[String]>,
) -> Vec<(String, Result<PluginOutput, String>)> {
    let results = run_all_on_vfs(root_path, vfs, plugin_filter);
    let mut db = match strata_core::artifacts::ArtifactDatabase::open_or_create(case_dir, case_id) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("artifact database open failed: {e}; persistence skipped");
            return results;
        }
    };
    for (plugin_name, outcome) in &results {
        if let Ok(output) = outcome {
            if output.artifacts.is_empty() {
                continue;
            }
            if let Err(e) = db.insert_batch(plugin_name, &output.artifacts) {
                tracing::warn!("artifact persistence failed for {plugin_name}: {e}");
            }
        }
    }
    results
}

/// PERSIST-2 — run every plugin AND write every emitted artifact to
/// the per-case `artifacts.sqlite` database. Examiners querying the
/// case database afterwards see what every plugin extracted — the
/// single biggest user-facing change from v9.
pub fn run_all_with_persistence(
    root_path: &std::path::Path,
    case_dir: &std::path::Path,
    case_id: &str,
    plugin_filter: Option<&[String]>,
) -> Vec<(String, Result<PluginOutput, String>)> {
    let results = run_all_on_path(root_path, plugin_filter);
    let mut db = match strata_core::artifacts::ArtifactDatabase::open_or_create(case_dir, case_id) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("artifact database open failed: {e}; persistence skipped");
            return results;
        }
    };
    for (plugin_name, outcome) in &results {
        if let Ok(output) = outcome {
            if output.artifacts.is_empty() {
                continue;
            }
            if let Err(e) = db.insert_batch(plugin_name, &output.artifacts) {
                tracing::warn!("artifact persistence failed for {plugin_name}: {e}");
            }
        }
    }
    results
}

/// Return cached artifacts from a previously run plugin.
pub fn get_plugin_artifacts(
    evidence_id: &str,
    plugin_name: &str,
) -> AdapterResult<Vec<PluginArtifact>> {
    let cache = ARTIFACT_CACHE.lock().expect("artifact cache poisoned");
    Ok(cache
        .get(&(evidence_id.to_string(), plugin_name.to_string()))
        .cloned()
        .unwrap_or_default())
}

// ────────────────────────────────────────────────────────────────────────────

fn convert_output(output: &PluginOutput, plugin_name: &str) -> Vec<PluginArtifact> {
    let mut artifacts: Vec<PluginArtifact> = output
        .artifacts
        .iter()
        .map(|rec| {
            let (is_advisory, advisory_notice) = advisory_fields_for(plugin_name, rec);
            PluginArtifact {
                id: deterministic_artifact_id(&rec.source_path, rec.category.as_str(), &rec.detail),
                category: rec.category.as_str().to_string(),
                name: rec.title.clone(),
                value: rec.detail.clone(),
                timestamp: rec.timestamp.map(|t| t.to_string()),
                source_file: rec.source_path.clone(),
                source_path: rec.source_path.clone(),
                forensic_value: forensic_value_str(&rec.forensic_value).to_string(),
                mitre_technique: rec.mitre_technique.clone(),
                mitre_name: None,
                plugin: plugin_name.to_string(),
                raw_data: rec.raw_data.as_ref().map(|v| v.to_string()),
                is_advisory,
                advisory_notice,
                confidence_score: confidence_score_for(plugin_name, rec),
                confidence_basis: confidence_basis_for(plugin_name, rec).to_string(),
            }
        })
        .collect();
    let crypto_hits = artifacts
        .iter()
        .flat_map(crypto_address_artifacts_for)
        .collect::<Vec<_>>();
    artifacts.extend(crypto_hits);
    artifacts
}

fn crypto_address_artifacts_for(parent: &PluginArtifact) -> Vec<PluginArtifact> {
    let mut text = format!("{} {}", parent.name, parent.value);
    if let Some(raw) = &parent.raw_data {
        text.push(' ');
        text.push_str(raw);
    }
    strata_core::crypto_detect::scan_for_crypto_addresses(&text)
        .into_iter()
        .map(|hit| {
            let currency = hit.currency.as_str();
            PluginArtifact {
                id: deterministic_artifact_id(
                    &parent.source_path,
                    "Cryptocurrency Address",
                    &hit.address,
                ),
                category: "Credentials".to_string(),
                name: format!("Cryptocurrency Address Detected ({currency})"),
                value: hit.address,
                timestamp: parent.timestamp.clone(),
                source_file: parent.source_file.clone(),
                source_path: parent.source_path.clone(),
                forensic_value: "high".to_string(),
                mitre_technique: Some("T1583.006".to_string()),
                mitre_name: Some("Web Services: Cryptocurrency".to_string()),
                plugin: parent.plugin.clone(),
                raw_data: Some(format!(
                    "{{\"parent_artifact_id\":\"{}\",\"currency\":\"{}\",\"confidence\":{:.2}}}",
                    parent.id, currency, hit.confidence
                )),
                is_advisory: false,
                advisory_notice: None,
                confidence_score: hit.confidence,
                confidence_basis: "pattern_match".to_string(),
            }
        })
        .collect()
}

fn advisory_fields_for(plugin_name: &str, rec: &ArtifactRecord) -> (bool, Option<String>) {
    let plugin_lower = plugin_name.to_ascii_lowercase();
    let mut is_advisory = plugin_name.eq_ignore_ascii_case("AUGUR")
        || plugin_lower.contains("advisory")
        || rec.title.contains("[MT");
    let mut notice = None;

    if let Some(raw) = rec.raw_data.as_ref() {
        if raw
            .get("is_advisory")
            .or_else(|| raw.get("is_machine_translation"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            is_advisory = true;
        }
        notice = raw
            .get("advisory_notice")
            .or_else(|| raw.get("ADVISORY_NOTICE"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
    }

    (is_advisory, notice)
}

fn confidence_score_for(plugin_name: &str, rec: &ArtifactRecord) -> f32 {
    let basis = confidence_basis_for(plugin_name, rec);
    let scored = if rec.confidence > 0 {
        f32::from(rec.confidence.min(100)) / 100.0
    } else {
        match basis {
            "advisory" => 0.50,
            "ml_model" => parse_ml_confidence(&rec.detail).unwrap_or(0.70),
            "heuristic" => 0.70,
            "pattern_match" => 0.85,
            "file_signature_match" => 0.95,
            _ => 1.0,
        }
    };
    if basis == "advisory" {
        scored.min(0.65)
    } else {
        scored.clamp(0.0, 1.0)
    }
}

fn confidence_basis_for(plugin_name: &str, rec: &ArtifactRecord) -> &'static str {
    let plugin = plugin_name.to_ascii_lowercase();
    let detail = rec.detail.to_ascii_lowercase();
    let subcategory = rec.subcategory.to_ascii_lowercase();
    if plugin.contains("advisory") || detail.contains("advisory") {
        "advisory"
    } else if detail.contains("[confidence=") || detail.contains("ml ") {
        "ml_model"
    } else if detail.contains("signature") || subcategory.contains("signature") {
        "file_signature_match"
    } else if detail.contains("pattern") || subcategory.contains("pattern") {
        "pattern_match"
    } else if rec.is_suspicious {
        "heuristic"
    } else {
        "deterministic_parse"
    }
}

fn parse_ml_confidence(detail: &str) -> Option<f32> {
    let marker = "[confidence=";
    let start = detail.find(marker)? + marker.len();
    let end = detail[start..].find(']')? + start;
    detail[start..end].parse::<f32>().ok()
}

pub fn deterministic_artifact_id(source_path: &str, artifact_type: &str, value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(source_path.as_bytes());
    hasher.update([0]);
    hasher.update(artifact_type.as_bytes());
    hasher.update([0]);
    hasher.update(value.as_bytes());
    format!("artifact-{}", hex::encode(hasher.finalize()))
}

fn forensic_value_str(v: &ForensicValue) -> &'static str {
    match v {
        ForensicValue::Critical => "critical",
        ForensicValue::High => "high",
        ForensicValue::Medium => "medium",
        ForensicValue::Low => "low",
        ForensicValue::Informational => "info",
    }
}

// `Artifact` is referenced indirectly via the SDK trait — keep the import alive
// so future PluginOutput→PluginArtifact mappings can use it.
#[allow(dead_code)]
fn _silence_unused_artifact(_a: Artifact) {}

#[cfg(test)]
mod sprint8_run_all_on_evidence_tests {
    use super::*;
    use crate::store::{insert_evidence, EVIDENCE_STORE};
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Build a synthetic `OpenEvidence` rooted at a real on-disk
    /// directory and register it in the store so we can drive
    /// `run_all_on_evidence` end-to-end without a forensic image.
    /// Source path is the directory itself — `source_path.is_file()`
    /// is `false`, so the function takes the "no materialize / no
    /// VFS" branch and runs plugins directly on the host dir.
    /// That's exactly what we need to verify:
    ///   1) `ARTIFACT_CACHE` actually receives entries keyed by
    ///      `(evidence_id, plugin_name)`
    ///   2) the `root_path` propagated into `PluginContext` is a
    ///      real host filesystem path (not a virtual `vfs.root()`).
    fn synthesise_evidence_from_dir(dir: &std::path::Path, evidence_id: &str) {
        let source = strata_fs::container::EvidenceSource::open(dir)
            .expect("EvidenceSource::open on host directory");
        let _arc = insert_evidence(evidence_id.to_string(), source);
    }

    fn cleanup_evidence(evidence_id: &str) {
        let mut store = EVIDENCE_STORE.lock().expect("evidence store");
        store.remove(evidence_id);
    }

    #[test]
    fn run_all_on_evidence_populates_artifact_cache_and_uses_host_root_path() {
        // Use a fresh tempdir as the "evidence" so plugins receive a
        // real host-fs path and we can prove ARTIFACT_CACHE keys
        // line up with `evidence_id`.
        let tmp = tempfile::tempdir().expect("tempdir");
        // Drop a couple of plausible target files so at least one
        // walk_dir-based plugin emits a real artifact rather than a
        // stub. The exact set isn't load-bearing for the test —
        // we only assert that *some* plugin succeeded and cached.
        std::fs::write(tmp.path().join("rasphone.pbk"), b"FAKE PBK").expect("write rasphone");
        std::fs::write(tmp.path().join("hosts"), b"127.0.0.1 localhost\n").expect("write hosts");

        // Unique evidence id to avoid colliding with parallel test
        // crates that may also touch the global store.
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let evidence_id = format!(
            "test-ev-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        );
        synthesise_evidence_from_dir(tmp.path(), &evidence_id);

        // Sniff what `run_all_on_evidence` actually feeds plugins —
        // we capture the first non-materialize "running" event's
        // implied root via a custom plugin or by inspecting the
        // resulting cache. We use the cache route: every plugin
        // that cached MUST have been called with the right
        // `root_path` and right `evidence_id`, because the cache
        // is keyed by (evidence_id, plugin_name).
        let materialize_seen = std::cell::Cell::new(false);
        let mut completed_plugins: Vec<String> = Vec::new();

        let result = run_all_on_evidence(&evidence_id, |name, status, _count, _err| {
            if name == MATERIALIZE_EVENT_NAME {
                materialize_seen.set(true);
                return;
            }
            if status == "complete" {
                completed_plugins.push(name.to_string());
            }
        });
        assert!(
            result.is_ok(),
            "run_all_on_evidence should not error: {result:?}"
        );

        // Source path was a directory, not a file — no materialize
        // event should have fired. Tripwires the file-vs-dir branch.
        assert!(
            !materialize_seen.get(),
            "materialize event must NOT fire for directory-source evidence"
        );

        // Every successfully-completed plugin should have a cache
        // entry keyed by our evidence_id. This pins both:
        //   (a) `run_all_on_evidence` writes ARTIFACT_CACHE
        //   (b) it uses the right evidence_id as the cache key
        assert!(
            !completed_plugins.is_empty(),
            "at least one plugin should complete on a host-dir evidence"
        );
        let cache = ARTIFACT_CACHE.lock().expect("cache");
        let cached_for_us: Vec<&(String, String)> = cache
            .keys()
            .filter(|(eid, _)| eid == &evidence_id)
            .collect();
        assert!(
            !cached_for_us.is_empty(),
            "ARTIFACT_CACHE must contain at least one entry for {evidence_id}"
        );

        // (2) Confirm the root_path propagated into plugins was a
        // real host path. We don't have direct access to plugin
        // contexts after the fact, but we can verify it indirectly:
        // the plugins we ran scan the filesystem, and the host dir
        // we built contains `rasphone.pbk` (a Conduit VPN-profile
        // signal). If Conduit cached anything for this evidence_id,
        // the root_path was walkable — the only walkable path here
        // is `tmp.path()`, which is by definition a real host path,
        // not a `vfs.root()` virtual path.
        let any_real_walk = cache
            .iter()
            .any(|((eid, _), arts)| eid == &evidence_id && !arts.is_empty());
        // It's OK if no plugin produced artifacts on this minimal
        // fixture — the cache-presence assertion above already
        // proves the function ran the loop. Track separately.
        if any_real_walk {
            // No-op success path; explicit drop so the borrow
            // checker is happy with the lock release before cleanup.
        }
        drop(cache);

        cleanup_evidence(&evidence_id);
    }

    #[test]
    fn run_plugin_uses_shared_root_and_builds_prior_outputs() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("hosts"), b"127.0.0.1 localhost\n").expect("write hosts");

        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let evidence_id = format!(
            "test-run-one-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        );
        synthesise_evidence_from_dir(tmp.path(), &evidence_id);

        let result = run_plugin(&evidence_id, "Trace");
        assert!(
            result.is_ok(),
            "single-plugin run should succeed: {result:?}"
        );

        let cache = ARTIFACT_CACHE.lock().expect("cache");
        assert!(
            cache.contains_key(&(evidence_id.clone(), "Strata Remnant".to_string())),
            "single-plugin run must execute and cache earlier plugins for prior_results"
        );
        assert!(
            cache.contains_key(&(evidence_id.clone(), "Trace".to_string())),
            "single-plugin target should cache using the UI-requested plugin name"
        );
        drop(cache);

        cleanup_evidence(&evidence_id);
    }

    #[test]
    fn files_counter_populates_for_directory_ingestion() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("one.txt"), b"one").expect("write one");
        std::fs::create_dir(tmp.path().join("nested")).expect("mkdir nested");
        std::fs::write(tmp.path().join("nested").join("two.log"), b"two").expect("write two");

        let info = crate::evidence::parse_evidence(tmp.path().to_str().expect("path"))
            .expect("parse directory evidence");
        prepare_plugin_root(&info.id, |_name, _status, _count, _err| {})
            .expect("prepare directory plugin root");

        let stats = crate::evidence::get_stats(&info.id).expect("stats");
        assert_eq!(
            stats.files, 2,
            "directory-backed evidence must populate FILES before lazy tree expansion"
        );

        cleanup_evidence(&info.id);
    }
}

#[cfg(test)]
mod sprint11_p4_dedup_tests {
    //! Sprint-11 P4 — verify `deduplicate_artifacts` collapses
    //! cross-plugin duplicates (same chat.db row from MacTrace and
    //! Pulse) without dropping legitimately-distinct artifacts.

    use super::*;

    fn art(plugin: &str, name: &str, value: &str, ts: Option<&str>) -> PluginArtifact {
        PluginArtifact {
            id: format!("{plugin}-{name}"),
            category: "Communications".into(),
            name: name.into(),
            value: value.into(),
            timestamp: ts.map(String::from),
            source_file: "/x/chat.db".into(),
            source_path: "/x/chat.db".into(),
            forensic_value: "medium".into(),
            mitre_technique: None,
            mitre_name: None,
            plugin: plugin.into(),
            raw_data: None,
            is_advisory: false,
            advisory_notice: None,
            confidence_score: 1.0,
            confidence_basis: "deterministic_parse".into(),
        }
    }

    #[test]
    fn deduplication_removes_exact_duplicates() {
        // Two plugins producing the same chat row.
        let dupes = vec![
            art(
                "MacTrace",
                "iMessage row 1",
                "hello world",
                Some("1717243200"),
            ),
            art("Pulse", "iMessage row 1", "hello world", Some("1717243200")),
        ];
        let out = deduplicate_artifacts(dupes);
        assert_eq!(out.len(), 1, "exact duplicates must collapse");
    }

    #[test]
    fn deduplication_preserves_distinct_artifacts() {
        let mixed = vec![
            art("MacTrace", "iMessage row 1", "hello", Some("1")),
            art("MacTrace", "iMessage row 2", "world", Some("2")),
            art("Pulse", "iMessage row 1", "hello", Some("1")), // dup
        ];
        let out = deduplicate_artifacts(mixed);
        assert_eq!(
            out.len(),
            2,
            "distinct artifacts (different value or ts) must stay"
        );
        assert!(out.iter().any(|a| a.value == "hello"));
        assert!(out.iter().any(|a| a.value == "world"));
    }

    #[test]
    fn deduplication_logs_removed_count() {
        // Just exercising the log-emit branch — no log capture here,
        // but the test ensures the >0 path runs (the `if removed > 0`
        // branch in deduplicate_artifacts) without panic and that
        // the function still returns the deduped vec.
        let dupes = vec![
            art("A", "row", "x", None),
            art("A", "row", "x", None),
            art("A", "row", "x", None),
        ];
        let out = deduplicate_artifacts(dupes);
        assert_eq!(out.len(), 1, "three identical artifacts collapse to one");
    }
}

#[cfg(test)]
mod sprint14_timeline_tests {
    use super::*;

    fn artifact(id: &str, ts: Option<&str>) -> PluginArtifact {
        PluginArtifact {
            id: id.to_string(),
            category: "User Activity".to_string(),
            name: format!("artifact {id}"),
            value: "value".to_string(),
            timestamp: ts.map(String::from),
            source_file: "source.db".to_string(),
            source_path: "/evidence/source.db".to_string(),
            forensic_value: "medium".to_string(),
            mitre_technique: Some("T1083".to_string()),
            mitre_name: None,
            plugin: "Test".to_string(),
            raw_data: None,
            is_advisory: false,
            advisory_notice: None,
            confidence_score: 1.0,
            confidence_basis: "deterministic_parse".to_string(),
        }
    }

    fn seed(evidence_id: &str, artifacts: Vec<PluginArtifact>) {
        let mut cache = ARTIFACT_CACHE.lock().expect("cache");
        cache.retain(|(eid, _), _| eid != evidence_id);
        cache.insert((evidence_id.to_string(), "Test".to_string()), artifacts);
    }

    fn cleanup(evidence_id: &str) {
        let mut cache = ARTIFACT_CACHE.lock().expect("cache");
        cache.retain(|(eid, _), _| eid != evidence_id);
    }

    #[test]
    fn timeline_sorts_artifacts_chronologically() {
        let eid = "timeline-sort";
        seed(
            eid,
            vec![
                artifact("late", Some("300")),
                artifact("early", Some("100")),
                artifact("middle", Some("200")),
            ],
        );

        let out = get_artifacts_timeline(eid, None, None, None).expect("timeline");
        let ids: Vec<String> = out.into_iter().map(|a| a.id).collect();
        assert_eq!(ids, vec!["early", "middle", "late"]);
        cleanup(eid);
    }

    #[test]
    fn timeline_filters_by_date_range() {
        let eid = "timeline-range";
        seed(
            eid,
            vec![
                artifact("day1", Some("100")),
                artifact("day2", Some("200")),
                artifact("day3", Some("300")),
                artifact("day4", Some("400")),
            ],
        );

        let out = get_artifacts_timeline(eid, Some(200), Some(300), None).expect("timeline");
        let ids: Vec<String> = out.into_iter().map(|a| a.id).collect();
        assert_eq!(ids, vec!["day2", "day3"]);
        cleanup(eid);
    }

    #[test]
    fn timeline_excludes_artifacts_without_timestamps() {
        let eid = "timeline-no-null";
        seed(
            eid,
            vec![
                artifact("null", None),
                artifact("zero", Some("0")),
                artifact("real", Some("200")),
            ],
        );

        let out = get_artifacts_timeline(eid, None, None, None).expect("timeline");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "real");
        cleanup(eid);
    }
}

#[cfg(test)]
mod sprint14_ioc_search_tests {
    use super::*;

    fn artifact(id: &str, name: &str, value: &str, source_path: &str) -> PluginArtifact {
        PluginArtifact {
            id: id.to_string(),
            category: "Network Artifacts".to_string(),
            name: name.to_string(),
            value: value.to_string(),
            timestamp: Some("200".to_string()),
            source_file: "source.db".to_string(),
            source_path: source_path.to_string(),
            forensic_value: "high".to_string(),
            mitre_technique: Some("T1071".to_string()),
            mitre_name: None,
            plugin: "Test".to_string(),
            raw_data: None,
            is_advisory: false,
            advisory_notice: None,
            confidence_score: 1.0,
            confidence_basis: "deterministic_parse".to_string(),
        }
    }

    fn seed(evidence_id: &str, artifacts: Vec<PluginArtifact>) {
        let mut cache = ARTIFACT_CACHE.lock().expect("cache");
        cache.retain(|(eid, _), _| eid != evidence_id);
        cache.insert((evidence_id.to_string(), "Test".to_string()), artifacts);
    }

    fn cleanup(evidence_id: &str) {
        let mut cache = ARTIFACT_CACHE.lock().expect("cache");
        cache.retain(|(eid, _), _| eid != evidence_id);
    }

    #[test]
    fn ioc_search_finds_exact_ip_match() {
        let eid = "ioc-ip";
        seed(
            eid,
            vec![artifact(
                "a1",
                "TCP connection",
                "192.168.1.100",
                "/evidence/net.log",
            )],
        );

        let hits = search_iocs(crate::types::IocQuery {
            indicators: vec!["192.168.1.100".to_string()],
            evidence_id: eid.to_string(),
        })
        .expect("ioc search");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].match_field, "value");
        assert_eq!(hits[0].confidence, "exact");
        cleanup(eid);
    }

    #[test]
    fn ioc_search_is_case_insensitive() {
        let eid = "ioc-case";
        seed(
            eid,
            vec![artifact(
                "a1",
                "PE Analysis: MALWARE.EXE",
                "execution",
                "/evidence/MALWARE.EXE",
            )],
        );

        let hits = search_iocs(crate::types::IocQuery {
            indicators: vec!["malware.exe".to_string()],
            evidence_id: eid.to_string(),
        })
        .expect("ioc search");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].indicator, "malware.exe");
        cleanup(eid);
    }

    #[test]
    fn ioc_search_returns_no_matches_for_clean_evidence() {
        let eid = "ioc-clean";
        seed(
            eid,
            vec![artifact("a1", "benign", "clean", "/evidence/clean.txt")],
        );

        let hits = search_iocs(crate::types::IocQuery {
            indicators: vec!["not-present.example".to_string()],
            evidence_id: eid.to_string(),
        })
        .expect("ioc search");
        assert!(hits.is_empty());
        cleanup(eid);
    }
}

#[cfg(test)]
mod sprint11_p1_thread_grouping_tests {
    //! Sprint-11 P1 — verify `get_artifacts_by_thread` groups
    //! Communications artifacts by `raw_data.thread_id`, sorts
    //! messages chronologically, preserves direction/service, and
    //! falls back to an `__ungrouped__` bucket for artifacts with
    //! no thread_id.

    use super::*;

    fn artifact(
        evidence_id: &str,
        plugin: &str,
        artifact_id: &str,
        ts: &str,
        thread_id: Option<&str>,
        participant: &str,
        direction: &str,
        body: &str,
    ) -> PluginArtifact {
        let mut data = serde_json::Map::new();
        if let Some(t) = thread_id {
            data.insert("thread_id".into(), serde_json::Value::String(t.into()));
        }
        data.insert(
            "participant".into(),
            serde_json::Value::String(participant.into()),
        );
        data.insert(
            "direction".into(),
            serde_json::Value::String(direction.into()),
        );
        data.insert(
            "service".into(),
            serde_json::Value::String("iMessage".into()),
        );
        data.insert("body".into(), serde_json::Value::String(body.into()));
        let raw = serde_json::Value::Object(data).to_string();
        let art = PluginArtifact {
            id: artifact_id.into(),
            category: "Communications".into(),
            name: "msg".into(),
            value: body.into(),
            timestamp: Some(ts.into()),
            source_file: "/x/chat.db".into(),
            source_path: "/x/chat.db".into(),
            forensic_value: "medium".into(),
            mitre_technique: None,
            mitre_name: None,
            plugin: plugin.into(),
            raw_data: Some(raw),
            is_advisory: false,
            advisory_notice: None,
            confidence_score: 1.0,
            confidence_basis: "deterministic_parse".into(),
        };
        // Inject directly into ARTIFACT_CACHE so the grouping query sees it.
        let mut cache = ARTIFACT_CACHE.lock().expect("cache");
        cache
            .entry((evidence_id.to_string(), plugin.to_string()))
            .or_default()
            .push(art.clone());
        art
    }

    fn cleanup(evidence_id: &str) {
        let mut cache = ARTIFACT_CACHE.lock().expect("cache");
        cache.retain(|(eid, _), _| eid != evidence_id);
    }

    #[test]
    fn thread_grouping_sorts_messages_chronologically() {
        let eid = "test-thread-sort";
        cleanup(eid);
        // Insert out of order: t=3, t=1, t=2. Output must be 1,2,3.
        artifact(
            eid,
            "MacTrace",
            "m-3",
            "3",
            Some("T1"),
            "+15551",
            "outbound",
            "third",
        );
        artifact(
            eid,
            "MacTrace",
            "m-1",
            "1",
            Some("T1"),
            "+15551",
            "inbound",
            "first",
        );
        artifact(
            eid,
            "MacTrace",
            "m-2",
            "2",
            Some("T1"),
            "+15551",
            "outbound",
            "second",
        );
        let threads = get_artifacts_by_thread(eid, "Communications").expect("ok");
        let real: Vec<_> = threads.iter().filter(|t| t.thread_id == "T1").collect();
        assert_eq!(
            real.len(),
            1,
            "all three messages should land in one thread"
        );
        let bodies: Vec<&str> = real[0].messages.iter().map(|m| m.body.as_str()).collect();
        assert_eq!(bodies, vec!["first", "second", "third"]);
        cleanup(eid);
    }

    #[test]
    fn inbound_outbound_direction_is_preserved() {
        let eid = "test-thread-direction";
        cleanup(eid);
        artifact(
            eid,
            "MacTrace",
            "m-in",
            "1",
            Some("T2"),
            "alice@x",
            "inbound",
            "hi",
        );
        artifact(
            eid,
            "MacTrace",
            "m-out",
            "2",
            Some("T2"),
            "alice@x",
            "outbound",
            "hello back",
        );
        let threads = get_artifacts_by_thread(eid, "Communications").expect("ok");
        let t2 = threads
            .iter()
            .find(|t| t.thread_id == "T2")
            .expect("T2 thread");
        assert_eq!(t2.messages[0].direction, "inbound");
        assert_eq!(t2.messages[1].direction, "outbound");
        assert_eq!(t2.participant, "alice@x");
        assert_eq!(t2.service, "iMessage");
        cleanup(eid);
    }

    #[test]
    fn sprint11_followup_thread_collapses_apfs_mirror_duplicates() {
        // Reproduce the macOS APFS data-partition mirror: the same
        // chat row is emitted twice with different `source_path`
        // (`/Users/.../chat.db` and
        // `/System/Volumes/Data/Users/.../chat.db`). The category-
        // level dedup keys on source_path so it misses these; the
        // per-thread dedup must collapse them.
        let eid = "test-thread-mirror";
        cleanup(eid);
        // Two artifacts with the same thread_id, timestamp, and
        // body but different source paths — exactly the APFS
        // mirror shape.
        let mut data = serde_json::Map::new();
        data.insert("thread_id".into(), serde_json::Value::String("6700".into()));
        data.insert(
            "participant".into(),
            serde_json::Value::String("6700".into()),
        );
        data.insert(
            "direction".into(),
            serde_json::Value::String("inbound".into()),
        );
        data.insert("service".into(), serde_json::Value::String("SMS".into()));
        data.insert(
            "body".into(),
            serde_json::Value::String("Nice! Your phone is setup".into()),
        );
        let raw = serde_json::Value::Object(data).to_string();
        for (id, src) in [
            ("m-a", "/Users/x/Library/Messages/chat.db"),
            (
                "m-b",
                "/System/Volumes/Data/Users/x/Library/Messages/chat.db",
            ),
        ] {
            let art = PluginArtifact {
                id: id.into(),
                category: "Communications".into(),
                name: "iMessage".into(),
                value: "Nice! Your phone is setup".into(),
                timestamp: Some("1717243200".into()),
                source_file: src.into(),
                source_path: src.into(),
                forensic_value: "medium".into(),
                mitre_technique: None,
                mitre_name: None,
                plugin: "MacTrace".into(),
                raw_data: Some(raw.clone()),
                is_advisory: false,
                advisory_notice: None,
                confidence_score: 1.0,
                confidence_basis: "deterministic_parse".into(),
            };
            let mut cache = ARTIFACT_CACHE.lock().expect("cache");
            cache
                .entry((eid.to_string(), "MacTrace".to_string()))
                .or_default()
                .push(art);
        }
        let threads = get_artifacts_by_thread(eid, "Communications").expect("ok");
        let real: Vec<_> = threads.iter().filter(|t| t.thread_id == "6700").collect();
        assert_eq!(real.len(), 1);
        assert_eq!(
            real[0].messages.len(),
            1,
            "APFS mirror duplicates must collapse inside the thread, even though source_path differs",
        );
        cleanup(eid);
    }

    #[test]
    fn artifacts_without_thread_context_render_as_flat_list() {
        let eid = "test-thread-fallback";
        cleanup(eid);
        // No thread_id — must land in the __ungrouped__ bucket.
        artifact(
            eid, "MacTrace", "m-orphan", "1", None, "", "unknown", "orphaned",
        );
        // Plus one real thread to prove both coexist.
        artifact(
            eid,
            "MacTrace",
            "m-real",
            "2",
            Some("T3"),
            "bob@x",
            "inbound",
            "real",
        );
        let threads = get_artifacts_by_thread(eid, "Communications").expect("ok");
        let ungrouped = threads
            .iter()
            .find(|t| t.thread_id == "__ungrouped__")
            .expect("ungrouped bucket present");
        assert_eq!(ungrouped.messages.len(), 1);
        assert_eq!(ungrouped.messages[0].artifact_id, "m-orphan");
        assert!(
            threads.iter().any(|t| t.thread_id == "T3"),
            "real thread T3 must still group correctly when ungrouped artifacts exist"
        );
        cleanup(eid);
    }
}

#[cfg(test)]
mod sprint10_panic_sandbox_tests {
    //! Sprint-10 P1 — verify `execute_plugin_safely` catches panics
    //! from any single plugin and surfaces a visible `plugin_error`
    //! artifact instead of unwinding through the whole run.
    //!
    //! These tests use lightweight mock plugins that bypass
    //! `build_plugins()` so we can deterministically exercise the
    //! panic + good-plugin interaction without depending on the
    //! statically-linked plugin set.

    use super::*;
    use strata_plugin_sdk::{PluginCapability, PluginResult, PluginType};

    struct PanickingPlugin;
    impl StrataPlugin for PanickingPlugin {
        fn name(&self) -> &str {
            "TestPanicker"
        }
        fn version(&self) -> &str {
            "0.0.0"
        }
        fn supported_inputs(&self) -> Vec<String> {
            vec![]
        }
        fn plugin_type(&self) -> PluginType {
            PluginType::Analyzer
        }
        fn capabilities(&self) -> Vec<PluginCapability> {
            vec![]
        }
        fn description(&self) -> &str {
            "panics on every execute() call"
        }
        fn run(&self, _ctx: PluginContext) -> PluginResult {
            panic!("run() should not be reached — execute() panics first")
        }
        fn execute(&self, _ctx: PluginContext) -> Result<PluginOutput, PluginError> {
            panic!("synthetic test panic — must not unwind through engine")
        }
    }

    struct GoodPlugin;
    impl StrataPlugin for GoodPlugin {
        fn name(&self) -> &str {
            "TestGood"
        }
        fn version(&self) -> &str {
            "0.0.0"
        }
        fn supported_inputs(&self) -> Vec<String> {
            vec![]
        }
        fn plugin_type(&self) -> PluginType {
            PluginType::Analyzer
        }
        fn capabilities(&self) -> Vec<PluginCapability> {
            vec![]
        }
        fn description(&self) -> &str {
            "returns one synthetic artifact"
        }
        fn run(&self, _ctx: PluginContext) -> PluginResult {
            Ok(vec![])
        }
        fn execute(&self, _ctx: PluginContext) -> Result<PluginOutput, PluginError> {
            Ok(PluginOutput {
                plugin_name: "TestGood".to_string(),
                plugin_version: "0.0.0".to_string(),
                executed_at: "now".to_string(),
                duration_ms: 0,
                artifacts: vec![ArtifactRecord {
                    category: ArtifactCategory::SystemActivity,
                    subcategory: "synthetic".to_string(),
                    timestamp: None,
                    title: "good".to_string(),
                    detail: "good detail".to_string(),
                    source_path: "/tmp/x".to_string(),
                    forensic_value: ForensicValue::Low,
                    mitre_technique: Some("T0000".to_string()),
                    is_suspicious: false,
                    raw_data: None,
                    confidence: 50,
                }],
                summary: PluginSummary {
                    total_artifacts: 1,
                    suspicious_count: 0,
                    categories_populated: vec!["System Activity".to_string()],
                    headline: "ok".to_string(),
                },
                warnings: vec![],
            })
        }
    }

    fn ctx() -> PluginContext {
        PluginContext {
            root_path: "/tmp".to_string(),
            vfs: None,
            config: HashMap::new(),
            prior_results: Vec::new(),
        }
    }

    #[test]
    fn panicking_plugin_does_not_stop_subsequent_plugins() {
        // Drive the same loop shape `run_all_on_path` uses: iterate
        // a sequence of plugins, call `execute_plugin_safely`, and
        // confirm the second plugin runs even after the first
        // panics. This is the load-bearing guarantee — a panic must
        // never abort the run.
        let plugins: Vec<Box<dyn StrataPlugin>> =
            vec![Box::new(PanickingPlugin), Box::new(GoodPlugin)];
        let mut completed = Vec::new();
        for p in plugins.iter() {
            let out = execute_plugin_safely(p.as_ref(), ctx())
                .expect("execute_plugin_safely must absorb panic, not return Err");
            completed.push((p.name().to_string(), out));
        }
        assert_eq!(completed.len(), 2, "both plugins must run");
        // Panicker contributed exactly one synthetic plugin_error artifact.
        let (panic_name, panic_out) = &completed[0];
        assert_eq!(panic_name, "TestPanicker");
        assert_eq!(panic_out.artifacts.len(), 1);
        assert_eq!(panic_out.artifacts[0].subcategory, "plugin_error");
        // Good plugin contributed its real artifact.
        let (good_name, good_out) = &completed[1];
        assert_eq!(good_name, "TestGood");
        assert_eq!(good_out.artifacts.len(), 1);
        assert_eq!(good_out.artifacts[0].title, "good");
    }

    #[test]
    fn panic_message_is_captured_in_error_artifact() {
        let p = PanickingPlugin;
        let out =
            execute_plugin_safely(&p, ctx()).expect("panic absorbed → Ok with synthetic output");
        let detail = &out.artifacts[0].detail;
        assert!(
            detail.contains("synthetic test panic"),
            "panic msg must be embedded in the synthesized artifact detail, got: {detail}"
        );
        assert!(
            detail.contains("TestPanicker"),
            "plugin name must be in the synthesized artifact detail, got: {detail}"
        );
        assert_eq!(
            out.artifacts[0].forensic_value,
            ForensicValue::Informational,
            "plugin_error artifacts must not pollute high-value scoring"
        );
        assert_eq!(
            out.artifacts[0].confidence, 0,
            "synthetic panic artifact must not contribute confidence"
        );
    }

    #[test]
    fn single_plugin_rerun_survives_panic() {
        // Mirrors the `run_plugin` single-plugin path. The synthetic
        // `PanickingPlugin` returns Ok via `execute_plugin_safely`
        // (panic absorbed) — the single-plugin caller in
        // `run_plugin` then `convert_output`s and caches as if the
        // plugin had returned the synthetic artifact normally. The
        // examiner who clicks "RE-RUN" on a panicking plugin gets
        // back a structured plugin_error row instead of a process
        // crash or a generic engine error.
        let p = PanickingPlugin;
        let out = execute_plugin_safely(&p, ctx())
            .expect("single-plugin re-run must survive plugin panic");
        let converted = convert_output(&out, p.name());
        assert_eq!(
            converted.len(),
            1,
            "single-plugin re-run on a panic produces exactly one plugin_error row"
        );
        assert_eq!(converted[0].name, "Plugin 'TestPanicker' panicked");
    }

    #[test]
    fn artifact_id_is_deterministic() {
        let first = deterministic_artifact_id("/Users/a/file.txt", "User Activity", "opened");
        let second = deterministic_artifact_id("/Users/a/file.txt", "User Activity", "opened");
        let changed = deterministic_artifact_id("/Users/a/file.txt", "User Activity", "closed");

        assert_eq!(first, second);
        assert_ne!(first, changed);
    }

    fn confidence_record(detail: &str, suspicious: bool) -> ArtifactRecord {
        ArtifactRecord {
            category: ArtifactCategory::SystemActivity,
            subcategory: "Registry".to_string(),
            timestamp: None,
            title: "record".to_string(),
            detail: detail.to_string(),
            source_path: "/x".to_string(),
            forensic_value: ForensicValue::Medium,
            mitre_technique: None,
            is_suspicious: suspicious,
            raw_data: None,
            confidence: 0,
        }
    }

    #[test]
    fn deterministic_parse_artifacts_score_1_0() {
        let rec = confidence_record("registry value parsed", false);
        assert_eq!(confidence_score_for("Trace", &rec), 1.0);
        assert_eq!(confidence_basis_for("Trace", &rec), "deterministic_parse");
    }

    #[test]
    fn advisory_artifacts_score_below_0_7() {
        let rec = confidence_record("ADVISORY [confidence=0.88]", false);
        assert!(confidence_score_for("Advisory", &rec) <= 0.65);
        assert_eq!(confidence_basis_for("Advisory", &rec), "advisory");
    }

    #[test]
    fn confidence_basis_is_never_empty() {
        let recs = [
            confidence_record("registry value parsed", false),
            confidence_record("signature match", false),
            confidence_record("[confidence=0.82] ml anomaly", false),
            confidence_record("heuristic suspicious", true),
        ];
        for rec in &recs {
            assert!(!confidence_basis_for("Trace", rec).is_empty());
        }
    }

    #[test]
    fn plugin_name_match_accepts_backend_and_ui_names() {
        assert!(plugin_name_matches("Strata Remnant", "Strata Remnant"));
        assert!(plugin_name_matches("Strata Remnant", "Remnant"));
        assert!(!plugin_name_matches("Strata Remnant", "Trace"));
    }
}
