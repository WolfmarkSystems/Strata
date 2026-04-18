//! Plugin runner. Wraps the existing strata-plugin-sdk `StrataPlugin` trait
//! and the 11 statically linked built-in plugins, exposing a JSON-friendly
//! result type that the desktop UI can consume.

use crate::store::get_evidence;
use crate::types::*;
#[allow(unused_imports)]
use crate::types::ArtifactCategoryInfo;
use std::collections::HashMap;
use std::sync::Mutex;
use strata_plugin_sdk::{
    Artifact, ForensicValue, PluginContext, PluginError, PluginOutput, StrataPlugin,
};

use once_cell::sync::Lazy;

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
        Box::new(strata_plugin_sigma::SigmaPlugin::new()),
    ]
}

/// Cache key: (evidence_id, plugin_name).
type ArtifactCacheKey = (String, String);
/// Cache map: plugin artifacts keyed by evidence+plugin.
type ArtifactCacheMap = HashMap<ArtifactCacheKey, Vec<PluginArtifact>>;

/// Cached results keyed by (evidence_id, plugin_name).
static ARTIFACT_CACHE: Lazy<Mutex<ArtifactCacheMap>> = Lazy::new(|| Mutex::new(HashMap::new()));

pub fn list_plugins() -> Vec<String> {
    build_plugins().iter().map(|p| p.name().to_string()).collect()
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
    Ok(out)
}

/// Run a single named plugin against the loaded evidence.
pub fn run_plugin(evidence_id: &str, plugin_name: &str) -> AdapterResult<Vec<PluginArtifact>> {
    let plugins = build_plugins();
    let plugin = plugins
        .iter()
        .find(|p| p.name() == plugin_name)
        .ok_or_else(|| AdapterError::EngineError(format!("plugin not found: {plugin_name}")))?;

    // Build a PluginContext rooted at the evidence's underlying VFS root.
    let root_path = {
        let arc = get_evidence(evidence_id)?;
        let guard = arc.lock().expect("evidence lock poisoned");
        guard
            .source
            .vfs
            .as_ref()
            .map(|v| v.root().to_string_lossy().into_owned())
            .unwrap_or_else(|| guard.source.path.to_string_lossy().into_owned())
    };

    let context = PluginContext {
        root_path,
        vfs: None,
        config: HashMap::new(),
        prior_results: Vec::new(),
    };

    let output = plugin
        .execute(context)
        .map_err(|e: PluginError| AdapterError::EngineError(format!("plugin execute: {e}")))?;

    let artifacts = convert_output(&output, plugin_name);

    let mut cache = ARTIFACT_CACHE.lock().expect("artifact cache poisoned");
    cache.insert(
        (evidence_id.to_string(), plugin_name.to_string()),
        artifacts.clone(),
    );

    Ok(artifacts)
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
    let mut results: Vec<(String, Result<PluginOutput, String>)> = Vec::with_capacity(plugins.len());
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
        match plugin.execute(context) {
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
        match plugin.execute(context) {
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
    let mut db =
        match strata_core::artifacts::ArtifactDatabase::open_or_create(case_dir, case_id) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(
                    "artifact database open failed: {e}; persistence skipped"
                );
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
    let mut db = match strata_core::artifacts::ArtifactDatabase::open_or_create(case_dir, case_id)
    {
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
    output
        .artifacts
        .iter()
        .enumerate()
        .map(|(i, rec)| PluginArtifact {
            id: format!("{}-{}", plugin_name, i),
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
        })
        .collect()
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
