//! # Sentinel — Windows Event Log Analyzer
//!
//! Sentinel is the Strata plugin that **owns** Windows Event Log
//! (`*.evtx`) parsing. It walks the evidence root, hands every `.evtx`
//! file to [`strata_core::parsers::evtx::EvtxParser`] (the v1.3.0
//! cross-platform per-event parser, plus the v1.3.x typed structured
//! extractors in `strata_core::parsers::evtx_structured`), and surfaces
//! one Strata `ArtifactRecord` per high-value event.
//!
//! Sentinel does not implement its own EVTX format parser — that lives
//! in `strata-core` so the same logic is reused by the CLI shield engine
//! and the desktop Tauri runtime. Sentinel's job is the **plugin
//! framing**: directory walk, per-event MITRE classification (already
//! computed by the structured extractors), forensic-value mapping, and
//! `PluginOutput` summary headline.
//!
//! ## MITRE coverage (per emitted event)
//!
//! Pulled from the structured extractors:
//!
//! | Event ID(s) | Technique | Meaning |
//! |---|---|---|
//! | 4624 | T1078    | Valid Accounts (logon success) |
//! | 4625 | T1110    | Brute Force (failed logon) |
//! | 4688 | T1059    | Command and Scripting Interpreter (process create) |
//! | 4698, 4702 | T1053.005 | Scheduled Task creation / update |
//! | 7045 | T1543.003 | Windows Service install |
//! | 4103, 4104 | T1059.001 | PowerShell script-block logging |
//! | 1102 | T1070.001 | Indicator Removal: Clear Windows Event Logs |
//!
//! Other high-value events recognised by `strata_core` (Sysmon, Defender,
//! Kerberos, account management) inherit a generic `T1078` mapping when
//! no per-EventID override exists.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println` per CLAUDE.md.

pub mod lateral_movement;

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use strata_core::parser::ArtifactParser;
use strata_core::parsers::evtx::EvtxParser as CoreEvtxParser;
use strata_plugin_sdk::{
    Artifact, ArtifactCategory, ArtifactRecord, ForensicValue, PluginCapability, PluginContext,
    PluginError, PluginOutput, PluginResult, PluginSummary, PluginType, StrataPlugin,
};

/// Hard cap on the number of `.evtx` files we'll process per evidence
/// root. Real Windows installs ship ~150 channel files; 1024 is a
/// generous bound that protects against malicious or misconfigured
/// directory trees.
const MAX_EVTX_FILES: usize = 1024;
/// Hard cap on the size of any single `.evtx` we'll load into memory.
/// 512 MB matches the cap Phantom uses for hive files and is well above
/// the largest real-world Security.evtx we've seen in case work (~150 MB
/// on a 90-day-rolled domain controller).
const MAX_EVTX_BYTES: u64 = 512 * 1024 * 1024;

pub struct SentinelPlugin {
    name: String,
    version: String,
}

impl Default for SentinelPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl SentinelPlugin {
    pub fn new() -> Self {
        Self {
            name: "Strata Sentinel".to_string(),
            version: "1.0.0".to_string(),
        }
    }

    /// Read an `.evtx` file with a size cap. Returns `None` for paths
    /// that exceed [`MAX_EVTX_BYTES`] or fail to open — the plugin
    /// continues with the remaining files rather than aborting.
    fn read_evtx_gated(path: &Path) -> Option<Vec<u8>> {
        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                log::warn!("sentinel: stat {} failed: {}", path.display(), e);
                return None;
            }
        };
        if metadata.len() > MAX_EVTX_BYTES {
            log::warn!(
                "sentinel: skipping {} ({} bytes > cap {})",
                path.display(),
                metadata.len(),
                MAX_EVTX_BYTES
            );
            return None;
        }
        match std::fs::read(path) {
            Ok(b) => Some(b),
            Err(e) => {
                log::warn!("sentinel: read {} failed: {}", path.display(), e);
                None
            }
        }
    }

    /// Run the strata-core EVTX parser on the bytes of one file and
    /// translate each `ParsedArtifact` into a plugin-SDK `Artifact`.
    /// Public for unit testing.
    pub fn parse_one_evtx(path: &Path, data: &[u8]) -> Vec<Artifact> {
        let core = CoreEvtxParser::new();
        let parsed = match core.parse_file(path, data) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("sentinel: evtx parser rejected {}: {}", path.display(), e);
                return Vec::new();
            }
        };
        let path_str = path.to_string_lossy().to_string();
        let mut out = Vec::with_capacity(parsed.len());
        for pa in parsed {
            // Skip the per-file summary "eventlog" artifact — Sentinel
            // emits its own headline. Keep the per-event records.
            if pa.artifact_type == "eventlog" {
                continue;
            }
            let mut a = Artifact::new("Windows Event", &path_str);
            if let Some(ts) = pa.timestamp {
                a.timestamp = Some(ts as u64);
            }
            // Pull typed fields from the json_data the structured
            // extractors populated (see strata_core::parsers::evtx_structured).
            let event_id = pa
                .json_data
                .get("event_id")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            let channel = pa
                .json_data
                .get("channel")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let computer = pa
                .json_data
                .get("computer")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let mitre = pa
                .json_data
                .get("mitre")
                .and_then(|v| v.as_str())
                .unwrap_or("T1078")
                .to_string();
            let forensic_value = pa
                .json_data
                .get("forensic_value")
                .and_then(|v| v.as_str())
                .unwrap_or("Medium")
                .to_string();

            a.add_field("title", &pa.description);
            a.add_field("file_type", "Windows Event");
            a.add_field("event_id", &event_id.to_string());
            a.add_field("channel", &channel);
            a.add_field("computer_name", &computer);
            a.add_field("mitre", &mitre);
            a.add_field("forensic_value", &forensic_value);
            a.add_field("source_path", &path_str);

            // Forward the structured payload verbatim so the desktop UI
            // can render typed fields without re-decoding.
            if let Some(structured) = pa.json_data.get("structured") {
                let serialized = serialize_value(structured);
                a.add_field("structured", &serialized);
            }
            // Convenience fields for the most-queried scalars.
            for key in [
                "username",
                "target_user",
                "subject_user",
                "source_ip",
                "logon_type",
                "process_name",
                "command_line",
                "service_name",
                "task_name",
                "script_block_text",
            ] {
                if let Some(v) = pa.json_data.get(key).and_then(|v| v.as_str()) {
                    if !v.is_empty() {
                        a.add_field(key, v);
                    }
                }
            }

            // 1102 is anti-forensic by definition — flag it suspicious so
            // Sigma's downstream rules treat it as critical.
            if event_id == 1102 {
                a.add_field("suspicious", "true");
            }
            out.push(a);
        }
        out
    }
}

/// Serialize a `serde_json::Value` to a compact JSON string. Returns
/// `"{}"` on serialization failure rather than propagating an error,
/// since this is a UI convenience field and a failure here must not
/// poison the artifact.
fn serialize_value(v: &serde_json::Value) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "{}".to_string())
}

impl StrataPlugin for SentinelPlugin {
    fn name(&self) -> &str {
        &self.name
    }
    fn version(&self) -> &str {
        &self.version
    }
    fn supported_inputs(&self) -> Vec<String> {
        vec!["*.evtx".to_string()]
    }
    fn plugin_type(&self) -> PluginType {
        PluginType::Analyzer
    }
    fn capabilities(&self) -> Vec<PluginCapability> {
        vec![PluginCapability::ArtifactExtraction]
    }
    fn description(&self) -> &str {
        "Windows Event Log analyzer \u{2014} per-event extraction with typed Security/System/PowerShell/Sysmon fields"
    }

    fn run(&self, ctx: PluginContext) -> PluginResult {
        let root = Path::new(&ctx.root_path);
        let mut results = Vec::new();

        let files = match walk_dir(root) {
            Ok(v) => v,
            Err(_) => return Ok(results),
        };

        let mut processed = 0usize;
        for path in files {
            if processed >= MAX_EVTX_FILES {
                log::warn!(
                    "sentinel: hit MAX_EVTX_FILES cap ({}) — remaining .evtx files skipped",
                    MAX_EVTX_FILES
                );
                break;
            }
            let is_evtx = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("evtx"))
                .unwrap_or(false);
            if !is_evtx {
                continue;
            }
            let Some(data) = Self::read_evtx_gated(&path) else {
                continue;
            };
            processed += 1;
            results.extend(Self::parse_one_evtx(&path, &data));
        }

        Ok(results)
    }

    fn execute(&self, context: PluginContext) -> Result<PluginOutput, PluginError> {
        let start = std::time::Instant::now();
        let artifacts = self.run(context)?;

        let mut records = Vec::with_capacity(artifacts.len());
        let mut suspicious_count = 0usize;
        let mut category_set: HashSet<String> = HashSet::new();

        for a in &artifacts {
            let suspicious = a
                .data
                .get("suspicious")
                .map(|v| v == "true")
                .unwrap_or(false);
            if suspicious {
                suspicious_count += 1;
            }
            let fv = match a.data.get("forensic_value").map(|s| s.as_str()) {
                Some("Critical") => ForensicValue::Critical,
                Some("High") => ForensicValue::High,
                Some("Low") => ForensicValue::Low,
                Some("Informational") => ForensicValue::Informational,
                _ => ForensicValue::Medium,
            };
            let category = ArtifactCategory::SystemActivity;
            category_set.insert(category.as_str().to_string());

            records.push(ArtifactRecord {
                category,
                subcategory: "Windows Event".to_string(),
                timestamp: a.timestamp.map(|t| t as i64),
                title: a.data.get("title").cloned().unwrap_or_else(|| a.source.clone()),
                detail: a.data.get("detail").cloned().unwrap_or_default(),
                source_path: a.source.clone(),
                forensic_value: fv,
                mitre_technique: a.data.get("mitre").cloned(),
                is_suspicious: suspicious,
                raw_data: None,
                confidence: 0,
            });
        }

        let total = records.len();
        let category_count = category_set.len();
        let categories_populated: Vec<String> = category_set.into_iter().collect();

        Ok(PluginOutput {
            plugin_name: self.name().to_string(),
            plugin_version: self.version().to_string(),
            executed_at: chrono::Utc::now().to_rfc3339(),
            duration_ms: start.elapsed().as_millis() as u64,
            artifacts: records,
            summary: PluginSummary {
                total_artifacts: total,
                suspicious_count,
                categories_populated,
                headline: format!(
                    "Sentinel: {} Windows Event records ({} suspicious) across {} categor{}",
                    total,
                    suspicious_count,
                    category_count,
                    if category_count == 1 { "y" } else { "ies" }
                ),
            },
            warnings: vec![],
        })
    }
}

/// Recursively list every file under `dir`. Mirrors the shape of the
/// helper in other Strata plugins so behaviour stays consistent.
fn walk_dir(dir: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut paths = Vec::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                if let Ok(sub) = walk_dir(&path) {
                    paths.extend(sub);
                }
            } else {
                paths.push(path);
            }
        }
    }
    Ok(paths)
}

#[no_mangle]
pub extern "C" fn create_plugin_sentinel() -> *mut std::ffi::c_void {
    let plugin: Box<dyn StrataPlugin> = Box::new(SentinelPlugin::new());
    Box::into_raw(Box::new(plugin)) as *mut std::ffi::c_void
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_metadata_is_well_formed() {
        let p = SentinelPlugin::new();
        assert_eq!(p.name(), "Strata Sentinel");
        assert_eq!(p.version(), "1.0.0");
        assert_eq!(p.supported_inputs(), vec!["*.evtx".to_string()]);
        assert!(matches!(p.plugin_type(), PluginType::Analyzer));
        assert_eq!(p.capabilities().len(), 1);
        assert!(!p.description().is_empty());
    }

    #[test]
    fn parse_one_evtx_handles_corrupt_bytes_without_panic() {
        // Random non-EVTX bytes — the strata-core parser should reject
        // these and return an empty Vec.
        let junk: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let path = Path::new("/tmp/Sentinel-test-corrupt.evtx");
        let result = SentinelPlugin::parse_one_evtx(path, &junk);
        assert!(result.is_empty());
    }

    #[test]
    fn parse_one_evtx_handles_empty_input_without_panic() {
        let path = Path::new("/tmp/Sentinel-test-empty.evtx");
        let result = SentinelPlugin::parse_one_evtx(path, &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn run_on_empty_directory_produces_no_artifacts() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let p = SentinelPlugin::new();
        let ctx = PluginContext {
            root_path: tmp.path().to_string_lossy().to_string(),
            config: std::collections::HashMap::new(),
            prior_results: Vec::new(),
        };
        let artifacts = p.run(ctx).expect("run must not fail on empty dir");
        assert!(artifacts.is_empty());
    }

    #[test]
    fn run_skips_non_evtx_files() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        // Drop a non-evtx file in the tree — Sentinel must ignore it.
        let txt_path = tmp.path().join("readme.txt");
        std::fs::write(&txt_path, b"not an evtx file").expect("write fixture");

        let p = SentinelPlugin::new();
        let ctx = PluginContext {
            root_path: tmp.path().to_string_lossy().to_string(),
            config: std::collections::HashMap::new(),
            prior_results: Vec::new(),
        };
        let artifacts = p.run(ctx).expect("run must succeed");
        assert!(artifacts.is_empty());
    }

    #[test]
    fn read_evtx_gated_rejects_missing_file() {
        let result = SentinelPlugin::read_evtx_gated(Path::new(
            "/nonexistent/path/that/does/not/exist.evtx",
        ));
        assert!(result.is_none());
    }

    #[test]
    fn execute_returns_well_formed_plugin_output_on_empty_evidence() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let p = SentinelPlugin::new();
        let ctx = PluginContext {
            root_path: tmp.path().to_string_lossy().to_string(),
            config: std::collections::HashMap::new(),
            prior_results: Vec::new(),
        };
        let output = p.execute(ctx).expect("execute must succeed");
        assert_eq!(output.plugin_name, "Strata Sentinel");
        assert_eq!(output.plugin_version, "1.0.0");
        assert_eq!(output.summary.total_artifacts, 0);
        assert_eq!(output.summary.suspicious_count, 0);
        assert!(output.summary.headline.contains("Sentinel"));
    }
}
