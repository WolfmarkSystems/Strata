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

#[derive(Debug, Clone, PartialEq)]
pub struct EvtxAnalytic {
    pub event_id: u32,
    pub channel: String,
    pub timestamp: i64,
    pub computer: String,
    pub subject_username: Option<String>,
    pub subject_domain: Option<String>,
    pub logon_type: Option<u32>,
    pub target_username: Option<String>,
    pub source_ip: Option<String>,
    pub process_name: Option<String>,
    pub command_line: Option<String>,
    pub significance: String,
    pub mitre_technique: String,
    pub forensic_value: ForensicValue,
    pub advisory_notice: Option<String>,
}

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
            if !is_high_value_event_id(event_id) {
                continue;
            }
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
            let mitre = mitre_for_event(event_id)
                .unwrap_or_else(|| {
                    pa.json_data
                        .get("mitre")
                        .and_then(|v| v.as_str())
                        .unwrap_or("T1078")
                })
                .to_string();
            let _prior_mitre = pa
                .json_data
                .get("mitre")
                .and_then(|v| v.as_str())
                .unwrap_or("T1078")
                .to_string();
            let forensic_value = if matches!(event_id, 1102 | 104) {
                "Critical".to_string()
            } else {
                pa.json_data
                    .get("forensic_value")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Medium")
                    .to_string()
            };

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
            if matches!(event_id, 1102 | 104) {
                a.add_field("suspicious", "true");
                a.add_field(
                    "advisory_notice",
                    "Event log was cleared. Prior events may be unrecoverable. This is a common anti-forensics technique.",
                );
            }
            out.push(a);
        }
        out
    }
}

fn is_high_value_event_id(event_id: u32) -> bool {
    matches!(
        event_id,
        4624 | 4625
            | 4634
            | 4647
            | 4648
            | 4672
            | 4720
            | 4726
            | 4732
            | 6005
            | 6006
            | 7045
            | 7040
            | 1102
            | 104
            | 4103
            | 4104
            | 4688
    )
}

fn mitre_for_event(event_id: u32) -> Option<&'static str> {
    match event_id {
        4624 | 4648 | 4672 => Some("T1078"),
        4625 => Some("T1110"),
        4720 | 4726 | 4732 => Some("T1098"),
        7045 => Some("T1543.003"),
        7040 => Some("T1562.001"),
        4103 | 4104 | 4688 => Some("T1059.001"),
        1102 | 104 => Some("T1070.001"),
        6005 | 6006 | 4634 | 4647 => Some("T1082"),
        _ => None,
    }
}

fn significance_for_event(event_id: u32, logon_type: Option<u32>) -> String {
    match event_id {
        4624 => format!(
            "Successful logon{}",
            logon_type
                .map(|t| format!(" ({})", logon_type_label(t)))
                .unwrap_or_default()
        ),
        4625 => "Failed logon attempt".to_string(),
        4648 => "Explicit credential logon; possible pass-the-hash pivot".to_string(),
        4672 => "Special privileges assigned to new logon".to_string(),
        7045 => "New service installed; persistence indicator".to_string(),
        4104 => "PowerShell script block content captured".to_string(),
        1102 | 104 => "Event log cleared; anti-forensics indicator".to_string(),
        _ => "High-value Windows event".to_string(),
    }
}

fn logon_type_label(logon_type: u32) -> &'static str {
    match logon_type {
        2 => "interactive",
        3 => "network",
        10 => "remote",
        _ => "other",
    }
}

pub fn analytic_from_event_xml(channel: &str, xml: &str) -> Option<EvtxAnalytic> {
    let event_id = extract_xml_text(xml, "EventID")?.parse::<u32>().ok()?;
    if !is_high_value_event_id(event_id) {
        return None;
    }
    let logon_type = extract_named_data(xml, "LogonType").and_then(|v| v.parse::<u32>().ok());
    let forensic_value = if matches!(event_id, 1102 | 104) {
        ForensicValue::Critical
    } else {
        ForensicValue::High
    };
    Some(EvtxAnalytic {
        event_id,
        channel: channel.to_string(),
        timestamp: 0,
        computer: extract_xml_text(xml, "Computer").unwrap_or_default(),
        subject_username: extract_named_data(xml, "SubjectUserName"),
        subject_domain: extract_named_data(xml, "SubjectDomainName"),
        logon_type,
        target_username: extract_named_data(xml, "TargetUserName"),
        source_ip: extract_named_data(xml, "IpAddress"),
        process_name: extract_named_data(xml, "ProcessName"),
        command_line: extract_named_data(xml, "CommandLine")
            .or_else(|| extract_named_data(xml, "ScriptBlockText")),
        significance: significance_for_event(event_id, logon_type),
        mitre_technique: mitre_for_event(event_id).unwrap_or("T1078").to_string(),
        forensic_value,
        advisory_notice: if matches!(event_id, 1102 | 104) {
            Some("Event log was cleared. Prior events may be unrecoverable. This is a common anti-forensics technique.".to_string())
        } else {
            None
        },
    })
}

fn extract_xml_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].trim().to_string())
}

fn extract_named_data(xml: &str, name: &str) -> Option<String> {
    let marker = format!("Name='{name}'>");
    let marker_alt = format!("Name=\"{name}\">");
    let start = xml
        .find(&marker)
        .map(|idx| idx + marker.len())
        .or_else(|| xml.find(&marker_alt).map(|idx| idx + marker_alt.len()))?;
    let end = xml[start..].find("</Data>")? + start;
    Some(xml[start..end].trim().to_string()).filter(|v| !v.is_empty())
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

            // Thread event_id (already parsed and stashed at
            // a.add_field("event_id", ...) in run()) into the
            // subcategory so Sigma rules keying on
            // `subcategory == "EVTX-<id>"` can fire. Without this
            // every record flattened to "Windows Event" and the
            // entire Hayabusa rule family (15 rules: 13–27 + 30
            // per docs/RESEARCH_POST_V16_SIGMA_INVENTORY.md §2)
            // was silently unreachable regardless of evidence
            // content. Missing / unparseable event_id falls back
            // to the legacy flat string so records don't vanish.
            let subcategory = evtx_subcategory_for(a.data.get("event_id"));

            records.push(ArtifactRecord {
                category,
                subcategory,
                timestamp: a.timestamp.map(|t| t as i64),
                title: a
                    .data
                    .get("title")
                    .cloned()
                    .unwrap_or_else(|| a.source.clone()),
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

/// Thread the parsed EVTX event ID into the Sigma subcategory
/// contract. Input is the raw string value previously stashed at
/// `Artifact.data["event_id"]` by `run()`. Returns `"EVTX-<id>"`
/// when parseable, `"Windows Event"` otherwise.
///
/// The legacy flat string fallback exists so records with missing
/// or malformed event_id still surface in the case output (less
/// useful than a typed record, but materially better than
/// dropping them). Sigma rules keying on `EVTX-<id>` naturally
/// skip the fallback records — which is the intended behaviour
/// when an event_id couldn't be determined.
fn evtx_subcategory_for(event_id_field: Option<&String>) -> String {
    match event_id_field.and_then(|v| v.parse::<u32>().ok()) {
        Some(id) => format!("EVTX-{id}"),
        None => "Windows Event".to_string(),
    }
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
            vfs: None,
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
            vfs: None,
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
    fn sentinel_lateral_movement_detector_pending_evtx_record_extraction() {
        // Sprint 5 Sentinel audit finding. `lateral_movement.rs`
        // (393 LOC) exposes `LateralMovementDetector::detect(&[EventRecord])`
        // returning `Vec<LateralMovement>` — a stateful correlator
        // across parsed EVTX event records. Wiring it into Sentinel's
        // run() would require refactoring `parse_one_evtx` to emit
        // both `Artifact`s AND typed `EventRecord`s, then running
        // the detector over the accumulated records and emitting a
        // new "Lateral Movement Indicator" subcategory.
        //
        // Current Charlie / Jo corpus has `.evt` (legacy) not
        // `.evtx` — Sentinel's extension gate skips them, so even
        // with full wiring the detector would produce zero
        // indicators on these images. Zero ROI on the canonical
        // test corpus blocks meaningful validation.
        //
        // Deferred to a future sprint that pairs:
        //   (1) Sentinel parse_one_evtx refactor to surface
        //       EventRecord objects alongside Artifact records, and
        //   (2) Win8+ evidence in the test corpus with actual
        //       EVTX 4624/4625/4648/4672 logon events
        //
        // The `_pending_evtx_record_extraction` suffix makes the
        // deferral discoverable. This tripwire pins the current
        // un-wired state by confirming production code does not
        // reference the detector.
        let src = include_str!("lib.rs");
        let production = src.split("#[cfg(test)]").next().expect("has production");
        let needle = format!("{}::detect", "LateralMovementDetector");
        assert!(
            !production.contains(&needle),
            "LateralMovementDetector wiring requires parse_one_evtx refactor + \
             Win8+ EVTX test corpus. When both land, update this tripwire. \
             Current production code must not invoke the detector."
        );
        // Confirm the detector itself still compiles + is publicly
        // reachable so future wiring has a target — if the module
        // got deleted, the wiring plan changes.
        let _: fn(i64) -> crate::lateral_movement::LateralMovementDetector =
            crate::lateral_movement::LateralMovementDetector::new;
    }

    #[test]
    fn sentinel_emits_evtx_typed_subcategory_for_windows_events() {
        // post-v16 Sprint 2 Fix 1 tripwire. Closes
        // docs/RESEARCH_POST_V16_SIGMA_INVENTORY.md §1.1 defect
        // (every Sentinel record flattened to subcategory =
        // "Windows Event" regardless of event ID, silently gating
        // out 15 Sigma rules keyed on "EVTX-<id>"). This test
        // pins the new threading behaviour: event IDs 4624, 4688,
        // 7045, 1102, 104 — the five Sigma rules reference most
        // heavily — must each map to their typed subcategory.
        //
        // When the `.evt` legacy parser ships (separate sprint),
        // its emitted records should follow the same contract.
        // If this test fails with "Windows Event" records, the
        // Sigma alignment regressed to the pre-Sprint-2 state.
        for id in [4624u32, 4688, 7045, 1102, 104, 4625, 4740, 4698] {
            let field = Some(id.to_string());
            let sub = evtx_subcategory_for(field.as_ref());
            assert_eq!(
                sub,
                format!("EVTX-{id}"),
                "event_id {id} must map to EVTX-{id}, got {sub}"
            );
        }
    }

    #[test]
    fn sentinel_subcategory_falls_back_on_missing_event_id() {
        // Records without a parseable event_id fall back to the
        // legacy "Windows Event" string. This preserves the case-
        // output contract (a record without event_id shouldn't
        // vanish) while ensuring Sigma rules keyed on EVTX-<id>
        // naturally skip it.
        assert_eq!(evtx_subcategory_for(None), "Windows Event");
        let bad = Some("not-a-number".to_string());
        assert_eq!(evtx_subcategory_for(bad.as_ref()), "Windows Event");
        let empty = Some(String::new());
        assert_eq!(evtx_subcategory_for(empty.as_ref()), "Windows Event");
    }

    #[test]
    fn evtx_4624_logon_type_extracted() {
        let xml = r#"
<Event><System><EventID>4624</EventID><Computer>host</Computer></System>
<EventData><Data Name='TargetUserName'>alice</Data><Data Name='LogonType'>10</Data><Data Name='IpAddress'>10.0.0.5</Data></EventData></Event>
"#;
        let analytic = analytic_from_event_xml("Security", xml).expect("analytic");
        assert_eq!(analytic.event_id, 4624);
        assert_eq!(analytic.logon_type, Some(10));
        assert!(analytic.significance.contains("remote"));
        assert_eq!(analytic.source_ip.as_deref(), Some("10.0.0.5"));
    }

    #[test]
    fn evtx_1102_audit_cleared_is_critical() {
        let xml = r#"
<Event><System><EventID>1102</EventID><Computer>host</Computer></System><EventData></EventData></Event>
"#;
        let analytic = analytic_from_event_xml("Security", xml).expect("analytic");
        assert_eq!(analytic.forensic_value, ForensicValue::Critical);
        assert!(analytic
            .advisory_notice
            .as_deref()
            .unwrap_or("")
            .contains("anti-forensics"));
    }

    #[test]
    fn evtx_analytics_filter_to_high_value_ids_only() {
        let mut produced = 0;
        for id in 1..=110 {
            let xml = format!(
                "<Event><System><EventID>{id}</EventID><Computer>host</Computer></System></Event>"
            );
            if analytic_from_event_xml("Security", &xml).is_some() {
                produced += 1;
            }
        }
        assert_eq!(produced, 1, "only event 104 in 1..=110 is high-value");
        assert!(analytic_from_event_xml(
            "System",
            "<Event><System><EventID>7045</EventID><Computer>host</Computer></System></Event>",
        )
        .is_some());
    }

    #[test]
    fn sentinel_evt_extension_skipped_pending_evt_parser() {
        // Tripwire pinning the current `.evt` (legacy BinXML)
        // behaviour: the extension filter in run() skips non-evtx
        // files, so a `.evt` log that carries valid Windows Event
        // data is currently unreachable. Charlie + Jo both contain
        // `.evt` files (2009-era XP/Win7 evidence); the Sigma
        // inventory doc §1 documents this as a deliberate
        // out-of-scope gap for Sprint 2.
        //
        // When `.evt` parser support ships, this test must be
        // intentionally changed or deleted with a commit message
        // explicitly noting "legacy .evt parser shipped in
        // [commit]." The `_pending_evt_parser` suffix makes the
        // deferral discoverable.
        let tmp = tempfile::tempdir().expect("tempdir");
        // Synthetic .evt file that's decidedly not parseable as
        // EVTX — the point is just to confirm the extension
        // filter skips it before any parser attempt.
        let evt_path = tmp.path().join("System.evt");
        std::fs::write(&evt_path, b"\x30\x00\x00\x00LfLe synthetic legacy").expect("write");
        let p = SentinelPlugin::new();
        let ctx = PluginContext {
            root_path: tmp.path().to_string_lossy().to_string(),
            vfs: None,
            config: std::collections::HashMap::new(),
            prior_results: Vec::new(),
        };
        let artifacts = p.run(ctx).expect("run must succeed");
        assert!(
            artifacts.is_empty(),
            "Sentinel must currently skip .evt files (pending .evt parser sprint); \
             got {} artifacts",
            artifacts.len()
        );
    }

    #[test]
    fn execute_returns_well_formed_plugin_output_on_empty_evidence() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let p = SentinelPlugin::new();
        let ctx = PluginContext {
            root_path: tmp.path().to_string_lossy().to_string(),
            vfs: None,
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
