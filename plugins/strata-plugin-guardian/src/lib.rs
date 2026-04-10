//! # Guardian — Antivirus + System Health Intelligence
//!
//! Guardian owns AV detection logs, quarantine entries, Windows Error Reporting
//! (WER) crash dumps, and Reliability Monitor data. It is the plugin that
//! proves "this malware was here even if it's been cleaned up since".
//!
//! Sources:
//!   * Windows Defender:
//!     %ProgramData%\Microsoft\Windows Defender\Support\MpEventLog.evtx
//!     %ProgramData%\Microsoft\Windows Defender\Quarantine\
//!   * Avast logs:
//!     %ProgramData%\Avast Software\Avast\Log\aswAr*.log
//!     %ProgramData%\Avast Software\Avast\Chest\index.xml
//!   * MalwareBytes:
//!     %ProgramData%\Malwarebytes\MBAMService\logs\
//!   * Windows Error Reporting:
//!     %ProgramData%\Microsoft\Windows\WER\ReportArchive\
//!     *.wer files (key=value plaintext format)
//!
//! v1.0 implementation: filename detection + plaintext log scraping. Full EVTX
//! and binary quarantine parsing is wired through the EVTX layer in v0.6.0+.

use std::path::{Path, PathBuf};

use strata_plugin_sdk::{
    Artifact, ArtifactCategory, ArtifactRecord, ForensicValue, PluginCapability, PluginContext,
    PluginError, PluginOutput, PluginResult, PluginSummary, PluginType, StrataPlugin,
};

pub struct GuardianPlugin {
    name: String,
    version: String,
}

impl Default for GuardianPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl GuardianPlugin {
    pub fn new() -> Self {
        Self {
            name: "Strata Guardian".to_string(),
            version: "1.0.0".to_string(),
        }
    }
}

impl StrataPlugin for GuardianPlugin {
    fn name(&self) -> &str {
        &self.name
    }
    fn version(&self) -> &str {
        &self.version
    }
    fn supported_inputs(&self) -> Vec<String> {
        vec![
            "MpEventLog.evtx".to_string(),
            "wer".to_string(),
            "log".to_string(),
            "xml".to_string(),
        ]
    }
    fn plugin_type(&self) -> PluginType {
        PluginType::Analyzer
    }
    fn capabilities(&self) -> Vec<PluginCapability> {
        vec![PluginCapability::ArtifactExtraction]
    }
    fn description(&self) -> &str {
        "Antivirus + System Health: Defender / Avast / MalwareBytes / WER / Reliability"
    }

    fn run(&self, ctx: PluginContext) -> PluginResult {
        let root = Path::new(&ctx.root_path);
        let mut out = Vec::new();
        let files = match walk_dir(root) {
            Ok(f) => f,
            Err(_) => return Ok(out),
        };

        for path in files {
            let lc_path = path.to_string_lossy().to_lowercase();
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_lowercase();

            // ── Windows Defender event log ──────────────────────────────
            if name == "mpeventlog.evtx" || lc_path.contains("\\windows defender\\support\\")
            {
                let mut a = Artifact::new("Defender Log", &path.to_string_lossy());
                a.add_field("title", "Windows Defender event log present");
                a.add_field(
                    "detail",
                    "Parse via EVTX layer for detection events (1116/1117/5001/5007)",
                );
                a.add_field("file_type", "Defender Log");
                a.add_field("forensic_value", "High");
                a.add_field("mitre", "T1562.001");
                out.push(a);
                continue;
            }

            // ── Defender quarantine directory ──────────────────────────
            if lc_path.contains("\\windows defender\\quarantine\\")
                && (lc_path.contains("\\entries\\")
                    || lc_path.contains("\\resourcedata\\"))
            {
                let mut a = Artifact::new("Defender Quarantine", &path.to_string_lossy());
                a.add_field("title", "Defender quarantined item");
                a.add_field(
                    "detail",
                    "File quarantined by Windows Defender (binary, encrypted)",
                );
                a.add_field("file_type", "Defender Quarantine");
                a.add_field("forensic_value", "Critical");
                a.add_field("suspicious", "true");
                a.add_field("mitre", "T1027");
                out.push(a);
                continue;
            }

            // ── Avast log ──────────────────────────────────────────────
            if name.starts_with("aswar") && name.ends_with(".log")
                || lc_path.contains("\\avast software\\avast\\log\\")
            {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    for line in content.lines().take(500) {
                        let lower = line.to_lowercase();
                        if lower.contains("infection")
                            || lower.contains("threat")
                            || lower.contains("quarantine")
                            || lower.contains("removed")
                        {
                            let mut a = Artifact::new("Avast Log", &path.to_string_lossy());
                            a.add_field("title", "Avast detection");
                            a.add_field(
                                "detail",
                                &line.chars().take(240).collect::<String>(),
                            );
                            a.add_field("file_type", "Avast Log");
                            a.add_field("forensic_value", "High");
                            a.add_field("suspicious", "true");
                            out.push(a);
                        }
                    }
                }
                continue;
            }

            // ── MalwareBytes log ───────────────────────────────────────
            if lc_path.contains("\\malwarebytes\\mbamservice\\logs\\") {
                let mut a = Artifact::new("MalwareBytes Log", &path.to_string_lossy());
                a.add_field("title", "MalwareBytes log present");
                a.add_field(
                    "detail",
                    "Inspect for detection records (binary or text format depending on version)",
                );
                a.add_field("file_type", "MalwareBytes Log");
                a.add_field("forensic_value", "High");
                out.push(a);
                continue;
            }

            // ── Windows Error Reporting (.wer) ─────────────────────────
            if name.ends_with(".wer") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    let mut app_name = String::new();
                    let mut app_path = String::new();
                    let mut event_name = String::new();
                    for line in content.lines() {
                        if let Some((k, v)) = line.split_once('=') {
                            match k {
                                "AppName" => app_name = v.to_string(),
                                "AppPath" => app_path = v.to_string(),
                                "EventName" => event_name = v.to_string(),
                                _ => {}
                            }
                        }
                    }
                    let lower_path = app_path.to_lowercase();
                    let suspicious = lower_path.contains("\\temp\\")
                        || lower_path.contains("\\appdata\\local\\temp")
                        || event_name.to_lowercase().contains("appcrash");
                    let mut a = Artifact::new("WER Crash", &path.to_string_lossy());
                    a.add_field(
                        "title",
                        &format!(
                            "WER: {} ({})",
                            if app_name.is_empty() { "(unknown)" } else { &app_name },
                            event_name
                        ),
                    );
                    a.add_field("detail", &format!("Path: {}", app_path));
                    a.add_field("file_type", "WER Crash");
                    if suspicious {
                        a.add_field("forensic_value", "High");
                        a.add_field("suspicious", "true");
                    } else {
                        a.add_field("forensic_value", "Medium");
                    }
                    out.push(a);
                }
                continue;
            }
        }

        Ok(out)
    }

    fn execute(&self, context: PluginContext) -> Result<PluginOutput, PluginError> {
        let start = std::time::Instant::now();
        let artifacts = self.run(context)?;

        let mut records = Vec::new();
        let mut categories: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut suspicious_count = 0usize;

        for a in &artifacts {
            let file_type = a.data.get("file_type").cloned().unwrap_or_default();
            let suspicious = a.data.get("suspicious").map(|s| s == "true").unwrap_or(false);
            if suspicious {
                suspicious_count += 1;
            }
            let category = ArtifactCategory::SystemActivity;
            categories.insert(category.as_str().to_string());

            let fv_str = a.data.get("forensic_value").cloned().unwrap_or_default();
            let forensic_value = match fv_str.as_str() {
                "Critical" => ForensicValue::Critical,
                "High" => ForensicValue::High,
                _ => {
                    if suspicious {
                        ForensicValue::High
                    } else {
                        ForensicValue::Medium
                    }
                }
            };

            records.push(ArtifactRecord {
                category,
                subcategory: file_type,
                timestamp: None,
                title: a.data.get("title").cloned().unwrap_or_else(|| a.source.clone()),
                detail: a.data.get("detail").cloned().unwrap_or_default(),
                source_path: a.source.clone(),
                forensic_value,
                mitre_technique: a.data.get("mitre").cloned(),
                is_suspicious: suspicious,
                raw_data: None,
            });
        }

        let total = records.len();
        Ok(PluginOutput {
            plugin_name: self.name().to_string(),
            plugin_version: self.version().to_string(),
            executed_at: chrono::Utc::now().to_rfc3339(),
            duration_ms: start.elapsed().as_millis() as u64,
            artifacts: records,
            summary: PluginSummary {
                total_artifacts: total,
                suspicious_count,
                categories_populated: categories.into_iter().collect(),
                headline: format!(
                    "Guardian: {} AV/health artifacts ({} flagged)",
                    total, suspicious_count
                ),
            },
            warnings: vec![],
        })
    }
}

fn walk_dir(dir: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut paths = Vec::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let p = entry.path();
            if p.is_dir() {
                if let Ok(sub) = walk_dir(&p) {
                    paths.extend(sub);
                }
            } else {
                paths.push(p);
            }
        }
    }
    Ok(paths)
}

#[no_mangle]
pub extern "C" fn create_plugin_guardian() -> *mut std::ffi::c_void {
    let plugin: Box<dyn StrataPlugin> = Box::new(GuardianPlugin::new());
    Box::into_raw(Box::new(plugin)) as *mut std::ffi::c_void
}
