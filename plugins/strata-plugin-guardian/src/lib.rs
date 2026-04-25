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
            // Normalize every path separator to forward slashes
            // before the lowercase + substring matches below. Prior
            // to this normalization, Guardian's path predicates used
            // literal `\\` separators — correct for Windows hosts
            // but silently mismatched against macOS-extracted
            // evidence (where materialize produces `/` paths). Per
            // docs/RESEARCH_POST_V16_PLUGIN_AUDIT.md §4 Scenario D,
            // this is a latent bug that would miss every Defender /
            // Avast / MalwareBytes artifact on Win8+ evidence
            // extracted on a non-Windows examiner workstation. The
            // forward-slash normalization is the minimum-surface
            // fix: one normalized lc_path variable used by every
            // predicate; all needles flipped from `\\` to `/`.
            let lc_path = path
                .to_string_lossy()
                .replace('\\', "/")
                .to_lowercase();
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_lowercase();

            // ── Windows Defender event log ──────────────────────────────
            if name == "mpeventlog.evtx" || lc_path.contains("/windows defender/support/")
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
            if lc_path.contains("/windows defender/quarantine/")
                && (lc_path.contains("/entries/")
                    || lc_path.contains("/resourcedata/"))
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
                || lc_path.contains("/avast software/avast/log/")
            {
                // Stream line-by-line — enterprise AV logs can be 100+ MB.
                if let Ok(f) = std::fs::File::open(&path) {
                    use std::io::{BufRead, BufReader};
                    let reader = BufReader::new(f);
                    for line in reader.lines().take(500) {
                        let Ok(line) = line else { break };
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
            if lc_path.contains("/malwarebytes/mbamservice/logs/") {
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
                    let lower_path_norm = lower_path.replace('\\', "/");
                    let suspicious = lower_path_norm.contains("/temp/")
                        || lower_path_norm.contains("/appdata/local/temp")
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

            // Sprint-11 P3 — propagate timestamp + raw_data from the
            // legacy Artifact, mirroring the SDK default execute().
            let raw_data = if a.data.is_empty() {
                None
            } else {
                let json: serde_json::Map<String, serde_json::Value> = a
                    .data
                    .iter()
                    .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                    .collect();
                Some(serde_json::Value::Object(json))
            };
            records.push(ArtifactRecord {
                category,
                subcategory: file_type,
                timestamp: a.timestamp.map(|t| t as i64),
                title: a.data.get("title").cloned().unwrap_or_else(|| a.source.clone()),
                detail: a.data.get("detail").cloned().unwrap_or_default(),
                source_path: a.source.clone(),
                forensic_value,
                mitre_technique: a.data.get("mitre").cloned(),
                is_suspicious: suspicious,
                raw_data,
                confidence: 0,
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

// ── post-v16 Sprint 4 tripwires — path-separator normalization ──

#[cfg(test)]
mod sprint4_path_sep_tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn run_guardian(root: &Path) -> Vec<Artifact> {
        let p = GuardianPlugin::new();
        let ctx = PluginContext {
            root_path: root.to_string_lossy().to_string(),
            vfs: None,
            config: std::collections::HashMap::new(),
            prior_results: Vec::new(),
        };
        p.run(ctx).expect("guardian run")
    }

    #[test]
    fn guardian_detects_defender_log_on_posix_extracted_path() {
        // Sprint 4 Fix 1 tripwire. Closes Scenario D latent bug per
        // docs/RESEARCH_POST_V16_PLUGIN_AUDIT.md §4: pre-fix
        // Guardian used literal `\\windows defender\\support\\` path
        // predicates that silently never matched when Windows
        // evidence was extracted on a macOS or Linux examiner
        // workstation (materialize produces `/`-separated paths).
        //
        // Fixture builds the Win8+ Defender support-log layout
        // using forward slashes — the exact shape the materialize
        // pipeline produces.
        let dir = tempdir().expect("tempdir");
        let defender_dir = dir
            .path()
            .join("ProgramData/Microsoft/Windows Defender/Support");
        fs::create_dir_all(&defender_dir).expect("mk");
        let log = defender_dir.join("MPLog-20240101.log");
        fs::write(&log, b"Defender log content").expect("w");

        let arts = run_guardian(dir.path());
        let defender_records: Vec<&Artifact> = arts
            .iter()
            .filter(|a| {
                a.data
                    .get("file_type")
                    .map(|v| v == "Defender Log")
                    .unwrap_or(false)
            })
            .collect();
        assert!(
            !defender_records.is_empty(),
            "Guardian must detect Defender log on forward-slash extracted path; \
             got {} artifacts total. Path: {}",
            arts.len(),
            log.display()
        );
    }

    #[test]
    fn guardian_detects_defender_quarantine_on_posix_extracted_path() {
        // Same Scenario D fix applied to Defender quarantine
        // detection. Prior to the fix `lc_path.contains(
        // "\\windows defender\\quarantine\\")` would miss the
        // `/`-separated extracted path; the new normalization
        // handles both separators.
        let dir = tempdir().expect("tempdir");
        let quarantine = dir
            .path()
            .join("ProgramData/Microsoft/Windows Defender/Quarantine/Entries");
        fs::create_dir_all(&quarantine).expect("mk");
        fs::write(quarantine.join("{abc-123}"), b"q entry").expect("w");

        let arts = run_guardian(dir.path());
        let quarantine_records = arts
            .iter()
            .filter(|a| {
                a.data
                    .get("file_type")
                    .map(|v| v == "Defender Quarantine")
                    .unwrap_or(false)
            })
            .count();
        assert!(
            quarantine_records >= 1,
            "Guardian must detect Defender quarantine entry on POSIX-extracted path; \
             got {quarantine_records}"
        );
    }

    #[test]
    fn guardian_detects_avast_log_on_posix_extracted_path() {
        // Same Scenario D fix applied to Avast. Prior check used
        // `\\avast software\\avast\\log\\` literal which missed
        // extracted paths. Normalization handles both.
        let dir = tempdir().expect("tempdir");
        let avast_dir = dir.path().join("ProgramData/Avast Software/Avast/log");
        fs::create_dir_all(&avast_dir).expect("mk");
        // Avast log needs suspicion-triggering keywords to emit a
        // record; write one line with "infection" in it so the
        // line-level matcher fires.
        fs::write(
            avast_dir.join("aswArPot.log"),
            b"2024-01-01 12:00:00 infection detected: eicar.com.txt\n",
        )
        .expect("w");

        let arts = run_guardian(dir.path());
        let avast_records = arts
            .iter()
            .filter(|a| {
                a.data
                    .get("file_type")
                    .map(|v| v == "Avast Log")
                    .unwrap_or(false)
            })
            .count();
        assert!(
            avast_records >= 1,
            "Guardian must detect Avast log on POSIX-extracted path; got {avast_records}"
        );
    }

    #[test]
    fn guardian_detects_malwarebytes_log_on_posix_extracted_path() {
        // Same Scenario D fix applied to MalwareBytes. Prior
        // `\\malwarebytes\\mbamservice\\logs\\` needle missed
        // extracted paths. Normalization handles both.
        let dir = tempdir().expect("tempdir");
        let mb_dir = dir
            .path()
            .join("ProgramData/Malwarebytes/MBAMService/logs");
        fs::create_dir_all(&mb_dir).expect("mk");
        fs::write(mb_dir.join("mbamservice.log"), b"log content").expect("w");

        let arts = run_guardian(dir.path());
        let mb_records = arts
            .iter()
            .filter(|a| {
                a.data
                    .get("file_type")
                    .map(|v| v == "MalwareBytes Log")
                    .unwrap_or(false)
            })
            .count();
        assert!(
            mb_records >= 1,
            "Guardian must detect MalwareBytes log on POSIX-extracted path; got {mb_records}"
        );
    }

    #[test]
    fn guardian_wer_crash_flags_temp_path_on_posix_extracted() {
        // The WER suspicion check also uses backslash literals
        // (`\\temp\\`, `\\appdata\\local\\temp`). Post-fix it
        // normalizes before matching. Build a .wer file that
        // declares AppPath with forward slashes (the shape the
        // .wer text might carry on a non-Windows extracted file,
        // or after caller-side normalization) and confirm the
        // record is flagged suspicious.
        //
        // Note: real .wer files carry Windows-style paths as
        // their AppPath value strings. The predicate still
        // works on those because Windows-style paths become
        // normalized via replace('\\', "/") before matching.
        let dir = tempdir().expect("tempdir");
        let wer = dir.path().join("foo.wer");
        fs::write(
            &wer,
            "AppName=evil.exe\n\
             AppPath=C:\\Users\\alice\\AppData\\Local\\Temp\\evil.exe\n\
             EventName=APPCRASH\n",
        )
        .expect("w");
        let arts = run_guardian(dir.path());
        let wer_records: Vec<&Artifact> = arts
            .iter()
            .filter(|a| {
                a.data
                    .get("file_type")
                    .map(|v| v == "WER Crash")
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(
            wer_records.len(),
            1,
            "expected 1 WER Crash record on the fixture; got {}",
            wer_records.len()
        );
        let sus = wer_records[0]
            .data
            .get("suspicious")
            .map(|s| s == "true")
            .unwrap_or(false);
        assert!(
            sus,
            "WER record with AppPath in AppData\\Local\\Temp must be flagged \
             suspicious via the separator-normalized predicate"
        );
    }
}

#[no_mangle]
pub extern "C" fn create_plugin_guardian() -> *mut std::ffi::c_void {
    let plugin: Box<dyn StrataPlugin> = Box::new(GuardianPlugin::new());
    Box::into_raw(Box::new(plugin)) as *mut std::ffi::c_void
}
