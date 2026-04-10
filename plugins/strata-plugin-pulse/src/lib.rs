//! # Pulse — iOS artifact plugin
//!
//! Pulse is Strata's iOS-focused artifact plugin, modelled after the Android
//! Logs Events And Protobuf Parser (ALEAPP) and its iOS sibling iLEAPP. Each
//! `ios::*` module implements one artifact family and owns its own path
//! matcher, parser, and unit tests.
//!
//! New parsers should:
//!   1. Expose `pub fn matches(path: &Path) -> bool` — cheap, filename/path
//!      based; never opens the file.
//!   2. Expose `pub fn parse(path: &Path) -> Vec<ArtifactRecord>` — opens the
//!      database read-only through [`ios::util::open_sqlite_ro`] and produces
//!      zero or more [`ArtifactRecord`]s.
//!   3. Carry a minimum of three unit tests in a `#[cfg(test)] mod tests`
//!      block per CLAUDE.md, covering the happy path, empty/missing tables,
//!      and any timestamp conversion edge cases.
//!
//! The plugin dispatches every file under `PluginContext::root_path` through
//! every registered parser — each parser's `matches()` acts as the gate.

use std::path::{Path, PathBuf};

use strata_plugin_sdk::{
    ArtifactRecord, PluginCapability, PluginContext, PluginError, PluginOutput, PluginResult,
    PluginSummary, PluginType, StrataPlugin,
};

pub mod ios;

pub struct PulsePlugin {
    name: String,
    version: String,
}

impl Default for PulsePlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl PulsePlugin {
    pub fn new() -> Self {
        Self {
            name: "Strata Pulse".to_string(),
            version: "1.0.0".to_string(),
        }
    }
}

impl StrataPlugin for PulsePlugin {
    fn name(&self) -> &str {
        &self.name
    }
    fn version(&self) -> &str {
        &self.version
    }
    fn supported_inputs(&self) -> Vec<String> {
        vec![
            "db".to_string(),
            "sqlite".to_string(),
            "sqlitedb".to_string(),
            "storedata".to_string(),
            "plist".to_string(),
            "log".to_string(),
        ]
    }
    fn plugin_type(&self) -> PluginType {
        PluginType::Analyzer
    }
    fn capabilities(&self) -> Vec<PluginCapability> {
        vec![PluginCapability::ArtifactExtraction]
    }
    fn description(&self) -> &str {
        "iOS artifact parsing: KnowledgeC, SMS, CallHistory, Contacts, Safari, Photos, Health, Location, AppInstall, Notes, Notifications, ScreenTime, Wi-Fi, Calendar, Voicemail, Reminders, Wallet, Maps, Keyboard cache, App groups, Accounts"
    }

    fn run(&self, _ctx: PluginContext) -> PluginResult {
        // Pulse emits ArtifactRecords directly via `execute()`, so the
        // legacy `run()` path is intentionally empty. The engine-adapter
        // calls `execute()` for every plugin, and the StrataPlugin
        // default `run()` → `execute()` fallback would return Artifact
        // shells without iOS-specific categories.
        Ok(Vec::new())
    }

    fn execute(&self, context: PluginContext) -> Result<PluginOutput, PluginError> {
        let start = std::time::Instant::now();
        let root = Path::new(&context.root_path);

        let files = walk_dir(root).unwrap_or_default();
        let mut records: Vec<ArtifactRecord> = Vec::new();
        for path in &files {
            records.extend(ios::dispatch(path));
        }

        let suspicious = records.iter().filter(|r| r.is_suspicious).count();
        let mut cats: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for r in &records {
            cats.insert(r.category.as_str().to_string());
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
                suspicious_count: suspicious,
                categories_populated: cats.into_iter().collect(),
                headline: format!(
                    "Pulse: {} iOS artifacts ({} suspicious)",
                    total, suspicious
                ),
            },
            warnings: vec![],
        })
    }
}

fn walk_dir(dir: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut out = Vec::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let p = entry.path();
            if p.is_dir() {
                if let Ok(sub) = walk_dir(&p) {
                    out.extend(sub);
                }
            } else {
                out.push(p);
            }
        }
    }
    Ok(out)
}

#[no_mangle]
pub extern "C" fn create_plugin_pulse() -> *mut std::ffi::c_void {
    let plugin: Box<dyn StrataPlugin> = Box::new(PulsePlugin::new());
    Box::into_raw(Box::new(plugin)) as *mut std::ffi::c_void
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_identity_is_stable() {
        let p = PulsePlugin::new();
        assert_eq!(p.name(), "Strata Pulse");
        assert_eq!(p.version(), "1.0.0");
    }

    #[test]
    fn execute_returns_empty_output_for_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let p = PulsePlugin::new();
        let ctx = PluginContext {
            root_path: tmp.path().to_string_lossy().to_string(),
            config: std::collections::HashMap::new(),
            prior_results: vec![],
        };
        let out = p.execute(ctx).unwrap();
        assert_eq!(out.summary.total_artifacts, 0);
        assert_eq!(out.summary.suspicious_count, 0);
    }

    #[test]
    fn supported_inputs_include_common_ios_extensions() {
        let p = PulsePlugin::new();
        let ext = p.supported_inputs();
        assert!(ext.iter().any(|e| e == "db"));
        assert!(ext.iter().any(|e| e == "sqlitedb"));
        assert!(ext.iter().any(|e| e == "plist"));
    }
}
