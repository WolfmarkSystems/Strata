//! # Pulse — iOS and Android artifact plugin
//!
//! Pulse is Strata's mobile artifact plugin, covering both Android (ALEAPP-style)
//! and iOS (iLEAPP-style) artifact families. Each `android::*` and `ios::*` module
//! implements one artifact family and owns its own path matcher, parser, and tests.
//!
//! New parsers should:
//!   1. Expose `pub fn matches(path: &Path) -> bool` — cheap, filename/path
//!      based; never opens the file.
//!   2. Expose `pub fn parse(path: &Path) -> Vec<ArtifactRecord>` — opens the
//!      database read-only and produces zero or more [`ArtifactRecord`]s.
//!   3. Carry a minimum of three unit tests per CLAUDE.md.

use std::path::{Path, PathBuf};

use strata_plugin_sdk::{
    ArtifactRecord, PluginCapability, PluginContext, PluginError, PluginOutput, PluginResult,
    PluginSummary, PluginType, StrataPlugin,
};

pub mod android;
pub mod chat_forensics;
pub mod electron_scanner;
pub mod gaming;
pub mod ios;
pub mod messaging_extended;
pub mod telegram;
pub mod whatsapp;

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
            "android".to_string(),
            "db".to_string(),
            "sqlite".to_string(),
            "sqlitedb".to_string(),
            "storedata".to_string(),
            "plist".to_string(),
            "log".to_string(),
            "*.xml".to_string(),
        ]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Analyzer
    }

    fn capabilities(&self) -> Vec<PluginCapability> {
        vec![
            PluginCapability::ArtifactExtraction,
            PluginCapability::TimelineEnrichment,
            PluginCapability::ExecutionTracking,
            PluginCapability::NetworkArtifacts,
            PluginCapability::CredentialExtraction,
        ]
    }

    fn description(&self) -> &str {
        "iOS and Android artifact extraction — SMS, calls, contacts, browser, \
         app usage, KnowledgeC, Safari, Photos, Health, Location, WhatsApp, \
         Signal, Telegram, Discord, Snapchat, and more"
    }

    fn run(&self, _ctx: PluginContext) -> PluginResult {
        // Pulse emits ArtifactRecords directly via execute().
        // Legacy run() path is intentionally empty.
        Ok(Vec::new())
    }

    fn execute(&self, context: PluginContext) -> Result<PluginOutput, PluginError> {
        let start = std::time::Instant::now();
        let root = Path::new(&context.root_path);

        let mut records: Vec<ArtifactRecord> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();

        // Android parsers — walk via android walker
        let android_paths = android::walker::walk(root);
        for candidate in &android_paths {
            for parser in android::ALL_PARSERS {
                if parser.matches(candidate) {
                    records.extend((parser.run)(candidate));
                }
            }
        }

        // iOS parsers — walk all files and dispatch
        let all_files = walk_dir(root).unwrap_or_default();
        for path in &all_files {
            records.extend(ios::dispatch(path));
        }

        if records.is_empty() {
            warnings.push(
                "No mobile artifacts detected under evidence root".to_string()
            );
        }

        let suspicious_count = records.iter().filter(|r| r.is_suspicious).count();
        let mut categories: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for r in &records {
            categories.insert(r.category.as_str().to_string());
        }
        let total = records.len();
        let category_count = categories.len();

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
                    "Pulse: {} mobile artifacts ({} suspicious) across {} categories",
                    total,
                    suspicious_count,
                    category_count
                ),
            },
            warnings,
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
        assert!(matches!(p.plugin_type(), PluginType::Analyzer));
        assert!(!p.capabilities().is_empty());
        assert!(!p.description().is_empty());
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
    fn legacy_run_returns_empty_ok() {
        let ctx = PluginContext {
            root_path: ".".to_string(),
            config: std::collections::HashMap::new(),
            prior_results: vec![],
        };
        let r = PulsePlugin::new().run(ctx).expect("run");
        assert!(r.is_empty());
    }

    #[test]
    fn supported_inputs_include_android_and_ios_types() {
        let p = PulsePlugin::new();
        let ext = p.supported_inputs();
        assert!(ext.iter().any(|e| e == "android"));
        assert!(ext.iter().any(|e| e == "db"));
        assert!(ext.iter().any(|e| e == "plist"));
    }
}
