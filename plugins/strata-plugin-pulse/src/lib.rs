<<<<<<< HEAD
//! Strata Pulse — Android / mobile artifact parsers.
//!
//! Pulse is the Android counterpart to strata-plugin-phantom (Windows
//! Registry) and strata-plugin-mactrace (macOS). It ports ALEAPP-style
//! SQLite / XML schema parsers into native Rust so examiners can pull
//! court-ready records out of a mounted Android extraction without
//! leaving Strata.
//!
//! ## Design
//!
//! Each parser lives in `android::<artifact>` and exposes a single
//! `parse(path: &Path) -> Vec<ArtifactRecord>` entry point that takes
//! the on-disk path of one target file (a SQLite database, XML file,
//! or protobuf). The top-level plugin (`PulsePlugin`) walks the
//! evidence root (supplied via `PluginContext::root_path`), matches
//! candidate files against each parser's path glob, and dispatches.
//!
//! ## Why this layout
//!
//! Keeping parsers as pure `(&Path) -> Vec<ArtifactRecord>` functions
//! makes every one of them independently unit-testable with an
//! in-process `tempfile::NamedTempFile` SQLite database. The plugin's
//! filesystem walk is separately testable and never has to be mocked.

use std::path::Path;
use strata_plugin_sdk::{
    ArtifactRecord, PluginCapability, PluginContext, PluginError, PluginOutput, PluginSummary,
    PluginType, StrataPlugin,
};

pub mod android;

/// The Pulse plugin — dispatches Android parsers across an evidence tree.
=======
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

>>>>>>> agent2/main
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
<<<<<<< HEAD
    /// Create a new Pulse plugin instance.
    pub fn new() -> Self {
        Self {
            name: "Strata Pulse".to_string(),
            version: "0.1.0".to_string(),
=======
    pub fn new() -> Self {
        Self {
            name: "Strata Pulse".to_string(),
            version: "1.0.0".to_string(),
>>>>>>> agent2/main
        }
    }
}

impl StrataPlugin for PulsePlugin {
    fn name(&self) -> &str {
        &self.name
    }
<<<<<<< HEAD

    fn version(&self) -> &str {
        &self.version
    }

    fn supported_inputs(&self) -> Vec<String> {
        vec![
            "android".to_string(),
            "directory".to_string(),
            "*.db".to_string(),
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
        "Android artifact extraction — SMS, calls, accounts, browser, app usage, and more"
    }

    fn run(&self, _ctx: PluginContext) -> strata_plugin_sdk::PluginResult {
        // Pulse returns rich ArtifactRecords directly via execute(); the
        // legacy Artifact-based run() is unused. Returning an empty vec
        // keeps the plugin loadable by hosts that still call run().
=======
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
>>>>>>> agent2/main
        Ok(Vec::new())
    }

    fn execute(&self, context: PluginContext) -> Result<PluginOutput, PluginError> {
        let start = std::time::Instant::now();
        let root = Path::new(&context.root_path);

<<<<<<< HEAD
        let mut records: Vec<ArtifactRecord> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();

        let paths = android::walker::walk(root);

        for candidate in &paths {
            for parser in android::ALL_PARSERS {
                if parser.matches(candidate) {
                    let parsed = (parser.run)(candidate);
                    records.extend(parsed);
                }
            }
        }

        let suspicious_count = records.iter().filter(|r| r.is_suspicious).count();
        let mut categories: Vec<String> = records
            .iter()
            .map(|r| r.category.as_str().to_string())
            .collect();
        categories.sort();
        categories.dedup();

        if records.is_empty() {
            warnings.push("No Android artifacts detected under evidence root".to_string());
        }

        let headline = format!(
            "Pulse: {} Android artifacts ({} suspicious) across {} categories",
            records.len(),
            suspicious_count,
            categories.len()
        );
=======
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
>>>>>>> agent2/main

        Ok(PluginOutput {
            plugin_name: self.name().to_string(),
            plugin_version: self.version().to_string(),
<<<<<<< HEAD
            executed_at: String::new(),
            duration_ms: start.elapsed().as_millis() as u64,
            artifacts: records.clone(),
            summary: PluginSummary {
                total_artifacts: records.len(),
                suspicious_count,
                categories_populated: categories,
                headline,
            },
            warnings,
=======
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
>>>>>>> agent2/main
        })
    }
}

<<<<<<< HEAD
/// Convenience FFI export matching the pattern used by other plugins.
///
/// # Safety
///
/// Returns an opaque pointer to a heap-allocated boxed `StrataPlugin`
/// trait object. The caller becomes the owner of the allocation and
/// must eventually reclaim it with `Box::from_raw` on the matching
/// inner type (`Box<dyn StrataPlugin>`). Misuse will leak or corrupt
/// memory — hosts should route this through the Strata plugin loader.
=======
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

>>>>>>> agent2/main
#[no_mangle]
pub extern "C" fn create_plugin_pulse() -> *mut std::ffi::c_void {
    let plugin: Box<dyn StrataPlugin> = Box::new(PulsePlugin::new());
    Box::into_raw(Box::new(plugin)) as *mut std::ffi::c_void
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
<<<<<<< HEAD
    fn plugin_metadata_is_populated() {
        let p = PulsePlugin::new();
        assert_eq!(p.name(), "Strata Pulse");
        assert_eq!(p.version(), "0.1.0");
        assert!(matches!(p.plugin_type(), PluginType::Analyzer));
        assert!(!p.capabilities().is_empty());
        assert!(!p.description().is_empty());
    }

    #[test]
    fn run_on_empty_root_returns_empty_output() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let ctx = PluginContext {
            root_path: tmp.path().to_string_lossy().into_owned(),
            config: Default::default(),
            prior_results: Vec::new(),
        };
        let out = PulsePlugin::new().execute(ctx).expect("execute");
        assert_eq!(out.summary.total_artifacts, 0);
        assert_eq!(out.artifacts.len(), 0);
        assert!(!out.warnings.is_empty());
    }

    #[test]
    fn legacy_run_returns_empty_ok() {
        let ctx = PluginContext {
            root_path: ".".to_string(),
            config: Default::default(),
            prior_results: Vec::new(),
        };
        let r = PulsePlugin::new().run(ctx).expect("run");
        assert!(r.is_empty());
    }

    #[test]
    fn expected_category_list_is_exposed() {
        // Quick guard that the ArtifactCategory enum is usable from here.
        let c = strata_plugin_sdk::ArtifactCategory::Communications;
        assert!(!c.as_str().is_empty());
=======
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
>>>>>>> agent2/main
    }
}
