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
    /// Create a new Pulse plugin instance.
    pub fn new() -> Self {
        Self {
            name: "Strata Pulse".to_string(),
            version: "0.1.0".to_string(),
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
        Ok(Vec::new())
    }

    fn execute(&self, context: PluginContext) -> Result<PluginOutput, PluginError> {
        let start = std::time::Instant::now();
        let root = Path::new(&context.root_path);

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

        let category_count = categories.len();
        let categories_vec: Vec<String> = categories.into_iter().collect();

        let headline = format!(
            "Pulse: {} Android artifacts ({} suspicious) across {} categories",
            records.len(),
            suspicious_count,
            category_count
        );

        Ok(PluginOutput {
            plugin_name: self.name().to_string(),
            plugin_version: self.version().to_string(),
            executed_at: String::new(),
            duration_ms: start.elapsed().as_millis() as u64,
            artifacts: records.clone(),
            summary: PluginSummary {
                total_artifacts: records.len(),
                suspicious_count,
                categories_populated: categories_vec,
                headline,
            },
            warnings,
        })
    }
}

/// Convenience FFI export matching the pattern used by other plugins.
///
/// # Safety
///
/// Returns an opaque pointer to a heap-allocated boxed `StrataPlugin`
/// trait object. The caller becomes the owner of the allocation and
/// must eventually reclaim it with `Box::from_raw` on the matching
/// inner type (`Box<dyn StrataPlugin>`). Misuse will leak or corrupt
/// memory — hosts should route this through the Strata plugin loader.
#[no_mangle]
pub extern "C" fn create_plugin_pulse() -> *mut std::ffi::c_void {
    let plugin: Box<dyn StrataPlugin> = Box::new(PulsePlugin::new());
    Box::into_raw(Box::new(plugin)) as *mut std::ffi::c_void
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
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
    }
}
