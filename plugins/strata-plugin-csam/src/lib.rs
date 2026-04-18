//! Strata CSAM Sentinel plugin.
//!
//! This is a thin shell that registers the CSAM scanner with the
//! unified plugin host so it appears in the Plugins panel alongside
//! the other Strata plugins. The actual scanning, hash-set import,
//! review/confirm/dismiss workflow, audit chain, and report generation
//! all live in the `strata-csam` crate and are surfaced via dedicated
//! `AppState` methods + a special-cased details pane in the Plugins
//! view (see `apps/tree/strata-tree/src/ui/plugins_view.rs`).
//!
//! ## Sentinel status
//!
//! `required_tier()` returns `PluginTier::Free`. This plugin is the
//! ONLY one in the workspace that is free on every license tier per
//! the v1.4.0 spec — child-safety work is non-negotiable and must be
//! available to every examiner regardless of license. **Do not change
//! this without explicit product approval.**
//!
//! ## Why `run()` is a no-op
//!
//! The standard plugin contract is "run on evidence and return a
//! `Vec<Artifact>`". CSAM doesn't fit that pattern: scanning is
//! interactive (examiner reviews each hit, confirms or dismisses,
//! generates a report on demand), hits are never auto-displayed,
//! and every state transition writes to the case audit chain. The
//! generic `run()` path would discard all of that.
//!
//! Instead, the CSAM plugin's run() returns a single informational
//! artifact directing examiners to the dedicated CSAM panel. The
//! actual workflow is driven by `AppState::csam_*` methods called
//! from the Plugins view's CSAM details pane.

use strata_plugin_sdk::{
    Artifact, PluginCapability, PluginContext, PluginResult, PluginTier, PluginType, StrataPlugin,
};

/// The plugin name string is the canonical identifier used by
/// `PluginHost::run_plugin`, by the Plugins panel selection state,
/// and by the audit log. **It must remain stable across versions**
/// — changing it would orphan existing audit entries that reference
/// it via `action_type` or `detail`.
pub const CSAM_PLUGIN_NAME: &str = "Strata CSAM Scanner";

pub struct CsamPlugin {
    name: String,
    version: String,
}

impl Default for CsamPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl CsamPlugin {
    pub fn new() -> Self {
        Self {
            name: CSAM_PLUGIN_NAME.to_string(),
            // Track the strata-csam crate version. Bump in lockstep
            // with crates/strata-csam/Cargo.toml.
            version: "0.1.0".to_string(),
        }
    }
}

impl StrataPlugin for CsamPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn supported_inputs(&self) -> Vec<String> {
        // CSAM scans every reachable file in the loaded EvidenceSource
        // (or just image extensions if scan_all_files = false). The
        // generic plugin "supported_inputs" string list doesn't
        // capture that — it's used by the host as an advisory hint.
        vec!["evidence".to_string(), "filesystem".to_string()]
    }

    fn plugin_type(&self) -> PluginType {
        // CSAM is conceptually an analyzer (it analyzes file hashes
        // against a known-bad database). There is no dedicated
        // "Sentinel" PluginType — sentinel status is captured by
        // `required_tier()`, not the type field.
        PluginType::Analyzer
    }

    fn capabilities(&self) -> Vec<PluginCapability> {
        // Closest existing capability — the CSAM scanner extracts
        // hash-match artefacts from media files. The capabilities
        // enum is used by the UI to colour-code plugin cards; it
        // doesn't affect runtime behaviour.
        vec![PluginCapability::ArtifactExtraction]
    }

    fn description(&self) -> &str {
        "Hash-based CSAM detection. Free on all license tiers. \
         Examiner-imported hash sets only. No image content is \
         ever auto-displayed."
    }

    /// Sentinel status: free on every license tier, no gating.
    fn required_tier(&self) -> PluginTier {
        PluginTier::Free
    }

    /// The standard plugin run path is a no-op for CSAM. Real CSAM
    /// scanning happens via dedicated `AppState::csam_*` methods
    /// invoked from the Plugins panel's CSAM details pane.
    ///
    /// We return one informational artefact rather than failing,
    /// so a "Run All Plugins" sweep doesn't error out — it just
    /// logs that CSAM was skipped and points the examiner to the
    /// dedicated workflow.
    fn run(&self, _ctx: PluginContext) -> PluginResult {
        let mut a = Artifact::new("CSAM Scanner", "strata-plugin-csam");
        a.add_field("title", "CSAM Scanner — open dedicated panel");
        a.add_field(
            "detail",
            "Open the Plugins view and select 'Strata CSAM Scanner' \
             to import hash sets and run a scan.",
        );
        Ok(vec![a])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csam_plugin_is_free_tier() {
        let p = CsamPlugin::new();
        assert_eq!(p.required_tier(), PluginTier::Free);
    }

    #[test]
    fn csam_plugin_name_is_stable() {
        // The name string is the canonical identifier in audit logs
        // and host registration — guard against accidental rename.
        assert_eq!(CsamPlugin::new().name(), "Strata CSAM Scanner");
        assert_eq!(CSAM_PLUGIN_NAME, "Strata CSAM Scanner");
    }

    #[test]
    fn csam_plugin_run_returns_no_op_artifact() {
        let p = CsamPlugin::new();
        let ctx = PluginContext {
            root_path: "/tmp".to_string(),
            vfs: None,
            config: std::collections::HashMap::new(),
            prior_results: vec![],
        };
        let result = p.run(ctx).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].category, "CSAM Scanner");
    }
}
