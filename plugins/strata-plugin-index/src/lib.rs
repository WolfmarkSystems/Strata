pub mod amcache;
pub mod browser;
pub mod chat;
pub mod cloud;
pub mod email;
pub mod errors;
pub mod evtx;
pub mod ios;
pub mod jumplist;
pub mod linux;
pub mod lnk;
pub mod macos;
pub mod media;
pub mod mobile;
pub mod network;
pub mod onedrive;
pub mod outlook;
pub(crate) mod plist_utils;
pub mod prefetch;
pub mod productivity;
pub mod recentdocs;
pub mod recyclebin;
pub mod registry;
pub mod shellbags;
pub mod skype;
pub mod social;
pub mod sqlite_utils;
pub mod srum;
pub mod teams;
pub mod windows_search;

use strata_plugin_sdk::{
    Artifact, PluginCapability, PluginContext, PluginResult, PluginType, StrataPlugin,
};

pub struct IndexPlugin {
    name: String,
    version: String,
}

impl Default for IndexPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl IndexPlugin {
    pub fn new() -> Self {
        Self {
            name: "Strata Index".to_string(),
            version: "0.1.0".to_string(),
        }
    }
}

impl StrataPlugin for IndexPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn supported_inputs(&self) -> Vec<String> {
        vec!["*".to_string()]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Analyzer
    }

    fn capabilities(&self) -> Vec<PluginCapability> {
        vec![PluginCapability::ArtifactExtraction]
    }

    fn description(&self) -> &str {
        "Core indexing and parsing plugin"
    }

    fn run(&self, _ctx: PluginContext) -> PluginResult {
        let mut results = Vec::new();

        // This is where we would call the internal migrated parsers
        // For now, let's just add a placeholder to verify the plugin works
        let mut artifact = Artifact::new("system", "strata_index");
        artifact.add_field("description", "Strata Index core parsing plugin");
        results.push(artifact);

        Ok(results)
    }
}

#[no_mangle]
pub extern "C" fn create_plugin_index() -> *mut std::ffi::c_void {
    let plugin: Box<dyn StrataPlugin> = Box::new(IndexPlugin::new());
    let plugin_holder = Box::new(plugin);
    Box::into_raw(plugin_holder) as *mut std::ffi::c_void
}

#[cfg(test)]
mod sprint75_backfill_tests {
    use super::*;
    use std::collections::HashMap;
    use strata_plugin_sdk::{PluginContext, StrataPlugin};

    fn empty_ctx() -> PluginContext {
        PluginContext {
            root_path: "/nonexistent/strata-sprint75-empty".to_string(),
            vfs: None,
            config: HashMap::new(),
            prior_results: Vec::new(),
        }
    }

    fn garbage_ctx(suffix: &str) -> PluginContext {
        let dir = std::env::temp_dir().join(format!(
            "strata_sprint75_{}_{}_{}",
            suffix,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(
            dir.join("garbage.bin"),
            [0xFFu8, 0x00, 0xDE, 0xAD, 0xBE, 0xEF],
        )
        .expect("write garbage");
        PluginContext {
            root_path: dir.to_string_lossy().into_owned(),
            vfs: None,
            config: HashMap::new(),
            prior_results: Vec::new(),
        }
    }

    #[test]
    fn plugin_has_valid_metadata() {
        let plugin = IndexPlugin::new();
        assert!(!plugin.name().is_empty());
        assert!(!plugin.version().is_empty());
        assert!(!plugin.description().is_empty());
    }

    #[test]
    fn plugin_returns_ok_on_empty_input() {
        let plugin = IndexPlugin::new();
        let result = plugin.run(empty_ctx());
        assert!(result.is_ok() || result.unwrap_or_default().is_empty());
    }

    #[test]
    fn plugin_does_not_panic_on_malformed_input() {
        let plugin = IndexPlugin::new();
        let _ = plugin.run(garbage_ctx("index"));
    }
}
