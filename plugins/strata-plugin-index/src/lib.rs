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
        artifact.add_field(
            "description",
            "Strata Index core parsing plugin",
        );
        results.push(artifact);

        Ok(results)
    }
}

#[no_mangle]
pub extern "C" fn create_plugin() -> *mut std::ffi::c_void {
    let plugin: Box<dyn StrataPlugin> = Box::new(IndexPlugin::new());
    let plugin_holder = Box::new(plugin);
    Box::into_raw(plugin_holder) as *mut std::ffi::c_void
}
