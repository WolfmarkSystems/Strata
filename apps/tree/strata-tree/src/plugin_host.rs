//! Plugin host — loads and runs all built-in Strata plugins.
//! Plugins are statically compiled into the binary (CJIS compliance).

use strata_plugin_sdk::{PluginContext, PluginError, PluginOutput, StrataPlugin};

pub struct PluginHost {
    plugins: Vec<Box<dyn StrataPlugin>>,
}

impl PluginHost {
    pub fn new() -> Self {
        Self {
            plugins: vec![
                Box::new(strata_plugin_remnant::RemnantPlugin::new()),
                Box::new(strata_plugin_chronicle::ChroniclePlugin::new()),
                Box::new(strata_plugin_cipher::CipherPlugin::new()),
                Box::new(strata_plugin_trace::TracePlugin::new()),
                Box::new(strata_plugin_specter::SpecterPlugin::new()),
                Box::new(strata_plugin_conduit::ConduitPlugin::new()),
                Box::new(strata_plugin_nimbus::NimbusPlugin::new()),
                Box::new(strata_plugin_wraith::WraithPlugin::new()),
                Box::new(strata_plugin_vector::VectorPlugin::new()),
                Box::new(strata_plugin_recon::ReconPlugin::new()),
                Box::new(strata_plugin_sigma::SigmaPlugin::new()),
            ],
        }
    }

    pub fn list(&self) -> &[Box<dyn StrataPlugin>] {
        &self.plugins
    }

    #[allow(dead_code)]
    pub fn plugin_names(&self) -> Vec<String> {
        self.plugins.iter().map(|p| p.name().to_string()).collect()
    }

    pub fn run_plugin(
        &self,
        plugin_name: &str,
        context: PluginContext,
    ) -> Result<PluginOutput, PluginError> {
        let plugin = self
            .plugins
            .iter()
            .find(|p| p.name() == plugin_name)
            .ok_or_else(|| PluginError::Internal(format!("Plugin not found: {}", plugin_name)))?;

        plugin.execute(context)
    }

    #[allow(dead_code)]
    pub fn run_all(&self, context: PluginContext) -> Vec<(String, Result<PluginOutput, PluginError>)> {
        self.plugins
            .iter()
            .map(|p| {
                let name = p.name().to_string();
                let ctx = context.clone();
                let result = p.execute(ctx);
                (name, result)
            })
            .collect()
    }
}

impl Default for PluginHost {
    fn default() -> Self {
        Self::new()
    }
}
