use serde::{Deserialize, Serialize};
use tera::{Context, Tera};

#[derive(Debug, Serialize, Deserialize)]
pub struct PluginTemplateData {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
}

pub struct ForgeGenerator {
    tera: Tera,
}

impl Default for ForgeGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl ForgeGenerator {
    pub fn new() -> Self {
        let mut tera = Tera::default();

        // Register the basic plugin template
        tera.add_raw_template("plugin_lib", include_str!("templates/plugin_lib.rs.tera"))
            .unwrap();
        tera.add_raw_template(
            "plugin_cargo",
            include_str!("templates/plugin_cargo.toml.tera"),
        )
        .unwrap();

        Self { tera }
    }

    pub fn generate_plugin(&self, data: PluginTemplateData) -> anyhow::Result<String> {
        let mut context = Context::new();
        context.insert("name", &data.name);
        context.insert("version", &data.version);
        context.insert("description", &data.description);
        context.insert("author", &data.author);

        self.tera
            .render("plugin_lib", &context)
            .map_err(anyhow::Error::from)
    }
}
