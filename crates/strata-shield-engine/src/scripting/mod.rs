use crate::parser::ArtifactParser;
use std::path::Path;

#[cfg(feature = "python-plugins")]
pub mod python;

#[cfg(feature = "lua-plugins")]
pub mod lua;

pub fn discover_and_load_scripts(plugin_dir: &Path) -> Vec<Box<dyn ArtifactParser>> {
    let parsers: Vec<Box<dyn ArtifactParser>> = Vec::new();

    if !plugin_dir.exists() {
        return parsers;
    }

    if let Ok(entries) = std::fs::read_dir(plugin_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                #[allow(unused_variables)]
                let ext_str = ext.to_string_lossy().to_lowercase();

                #[cfg(feature = "python-plugins")]
                if ext_str == "py" {
                    match python::load_python_parser(&path) {
                        Ok(parser) => parsers.push(parser),
                        Err(e) => tracing::error!("Failed to load Python plugin {:?}: {}", path, e),
                    }
                }

                #[cfg(feature = "lua-plugins")]
                if ext_str == "lua" {
                    match lua::load_lua_parser(&path) {
                        Ok(parser) => parsers.push(parser),
                        Err(e) => tracing::error!("Failed to load Lua plugin {:?}: {}", path, e),
                    }
                }
            }
        }
    }

    parsers
}

#[cfg(test)]
mod tests;
