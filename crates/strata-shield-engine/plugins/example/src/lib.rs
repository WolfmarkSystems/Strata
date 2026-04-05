use forensic_engine::parser::{ArtifactParser, ParsedArtifact, ParserError};
use forensic_engine::plugin::{Plugin, PluginInfo};
use std::path::Path;

const PLUGIN_VERSION: &str = "0.1.0";

#[no_mangle]
pub extern "C" fn plugin_name() -> *const std::ffi::c_char {
    use std::ffi::CString;
    CString::new("Example Plugin").unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn plugin_version() -> *const std::ffi::c_char {
    use std::ffi::CString;
    CString::new(PLUGIN_VERSION).unwrap().into_raw()
}

#[no_mangle]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn plugin_create() -> *mut dyn Plugin {
    Box::into_raw(Box::new(ExamplePlugin::new())) as *mut dyn Plugin
}

pub struct ExamplePlugin {
    info: PluginInfo,
    parser: ExampleParser,
}

impl ExamplePlugin {
    pub fn new() -> Self {
        Self {
            info: PluginInfo {
                name: "Example Plugin".to_string(),
                version: PLUGIN_VERSION.to_string(),
                author: "ForensicSuite Team".to_string(),
                description:
                    "Example plugin demonstrating the plugin API. Looks for .example files."
                        .to_string(),
                artifact_types: vec!["example_artifact".to_string()],
            },
            parser: ExampleParser,
        }
    }
}

impl Plugin for ExamplePlugin {
    fn info(&self) -> &PluginInfo {
        &self.info
    }

    fn parser(&self) -> &dyn ArtifactParser {
        &self.parser
    }
}

struct ExampleParser;

impl ArtifactParser for ExampleParser {
    fn name(&self) -> &str {
        "Example Parser"
    }

    fn artifact_type(&self) -> &str {
        "example_artifact"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![".example", "example"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        let content = String::from_utf8_lossy(data);
        let mut artifacts = Vec::new();

        for (i, line) in content.lines().enumerate() {
            if line.contains("suspicious") || line.contains("bad") {
                artifacts.push(ParsedArtifact {
                    timestamp: None,
                    artifact_type: "example_artifact".to_string(),
                    description: format!("Found suspicious marker on line {}: {}", i + 1, line),
                    source_path: path.to_string_lossy().to_string(),
                    json_data: serde_json::json!({
                        "line_number": i + 1,
                        "content": line,
                        "plugin": "example-plugin"
                    }),
                });
            }
        }

        if artifacts.is_empty() && !data.is_empty() {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "example_artifact".to_string(),
                description: format!("Processed example file: {} bytes", data.len()),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::json!({
                    "size": data.len(),
                    "plugin": "example-plugin"
                }),
            });
        }

        Ok(artifacts)
    }
}
