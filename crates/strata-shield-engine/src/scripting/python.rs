use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyString};
use serde_json::Value;
use std::path::Path;

pub fn load_python_parser(path: &Path) -> Result<Box<dyn ArtifactParser>, String> {
    let script_name = path
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let code = std::fs::read_to_string(path).map_err(|e| e.to_string())?;

    Python::with_gil(|py| {
        let module = PyModule::from_code(py, &code, &path.to_string_lossy(), &script_name)
            .map_err(|e| format!("Python compile error: {}", e))?;

        let parser_class = module
            .getattr("Parser")
            .map_err(|_| "Python plugin must define a 'Parser' class".to_string())?;

        let parser_instance = parser_class
            .call0()
            .map_err(|e| format!("Failed to instantiate Parser: {}", e))?
            .into_py(py);

        let name: String = parser_instance
            .getattr(py, "name")
            .map_err(|_| "Parser missing 'name' attribute".to_string())?
            .extract(py)
            .map_err(|_| "'name' must be a string".to_string())?;

        let artifact_type: String = parser_instance
            .getattr(py, "artifact_type")
            .map_err(|_| "Parser missing 'artifact_type' attribute".to_string())?
            .extract(py)
            .map_err(|_| "'artifact_type' must be a string".to_string())?;

        let target_patterns: Vec<String> = parser_instance
            .getattr(py, "target_patterns")
            .map_err(|_| "Parser missing 'target_patterns' attribute".to_string())?
            .extract(py)
            .map_err(|_| "'target_patterns' must be a list of strings".to_string())?;

        Ok(Box::new(PythonParser {
            instance: parser_instance,
            name,
            artifact_type,
            target_patterns,
        }) as Box<dyn ArtifactParser>)
    })
}

struct PythonParser {
    instance: PyObject,
    name: String,
    artifact_type: String,
    target_patterns: Vec<String>,
}

impl ArtifactParser for PythonParser {
    fn name(&self) -> &str {
        &self.name
    }

    fn artifact_type(&self) -> &str {
        &self.artifact_type
    }

    fn target_patterns(&self) -> Vec<&str> {
        self.target_patterns.iter().map(|s| s.as_str()).collect()
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        Python::with_gil(|py| -> Result<Vec<ParsedArtifact>, ParserError> {
            let py_path = path.to_string_lossy().to_string();
            let py_data = PyBytes::new(py, data);

            let result = self
                .instance
                .call_method1(py, "parse_file", (py_path.clone(), py_data))
                .map_err(|e| ParserError::Parse(format!("Python exception: {}", e)))?;

            let list = result
                .downcast::<PyList>(py)
                .map_err(|_| ParserError::Parse("parse_file must return a list of dicts".into()))?;

            let mut artifacts = Vec::new();
            for item in list {
                let dict = item
                    .downcast::<PyDict>()
                    .map_err(|_| ParserError::Parse("Items must be dictionaries".into()))?;

                let mut map = serde_json::Map::new();

                for (k, v) in dict {
                    let key: String = k.extract().unwrap_or_default();
                    let val: String = v
                        .str()
                        .unwrap_or(PyString::new(py, ""))
                        .to_string_lossy()
                        .into_owned();
                    map.insert(key, Value::String(val));
                }

                let p_art = ParsedArtifact {
                    timestamp: None,
                    artifact_type: self.artifact_type.clone(),
                    description: format!("Parsed by Python plugin: {}", self.name),
                    source_path: py_path.clone(),
                    json_data: Value::Object(map),
                };

                artifacts.push(p_art);
            }
            Ok(artifacts)
        })
    }
}
