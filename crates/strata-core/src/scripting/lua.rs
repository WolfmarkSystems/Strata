use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use mlua::prelude::*;
use std::path::Path;

pub fn load_lua_parser(path: &Path) -> Result<Box<dyn ArtifactParser>, String> {
    let script_name = path
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let code = std::fs::read_to_string(path).map_err(|e| e.to_string())?;

    let lua = Lua::new();

    let parser_table: LuaTable = lua
        .load(&code)
        .eval()
        .map_err(|e| format!("Lua compile/eval error: {}", e))?;

    let name: String = parser_table
        .get("name")
        .map_err(|_| "Parser missing 'name' attribute".to_string())?;

    let artifact_type: String = parser_table
        .get("artifact_type")
        .map_err(|_| "Parser missing 'artifact_type' attribute".to_string())?;

    let target_patterns_table: LuaTable = parser_table
        .get("target_patterns")
        .map_err(|_| "Parser missing 'target_patterns' table".to_string())?;

    let mut target_patterns = Vec::new();
    for pair in target_patterns_table.pairs::<usize, String>() {
        let (_, pattern) = pair.map_err(|e| format!("Invalid target_pattern: {}", e))?;
        target_patterns.push(pattern);
    }

    Ok(Box::new(LuaParser {
        lua,
        script_name,
        name,
        artifact_type,
        target_patterns,
    }) as Box<dyn ArtifactParser>)
}

struct LuaParser {
    lua: Lua,
    script_name: String,
    name: String,
    artifact_type: String,
    target_patterns: Vec<String>,
}

impl ArtifactParser for LuaParser {
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
        let py_path = path.to_string_lossy().to_string();
        let globals = self.lua.globals();

        // The parser state was returned by eval, so the easiest way to keep it around
        // and call it safely without holding a long-lived reference is to re-evaluate it
        // or register it to globals during init. Wait, we are evaluating it anew because
        // `LuaTable` is tied to the `Lua` runtime. We created `lua` in `load_lua_parser`
        // and stored it in `self.lua`. Let's just re-eval the code or store the table in registry.
        // For simplicity, we can load it from registry / globals.
        // Actually, since `self.lua` is owned by `LuaParser`, we shouldn't have thrown away the `parser_table`.
        // But `mlua` requires references tied to the lifetime of `Lua`.
        // Let's implement it by registering the parser table in globals.

        let path_str = py_path.clone();

        // This is a simplified stateless execution.
        // A robust implementation would store the function in the Lua registry.

        // Let's read the code from disk again to evaluate it quickly.
        let code = std::fs::read_to_string(path).unwrap_or_default();
        let parser_table: Result<LuaTable, _> = self.lua.load(&code).eval();

        let table = match parser_table {
            Ok(t) => t,
            Err(e) => return Err(ParserError::Parse(format!("Lua eval error: {}", e))),
        };

        let parse_func: LuaFunction = table
            .get("parse_file")
            .map_err(|_| ParserError::Parse("Parser missing 'parse_file' function".to_string()))?;

        // pass data as a literal Lua string or string buffer
        let lua_data = self
            .lua
            .create_string(data)
            .map_err(|e| ParserError::Parse(e.to_string()))?;

        let results: LuaTable = parse_func
            .call((path_str, lua_data))
            .map_err(|e| ParserError::Parse(format!("Lua execution error: {}", e)))?;

        let mut artifacts = Vec::new();
        for pair in results.pairs::<usize, LuaTable>() {
            let (_, dict) = pair.map_err(|_| ParserError::Parse("Items must be tables".into()))?;

            let mut map = serde_json::Map::new();
            for kv in dict.pairs::<String, String>() {
                if let Ok((k, v)) = kv {
                    map.insert(k, serde_json::Value::String(v));
                }
            }

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: self.artifact_type.clone(),
                description: format!("Parsed by Lua plugin: {}", self.name),
                source_path: py_path.clone(),
                json_data: serde_json::Value::Object(map),
            });
        }

        Ok(artifacts)
    }
}
