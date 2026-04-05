use crate::sqlite_utils::{table_exists, with_sqlite_connection};
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

use std::path::Path;

pub struct MacosHomeKitParser;

impl MacosHomeKitParser {
    pub fn new() -> Self {
        Self
    }
}

pub fn sqlite_get_string(row: &rusqlite::Row, idx: usize) -> Option<String> {
    row.get(idx).ok()
}

impl Default for MacosHomeKitParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosHomeKitParser {
    fn name(&self) -> &str {
        "macOS HomeKit Audit"
    }

    fn artifact_type(&self) -> &str {
        "system_config"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["homed.sqlite", "home.db", "homekit"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        let sqlite_result = with_sqlite_connection(path, data, |conn: &rusqlite::Connection| {
            let mut entries = Vec::new();
            if table_exists(conn, "HMPERSON") {
                let mut stmt = conn
                    .prepare("SELECT ZNAME FROM HMPERSON LIMIT 100")
                    .map_err(|e: rusqlite::Error| ParserError::Database(e.to_string()))?;
                let rows = stmt
                    .query_map([], |row: &rusqlite::Row| row.get::<_, String>(0))
                    .map_err(|e: rusqlite::Error| ParserError::Database(e.to_string()))?;
                for name in rows.flatten() {
                    entries.push(ParsedArtifact {
                        timestamp: None,
                        artifact_type: "system_config".to_string(),
                        description: format!("HomeKit Person: {}", name),
                        source_path: path.to_string_lossy().to_string(),
                        json_data: serde_json::json!({ "name": name }),
                    });
                }
            }
            Ok(entries)
        });

        if let Ok(mut entries) = sqlite_result {
            artifacts.append(&mut entries);
        }

        Ok(artifacts)
    }
}
