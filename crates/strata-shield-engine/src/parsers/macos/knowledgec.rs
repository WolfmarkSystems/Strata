use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::sqlite_utils::{with_sqlite_connection, table_exists};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct MacosKnowledgecParser;

impl MacosKnowledgecParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KnowledgecEntry {
    pub timestamp: Option<i64>,
    pub bundle_id: Option<String>,
    pub value: Option<String>,
    pub stream_name: Option<String>,
    pub duration: Option<i64>,
}

impl Default for MacosKnowledgecParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosKnowledgecParser {
    fn name(&self) -> &str {
        "macOS KnowledgeC"
    }

    fn artifact_type(&self) -> &str {
        "application_usage"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["knowledgeC.db"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let sqlite_result = with_sqlite_connection(path, data, |conn| {
            let mut entries = Vec::new();
            if table_exists(conn, "ZOBJECT") {
                 let mut stmt = conn.prepare(
                    "SELECT 
                        ZOBJECT.ZSTARTDATE, 
                        ZOBJECT.ZVALUESTRING, 
                        ZSOURCE.ZBUNDLEID,
                        ZOBJECT.ZSTREAMNAME,
                        ZOBJECT.ZENDDATE - ZOBJECT.ZSTARTDATE
                     FROM ZOBJECT 
                     LEFT JOIN ZSOURCE ON ZOBJECT.ZSOURCE = ZSOURCE.Z_PK
                     WHERE ZOBJECT.ZSTARTDATE IS NOT NULL
                     ORDER BY ZOBJECT.ZSTARTDATE DESC
                     LIMIT 5000"
                ).map_err(|e| ParserError::Database(e.to_string()))?;
                
                let rows = stmt.query_map([], |row| {
                    Ok(KnowledgecEntry {
                        timestamp: row.get::<_, f64>(0).ok().map(|d| (d + 978307200.0) as i64),
                        value: row.get(1).ok(),
                        bundle_id: row.get(2).ok(),
                        stream_name: row.get(3).ok(),
                        duration: row.get::<_, f64>(4).ok().map(|d| d as i64),
                    })
                }).map_err(|e| ParserError::Database(e.to_string()))?;

                for row in rows.flatten() {
                    let desc = format!("KnowledgeC: {} ({})", 
                        row.bundle_id.as_deref().unwrap_or("unknown"),
                        row.stream_name.as_deref().unwrap_or("unknown")
                    );
                    
                    entries.push(ParsedArtifact {
                        timestamp: row.timestamp,
                        artifact_type: "application_usage".to_string(),
                        description: desc,
                        source_path: path.to_string_lossy().to_string(),
                        json_data: serde_json::to_value(row).unwrap_or_default(),
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
