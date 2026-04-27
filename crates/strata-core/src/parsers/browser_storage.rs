use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::sqlite_utils::{table_exists, with_sqlite_connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Browser IndexedDB and LocalStorage Parser
///
/// Parses:
///   - Chrome/Edge: IndexedDB (LevelDB-backed, metadata extraction)
///   - Firefox: IndexedDB (SQLite: storage/default/*/idb/*.sqlite)
///   - Chrome/Edge: Local Storage (LevelDB-backed, metadata)
///   - Firefox: webappsstore.sqlite (LocalStorage)
///
/// Forensic value: Web applications store data locally via IndexedDB and
/// localStorage. This includes chat messages (web WhatsApp, Slack),
/// email content (Gmail offline), document data, and authentication tokens.
/// Increasingly important as more apps are web-based.
pub struct BrowserStorageParser;

impl Default for BrowserStorageParser {
    fn default() -> Self {
        Self::new()
    }
}

impl BrowserStorageParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LocalStorageEntry {
    pub origin: Option<String>,
    pub key: Option<String>,
    pub value_preview: Option<String>,
    pub value_size: usize,
    pub is_json: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IndexedDbMetadata {
    pub origin: Option<String>,
    pub database_name: Option<String>,
    pub version: Option<i64>,
    pub object_store_count: Option<i32>,
    pub size_bytes: usize,
}

impl ArtifactParser for BrowserStorageParser {
    fn name(&self) -> &str {
        "Browser IndexedDB/LocalStorage Parser"
    }

    fn artifact_type(&self) -> &str {
        "web_storage"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["webappsstore.sqlite", "*.sqlite", "Local Storage"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
            .to_lowercase();

        let path_str = path.to_string_lossy().to_lowercase();

        // Firefox webappsstore.sqlite (localStorage)
        if filename == "webappsstore.sqlite" {
            return self.parse_firefox_localstorage(path, data);
        }

        // Firefox IndexedDB (*.sqlite in idb directory)
        if path_str.contains("/idb/") && filename.ends_with(".sqlite") {
            return self.parse_firefox_indexeddb(path, data);
        }

        Ok(vec![])
    }
}

impl BrowserStorageParser {
    fn parse_firefox_localstorage(
        &self,
        path: &Path,
        data: &[u8],
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();

        let sqlite_result = with_sqlite_connection(path, data, |conn| {
            let mut entries = Vec::new();

            if table_exists(conn, "webappsstore2") {
                let mut stmt = conn
                    .prepare(
                        "SELECT originAttributes, originKey, scope, key, value
                         FROM webappsstore2
                         ORDER BY scope
                         LIMIT 10000",
                    )
                    .map_err(|e| ParserError::Database(e.to_string()))?;

                let rows = stmt
                    .query_map([], |row| {
                        let value: String = row.get::<_, String>(4).unwrap_or_default();
                        let value_size = value.len();
                        let is_json = value.starts_with('{') || value.starts_with('[');
                        let preview = if value.len() > 200 {
                            format!("{}...", &value[..200])
                        } else {
                            value
                        };

                        Ok(LocalStorageEntry {
                            origin: row.get(2).ok(),
                            key: row.get(3).ok(),
                            value_preview: Some(preview),
                            value_size,
                            is_json,
                        })
                    })
                    .map_err(|e| ParserError::Database(e.to_string()))?;

                for row in rows.flatten() {
                    let origin = row.origin.as_deref().unwrap_or("unknown");
                    let key = row.key.as_deref().unwrap_or("unknown");

                    entries.push(ParsedArtifact {
                        timestamp: None,
                        artifact_type: "local_storage".to_string(),
                        description: format!(
                            "LocalStorage [Firefox]: {} / {} ({} bytes){}",
                            origin,
                            key,
                            row.value_size,
                            if row.is_json { " [JSON]" } else { "" },
                        ),
                        source_path: source.clone(),
                        json_data: serde_json::to_value(&row).unwrap_or_default(),
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

    fn parse_firefox_indexeddb(
        &self,
        path: &Path,
        data: &[u8],
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();

        // Extract origin from path: storage/default/<origin>/idb/<dbname>.sqlite
        let origin = path
            .parent() // idb/
            .and_then(|p| p.parent()) // <origin>/
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .map(|s| s.replace("+++", "://").replace("+", "."));

        let sqlite_result = with_sqlite_connection(path, data, |conn| {
            let mut entries = Vec::new();

            // Get database metadata
            if table_exists(conn, "database") {
                let mut stmt = conn
                    .prepare("SELECT name, version FROM database LIMIT 1")
                    .map_err(|e| ParserError::Database(e.to_string()))?;

                let rows = stmt
                    .query_map([], |row| {
                        Ok((row.get::<_, String>(0).ok(), row.get::<_, i64>(1).ok()))
                    })
                    .map_err(|e| ParserError::Database(e.to_string()))?;

                for row in rows.flatten() {
                    let meta = IndexedDbMetadata {
                        origin: origin.clone(),
                        database_name: row.0.clone(),
                        version: row.1,
                        object_store_count: None,
                        size_bytes: data.len(),
                    };

                    entries.push(ParsedArtifact {
                        timestamp: None,
                        artifact_type: "indexed_db".to_string(),
                        description: format!(
                            "IndexedDB [Firefox]: {} / {} (v{}, {} bytes)",
                            origin.as_deref().unwrap_or("unknown"),
                            row.0.as_deref().unwrap_or("unknown"),
                            row.1.unwrap_or(0),
                            data.len(),
                        ),
                        source_path: source.clone(),
                        json_data: serde_json::to_value(&meta).unwrap_or_default(),
                    });
                }
            }

            // Get object store names
            if table_exists(conn, "object_store") {
                let mut stmt = conn
                    .prepare("SELECT name FROM object_store LIMIT 100")
                    .map_err(|e| ParserError::Database(e.to_string()))?;

                let stores: Vec<String> = stmt
                    .query_map([], |row| row.get::<_, String>(0))
                    .map_err(|e| ParserError::Database(e.to_string()))?
                    .filter_map(|r| r.ok())
                    .collect();

                if !stores.is_empty() {
                    entries.push(ParsedArtifact {
                        timestamp: None,
                        artifact_type: "indexed_db_stores".to_string(),
                        description: format!(
                            "IndexedDB Stores [Firefox]: {} / [{}]",
                            origin.as_deref().unwrap_or("unknown"),
                            stores.join(", "),
                        ),
                        source_path: source.clone(),
                        json_data: serde_json::json!({
                            "origin": origin,
                            "object_stores": stores,
                        }),
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
