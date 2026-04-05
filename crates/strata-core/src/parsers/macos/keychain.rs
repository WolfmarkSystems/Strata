use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct KeychainParser;

impl KeychainParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeychainEntry {
    pub service: Option<String>,
    pub account: Option<String>,
    pub server: Option<String>,
    pub password: Option<String>,
    pub creation_date: Option<i64>,
    pub modification_date: Option<i64>,
    pub item_class: Option<String>,
}

impl Default for KeychainParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for KeychainParser {
    fn name(&self) -> &str {
        "Keychain"
    }

    fn artifact_type(&self) -> &str {
        "credential"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["keychain", ".keychain"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if data.len() < 20 {
            return Ok(artifacts);
        }

        // Keychain-db header is usually 'kych' or similar
        let is_keychain_db = &data[0..4] == b"kych";
        let is_legacy_keychain = &data[0..4] == b"KyCh";

        if is_keychain_db {
            use crate::parsers::sqlite_utils::{table_exists, with_sqlite_connection};
            let sqlite_result = with_sqlite_connection(path, data, |conn| {
                let mut entries = Vec::new();
                if table_exists(conn, "genp") {
                    let mut stmt = conn
                        .prepare("SELECT service, acct, cdate, mdate FROM genp LIMIT 10000")
                        .map_err(|e| ParserError::Database(e.to_string()))?;
                    let rows = stmt
                        .query_map([], |row| {
                            Ok(KeychainEntry {
                                service: row.get::<_, String>(0).ok(),
                                account: row.get::<_, String>(1).ok(),
                                server: None,
                                password: None,
                                creation_date: row
                                    .get::<_, f64>(2)
                                    .ok()
                                    .map(|d| d as i64 + 978307200),
                                modification_date: row
                                    .get::<_, f64>(3)
                                    .ok()
                                    .map(|d| d as i64 + 978307200),
                                item_class: Some("General Password".to_string()),
                            })
                        })
                        .map_err(|e| ParserError::Database(e.to_string()))?;

                    for row in rows.flatten() {
                        entries.push(ParsedArtifact {
                            timestamp: row.modification_date,
                            artifact_type: "credential".to_string(),
                            description: format!(
                                "Keychain Entry ({}): {}",
                                row.account.as_deref().unwrap_or("unknown"),
                                row.service.as_deref().unwrap_or("unknown")
                            ),
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
        } else if is_legacy_keychain {
            let entry = KeychainEntry {
                service: path.file_stem().map(|s| s.to_string_lossy().to_string()),
                account: None,
                server: None,
                password: None,
                creation_date: None,
                modification_date: None,
                item_class: Some("Legacy Keychain".to_string()),
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "credential".to_string(),
                description: format!(
                    "macOS Keychain File ({})",
                    entry.item_class.as_deref().unwrap_or("unknown")
                ),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}
