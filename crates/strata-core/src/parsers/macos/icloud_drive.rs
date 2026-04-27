//! iCloud Drive artifact parser.
//!
//! Targets the on-disk artifacts that iCloud Drive leaves under
//! `~/Library/Mobile Documents/`, `~/Library/Application Support/CloudDocs/`,
//! and `~/Library/Application Support/com.apple.cloud-DOCS-cl/`. These include:
//!
//!   * `Mobile Documents/com~apple~CloudDocs/...` — synced container files
//!   * `client.db` (CloudDocs) — local cache of fileproviderd metadata
//!   * `server.db` (CloudDocs) — server-side metadata mirror
//!   * `com.apple.bird.plist` — bird daemon prefs
//!   * `.ubd/` directories — ubiquity bridge metadata files
//!
//! Forensic value:
//! When a file disappears from a Mac because the user moved it into iCloud,
//! the `Mobile Documents` tree is the *only* on-disk record. The CloudDocs
//! `client.db` is the source of truth for sync timestamps, conflict copies,
//! and the original file location before iCloud took over.

use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::plist_utils::parse_plist_data;
use crate::parsers::sqlite_utils::{list_tables, table_exists, with_sqlite_connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

const ICLOUD_LIMIT: usize = 5000;

pub struct ICloudDriveParser;

impl ICloudDriveParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ICloudDriveParser {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ICloudFileEntry {
    pub container: Option<String>,
    pub item_filename: Option<String>,
    pub item_parent_id: Option<i64>,
    pub item_birthtime: Option<i64>,
    pub item_lastusedtime: Option<i64>,
    pub item_size: Option<i64>,
    pub item_state: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ICloudContainerHint {
    pub source: String,
    pub container_id: Option<String>,
    pub user_email: Option<String>,
    pub last_modified: Option<i64>,
}

impl ArtifactParser for ICloudDriveParser {
    fn name(&self) -> &str {
        "iCloud Drive Artifacts"
    }

    fn artifact_type(&self) -> &str {
        "cloud_storage"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "client.db",
            "server.db",
            "com.apple.bird.plist",
            "com.apple.clouddocs.plist",
            "com.apple.cloud-docs-cl",
            "mobile documents",
            ".ubd",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let path_str = path.to_string_lossy().to_lowercase();

        let in_clouddocs = path_str.contains("/clouddocs/")
            || path_str.contains("/cloud-docs-cl/")
            || path_str.contains("/mobile documents/");
        let is_bird_pref = path_str.contains("com.apple.bird.plist");

        if !in_clouddocs && !is_bird_pref {
            return Ok(Vec::new());
        }

        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();

        // Bird daemon plist — extract container/account hints.
        if is_bird_pref || file_name == "com.apple.clouddocs.plist" {
            return Ok(parse_bird_plist(path, data));
        }

        // CloudDocs SQLite databases (client.db / server.db).
        if file_name == "client.db" || file_name == "server.db" {
            let mut artifacts = Vec::new();
            let result = with_sqlite_connection(path, data, |conn| {
                let mut entries: Vec<ParsedArtifact> = Vec::new();

                // Newer schemas use `client_items`, older use `client_files`.
                let table = if table_exists(conn, "client_items") {
                    Some("client_items")
                } else if table_exists(conn, "client_files") {
                    Some("client_files")
                } else {
                    // Fall back to listing tables so the artifact still emits
                    // a "container present" record for triage.
                    let tables = list_tables(conn);
                    entries.push(ParsedArtifact {
                        timestamp: None,
                        artifact_type: "cloud_storage".to_string(),
                        description: format!(
                            "iCloud CloudDocs database (no item table): {} tables",
                            tables.len()
                        ),
                        source_path: path.to_string_lossy().to_string(),
                        json_data: serde_json::json!({ "tables": tables }),
                    });
                    None
                };

                if let Some(table) = table {
                    let sql = format!(
                        "SELECT item_filename, item_parent_id, item_birthtime, \
                         item_lastusedtime, item_size, item_state FROM {} LIMIT {}",
                        table, ICLOUD_LIMIT
                    );
                    if let Ok(mut stmt) = conn.prepare(&sql) {
                        let rows = stmt
                            .query_map([], |row| {
                                Ok(ICloudFileEntry {
                                    container: extract_container(&path_str),
                                    item_filename: row.get(0).ok(),
                                    item_parent_id: row.get(1).ok(),
                                    item_birthtime: row.get::<_, f64>(2).ok().map(|d| d as i64),
                                    item_lastusedtime: row.get::<_, f64>(3).ok().map(|d| d as i64),
                                    item_size: row.get(4).ok(),
                                    item_state: row.get(5).ok(),
                                })
                            })
                            .map_err(|e| ParserError::Database(e.to_string()))?;
                        for entry in rows.flatten() {
                            entries.push(ParsedArtifact {
                                timestamp: entry.item_lastusedtime.or(entry.item_birthtime),
                                artifact_type: "cloud_storage".to_string(),
                                description: format!(
                                    "iCloud item: {}",
                                    entry.item_filename.as_deref().unwrap_or("(unknown)")
                                ),
                                source_path: path.to_string_lossy().to_string(),
                                json_data: serde_json::to_value(entry).unwrap_or_default(),
                            });
                        }
                    }
                }
                Ok(entries)
            });
            if let Ok(mut entries) = result {
                artifacts.append(&mut entries);
            }
            return Ok(artifacts);
        }

        // Mobile Documents container files — emit presence records so MacTrace
        // can correlate them. We don't try to read the actual file content
        // here; the existence + path is the artifact.
        if path_str.contains("/mobile documents/") {
            let container = extract_container(&path_str);
            return Ok(vec![ParsedArtifact {
                timestamp: None,
                artifact_type: "cloud_storage".to_string(),
                description: format!(
                    "iCloud Drive synced file in {}",
                    container.as_deref().unwrap_or("(unknown container)")
                ),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::json!({
                    "container": container,
                    "file_size": data.len(),
                }),
            }]);
        }

        Ok(Vec::new())
    }
}

fn parse_bird_plist(path: &Path, data: &[u8]) -> Vec<ParsedArtifact> {
    let mut out = Vec::new();
    let Ok(plist_val) = parse_plist_data(data) else {
        return out;
    };
    let dict = match plist_val.as_dictionary() {
        Some(d) => d,
        None => return out,
    };

    let user_email = dict
        .get("CKAccountInfo")
        .and_then(|v| v.as_dictionary())
        .and_then(|d| d.get("UserRecordName"))
        .and_then(|v| v.as_string())
        .map(String::from)
        .or_else(|| {
            dict.get("UserEmail")
                .and_then(|v| v.as_string())
                .map(String::from)
        });

    let container = dict
        .get("DefaultContainer")
        .and_then(|v| v.as_string())
        .map(String::from);

    let last_modified = dict
        .get("LastSyncDate")
        .and_then(|v| v.as_real())
        .map(|d| d as i64);

    out.push(ParsedArtifact {
        timestamp: last_modified,
        artifact_type: "cloud_storage".to_string(),
        description: format!(
            "iCloud bird daemon configuration: {}",
            container.as_deref().unwrap_or("(unknown)")
        ),
        source_path: path.to_string_lossy().to_string(),
        json_data: serde_json::to_value(ICloudContainerHint {
            source: "com.apple.bird.plist".to_string(),
            container_id: container,
            user_email,
            last_modified,
        })
        .unwrap_or_default(),
    });
    out
}

fn extract_container(path_lower: &str) -> Option<String> {
    if let Some(idx) = path_lower.find("/mobile documents/") {
        let tail = &path_lower[idx + "/mobile documents/".len()..];
        if let Some(slash) = tail.find('/') {
            return Some(tail[..slash].to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn extracts_apple_clouddocs_container() {
        let p = "/users/test/library/mobile documents/com~apple~clouddocs/desktop/notes.txt";
        assert_eq!(
            extract_container(p),
            Some("com~apple~clouddocs".to_string())
        );
    }

    #[test]
    fn parses_bird_plist() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>DefaultContainer</key>
    <string>com.apple.CloudDocs</string>
    <key>UserEmail</key>
    <string>korbyn@wolfmark.dev</string>
    <key>LastSyncDate</key>
    <real>700000000.0</real>
</dict>
</plist>"#;
        let parser = ICloudDriveParser::new();
        let path = PathBuf::from("/Users/test/Library/Preferences/com.apple.bird.plist");
        let out = parser.parse_file(&path, xml.as_bytes()).unwrap();
        assert_eq!(out.len(), 1);
        let json = &out[0].json_data;
        assert_eq!(
            json.get("container_id").and_then(|v| v.as_str()),
            Some("com.apple.CloudDocs")
        );
        assert_eq!(
            json.get("user_email").and_then(|v| v.as_str()),
            Some("korbyn@wolfmark.dev")
        );
    }

    #[test]
    fn emits_presence_record_for_mobile_documents_file() {
        let parser = ICloudDriveParser::new();
        let path =
            PathBuf::from("/Users/test/Library/Mobile Documents/com~apple~CloudDocs/Notes.txt");
        let out = parser.parse_file(&path, b"some content here").unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].json_data.get("file_size").and_then(|v| v.as_u64()),
            Some(17)
        );
    }

    #[test]
    fn ignores_unrelated_paths() {
        let parser = ICloudDriveParser::new();
        let path = PathBuf::from("/Users/test/Documents/note.txt");
        let out = parser.parse_file(&path, b"x").unwrap();
        assert!(out.is_empty());
    }
}
