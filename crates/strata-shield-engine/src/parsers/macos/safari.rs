use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct SafariParser {
    data_type: SafariDataType,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SafariDataType {
    History,
    Cookies,
    Downloads,
}

impl SafariDataType {
    pub fn from_path(path: &Path) -> Option<Self> {
        let path_str = path.to_string_lossy().to_lowercase();
        if path_str.contains("history") {
            Some(SafariDataType::History)
        } else if path_str.contains("cookies") {
            Some(SafariDataType::Cookies)
        } else if path_str.contains("downloads") {
            Some(SafariDataType::Downloads)
        } else if path_str.ends_with(".db") || path_str.ends_with(".sqlite") {
            Some(SafariDataType::History)
        } else {
            None
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            SafariDataType::History => "Safari History",
            SafariDataType::Cookies => "Safari Cookies",
            SafariDataType::Downloads => "Safari Downloads",
        }
    }
}

impl SafariParser {
    pub fn new(data_type: SafariDataType) -> Self {
        Self { data_type }
    }

    pub fn for_history() -> Self {
        Self {
            data_type: SafariDataType::History,
        }
    }

    pub fn for_cookies() -> Self {
        Self {
            data_type: SafariDataType::Cookies,
        }
    }

    pub fn for_downloads() -> Self {
        Self {
            data_type: SafariDataType::Downloads,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SafariHistoryEntry {
    pub url: Option<String>,
    pub title: Option<String>,
    pub visit_time: Option<i64>,
    pub visit_count: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SafariCookieEntry {
    pub domain: Option<String>,
    pub name: Option<String>,
    pub value: Option<String>,
    pub path: Option<String>,
    pub expiration: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SafariDownloadEntry {
    pub url: Option<String>,
    pub file_path: Option<String>,
    pub file_name: Option<String>,
    pub size: i64,
    pub download_time: Option<i64>,
}

impl ArtifactParser for SafariParser {
    fn name(&self) -> &str {
        self.data_type.name()
    }

    fn artifact_type(&self) -> &str {
        "browser"
    }

    fn target_patterns(&self) -> Vec<&str> {
        match self.data_type {
            SafariDataType::History => vec!["history", ".db"],
            SafariDataType::Cookies => vec!["cookies", ".db"],
            SafariDataType::Downloads => vec!["downloads", ".db"],
        }
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        use crate::parsers::sqlite_utils::{with_sqlite_connection, table_exists};
        use crate::parsers::plist_utils::parse_plist_data;

        let mut artifacts = Vec::new();
        let path_str = path.to_string_lossy().to_lowercase();

        if path_str.ends_with(".plist") {
             if let Ok(plist_val) = parse_plist_data(data) {
                artifacts.push(ParsedArtifact {
                    timestamp: None,
                    artifact_type: "browser".to_string(),
                    description: format!("Safari {} (plist)", self.data_type.name()),
                    source_path: path.to_string_lossy().to_string(),
                    json_data: serde_json::to_value(&plist_val).unwrap_or_default(),
                });
             }
             return Ok(artifacts);
        }

        let sqlite_result = with_sqlite_connection(path, data, |conn| {
            let mut entries = Vec::new();
            match self.data_type {
                SafariDataType::History => {
                    if table_exists(conn, "history_items") {
                        let mut stmt = conn.prepare(
                            "SELECT history_items.url, history_visits.visit_time, history_items.visit_count 
                             FROM history_items 
                             JOIN history_visits ON history_items.id = history_visits.history_item 
                             LIMIT 5000"
                        ).map_err(|e| ParserError::Database(e.to_string()))?;
                        
                        let rows = stmt.query_map([], |row| {
                            Ok(SafariHistoryEntry {
                                url: row.get(0).ok(),
                                title: None,
                                visit_time: row.get::<_, f64>(1).ok().map(|d| (d + 978307200.0) as i64),
                                visit_count: row.get(2).unwrap_or(0),
                            })
                        }).map_err(|e| ParserError::Database(e.to_string()))?;

                        for row in rows.flatten() {
                             entries.push(ParsedArtifact {
                                timestamp: row.visit_time,
                                artifact_type: "browser".to_string(),
                                description: format!("Safari History: {}", row.url.as_deref().unwrap_or("unknown")),
                                source_path: path.to_string_lossy().to_string(),
                                json_data: serde_json::to_value(row).unwrap_or_default(),
                            });
                        }
                    }
                },
                SafariDataType::Downloads => {
                    if table_exists(conn, "downloads") {
                         let mut stmt = conn.prepare(
                            "SELECT download_url, full_path, total_bytes, start_time FROM downloads LIMIT 1000"
                        ).map_err(|e| ParserError::Database(e.to_string()))?;
                        
                        let rows = stmt.query_map([], |row| {
                            Ok(SafariDownloadEntry {
                                url: row.get(0).ok(),
                                file_path: row.get(1).ok(),
                                file_name: None,
                                size: row.get(2).unwrap_or(0),
                                download_time: row.get::<_, f64>(3).ok().map(|d| (d + 978307200.0) as i64),
                            })
                        }).map_err(|e| ParserError::Database(e.to_string()))?;

                        for row in rows.flatten() {
                             entries.push(ParsedArtifact {
                                timestamp: row.download_time,
                                artifact_type: "browser".to_string(),
                                description: format!("Safari Download: {}", row.url.as_deref().unwrap_or("unknown")),
                                source_path: path.to_string_lossy().to_string(),
                                json_data: serde_json::to_value(row).unwrap_or_default(),
                            });
                        }
                    }
                },
                SafariDataType::Cookies => {
                    if table_exists(conn, "moz_cookies") || table_exists(conn, "cookies") {
                         artifacts.push(ParsedArtifact {
                            timestamp: None,
                            artifact_type: "browser".to_string(),
                            description: "Safari Cookies database found".to_string(),
                            source_path: path.to_string_lossy().to_string(),
                            json_data: serde_json::json!({ "status": "detected" }),
                        });
                    }
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
