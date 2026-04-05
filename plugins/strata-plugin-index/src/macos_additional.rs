use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct MacosSafariTabsParser;

impl MacosSafariTabsParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SafariTab {
    pub title: Option<String>,
    pub url: Option<String>,
    pub last_viewed: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SafariWindow {
    pub window_id: i64,
    pub tabs: Vec<SafariTab>,
}

impl Default for MacosSafariTabsParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosSafariTabsParser {
    fn name(&self) -> &str {
        "macOS Safari Tabs"
    }

    fn artifact_type(&self) -> &str {
        "macos_safari_tabs"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["History.plist", "Safari/Bookmarks.plist"]
    }

    fn parse_file(
        &self,
        path: &Path,
        data: &[u8],
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        
        if data.len() < 4 {
            return Ok(artifacts);
        }

        let relative_path = path.to_string_lossy().to_string();
        
        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "macos_safari_tabs".to_string(),
            description: "macOS Safari tabs data".to_string(),
            source_path: relative_path,
            json_data: serde_json::json!({
                "path": path.display().to_string(),
                "size": data.len(),
            }),
        });

        Ok(artifacts)
    }
}

pub struct MacosNotesParser;

impl MacosNotesParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NoteEntry {
    pub title: Option<String>,
    pub snippet: Option<String>,
    pub account: Option<String>,
    pub created: Option<i64>,
    pub modified: Option<i64>,
}

impl Default for MacosNotesParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosNotesParser {
    fn name(&self) -> &str {
        "macOS Notes"
    }

    fn artifact_type(&self) -> &str {
        "macos_notes"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["NoteStore.sqlite"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        use crate::sqlite_utils::{with_sqlite_connection, table_exists};
        
        let mut artifacts = Vec::new();
        let sqlite_result = with_sqlite_connection(path, data, |conn: &rusqlite::Connection| {
            let mut entries = Vec::new();
            if table_exists(conn, "ZICCLOUDIDENTIFIER") || table_exists(conn, "ZICCLOUDOBJECT") {
                 let mut stmt = conn.prepare(
                    "SELECT ZTITLE, ZSNIPPET, ZCREATIONDATE, ZMODIFICATIONDATE FROM ZICCLOUDOBJECT WHERE ZTITLE IS NOT NULL LIMIT 1000"
                ).map_err(|e: rusqlite::Error| ParserError::Database(e.to_string()))?;
                
                let rows = stmt.query_map([], |row: &rusqlite::Row| {
                    Ok(NoteEntry {
                        title: row.get(0).ok(),
                        snippet: row.get(1).ok(),
                        account: None,
                        created: row.get::<_, f64>(2).ok().map(|d| (d + 978307200.0) as i64),
                        modified: row.get::<_, f64>(3).ok().map(|d| (d + 978307200.0) as i64),
                    })
                }).map_err(|e: rusqlite::Error| ParserError::Database(e.to_string()))?;

                for row in rows.flatten() {
                    entries.push(ParsedArtifact {
                        timestamp: row.modified,
                        artifact_type: "macos_notes".to_string(),
                        description: format!("Note: {}", row.title.as_deref().unwrap_or("Untitled")),
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

        if artifacts.is_empty() && !data.is_empty() {
             artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "macos_notes".to_string(),
                description: "macOS Notes database (metadata only)".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::json!({ "size": data.len() }),
            });
        }

        Ok(artifacts)
    }
}

pub struct MacosCalendarParser;

impl MacosCalendarParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CalendarEvent {
    pub summary: Option<String>,
    pub start_date: Option<i64>,
    pub end_date: Option<i64>,
    pub location: Option<String>,
}

impl Default for MacosCalendarParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosCalendarParser {
    fn name(&self) -> &str {
        "macOS Calendar"
    }

    fn artifact_type(&self) -> &str {
        "macos_calendar"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["Calendar Cache"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        use crate::sqlite_utils::{with_sqlite_connection, table_exists};

        let mut artifacts = Vec::new();
        let sqlite_result = with_sqlite_connection(path, data, |conn: &rusqlite::Connection| {
            let mut entries = Vec::new();
            if table_exists(conn, "CalendarItem") {
                 let mut stmt = conn.prepare(
                    "SELECT summary, start_date, end_date, location FROM CalendarItem WHERE summary IS NOT NULL LIMIT 1000"
                ).map_err(|e: rusqlite::Error| ParserError::Database(e.to_string()))?;
                
                let rows = stmt.query_map([], |row: &rusqlite::Row| {
                    Ok(CalendarEvent {
                        summary: row.get(0).ok(),
                        start_date: row.get::<_, f64>(1).ok().map(|d| (d + 978307200.0) as i64),
                        end_date: row.get::<_, f64>(2).ok().map(|d| (d + 978307200.0) as i64),
                        location: row.get(3).ok(),
                    })
                }).map_err(|e: rusqlite::Error| ParserError::Database(e.to_string()))?;

                for row in rows.flatten() {
                    entries.push(ParsedArtifact {
                        timestamp: row.start_date,
                        artifact_type: "macos_calendar".to_string(),
                        description: format!("Calendar Event: {}", row.summary.as_deref().unwrap_or("Unnamed")),
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

pub struct MacosContactsParser;

impl MacosContactsParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContactEntry {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub organization: Option<String>,
}

impl Default for MacosContactsParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosContactsParser {
    fn name(&self) -> &str {
        "macOS Contacts"
    }

    fn artifact_type(&self) -> &str {
        "macos_contacts"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["AddressBook-v22.abcdp", "AddressBook.sqlitedb"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        use crate::sqlite_utils::{with_sqlite_connection, table_exists};

        let mut artifacts = Vec::new();
        let sqlite_result = with_sqlite_connection(path, data, |conn: &rusqlite::Connection| {
            let mut entries = Vec::new();
            if table_exists(conn, "ZABCDCONTACTINDEX") || table_exists(conn, "ZABCDRECORD") {
                 let mut stmt = conn.prepare(
                    "SELECT ZFIRSTNAME, ZLASTNAME, ZORGANIZATION FROM ZABCDRECORD WHERE ZFIRSTNAME IS NOT NULL OR ZLASTNAME IS NOT NULL LIMIT 1000"
                ).map_err(|e: rusqlite::Error| ParserError::Database(e.to_string()))?;
                
                let rows = stmt.query_map([], |row: &rusqlite::Row| {
                    Ok(ContactEntry {
                        first_name: row.get(0).ok(),
                        last_name: row.get(1).ok(),
                        organization: row.get(2).ok(),
                    })
                }).map_err(|e: rusqlite::Error| ParserError::Database(e.to_string()))?;

                for row in rows.flatten() {
                    entries.push(ParsedArtifact {
                        timestamp: None,
                        artifact_type: "macos_contacts".to_string(),
                        description: format!("Contact: {} {}", 
                            row.first_name.as_deref().unwrap_or(""), 
                            row.last_name.as_deref().unwrap_or("")),
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

pub struct MacosLaunchAgentsParser;

impl MacosLaunchAgentsParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MacosLaunchAgentsParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for MacosLaunchAgentsParser {
    fn name(&self) -> &str {
        "macOS LaunchAgents"
    }

    fn artifact_type(&self) -> &str {
        "macos_launchagent"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["Library/LaunchAgents/*.plist", "Library/LaunchDaemons/*.plist"]
    }

    fn parse_file(
        &self,
        path: &Path,
        data: &[u8],
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        
        if data.is_empty() {
            return Ok(artifacts);
        }

        let is_daemon = path.to_string_lossy().contains("LaunchDaemons");
        
        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: if is_daemon { "macos_launchdaemon" } else { "macos_launchagent" }.to_string(),
            description: format!("macOS {} plist", if is_daemon { "LaunchDaemon" } else { "LaunchAgent" }),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::json!({
                "path": path.display().to_string(),
                "is_daemon": is_daemon,
                "size": data.len(),
            }),
        });

        Ok(artifacts)
    }
}
