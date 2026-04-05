use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::path::Path;
use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};

pub struct BrowserParser {
    browser_type: BrowserType,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BrowserType {
    Chrome,
    Edge,
    Firefox,
    Brave,
    IE,
}

impl BrowserType {
    pub fn from_path(path: &Path) -> Option<Self> {
        let path_str = path.to_string_lossy().to_lowercase();

        if path_str.contains("chrome") || path_str.contains("google") {
            Some(BrowserType::Chrome)
        } else if path_str.contains("microsoft") || path_str.contains("edge") {
            Some(BrowserType::Edge)
        } else if path_str.contains("firefox") || path_str.contains("mozilla") {
            Some(BrowserType::Firefox)
        } else if path_str.contains("brave") {
            Some(BrowserType::Brave)
        } else if path_str.contains("internet explorer")
            || path_str.contains("ie")
            || path_str.contains("microsoftedge")
        {
            Some(BrowserType::IE)
        } else {
            None
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            BrowserType::Chrome => "Chrome",
            BrowserType::Edge => "Edge",
            BrowserType::Firefox => "Firefox",
            BrowserType::Brave => "Brave",
            BrowserType::IE => "Internet Explorer",
        }
    }
}

impl BrowserParser {
    pub fn new(browser_type: BrowserType) -> Self {
        Self { browser_type }
    }

    pub fn for_chrome() -> Self {
        Self {
            browser_type: BrowserType::Chrome,
        }
    }

    pub fn for_edge() -> Self {
        Self {
            browser_type: BrowserType::Edge,
        }
    }

    pub fn for_firefox() -> Self {
        Self {
            browser_type: BrowserType::Firefox,
        }
    }

    pub fn for_brave() -> Self {
        Self {
            browser_type: BrowserType::Brave,
        }
    }

    pub fn for_ie() -> Self {
        Self {
            browser_type: BrowserType::IE,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub url: String,
    pub title: Option<String>,
    pub visit_time: Option<i64>,
    pub visit_count: i32,
    pub typed_count: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DownloadEntry {
    pub path: String,
    pub url: String,
    pub start_time: Option<i64>,
    pub end_time: Option<i64>,
    pub size: i64,
    pub state: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CookieEntry {
    pub host: String,
    pub name: String,
    pub value: String,
    pub path: Option<String>,
    pub expiration: Option<i64>,
    pub creation_time: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AutofillEntry {
    pub name: String,
    pub value: String,
    pub count: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BookmarkEntry {
    pub title: String,
    pub url: Option<String>,
    pub parent_folder: Option<String>,
    pub add_date: Option<i64>,
}

impl ArtifactParser for BrowserParser {
    fn name(&self) -> &str {
        match self.browser_type {
            BrowserType::Chrome => "Chrome History Parser",
            BrowserType::Edge => "Edge History Parser",
            BrowserType::Firefox => "Firefox History Parser",
            BrowserType::Brave => "Brave History Parser",
            BrowserType::IE => "IE History Parser",
        }
    }

    fn artifact_type(&self) -> &str {
        "browser"
    }

    fn target_patterns(&self) -> Vec<&str> {
        match self.browser_type {
            BrowserType::Chrome | BrowserType::Edge | BrowserType::Brave => vec![
                "History",
                "history.db",
                "Cookies",
                "cookies.db",
                "Login Data",
                "Web Data",
                "Bookmarks",
                "bookmarks",
                "History-journal",
            ],
            BrowserType::Firefox => vec![
                "places.sqlite",
                "cookies.sqlite",
                "formhistory.sqlite",
                "logins.json",
                "bookmarks.json",
            ],
            BrowserType::IE => vec!["iedat.ie", "iedat2.ie"],
        }
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
            .to_lowercase();

        if filename.contains("history") || filename.contains("places") {
            if let Ok(history) = self.parse_history(path, data) {
                for entry in history {
                    artifacts.push(ParsedArtifact {
                        timestamp: entry.visit_time,
                        artifact_type: "browser_history".to_string(),
                        description: format!("{} visited: {}", self.browser_type.name(), entry.url),
                        source_path: path.to_string_lossy().to_string(),
                        json_data: serde_json::to_value(entry).unwrap_or_default(),
                    });
                }
            }
        } else if filename.contains("cookie") || filename.contains("cookies") {
            if let Ok(cookies) = self.parse_cookies(path, data) {
                for entry in cookies {
                    artifacts.push(ParsedArtifact {
                        timestamp: entry.creation_time,
                        artifact_type: "browser_cookie".to_string(),
                        description: format!("{} cookie: {}", self.browser_type.name(), entry.name),
                        source_path: path.to_string_lossy().to_string(),
                        json_data: serde_json::to_value(entry).unwrap_or_default(),
                    });
                }
            }
        } else if filename.contains("download") {
            if let Ok(downloads) = self.parse_downloads(path, data) {
                for entry in downloads {
                    artifacts.push(ParsedArtifact {
                        timestamp: entry.start_time,
                        artifact_type: "browser_download".to_string(),
                        description: format!(
                            "{} download: {}",
                            self.browser_type.name(),
                            entry.path
                        ),
                        source_path: path.to_string_lossy().to_string(),
                        json_data: serde_json::to_value(entry).unwrap_or_default(),
                    });
                }
            }
        } else if filename.contains("bookmark") {
            if let Ok(bookmarks) = self.parse_bookmarks(path, data) {
                for entry in bookmarks {
                    artifacts.push(ParsedArtifact {
                        timestamp: entry.add_date,
                        artifact_type: "browser_bookmark".to_string(),
                        description: format!(
                            "{} bookmark: {}",
                            self.browser_type.name(),
                            entry.title
                        ),
                        source_path: path.to_string_lossy().to_string(),
                        json_data: serde_json::to_value(entry).unwrap_or_default(),
                    });
                }
            }
        } else if filename.contains("login") || filename.contains("web data") {
            if let Ok(autofill) = self.parse_autofill(path, data) {
                for entry in autofill {
                    artifacts.push(ParsedArtifact {
                        timestamp: None,
                        artifact_type: "browser_autofill".to_string(),
                        description: format!(
                            "{} autofill: {}",
                            self.browser_type.name(),
                            entry.name
                        ),
                        source_path: path.to_string_lossy().to_string(),
                        json_data: serde_json::to_value(entry).unwrap_or_default(),
                    });
                }
            }
        }

        if artifacts.is_empty() {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "browser_file".to_string(),
                description: format!("Browser data file: {}", filename),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::json!({
                    "browser": self.browser_type.name(),
                    "filename": filename,
                    "size_bytes": data.len(),
                    "note": "Browser file detected but parsing requires SQLite format"
                }),
            });
        }

        Ok(artifacts)
    }
}

impl BrowserParser {
    fn parse_history(&self, path: &Path, _data: &[u8]) -> Result<Vec<HistoryEntry>, ParserError> {
        let mut entries = Vec::new();

        if let Ok(conn) = Connection::open(path) {
            let query = match self.browser_type {
                BrowserType::Firefox => {
                    "SELECT p.url, p.title, h.visit_date, p.visit_count, p.typed 
                     FROMmoz_places p 
                     LEFT JOIN moz_historyvisits h ON p.id = h.place_id 
                     ORDER BY h.visit_date DESC LIMIT 1000"
                }
                _ => {
                    "SELECT url, title, last_visit_time, visit_count, typed_count 
                     FROM urls 
                     ORDER BY last_visit_time DESC LIMIT 1000"
                }
            };

            if let Ok(mut stmt) = conn.prepare(query) {
                let rows = stmt.query_map([], |row: &rusqlite::Row| {
                    Ok(HistoryEntry {
                        url: row.get(0).unwrap_or_default(),
                        title: row.get(1).ok(),
                        visit_time: row.get::<_, i64>(2).ok().map(|t| {
                            if t > 1000000000000 {
                                t
                            } else {
                                t * 1000
                            }
                        }),
                        visit_count: row.get(3).unwrap_or(0),
                        typed_count: row.get(4).unwrap_or(0),
                    })
                });

                if let Ok(rows) = rows {
                    for entry in rows.flatten() {
                        if !entry.url.is_empty() {
                            entries.push(entry);
                        }
                    }
                }
            }
        }

        Ok(entries)
    }

    fn parse_cookies(&self, path: &Path, _data: &[u8]) -> Result<Vec<CookieEntry>, ParserError> {
        let mut entries = Vec::new();

        if let Ok(conn) = Connection::open(path) {
            let query = match self.browser_type {
                BrowserType::Firefox => {
                    "SELECT host, name, value, path, expiry, creationTime 
                     FROM moz_cookies ORDER BY creationTime DESC LIMIT 1000"
                }
                _ => {
                    "SELECT host, name, value, path, expires_utc, creation_utc 
                     FROM cookies ORDER BY creation_utc DESC LIMIT 1000"
                }
            };

            if let Ok(mut stmt) = conn.prepare(query) {
                let rows = stmt.query_map([], |row: &rusqlite::Row| {
                    Ok(CookieEntry {
                        host: row.get(0).unwrap_or_default(),
                        name: row.get(1).unwrap_or_default(),
                        value: row.get(2).unwrap_or_default(),
                        path: row.get(3).ok(),
                        expiration: row.get::<_, i64>(4).ok().map(|t| {
                            if t > 1000000000000 {
                                t
                            } else {
                                t * 1000
                            }
                        }),
                        creation_time: row.get::<_, i64>(5).ok().map(|t| {
                            if t > 1000000000000 {
                                t
                            } else {
                                t * 1000
                            }
                        }),
                    })
                });

                if let Ok(rows) = rows {
                    for entry in rows.flatten() {
                        if !entry.name.is_empty() {
                            entries.push(entry);
                        }
                    }
                }
            }
        }

        Ok(entries)
    }

    fn parse_downloads(
        &self,
        path: &Path,
        _data: &[u8],
    ) -> Result<Vec<DownloadEntry>, ParserError> {
        let mut entries = Vec::new();

        if let Ok(conn) = Connection::open(path) {
            let query = "SELECT path, url, start_time, end_time, size, state 
                         FROM downloads ORDER BY start_time DESC LIMIT 1000";

            if let Ok(mut stmt) = conn.prepare(query) {
                let rows = stmt.query_map([], |row: &rusqlite::Row| {
                    Ok(DownloadEntry {
                        path: row.get(0).unwrap_or_default(),
                        url: row.get(1).unwrap_or_default(),
                        start_time: row.get::<_, i64>(2).ok().map(|t| {
                            if t > 1000000000000 {
                                t
                            } else {
                                t * 1000
                            }
                        }),
                        end_time: row.get::<_, i64>(3).ok().map(|t| {
                            if t > 1000000000000 {
                                t
                            } else {
                                t * 1000
                            }
                        }),
                        size: row.get(4).unwrap_or(0),
                        state: row.get(5).unwrap_or(0),
                    })
                });

                if let Ok(rows) = rows {
                    for entry in rows.flatten() {
                        if !entry.path.is_empty() {
                            entries.push(entry);
                        }
                    }
                }
            }
        }

        Ok(entries)
    }

    fn parse_bookmarks(
        &self,
        path: &Path,
        _data: &[u8],
    ) -> Result<Vec<BookmarkEntry>, ParserError> {
        let mut entries = Vec::new();

        if let Ok(conn) = Connection::open(path) {
            let query = match self.browser_type {
                BrowserType::Firefox => {
                    "SELECT p.title, p.url, f.title, p.date_added 
                     FROM moz_bookmarks p 
                     LEFT JOIN moz_bookmarks f ON p.parent = f.id 
                     WHERE p.type = 1 ORDER BY p.date_added DESC LIMIT 500"
                }
                _ => {
                    "SELECT title, url, parent_id, date_added 
                     FROM bookmarks WHERE type = 1 ORDER BY date_added DESC LIMIT 500"
                }
            };

            if let Ok(mut stmt) = conn.prepare(query) {
                let rows = stmt.query_map([], |row: &rusqlite::Row| {
                    Ok(BookmarkEntry {
                        title: row.get(0).unwrap_or_default(),
                        url: row.get(1).ok(),
                        parent_folder: row.get(2).ok(),
                        add_date: row.get::<_, i64>(3).ok().map(|t| {
                            if t > 1000000000000 {
                                t
                            } else {
                                t * 1000
                            }
                        }),
                    })
                });

                if let Ok(rows) = rows {
                    for entry in rows.flatten() {
                        if !entry.title.is_empty() {
                            entries.push(entry);
                        }
                    }
                }
            }
        }

        Ok(entries)
    }

    fn parse_autofill(&self, path: &Path, _data: &[u8]) -> Result<Vec<AutofillEntry>, ParserError> {
        let mut entries = Vec::new();

        if let Ok(conn) = Connection::open(path) {
            let query =
                "SELECT name, value, use_count FROM autofill ORDER BY use_count DESC LIMIT 500";

            if let Ok(mut stmt) = conn.prepare(query) {
                let rows = stmt.query_map([], |row: &rusqlite::Row| {
                    Ok(AutofillEntry {
                        name: row.get(0).unwrap_or_default(),
                        value: row.get(1).unwrap_or_default(),
                        count: row.get(2).unwrap_or(0),
                    })
                });

                if let Ok(rows) = rows {
                    for entry in rows.flatten() {
                        if !entry.name.is_empty() {
                            entries.push(entry);
                        }
                    }
                }
            }
        }

        Ok(entries)
    }
}
