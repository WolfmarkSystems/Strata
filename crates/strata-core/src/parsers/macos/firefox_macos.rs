//! Firefox on macOS parser.
//!
//! Targets `~/Library/Application Support/Firefox/Profiles/<profile>/` and
//! parses the SQLite databases that contain web activity:
//!
//!   * `places.sqlite` — moz_places (history) + moz_bookmarks + moz_historyvisits
//!   * `cookies.sqlite` — moz_cookies (per-host cookies)
//!   * `formhistory.sqlite` — saved form fields
//!   * `extensions.json` — installed add-ons (JSON)
//!
//! Forensic value:
//! Firefox uses a different epoch than Chrome (Unix microseconds, 1970-based)
//! and a different schema. The generic `BrowserParser::for_firefox()` does
//! handle Firefox, but it does not differentiate by macOS profile path or
//! pull form history. This parser is mac-specific and complements the generic
//! one with profile-name attribution and the formhistory + extensions.json
//! sources.

use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::sqlite_utils::{table_exists, with_sqlite_connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

const PLACES_LIMIT: usize = 5000;
const COOKIE_LIMIT: usize = 2000;

pub struct FirefoxMacOsParser;

impl FirefoxMacOsParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for FirefoxMacOsParser {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FirefoxPlace {
    pub url: String,
    pub title: Option<String>,
    pub visit_count: i64,
    pub last_visit_date: Option<i64>,
    pub typed: bool,
    pub frecency: i64,
    pub profile: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FirefoxBookmark {
    pub title: Option<String>,
    pub url: Option<String>,
    pub date_added: Option<i64>,
    pub last_modified: Option<i64>,
    pub profile: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FirefoxCookie {
    pub host: String,
    pub name: String,
    pub path: String,
    pub creation_time: Option<i64>,
    pub expiry: Option<i64>,
    pub is_secure: bool,
    pub profile: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FirefoxFormEntry {
    pub field_name: String,
    pub value: String,
    pub times_used: i64,
    pub first_used: Option<i64>,
    pub last_used: Option<i64>,
    pub profile: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FirefoxExtensionEntry {
    pub addon_id: String,
    pub name: Option<String>,
    pub version: Option<String>,
    pub active: bool,
    pub install_date: Option<i64>,
    pub source_uri: Option<String>,
    pub profile: Option<String>,
}

impl ArtifactParser for FirefoxMacOsParser {
    fn name(&self) -> &str {
        "macOS Firefox Browser"
    }

    fn artifact_type(&self) -> &str {
        "browser"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "places.sqlite",
            "cookies.sqlite",
            "formhistory.sqlite",
            "extensions.json",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let path_str = path.to_string_lossy().to_lowercase();
        // Restrict to Firefox profile paths so we don't accidentally claim
        // other apps' SQLite files (Thunderbird also uses places-like names).
        if !path_str.contains("/firefox/profiles/") && !path_str.contains("/firefox/") {
            return Ok(Vec::new());
        }

        let profile = extract_firefox_profile(&path_str);
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();

        if file_name == "extensions.json" {
            return Ok(parse_firefox_extensions_json(path, data, profile.as_deref()));
        }

        let mut artifacts = Vec::new();
        let result = with_sqlite_connection(path, data, |conn| {
            let mut entries: Vec<ParsedArtifact> = Vec::new();

            if file_name == "places.sqlite" {
                if table_exists(conn, "moz_places") {
                    let mut stmt = conn
                        .prepare(&format!(
                            "SELECT url, title, visit_count, last_visit_date, typed, frecency \
                             FROM moz_places ORDER BY last_visit_date DESC LIMIT {}",
                            PLACES_LIMIT
                        ))
                        .map_err(|e| ParserError::Database(e.to_string()))?;
                    let rows = stmt
                        .query_map([], |row| {
                            Ok(FirefoxPlace {
                                url: row.get::<_, String>(0).unwrap_or_default(),
                                title: row.get(1).ok(),
                                visit_count: row.get::<_, i64>(2).unwrap_or(0),
                                last_visit_date: row
                                    .get::<_, i64>(3)
                                    .ok()
                                    .map(firefox_us_to_unix),
                                typed: row.get::<_, i64>(4).unwrap_or(0) != 0,
                                frecency: row.get::<_, i64>(5).unwrap_or(0),
                                profile: profile.clone(),
                            })
                        })
                        .map_err(|e| ParserError::Database(e.to_string()))?;
                    for entry in rows.flatten() {
                        entries.push(ParsedArtifact {
                            timestamp: entry.last_visit_date,
                            artifact_type: "browser".to_string(),
                            description: format!("Firefox URL: {}", entry.url),
                            source_path: path.to_string_lossy().to_string(),
                            json_data: serde_json::to_value(entry).unwrap_or_default(),
                        });
                    }
                }
                if table_exists(conn, "moz_bookmarks") {
                    let mut stmt = conn
                        .prepare(
                            "SELECT b.title, p.url, b.dateAdded, b.lastModified \
                             FROM moz_bookmarks b LEFT JOIN moz_places p ON b.fk = p.id \
                             WHERE b.type = 1 LIMIT 5000",
                        )
                        .map_err(|e| ParserError::Database(e.to_string()))?;
                    let rows = stmt
                        .query_map([], |row| {
                            Ok(FirefoxBookmark {
                                title: row.get(0).ok(),
                                url: row.get(1).ok(),
                                date_added: row
                                    .get::<_, i64>(2)
                                    .ok()
                                    .map(firefox_us_to_unix),
                                last_modified: row
                                    .get::<_, i64>(3)
                                    .ok()
                                    .map(firefox_us_to_unix),
                                profile: profile.clone(),
                            })
                        })
                        .map_err(|e| ParserError::Database(e.to_string()))?;
                    for entry in rows.flatten() {
                        entries.push(ParsedArtifact {
                            timestamp: entry.date_added,
                            artifact_type: "browser".to_string(),
                            description: format!(
                                "Firefox bookmark: {}",
                                entry.title.as_deref().unwrap_or("(untitled)")
                            ),
                            source_path: path.to_string_lossy().to_string(),
                            json_data: serde_json::to_value(entry).unwrap_or_default(),
                        });
                    }
                }
            } else if file_name == "cookies.sqlite" && table_exists(conn, "moz_cookies") {
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT host, name, path, creationTime, expiry, isSecure \
                         FROM moz_cookies LIMIT {}",
                        COOKIE_LIMIT
                    ))
                    .map_err(|e| ParserError::Database(e.to_string()))?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok(FirefoxCookie {
                            host: row.get::<_, String>(0).unwrap_or_default(),
                            name: row.get::<_, String>(1).unwrap_or_default(),
                            path: row.get::<_, String>(2).unwrap_or_default(),
                            creation_time: row
                                .get::<_, i64>(3)
                                .ok()
                                .map(firefox_us_to_unix),
                            // moz_cookies expiry is *seconds* not microseconds
                            expiry: row.get::<_, i64>(4).ok(),
                            is_secure: row.get::<_, i64>(5).unwrap_or(0) != 0,
                            profile: profile.clone(),
                        })
                    })
                    .map_err(|e| ParserError::Database(e.to_string()))?;
                for entry in rows.flatten() {
                    entries.push(ParsedArtifact {
                        timestamp: entry.creation_time,
                        artifact_type: "browser".to_string(),
                        description: format!("Firefox cookie: {} on {}", entry.name, entry.host),
                        source_path: path.to_string_lossy().to_string(),
                        json_data: serde_json::to_value(entry).unwrap_or_default(),
                    });
                }
            } else if file_name == "formhistory.sqlite" && table_exists(conn, "moz_formhistory") {
                let mut stmt = conn
                    .prepare(
                        "SELECT fieldname, value, timesUsed, firstUsed, lastUsed FROM moz_formhistory",
                    )
                    .map_err(|e| ParserError::Database(e.to_string()))?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok(FirefoxFormEntry {
                            field_name: row.get::<_, String>(0).unwrap_or_default(),
                            value: row.get::<_, String>(1).unwrap_or_default(),
                            times_used: row.get::<_, i64>(2).unwrap_or(0),
                            first_used: row
                                .get::<_, i64>(3)
                                .ok()
                                .map(firefox_us_to_unix),
                            last_used: row
                                .get::<_, i64>(4)
                                .ok()
                                .map(firefox_us_to_unix),
                            profile: profile.clone(),
                        })
                    })
                    .map_err(|e| ParserError::Database(e.to_string()))?;
                for entry in rows.flatten() {
                    entries.push(ParsedArtifact {
                        timestamp: entry.last_used,
                        artifact_type: "browser".to_string(),
                        description: format!(
                            "Firefox form value: {} = {}",
                            entry.field_name, entry.value
                        ),
                        source_path: path.to_string_lossy().to_string(),
                        json_data: serde_json::to_value(entry).unwrap_or_default(),
                    });
                }
            }

            Ok(entries)
        });

        if let Ok(mut entries) = result {
            artifacts.append(&mut entries);
        }

        Ok(artifacts)
    }
}

/// Convert Firefox PRTime (microseconds since Unix epoch) to Unix seconds.
fn firefox_us_to_unix(microseconds: i64) -> i64 {
    if microseconds <= 0 {
        return 0;
    }
    microseconds / 1_000_000
}

fn extract_firefox_profile(path_lower: &str) -> Option<String> {
    if let Some(idx) = path_lower.find("/profiles/") {
        let tail = &path_lower[idx + "/profiles/".len()..];
        if let Some(slash) = tail.find('/') {
            return Some(tail[..slash].to_string());
        }
    }
    None
}

fn parse_firefox_extensions_json(
    path: &Path,
    data: &[u8],
    profile: Option<&str>,
) -> Vec<ParsedArtifact> {
    let mut out = Vec::new();
    let value: serde_json::Value = match serde_json::from_slice(data) {
        Ok(v) => v,
        Err(_) => return out,
    };

    let addons = value.get("addons").and_then(|a| a.as_array());
    let Some(addons) = addons else {
        return out;
    };

    for addon in addons {
        let id = addon
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if id.is_empty() {
            continue;
        }
        let name = addon
            .get("defaultLocale")
            .and_then(|d| d.get("name"))
            .and_then(|n| n.as_str())
            .map(String::from);
        let version = addon
            .get("version")
            .and_then(|v| v.as_str())
            .map(String::from);
        let active = addon.get("active").and_then(|v| v.as_bool()).unwrap_or(false);
        let install_date = addon
            .get("installDate")
            .and_then(|v| v.as_i64())
            .map(|ms| ms / 1000);
        let source_uri = addon
            .get("sourceURI")
            .and_then(|v| v.as_str())
            .map(String::from);

        let entry = FirefoxExtensionEntry {
            addon_id: id.clone(),
            name: name.clone(),
            version,
            active,
            install_date,
            source_uri,
            profile: profile.map(String::from),
        };
        out.push(ParsedArtifact {
            timestamp: install_date,
            artifact_type: "browser".to_string(),
            description: format!(
                "Firefox extension: {} ({})",
                name.as_deref().unwrap_or("unknown"),
                id
            ),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn extracts_profile_from_path() {
        let p = "/users/test/library/application support/firefox/profiles/abc123.default-release/places.sqlite";
        assert_eq!(
            extract_firefox_profile(p),
            Some("abc123.default-release".to_string())
        );
    }

    #[test]
    fn firefox_us_conversion_handles_zero_and_positive() {
        assert_eq!(firefox_us_to_unix(0), 0);
        assert_eq!(firefox_us_to_unix(-5), 0);
        assert_eq!(firefox_us_to_unix(1_678_307_200_000_000), 1_678_307_200);
    }

    #[test]
    fn parses_extensions_json() {
        let json = r#"{
            "addons": [
                {
                    "id": "{abc-123}",
                    "version": "2.5.0",
                    "active": true,
                    "installDate": 1700000000000,
                    "defaultLocale": { "name": "uBlock Origin" },
                    "sourceURI": "https://addons.mozilla.org/uBlock"
                }
            ]
        }"#;
        let parser = FirefoxMacOsParser::new();
        let path = PathBuf::from(
            "/Users/test/Library/Application Support/Firefox/Profiles/abc/extensions.json",
        );
        let out = parser.parse_file(&path, json.as_bytes()).unwrap();
        assert_eq!(out.len(), 1);
        let entry = &out[0];
        assert_eq!(
            entry.json_data.get("name").and_then(|v| v.as_str()),
            Some("uBlock Origin")
        );
        assert_eq!(entry.timestamp, Some(1_700_000_000));
    }

    #[test]
    fn ignores_non_firefox_paths() {
        let parser = FirefoxMacOsParser::new();
        let path = PathBuf::from("/Users/test/Library/Application Support/Other/places.sqlite");
        let out = parser.parse_file(&path, b"x").unwrap();
        assert!(out.is_empty());
    }
}
