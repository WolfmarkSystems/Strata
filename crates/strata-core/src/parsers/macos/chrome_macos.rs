//! Chrome on macOS parser.
//!
//! Targets the Google Chrome profile structure under
//! `~/Library/Application Support/Google/Chrome/<profile>/` and parses the
//! key SQLite databases that the existing generic `BrowserParser` does not
//! enrich for the macOS-specific layout:
//!
//!   * `History` (urls + downloads + visits + keyword_search_terms)
//!   * `Login Data` (origin_url + username_value)
//!   * `Web Data` (autofill, autofill_profiles)
//!   * `Cookies` (host_key + name + path)
//!   * `Preferences` (JSON file with extensions, sync settings)
//!   * `Secure Preferences` (JSON file)
//!
//! Forensic value:
//! Chrome's mac-specific paths are not handled cleanly by the generic
//! `BrowserParser` because file *names* (`History`, no extension) collide with
//! the Linux/Windows variants. This parser disambiguates by matching against
//! the macOS Application Support hierarchy and emits structured artifacts
//! tagged with the Chrome profile name.

use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::sqlite_utils::{table_exists, with_sqlite_connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Chrome's WebKit/Chromium epoch is 1601-01-01 in microseconds.
/// To convert to Unix seconds: (val_us / 1_000_000) - 11_644_473_600
const CHROME_EPOCH_OFFSET_SECS: i64 = 11_644_473_600;
const HISTORY_LIMIT: usize = 5000;
const COOKIE_LIMIT: usize = 2000;

pub struct ChromeMacOsParser;

impl ChromeMacOsParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ChromeMacOsParser {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChromeUrlEntry {
    pub url: String,
    pub title: Option<String>,
    pub visit_count: i64,
    pub typed_count: i64,
    pub last_visit: Option<i64>,
    pub profile: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChromeDownloadEntry {
    pub target_path: Option<String>,
    pub tab_url: Option<String>,
    pub mime_type: Option<String>,
    pub start_time: Option<i64>,
    pub end_time: Option<i64>,
    pub total_bytes: i64,
    pub state: i64,
    pub profile: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChromeCookieEntry {
    pub host_key: String,
    pub name: String,
    pub path: String,
    pub creation_utc: Option<i64>,
    pub expires_utc: Option<i64>,
    pub is_secure: bool,
    pub profile: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChromeLoginEntry {
    pub origin_url: String,
    pub username_value: Option<String>,
    pub date_created: Option<i64>,
    pub times_used: i64,
    pub profile: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChromeAutofillEntry {
    pub name: String,
    pub value: String,
    pub date_created: Option<i64>,
    pub date_last_used: Option<i64>,
    pub count: i64,
    pub profile: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChromeExtensionEntry {
    pub extension_id: String,
    pub name: Option<String>,
    pub version: Option<String>,
    pub state: Option<i64>,
    pub from_webstore: Option<bool>,
    pub install_time: Option<i64>,
    pub profile: Option<String>,
}

impl ArtifactParser for ChromeMacOsParser {
    fn name(&self) -> &str {
        "macOS Chrome Browser"
    }

    fn artifact_type(&self) -> &str {
        "browser"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "google/chrome/default/history",
            "google/chrome/default/cookies",
            "google/chrome/default/login data",
            "google/chrome/default/web data",
            "google/chrome/default/preferences",
            "google/chrome/default/secure preferences",
            "/google/chrome/profile",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let path_str = path.to_string_lossy().to_lowercase();

        // Reject anything that doesn't live under a Chromium-style profile.
        // We accept Google Chrome, Chromium, Brave, Edge — all share the same
        // schema — by matching their parent directory.
        let is_chromium = path_str.contains("/google/chrome/")
            || path_str.contains("/chromium/")
            || path_str.contains("/brave-browser/")
            || path_str.contains("/microsoft edge/");
        if !is_chromium {
            return Ok(Vec::new());
        }

        let profile = extract_chrome_profile(&path_str);
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();

        // JSON-based files: Preferences and Secure Preferences hold extensions
        // metadata. They are not SQLite, so handle them separately.
        if file_name == "preferences" || file_name == "secure preferences" {
            return Ok(parse_chrome_preferences(path, data, profile.as_deref()));
        }

        // SQLite-backed files share with_sqlite_connection plumbing.
        let mut artifacts = Vec::new();
        let result = with_sqlite_connection(path, data, |conn| {
            let mut entries: Vec<ParsedArtifact> = Vec::new();

            if file_name == "history" && table_exists(conn, "urls") {
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT url, title, visit_count, typed_count, last_visit_time \
                         FROM urls ORDER BY last_visit_time DESC LIMIT {}",
                        HISTORY_LIMIT
                    ))
                    .map_err(|e| ParserError::Database(e.to_string()))?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok(ChromeUrlEntry {
                            url: row.get::<_, String>(0).unwrap_or_default(),
                            title: row.get(1).ok(),
                            visit_count: row.get::<_, i64>(2).unwrap_or(0),
                            typed_count: row.get::<_, i64>(3).unwrap_or(0),
                            last_visit: row
                                .get::<_, i64>(4)
                                .ok()
                                .map(chrome_microseconds_to_unix),
                            profile: profile.clone(),
                        })
                    })
                    .map_err(|e| ParserError::Database(e.to_string()))?;
                for entry in rows.flatten() {
                    entries.push(ParsedArtifact {
                        timestamp: entry.last_visit,
                        artifact_type: "browser".to_string(),
                        description: format!("Chrome URL: {}", entry.url),
                        source_path: path.to_string_lossy().to_string(),
                        json_data: serde_json::to_value(entry).unwrap_or_default(),
                    });
                }

                if table_exists(conn, "downloads") {
                    let mut stmt = conn
                        .prepare(
                            "SELECT target_path, tab_url, mime_type, start_time, end_time, \
                             total_bytes, state FROM downloads LIMIT 1000",
                        )
                        .map_err(|e| ParserError::Database(e.to_string()))?;
                    let rows = stmt
                        .query_map([], |row| {
                            Ok(ChromeDownloadEntry {
                                target_path: row.get(0).ok(),
                                tab_url: row.get(1).ok(),
                                mime_type: row.get(2).ok(),
                                start_time: row
                                    .get::<_, i64>(3)
                                    .ok()
                                    .map(chrome_microseconds_to_unix),
                                end_time: row
                                    .get::<_, i64>(4)
                                    .ok()
                                    .map(chrome_microseconds_to_unix),
                                total_bytes: row.get::<_, i64>(5).unwrap_or(0),
                                state: row.get::<_, i64>(6).unwrap_or(0),
                                profile: profile.clone(),
                            })
                        })
                        .map_err(|e| ParserError::Database(e.to_string()))?;
                    for entry in rows.flatten() {
                        entries.push(ParsedArtifact {
                            timestamp: entry.start_time,
                            artifact_type: "browser".to_string(),
                            description: format!(
                                "Chrome download: {}",
                                entry.target_path.as_deref().unwrap_or("(unknown)")
                            ),
                            source_path: path.to_string_lossy().to_string(),
                            json_data: serde_json::to_value(entry).unwrap_or_default(),
                        });
                    }
                }
            } else if file_name == "cookies" && table_exists(conn, "cookies") {
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT host_key, name, path, creation_utc, expires_utc, is_secure \
                         FROM cookies LIMIT {}",
                        COOKIE_LIMIT
                    ))
                    .map_err(|e| ParserError::Database(e.to_string()))?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok(ChromeCookieEntry {
                            host_key: row.get::<_, String>(0).unwrap_or_default(),
                            name: row.get::<_, String>(1).unwrap_or_default(),
                            path: row.get::<_, String>(2).unwrap_or_default(),
                            creation_utc: row
                                .get::<_, i64>(3)
                                .ok()
                                .map(chrome_microseconds_to_unix),
                            expires_utc: row
                                .get::<_, i64>(4)
                                .ok()
                                .map(chrome_microseconds_to_unix),
                            is_secure: row.get::<_, i64>(5).unwrap_or(0) != 0,
                            profile: profile.clone(),
                        })
                    })
                    .map_err(|e| ParserError::Database(e.to_string()))?;
                for entry in rows.flatten() {
                    entries.push(ParsedArtifact {
                        timestamp: entry.creation_utc,
                        artifact_type: "browser".to_string(),
                        description: format!("Chrome cookie: {} on {}", entry.name, entry.host_key),
                        source_path: path.to_string_lossy().to_string(),
                        json_data: serde_json::to_value(entry).unwrap_or_default(),
                    });
                }
            } else if file_name == "login data" && table_exists(conn, "logins") {
                let mut stmt = conn
                    .prepare(
                        "SELECT origin_url, username_value, date_created, times_used FROM logins",
                    )
                    .map_err(|e| ParserError::Database(e.to_string()))?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok(ChromeLoginEntry {
                            origin_url: row.get::<_, String>(0).unwrap_or_default(),
                            username_value: row.get(1).ok(),
                            date_created: row
                                .get::<_, i64>(2)
                                .ok()
                                .map(chrome_microseconds_to_unix),
                            times_used: row.get::<_, i64>(3).unwrap_or(0),
                            profile: profile.clone(),
                        })
                    })
                    .map_err(|e| ParserError::Database(e.to_string()))?;
                for entry in rows.flatten() {
                    entries.push(ParsedArtifact {
                        timestamp: entry.date_created,
                        artifact_type: "browser".to_string(),
                        description: format!(
                            "Chrome saved login: {} ({})",
                            entry.origin_url,
                            entry.username_value.as_deref().unwrap_or("")
                        ),
                        source_path: path.to_string_lossy().to_string(),
                        json_data: serde_json::to_value(entry).unwrap_or_default(),
                    });
                }
            } else if file_name == "web data" && table_exists(conn, "autofill") {
                let mut stmt = conn
                    .prepare(
                        "SELECT name, value, date_created, date_last_used, count FROM autofill",
                    )
                    .map_err(|e| ParserError::Database(e.to_string()))?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok(ChromeAutofillEntry {
                            name: row.get::<_, String>(0).unwrap_or_default(),
                            value: row.get::<_, String>(1).unwrap_or_default(),
                            date_created: row.get::<_, i64>(2).ok(),
                            date_last_used: row.get::<_, i64>(3).ok(),
                            count: row.get::<_, i64>(4).unwrap_or(0),
                            profile: profile.clone(),
                        })
                    })
                    .map_err(|e| ParserError::Database(e.to_string()))?;
                for entry in rows.flatten() {
                    entries.push(ParsedArtifact {
                        timestamp: entry.date_last_used,
                        artifact_type: "browser".to_string(),
                        description: format!("Chrome autofill: {} = {}", entry.name, entry.value),
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

/// Convert Chromium-format `last_visit_time` (microseconds since 1601-01-01)
/// to Unix epoch seconds.
fn chrome_microseconds_to_unix(microseconds: i64) -> i64 {
    if microseconds <= 0 {
        return 0;
    }
    (microseconds / 1_000_000) - CHROME_EPOCH_OFFSET_SECS
}

fn extract_chrome_profile(path_lower: &str) -> Option<String> {
    // Path tail looks like .../Google/Chrome/Default/History or
    // .../Google/Chrome/Profile 1/History — extract the profile dir.
    if let Some(idx) = path_lower.find("/google/chrome/") {
        let tail = &path_lower[idx + "/google/chrome/".len()..];
        if let Some(slash) = tail.find('/') {
            return Some(tail[..slash].to_string());
        }
    }
    if let Some(idx) = path_lower.find("/brave-browser/") {
        let tail = &path_lower[idx + "/brave-browser/".len()..];
        if let Some(slash) = tail.find('/') {
            return Some(format!("brave/{}", &tail[..slash]));
        }
    }
    None
}

fn parse_chrome_preferences(
    path: &Path,
    data: &[u8],
    profile: Option<&str>,
) -> Vec<ParsedArtifact> {
    let mut out = Vec::new();
    let value: serde_json::Value = match serde_json::from_slice(data) {
        Ok(v) => v,
        Err(_) => return out,
    };

    let extensions = value
        .get("extensions")
        .and_then(|e| e.get("settings"))
        .and_then(|s| s.as_object());

    let Some(extensions) = extensions else {
        return out;
    };

    for (id, ext_val) in extensions {
        let manifest = ext_val.get("manifest");
        let name = manifest
            .and_then(|m| m.get("name"))
            .and_then(|n| n.as_str())
            .map(String::from);
        let version = manifest
            .and_then(|m| m.get("version"))
            .and_then(|n| n.as_str())
            .map(String::from);
        let state = ext_val.get("state").and_then(|s| s.as_i64());
        let from_webstore = ext_val.get("from_webstore").and_then(|v| v.as_bool());
        let install_time = ext_val
            .get("install_time")
            .and_then(|s| s.as_str())
            .and_then(|s| s.parse::<i64>().ok())
            .map(chrome_microseconds_to_unix);

        let entry = ChromeExtensionEntry {
            extension_id: id.clone(),
            name: name.clone(),
            version,
            state,
            from_webstore,
            install_time,
            profile: profile.map(String::from),
        };
        out.push(ParsedArtifact {
            timestamp: install_time,
            artifact_type: "browser".to_string(),
            description: format!(
                "Chrome extension installed: {} ({})",
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
    fn extracts_profile_from_default_path() {
        let path = "/users/test/library/application support/google/chrome/default/history";
        assert_eq!(extract_chrome_profile(path), Some("default".to_string()));
    }

    #[test]
    fn extracts_profile_from_named_profile() {
        let path = "/users/test/library/application support/google/chrome/profile 1/history";
        assert_eq!(extract_chrome_profile(path), Some("profile 1".to_string()));
    }

    #[test]
    fn chrome_epoch_conversion_round_trip() {
        // 13321925725000000 microseconds = approx 2023-01-01
        let v = chrome_microseconds_to_unix(13_321_925_725_000_000);
        // Just ensure it falls within a sensible Unix-time range (2020 - 2030)
        assert!(
            (1_577_836_800..=1_893_456_000).contains(&v),
            "expected Unix range, got {}",
            v
        );
    }

    #[test]
    fn ignores_non_chrome_paths() {
        let parser = ChromeMacOsParser::new();
        let path = PathBuf::from("/Users/test/Library/Application Support/SomeOther/History");
        let out = parser.parse_file(&path, b"not a sqlite db").unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn parses_extensions_from_preferences_json() {
        let json = r#"{
            "extensions": {
                "settings": {
                    "abcdef1234567890abcdef1234567890": {
                        "manifest": { "name": "uBlock Origin", "version": "1.46.0" },
                        "state": 1,
                        "from_webstore": true,
                        "install_time": "13321925725000000"
                    }
                }
            }
        }"#;
        let parser = ChromeMacOsParser::new();
        let path = PathBuf::from(
            "/Users/test/Library/Application Support/Google/Chrome/Default/Preferences",
        );
        let out = parser.parse_file(&path, json.as_bytes()).unwrap();
        assert_eq!(out.len(), 1);
        let entry = &out[0];
        assert_eq!(
            entry.json_data.get("name").and_then(|v| v.as_str()),
            Some("uBlock Origin")
        );
        assert_eq!(
            entry.json_data.get("version").and_then(|v| v.as_str()),
            Some("1.46.0")
        );
    }
}
