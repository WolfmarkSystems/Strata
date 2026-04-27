use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::sqlite_utils::{table_exists, with_sqlite_connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Browser Autofill and Saved Password Parser
///
/// Parses:
///   - Chrome/Edge/Brave: Login Data (SQLite), Web Data (SQLite)
///   - Firefox: logins.json, key4.db
///
/// Forensic value: Saved passwords and form data are critical for fraud,
/// unauthorized access, and identity theft investigations. Proves what
/// credentials existed on the system and what forms were filled.
///
/// Note: Actual password values are encrypted (DPAPI on Windows, Keychain on macOS).
/// This parser extracts metadata (URLs, usernames, timestamps) without decrypting.
pub struct BrowserAutofillParser;

impl Default for BrowserAutofillParser {
    fn default() -> Self {
        Self::new()
    }
}

impl BrowserAutofillParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SavedCredentialEntry {
    pub origin_url: Option<String>,
    pub action_url: Option<String>,
    pub username: Option<String>,
    pub date_created: Option<i64>,
    pub date_last_used: Option<i64>,
    pub times_used: Option<i32>,
    pub password_encrypted: bool,
    pub browser: String,
    pub blacklisted_by_user: Option<bool>,
    pub scheme: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AutofillEntry {
    pub name: Option<String>,
    pub value: Option<String>,
    pub date_created: Option<i64>,
    pub date_last_used: Option<i64>,
    pub count: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreditCardEntry {
    pub name_on_card: Option<String>,
    pub card_number_last_four: Option<String>,
    pub expiration_month: Option<i32>,
    pub expiration_year: Option<i32>,
    pub date_modified: Option<i64>,
    pub origin: Option<String>,
    pub billing_address_id: Option<String>,
}

impl ArtifactParser for BrowserAutofillParser {
    fn name(&self) -> &str {
        "Browser Autofill/Password Parser"
    }

    fn artifact_type(&self) -> &str {
        "credentials"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "Login Data",
            "Login Data-journal",
            "Web Data",
            "Web Data-journal",
            "logins.json",
            "key4.db",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let filename_lower = filename.to_lowercase();

        if filename_lower == "logins.json" {
            return self.parse_firefox_logins(path, data);
        }

        if filename_lower.starts_with("login data") {
            return self.parse_chromium_login_data(path, data);
        }

        if filename_lower.starts_with("web data") {
            return self.parse_chromium_web_data(path, data);
        }

        Ok(vec![])
    }
}

impl BrowserAutofillParser {
    fn parse_chromium_login_data(
        &self,
        path: &Path,
        data: &[u8],
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();
        let browser = detect_browser_from_path(path);

        let sqlite_result = with_sqlite_connection(path, data, |conn| {
            let mut entries = Vec::new();

            if table_exists(conn, "logins") {
                let mut stmt = conn
                    .prepare(
                        "SELECT
                            origin_url,
                            action_url,
                            username_value,
                            date_created,
                            date_last_used,
                            times_used,
                            blacklisted_by_user,
                            scheme
                         FROM logins
                         ORDER BY date_last_used DESC
                         LIMIT 10000",
                    )
                    .map_err(|e| ParserError::Database(e.to_string()))?;

                let rows = stmt
                    .query_map([], |row| {
                        Ok(SavedCredentialEntry {
                            origin_url: row.get(0).ok(),
                            action_url: row.get(1).ok(),
                            username: row.get(2).ok(),
                            date_created: chromium_time_to_epoch(row.get::<_, i64>(3).ok()),
                            date_last_used: chromium_time_to_epoch(row.get::<_, i64>(4).ok()),
                            times_used: row.get(5).ok(),
                            password_encrypted: true,
                            browser: browser.clone(),
                            blacklisted_by_user: row.get::<_, bool>(6).ok(),
                            scheme: row.get(7).ok(),
                        })
                    })
                    .map_err(|e| ParserError::Database(e.to_string()))?;

                for row in rows.flatten() {
                    let url = row.origin_url.as_deref().unwrap_or("unknown");
                    let user = row.username.as_deref().unwrap_or("(empty)");
                    let times = row.times_used.unwrap_or(0);

                    entries.push(ParsedArtifact {
                        timestamp: row.date_last_used.or(row.date_created),
                        artifact_type: "saved_credential".to_string(),
                        description: format!(
                            "Saved Login [{}]: {} — user: {} (used {} times)",
                            browser, url, user, times,
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

    fn parse_chromium_web_data(
        &self,
        path: &Path,
        data: &[u8],
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();
        let browser = detect_browser_from_path(path);

        let sqlite_result = with_sqlite_connection(path, data, |conn| {
            let mut entries = Vec::new();

            // Autofill entries
            if table_exists(conn, "autofill") {
                let mut stmt = conn
                    .prepare(
                        "SELECT name, value, date_created, date_last_used, count
                         FROM autofill
                         ORDER BY date_last_used DESC
                         LIMIT 10000",
                    )
                    .map_err(|e| ParserError::Database(e.to_string()))?;

                let rows = stmt
                    .query_map([], |row| {
                        Ok(AutofillEntry {
                            name: row.get(0).ok(),
                            value: row.get(1).ok(),
                            date_created: chromium_time_to_epoch(row.get::<_, i64>(2).ok()),
                            date_last_used: chromium_time_to_epoch(row.get::<_, i64>(3).ok()),
                            count: row.get(4).ok(),
                        })
                    })
                    .map_err(|e| ParserError::Database(e.to_string()))?;

                for row in rows.flatten() {
                    let field = row.name.as_deref().unwrap_or("unknown");
                    let value = row.value.as_deref().unwrap_or("");
                    let value_preview = if value.len() > 50 {
                        format!("{}...", &value[..50])
                    } else {
                        value.to_string()
                    };

                    entries.push(ParsedArtifact {
                        timestamp: row.date_last_used.or(row.date_created),
                        artifact_type: "autofill_entry".to_string(),
                        description: format!(
                            "Autofill [{}]: {} = {} (used {} times)",
                            browser,
                            field,
                            value_preview,
                            row.count.unwrap_or(0),
                        ),
                        source_path: source.clone(),
                        json_data: serde_json::to_value(&row).unwrap_or_default(),
                    });
                }
            }

            // Credit card entries (metadata only — number is encrypted)
            if table_exists(conn, "credit_cards") {
                let mut stmt = conn
                    .prepare(
                        "SELECT
                            name_on_card,
                            expiration_month,
                            expiration_year,
                            date_modified,
                            origin,
                            billing_address_id
                         FROM credit_cards
                         LIMIT 1000",
                    )
                    .map_err(|e| ParserError::Database(e.to_string()))?;

                let rows = stmt
                    .query_map([], |row| {
                        Ok(CreditCardEntry {
                            name_on_card: row.get(0).ok(),
                            card_number_last_four: None,
                            expiration_month: row.get(1).ok(),
                            expiration_year: row.get(2).ok(),
                            date_modified: chromium_time_to_epoch(row.get::<_, i64>(3).ok()),
                            origin: row.get(4).ok(),
                            billing_address_id: row.get(5).ok(),
                        })
                    })
                    .map_err(|e| ParserError::Database(e.to_string()))?;

                for row in rows.flatten() {
                    entries.push(ParsedArtifact {
                        timestamp: row.date_modified,
                        artifact_type: "credit_card".to_string(),
                        description: format!(
                            "Saved Card [{}]: {} (exp {}/{})",
                            browser,
                            row.name_on_card.as_deref().unwrap_or("unknown"),
                            row.expiration_month.unwrap_or(0),
                            row.expiration_year.unwrap_or(0),
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

    fn parse_firefox_logins(
        &self,
        path: &Path,
        data: &[u8],
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();

        let Ok(json) = serde_json::from_slice::<serde_json::Value>(data) else {
            return Ok(artifacts);
        };

        if let Some(logins) = json.get("logins").and_then(|l| l.as_array()) {
            for login in logins.iter().take(10000) {
                let hostname = login
                    .get("hostname")
                    .and_then(|h| h.as_str())
                    .unwrap_or("unknown");
                let username = login
                    .get("encryptedUsername")
                    .and_then(|u| u.as_str())
                    .map(|_| "[encrypted]")
                    .unwrap_or("unknown");
                let time_created = login
                    .get("timeCreated")
                    .and_then(|t| t.as_i64())
                    .map(|ms| ms / 1000);
                let time_last_used = login
                    .get("timeLastUsed")
                    .and_then(|t| t.as_i64())
                    .map(|ms| ms / 1000);
                let times_used = login.get("timesUsed").and_then(|t| t.as_i64()).unwrap_or(0);

                artifacts.push(ParsedArtifact {
                    timestamp: time_last_used.or(time_created),
                    artifact_type: "saved_credential".to_string(),
                    description: format!(
                        "Saved Login [Firefox]: {} — user: {} (used {} times)",
                        hostname, username, times_used,
                    ),
                    source_path: source.clone(),
                    json_data: serde_json::json!({
                        "origin_url": hostname,
                        "username": username,
                        "date_created": time_created,
                        "date_last_used": time_last_used,
                        "times_used": times_used,
                        "password_encrypted": true,
                        "browser": "Firefox",
                    }),
                });
            }
        }

        Ok(artifacts)
    }
}

/// Chromium timestamps are microseconds since 1601-01-01
fn chromium_time_to_epoch(chromium_ts: Option<i64>) -> Option<i64> {
    chromium_ts.and_then(|ts| {
        if ts <= 0 {
            return None;
        }
        // Chromium epoch offset from Unix epoch in microseconds
        let epoch_offset: i64 = 11_644_473_600_000_000;
        let unix_us = ts - epoch_offset;
        if unix_us > 0 {
            Some(unix_us / 1_000_000)
        } else {
            None
        }
    })
}

fn detect_browser_from_path(path: &Path) -> String {
    let path_str = path.to_string_lossy().to_lowercase();
    if path_str.contains("brave") {
        "Brave".to_string()
    } else if path_str.contains("edge") {
        "Edge".to_string()
    } else if path_str.contains("chrome") {
        "Chrome".to_string()
    } else if path_str.contains("chromium") {
        "Chromium".to_string()
    } else if path_str.contains("opera") {
        "Opera".to_string()
    } else if path_str.contains("vivaldi") {
        "Vivaldi".to_string()
    } else {
        "Chromium-based".to_string()
    }
}
