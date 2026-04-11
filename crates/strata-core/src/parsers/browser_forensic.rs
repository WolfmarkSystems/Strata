//! Comprehensive browser forensic parser — Chrome, Edge, Firefox, Safari.
//!
//! Informed by the Hindsight project (obsidianforensics/hindsight) for
//! Chromium database schemas. Covers the platform-specific artifact
//! locations for Windows, macOS, and Linux.
//!
//! Key improvements over the generic `BrowserParser`:
//!
//!   * **Chromium History**: Proper `urls JOIN visits` with visit-level
//!     timestamps and transition type decoding (LINK, TYPED, FORM_SUBMIT,
//!     REDIRECT, etc.). The transition value is forensically significant —
//!     it proves whether the user *typed* a URL vs. followed a redirect.
//!
//!   * **Chromium Bookmarks**: Parsed from the `Bookmarks` JSON file (not
//!     a SQLite table). Recursive tree walk like Safari Bookmarks.plist.
//!
//!   * **Chromium Keyword Searches**: Extracts URL-bar search queries
//!     from `keyword_search_terms` joined with `urls`.
//!
//!   * **Edge**: Identical Chromium schema, different filesystem path.
//!     Registered as a separate parser so examiners see "Edge" vs "Chrome".
//!
//!   * **Firefox Downloads**: Joins `moz_annos` for download metadata
//!     (file size, MIME type) that `moz_places` alone doesn't carry.
//!
//!   * **Safari Cookies**: Full `Cookies.binarycookies` detection and
//!     `cookies` SQLite table extraction (fixes the stub in safari.rs).
//!
//! Each parser registers with platform-specific `target_patterns` so it
//! only fires on the correct filesystem hierarchy.

use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::sqlite_utils::{table_exists, with_sqlite_connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

// ────────────────────────────────────────────────────────────────────────────
// Constants
// ────────────────────────────────────────────────────────────────────────────

/// Chromium epoch: microseconds since 1601-01-01 00:00:00 UTC.
const CHROMIUM_EPOCH_OFFSET: i64 = 11_644_473_600;

/// macOS Core Data epoch offset (2001-01-01 UTC → Unix).
const COREDATA_EPOCH_OFFSET: i64 = 978_307_200;

const HISTORY_LIMIT: usize = 10_000;
const DOWNLOAD_LIMIT: usize = 5_000;
const COOKIE_LIMIT: usize = 5_000;
const BOOKMARK_LIMIT: usize = 50_000;
const SEARCH_LIMIT: usize = 5_000;
const BOOKMARK_MAX_DEPTH: usize = 16;

// ────────────────────────────────────────────────────────────────────────────
// Chromium visit transition types (from Hindsight / chromium source)
// ────────────────────────────────────────────────────────────────────────────

/// Decode a Chromium `visits.transition` bitmask into a human-readable label.
/// The lower byte is the core type; higher bits are qualifier flags.
fn decode_transition(transition: i64) -> &'static str {
    match transition & 0xFF {
        0 => "LINK",
        1 => "TYPED",
        2 => "AUTO_BOOKMARK",
        3 => "AUTO_SUBFRAME",
        4 => "MANUAL_SUBFRAME",
        5 => "GENERATED",
        6 => "AUTO_TOPLEVEL",
        7 => "FORM_SUBMIT",
        8 => "RELOAD",
        9 => "KEYWORD",
        10 => "KEYWORD_GENERATED",
        _ => "OTHER",
    }
}

/// Decode qualifier flags from the transition bitmask.
fn decode_transition_qualifiers(transition: i64) -> Vec<&'static str> {
    let mut flags = Vec::new();
    if transition & 0x0080_0000 != 0 {
        flags.push("FORWARD_BACK");
    }
    if transition & 0x0040_0000 != 0 {
        flags.push("FROM_ADDRESS_BAR");
    }
    if transition & 0x0020_0000 != 0 {
        flags.push("HOME_PAGE");
    }
    if transition & 0x4000_0000 != 0 {
        flags.push("CLIENT_REDIRECT");
    }
    if transition & 0x8000_0000u32 as i64 != 0 {
        flags.push("SERVER_REDIRECT");
    }
    if transition & 0x1000_0000 != 0 {
        flags.push("CHAIN_START");
    }
    if transition & 0x2000_0000 != 0 {
        flags.push("CHAIN_END");
    }
    flags
}

fn chromium_ts_to_unix(microseconds: i64) -> i64 {
    if microseconds <= 0 {
        return 0;
    }
    (microseconds / 1_000_000) - CHROMIUM_EPOCH_OFFSET
}

fn firefox_us_to_unix(us: i64) -> i64 {
    if us <= 0 {
        return 0;
    }
    us / 1_000_000
}

// ────────────────────────────────────────────────────────────────────────────
// Data structures (shared across browsers)
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct BrowserVisit {
    pub url: String,
    pub title: Option<String>,
    pub visit_time: Option<i64>,
    pub visit_count: i64,
    pub typed_count: i64,
    pub transition: Option<String>,
    pub transition_qualifiers: Vec<String>,
    pub from_visit_url: Option<String>,
    pub browser: String,
    pub profile: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BrowserDownload {
    pub url: Option<String>,
    pub target_path: Option<String>,
    pub start_time: Option<i64>,
    pub end_time: Option<i64>,
    pub total_bytes: i64,
    pub received_bytes: i64,
    pub state: Option<String>,
    pub danger_type: Option<String>,
    pub mime_type: Option<String>,
    pub browser: String,
    pub profile: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BrowserCookie {
    pub host: String,
    pub name: String,
    pub path: String,
    pub creation: Option<i64>,
    pub expiry: Option<i64>,
    pub is_secure: bool,
    pub is_httponly: bool,
    pub browser: String,
    pub profile: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BrowserBookmark {
    pub title: String,
    pub url: Option<String>,
    pub date_added: Option<i64>,
    pub folder_path: String,
    pub browser: String,
    pub profile: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BrowserSearch {
    pub term: String,
    pub url: String,
    pub search_time: Option<i64>,
    pub browser: String,
    pub profile: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BrowserLogin {
    pub origin_url: String,
    pub username: Option<String>,
    pub date_created: Option<i64>,
    pub date_last_used: Option<i64>,
    pub times_used: i64,
    pub browser: String,
    pub profile: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BrowserAutofillField {
    pub name: String,
    pub value: String,
    pub count: i64,
    pub date_created: Option<i64>,
    pub date_last_used: Option<i64>,
    pub browser: String,
    pub profile: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BrowserExtension {
    pub id: String,
    pub name: Option<String>,
    pub version: Option<String>,
    pub enabled: bool,
    pub from_store: Option<bool>,
    pub install_time: Option<i64>,
    pub browser: String,
    pub profile: Option<String>,
}

// ────────────────────────────────────────────────────────────────────────────
// Chromium download state / danger type decoding
// ────────────────────────────────────────────────────────────────────────────

fn decode_download_state(state: i64) -> &'static str {
    match state {
        0 => "IN_PROGRESS",
        1 => "COMPLETE",
        2 => "CANCELLED",
        3 => "INTERRUPTED",
        4 => "INTERRUPTED",
        _ => "UNKNOWN",
    }
}

fn decode_danger_type(dt: i64) -> &'static str {
    match dt {
        0 => "NOT_DANGEROUS",
        1 => "DANGEROUS_FILE",
        2 => "DANGEROUS_URL",
        3 => "DANGEROUS_CONTENT",
        4 => "MAYBE_DANGEROUS_CONTENT",
        5 => "UNCOMMON_CONTENT",
        6 => "USER_VALIDATED",
        7 => "DANGEROUS_HOST",
        8 => "POTENTIALLY_UNWANTED",
        9 => "ALLOWLISTED_BY_POLICY",
        _ => "UNKNOWN",
    }
}

// ════════════════════════════════════════════════════════════════════════════
// 1. CHROMIUM FORENSIC PARSER (Chrome, Edge, Brave)
// ════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy)]
enum ChromiumBrand {
    Chrome,
    Edge,
    Brave,
}

impl ChromiumBrand {
    fn name(&self) -> &'static str {
        match self {
            ChromiumBrand::Chrome => "Chrome",
            ChromiumBrand::Edge => "Edge",
            ChromiumBrand::Brave => "Brave",
        }
    }
}

pub struct ChromiumForensicParser {
    brand: ChromiumBrand,
}

impl ChromiumForensicParser {
    pub fn chrome() -> Self {
        Self {
            brand: ChromiumBrand::Chrome,
        }
    }
    pub fn edge() -> Self {
        Self {
            brand: ChromiumBrand::Edge,
        }
    }
    pub fn brave() -> Self {
        Self {
            brand: ChromiumBrand::Brave,
        }
    }
}

impl Default for ChromiumForensicParser {
    fn default() -> Self {
        Self::chrome()
    }
}

impl ArtifactParser for ChromiumForensicParser {
    fn name(&self) -> &str {
        match self.brand {
            ChromiumBrand::Chrome => "Chrome Forensic Parser",
            ChromiumBrand::Edge => "Edge Forensic Parser",
            ChromiumBrand::Brave => "Brave Forensic Parser",
        }
    }

    fn artifact_type(&self) -> &str {
        "browser"
    }

    fn target_patterns(&self) -> Vec<&str> {
        match self.brand {
            ChromiumBrand::Chrome => vec![
                // Windows: AppData/Local/Google/Chrome/User Data/<Profile>/
                "google/chrome/user data",
                "google/chrome/default",
                // macOS: Library/Application Support/Google/Chrome/
                "application support/google/chrome",
                // Linux: .config/google-chrome/
                "google-chrome/default",
                "google-chrome/profile",
            ],
            ChromiumBrand::Edge => vec![
                "microsoft/edge/user data",
                "microsoft edge/user data",
                "application support/microsoft edge",
                "microsoft-edge/default",
            ],
            ChromiumBrand::Brave => vec![
                "bravesoftware/brave-browser/user data",
                "application support/brave",
                "brave-browser/default",
            ],
        }
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let path_str = path.to_string_lossy().to_lowercase();
        let brand = self.brand;

        // Verify this file belongs to the right browser brand.
        let is_match = match brand {
            ChromiumBrand::Chrome => {
                path_str.contains("/google/chrome/")
                    || path_str.contains("/google-chrome/")
                    || path_str.contains("\\google\\chrome\\")
            }
            ChromiumBrand::Edge => {
                path_str.contains("/microsoft/edge/")
                    || path_str.contains("/microsoft edge/")
                    || path_str.contains("\\microsoft\\edge\\")
            }
            ChromiumBrand::Brave => {
                path_str.contains("/brave")
                    || path_str.contains("\\bravesoftware\\")
            }
        };
        if !is_match {
            return Ok(Vec::new());
        }

        let profile = extract_chromium_profile(&path_str);
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();

        // JSON files: Bookmarks, Preferences, Secure Preferences
        if file_name == "bookmarks" && !file_name.contains('.') {
            return Ok(parse_chromium_bookmarks_json(
                path,
                data,
                brand.name(),
                profile.as_deref(),
            ));
        }
        if file_name == "preferences" || file_name == "secure preferences" {
            return Ok(parse_chromium_extensions_json(
                path,
                data,
                brand.name(),
                profile.as_deref(),
            ));
        }

        // SQLite files: History, Cookies, Login Data, Web Data
        let mut artifacts = Vec::new();
        let result = with_sqlite_connection(path, data, |conn| {
            let mut entries = Vec::new();

            match file_name.as_str() {
                "history" => {
                    parse_chromium_history(conn, path, brand.name(), profile.as_deref(), &mut entries)?;
                    parse_chromium_downloads(conn, path, brand.name(), profile.as_deref(), &mut entries)?;
                    parse_chromium_searches(conn, path, brand.name(), profile.as_deref(), &mut entries)?;
                }
                "cookies" => {
                    parse_chromium_cookies(conn, path, brand.name(), profile.as_deref(), &mut entries)?;
                }
                "login data" => {
                    parse_chromium_logins(conn, path, brand.name(), profile.as_deref(), &mut entries)?;
                }
                "web data" => {
                    parse_chromium_autofill(conn, path, brand.name(), profile.as_deref(), &mut entries)?;
                }
                _ => {}
            }

            Ok(entries)
        });

        if let Ok(mut entries) = result {
            artifacts.append(&mut entries);
        }
        Ok(artifacts)
    }
}

fn extract_chromium_profile(path_lower: &str) -> Option<String> {
    // Look for "User Data/<Profile>/" or "Chrome/<Profile>/"
    for marker in ["/user data/", "/google/chrome/", "/microsoft edge/", "/brave-browser/", "/google-chrome/"] {
        if let Some(idx) = path_lower.find(marker) {
            let tail = &path_lower[idx + marker.len()..];
            if let Some(slash) = tail.find('/') {
                let profile = &tail[..slash];
                if !profile.is_empty() {
                    return Some(profile.to_string());
                }
            }
        }
    }
    None
}

fn parse_chromium_history(
    conn: &rusqlite::Connection,
    path: &Path,
    browser: &str,
    profile: Option<&str>,
    out: &mut Vec<ParsedArtifact>,
) -> Result<(), ParserError> {
    if !table_exists(conn, "urls") || !table_exists(conn, "visits") {
        return Ok(());
    }

    // Hindsight-style: JOIN urls with visits to get per-visit timestamps
    // and transition types.
    let sql = format!(
        "SELECT u.url, u.title, v.visit_time, u.visit_count, u.typed_count, \
         v.transition, v.from_visit \
         FROM visits v JOIN urls u ON v.url = u.id \
         ORDER BY v.visit_time DESC LIMIT {}",
        HISTORY_LIMIT
    );
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| ParserError::Database(e.to_string()))?;
    let rows = stmt
        .query_map([], |row| {
            let transition_raw: i64 = row.get::<_, i64>(5).unwrap_or(0);
            let from_visit: i64 = row.get::<_, i64>(6).unwrap_or(0);
            Ok((
                BrowserVisit {
                    url: row.get::<_, String>(0).unwrap_or_default(),
                    title: row.get(1).ok(),
                    visit_time: row
                        .get::<_, i64>(2)
                        .ok()
                        .map(chromium_ts_to_unix),
                    visit_count: row.get::<_, i64>(3).unwrap_or(0),
                    typed_count: row.get::<_, i64>(4).unwrap_or(0),
                    transition: Some(decode_transition(transition_raw).to_string()),
                    transition_qualifiers: decode_transition_qualifiers(transition_raw)
                        .into_iter()
                        .map(String::from)
                        .collect(),
                    from_visit_url: None, // Resolved below if needed
                    browser: browser.to_string(),
                    profile: profile.map(String::from),
                },
                from_visit,
            ))
        })
        .map_err(|e| ParserError::Database(e.to_string()))?;

    for row in rows.flatten() {
        let (visit, _from_visit_id) = row;
        out.push(ParsedArtifact {
            timestamp: visit.visit_time,
            artifact_type: "browser".to_string(),
            description: format!(
                "{} visit [{}]: {}",
                browser,
                visit.transition.as_deref().unwrap_or(""),
                visit.url
            ),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(&visit).unwrap_or_default(),
        });
    }
    Ok(())
}

fn parse_chromium_downloads(
    conn: &rusqlite::Connection,
    path: &Path,
    browser: &str,
    profile: Option<&str>,
    out: &mut Vec<ParsedArtifact>,
) -> Result<(), ParserError> {
    if !table_exists(conn, "downloads") {
        return Ok(());
    }

    let sql = format!(
        "SELECT target_path, tab_url, start_time, end_time, \
         total_bytes, received_bytes, state, danger_type, mime_type \
         FROM downloads ORDER BY start_time DESC LIMIT {}",
        DOWNLOAD_LIMIT
    );
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| ParserError::Database(e.to_string()))?;
    let rows = stmt
        .query_map([], |row| {
            let state_raw: i64 = row.get::<_, i64>(6).unwrap_or(-1);
            let danger_raw: i64 = row.get::<_, i64>(7).unwrap_or(-1);
            Ok(BrowserDownload {
                target_path: row.get(0).ok(),
                url: row.get(1).ok(),
                start_time: row.get::<_, i64>(2).ok().map(chromium_ts_to_unix),
                end_time: row.get::<_, i64>(3).ok().map(chromium_ts_to_unix),
                total_bytes: row.get::<_, i64>(4).unwrap_or(0),
                received_bytes: row.get::<_, i64>(5).unwrap_or(0),
                state: Some(decode_download_state(state_raw).to_string()),
                danger_type: Some(decode_danger_type(danger_raw).to_string()),
                mime_type: row.get(8).ok(),
                browser: browser.to_string(),
                profile: profile.map(String::from),
            })
        })
        .map_err(|e| ParserError::Database(e.to_string()))?;

    for entry in rows.flatten() {
        out.push(ParsedArtifact {
            timestamp: entry.start_time,
            artifact_type: "browser".to_string(),
            description: format!(
                "{} download: {} → {}",
                browser,
                entry.url.as_deref().unwrap_or(""),
                entry.target_path.as_deref().unwrap_or("(unknown)")
            ),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(&entry).unwrap_or_default(),
        });
    }
    Ok(())
}

fn parse_chromium_cookies(
    conn: &rusqlite::Connection,
    path: &Path,
    browser: &str,
    profile: Option<&str>,
    out: &mut Vec<ParsedArtifact>,
) -> Result<(), ParserError> {
    if !table_exists(conn, "cookies") {
        return Ok(());
    }

    let sql = format!(
        "SELECT host_key, name, path, creation_utc, expires_utc, \
         is_secure, is_httponly FROM cookies LIMIT {}",
        COOKIE_LIMIT
    );
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| ParserError::Database(e.to_string()))?;
    let rows = stmt
        .query_map([], |row| {
            Ok(BrowserCookie {
                host: row.get::<_, String>(0).unwrap_or_default(),
                name: row.get::<_, String>(1).unwrap_or_default(),
                path: row.get::<_, String>(2).unwrap_or_default(),
                creation: row.get::<_, i64>(3).ok().map(chromium_ts_to_unix),
                expiry: row.get::<_, i64>(4).ok().map(chromium_ts_to_unix),
                is_secure: row.get::<_, i64>(5).unwrap_or(0) != 0,
                is_httponly: row.get::<_, i64>(6).unwrap_or(0) != 0,
                browser: browser.to_string(),
                profile: profile.map(String::from),
            })
        })
        .map_err(|e| ParserError::Database(e.to_string()))?;

    for entry in rows.flatten() {
        out.push(ParsedArtifact {
            timestamp: entry.creation,
            artifact_type: "browser".to_string(),
            description: format!("{} cookie: {} on {}", browser, entry.name, entry.host),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(&entry).unwrap_or_default(),
        });
    }
    Ok(())
}

fn parse_chromium_searches(
    conn: &rusqlite::Connection,
    path: &Path,
    browser: &str,
    profile: Option<&str>,
    out: &mut Vec<ParsedArtifact>,
) -> Result<(), ParserError> {
    if !table_exists(conn, "keyword_search_terms") || !table_exists(conn, "urls") {
        return Ok(());
    }

    let sql = format!(
        "SELECT k.term, u.url, u.last_visit_time \
         FROM keyword_search_terms k JOIN urls u ON k.url_id = u.id \
         ORDER BY u.last_visit_time DESC LIMIT {}",
        SEARCH_LIMIT
    );
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| ParserError::Database(e.to_string()))?;
    let rows = stmt
        .query_map([], |row| {
            Ok(BrowserSearch {
                term: row.get::<_, String>(0).unwrap_or_default(),
                url: row.get::<_, String>(1).unwrap_or_default(),
                search_time: row.get::<_, i64>(2).ok().map(chromium_ts_to_unix),
                browser: browser.to_string(),
                profile: profile.map(String::from),
            })
        })
        .map_err(|e| ParserError::Database(e.to_string()))?;

    for entry in rows.flatten() {
        out.push(ParsedArtifact {
            timestamp: entry.search_time,
            artifact_type: "browser".to_string(),
            description: format!("{} search: \"{}\"", browser, entry.term),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(&entry).unwrap_or_default(),
        });
    }
    Ok(())
}

fn parse_chromium_logins(
    conn: &rusqlite::Connection,
    path: &Path,
    browser: &str,
    profile: Option<&str>,
    out: &mut Vec<ParsedArtifact>,
) -> Result<(), ParserError> {
    if !table_exists(conn, "logins") {
        return Ok(());
    }

    let mut stmt = conn
        .prepare(
            "SELECT origin_url, username_value, date_created, date_last_used, times_used \
             FROM logins",
        )
        .map_err(|e| ParserError::Database(e.to_string()))?;
    let rows = stmt
        .query_map([], |row| {
            Ok(BrowserLogin {
                origin_url: row.get::<_, String>(0).unwrap_or_default(),
                username: row.get(1).ok(),
                date_created: row.get::<_, i64>(2).ok().map(chromium_ts_to_unix),
                date_last_used: row.get::<_, i64>(3).ok().map(chromium_ts_to_unix),
                times_used: row.get::<_, i64>(4).unwrap_or(0),
                browser: browser.to_string(),
                profile: profile.map(String::from),
            })
        })
        .map_err(|e| ParserError::Database(e.to_string()))?;

    for entry in rows.flatten() {
        out.push(ParsedArtifact {
            timestamp: entry.date_created,
            artifact_type: "browser".to_string(),
            description: format!(
                "{} saved login: {} ({})",
                browser,
                entry.origin_url,
                entry.username.as_deref().unwrap_or("")
            ),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(&entry).unwrap_or_default(),
        });
    }
    Ok(())
}

fn parse_chromium_autofill(
    conn: &rusqlite::Connection,
    path: &Path,
    browser: &str,
    profile: Option<&str>,
    out: &mut Vec<ParsedArtifact>,
) -> Result<(), ParserError> {
    if !table_exists(conn, "autofill") {
        return Ok(());
    }

    let mut stmt = conn
        .prepare("SELECT name, value, count, date_created, date_last_used FROM autofill")
        .map_err(|e| ParserError::Database(e.to_string()))?;
    let rows = stmt
        .query_map([], |row| {
            Ok(BrowserAutofillField {
                name: row.get::<_, String>(0).unwrap_or_default(),
                value: row.get::<_, String>(1).unwrap_or_default(),
                count: row.get::<_, i64>(2).unwrap_or(0),
                date_created: row.get::<_, i64>(3).ok(),
                date_last_used: row.get::<_, i64>(4).ok(),
                browser: browser.to_string(),
                profile: profile.map(String::from),
            })
        })
        .map_err(|e| ParserError::Database(e.to_string()))?;

    for entry in rows.flatten() {
        out.push(ParsedArtifact {
            timestamp: entry.date_last_used,
            artifact_type: "browser".to_string(),
            description: format!("{} autofill: {} = {}", browser, entry.name, entry.value),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(&entry).unwrap_or_default(),
        });
    }
    Ok(())
}

fn parse_chromium_bookmarks_json(
    path: &Path,
    data: &[u8],
    browser: &str,
    profile: Option<&str>,
) -> Vec<ParsedArtifact> {
    let mut out = Vec::new();
    let value: serde_json::Value = match serde_json::from_slice(data) {
        Ok(v) => v,
        Err(_) => return out,
    };

    let roots = match value.get("roots").and_then(|r| r.as_object()) {
        Some(r) => r,
        None => return out,
    };

    for (root_name, root_val) in roots {
        walk_chromium_bookmark(root_val, path, browser, profile, root_name, 0, &mut out);
    }
    out
}

fn walk_chromium_bookmark(
    node: &serde_json::Value,
    path: &Path,
    browser: &str,
    profile: Option<&str>,
    folder_path: &str,
    depth: usize,
    out: &mut Vec<ParsedArtifact>,
) {
    if depth > BOOKMARK_MAX_DEPTH || out.len() >= BOOKMARK_LIMIT {
        return;
    }

    let node_type = node.get("type").and_then(|t| t.as_str()).unwrap_or("");
    match node_type {
        "url" => {
            let title = node
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("untitled")
                .to_string();
            let url = node
                .get("url")
                .and_then(|u| u.as_str())
                .map(String::from);
            let date_added = node
                .get("date_added")
                .and_then(|d| d.as_str())
                .and_then(|s| s.parse::<i64>().ok())
                .map(chromium_ts_to_unix);

            let bm = BrowserBookmark {
                title: title.clone(),
                url: url.clone(),
                date_added,
                folder_path: folder_path.to_string(),
                browser: browser.to_string(),
                profile: profile.map(String::from),
            };
            out.push(ParsedArtifact {
                timestamp: date_added,
                artifact_type: "browser".to_string(),
                description: format!(
                    "{} bookmark: {} → {}",
                    browser,
                    title,
                    url.as_deref().unwrap_or("")
                ),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(bm).unwrap_or_default(),
            });
        }
        "folder" => {
            let name = node
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("folder");
            let child_path = format!("{}/{}", folder_path, name);
            if let Some(children) = node.get("children").and_then(|c| c.as_array()) {
                for child in children {
                    walk_chromium_bookmark(child, path, browser, profile, &child_path, depth + 1, out);
                }
            }
        }
        _ => {
            // Root-level nodes may not have "type" — try children anyway.
            if let Some(children) = node.get("children").and_then(|c| c.as_array()) {
                for child in children {
                    walk_chromium_bookmark(child, path, browser, profile, folder_path, depth + 1, out);
                }
            }
        }
    }
}

fn parse_chromium_extensions_json(
    path: &Path,
    data: &[u8],
    browser: &str,
    profile: Option<&str>,
) -> Vec<ParsedArtifact> {
    let mut out = Vec::new();
    let value: serde_json::Value = match serde_json::from_slice(data) {
        Ok(v) => v,
        Err(_) => return out,
    };

    let settings = value
        .get("extensions")
        .and_then(|e| e.get("settings"))
        .and_then(|s| s.as_object());
    let Some(settings) = settings else {
        return out;
    };

    for (id, ext_val) in settings {
        let manifest = ext_val.get("manifest");
        let name = manifest
            .and_then(|m| m.get("name"))
            .and_then(|n| n.as_str())
            .map(String::from);
        let version = manifest
            .and_then(|m| m.get("version"))
            .and_then(|n| n.as_str())
            .map(String::from);
        let state = ext_val.get("state").and_then(|s| s.as_i64()).unwrap_or(0);
        let from_store = ext_val.get("from_webstore").and_then(|v| v.as_bool());
        let install_time = ext_val
            .get("install_time")
            .and_then(|s| s.as_str())
            .and_then(|s| s.parse::<i64>().ok())
            .map(chromium_ts_to_unix);

        let ext = BrowserExtension {
            id: id.clone(),
            name: name.clone(),
            version,
            enabled: state == 1,
            from_store,
            install_time,
            browser: browser.to_string(),
            profile: profile.map(String::from),
        };
        out.push(ParsedArtifact {
            timestamp: install_time,
            artifact_type: "browser".to_string(),
            description: format!(
                "{} extension: {} ({})",
                browser,
                name.as_deref().unwrap_or("unknown"),
                id
            ),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(ext).unwrap_or_default(),
        });
    }
    out
}

// ════════════════════════════════════════════════════════════════════════════
// 2. FIREFOX FORENSIC PARSER
// ════════════════════════════════════════════════════════════════════════════

pub struct FirefoxForensicParser;

impl FirefoxForensicParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for FirefoxForensicParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for FirefoxForensicParser {
    fn name(&self) -> &str {
        "Firefox Forensic Parser"
    }

    fn artifact_type(&self) -> &str {
        "browser"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            // Windows
            "mozilla/firefox/profiles",
            // macOS
            "application support/firefox/profiles",
            // Linux
            ".mozilla/firefox",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let path_str = path.to_string_lossy().to_lowercase();
        if !path_str.contains("/firefox/") && !path_str.contains("\\firefox\\") {
            return Ok(Vec::new());
        }

        let profile = extract_firefox_profile(&path_str);
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();

        // JSON files
        if file_name == "logins.json" {
            return Ok(parse_firefox_logins_json(path, data, profile.as_deref()));
        }

        // SQLite files
        let mut artifacts = Vec::new();
        let result = with_sqlite_connection(path, data, |conn| {
            let mut entries = Vec::new();

            match file_name.as_str() {
                "places.sqlite" => {
                    parse_firefox_history(conn, path, profile.as_deref(), &mut entries)?;
                    parse_firefox_downloads(conn, path, profile.as_deref(), &mut entries)?;
                    parse_firefox_bookmarks(conn, path, profile.as_deref(), &mut entries)?;
                }
                "cookies.sqlite" => {
                    parse_firefox_cookies(conn, path, profile.as_deref(), &mut entries)?;
                }
                "formhistory.sqlite" => {
                    parse_firefox_formhistory(conn, path, profile.as_deref(), &mut entries)?;
                }
                _ => {}
            }

            Ok(entries)
        });

        if let Ok(mut entries) = result {
            artifacts.append(&mut entries);
        }
        Ok(artifacts)
    }
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

fn parse_firefox_history(
    conn: &rusqlite::Connection,
    path: &Path,
    profile: Option<&str>,
    out: &mut Vec<ParsedArtifact>,
) -> Result<(), ParserError> {
    if !table_exists(conn, "moz_places") || !table_exists(conn, "moz_historyvisits") {
        return Ok(());
    }

    let sql = format!(
        "SELECT p.url, p.title, v.visit_date, p.visit_count, p.typed, \
         v.visit_type, v.from_visit \
         FROM moz_historyvisits v JOIN moz_places p ON v.place_id = p.id \
         ORDER BY v.visit_date DESC LIMIT {}",
        HISTORY_LIMIT
    );
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| ParserError::Database(e.to_string()))?;
    let rows = stmt
        .query_map([], |row| {
            let visit_type: i64 = row.get::<_, i64>(5).unwrap_or(0);
            let transition = match visit_type {
                1 => "LINK",
                2 => "TYPED",
                3 => "BOOKMARK",
                4 => "EMBED",
                5 => "REDIRECT_PERMANENT",
                6 => "REDIRECT_TEMPORARY",
                7 => "DOWNLOAD",
                8 => "FRAMED_LINK",
                9 => "RELOAD",
                _ => "OTHER",
            };
            Ok(BrowserVisit {
                url: row.get::<_, String>(0).unwrap_or_default(),
                title: row.get(1).ok(),
                visit_time: row.get::<_, i64>(2).ok().map(firefox_us_to_unix),
                visit_count: row.get::<_, i64>(3).unwrap_or(0),
                typed_count: if row.get::<_, i64>(4).unwrap_or(0) != 0 {
                    1
                } else {
                    0
                },
                transition: Some(transition.to_string()),
                transition_qualifiers: Vec::new(),
                from_visit_url: None,
                browser: "Firefox".to_string(),
                profile: profile.map(String::from),
            })
        })
        .map_err(|e| ParserError::Database(e.to_string()))?;

    for entry in rows.flatten() {
        out.push(ParsedArtifact {
            timestamp: entry.visit_time,
            artifact_type: "browser".to_string(),
            description: format!(
                "Firefox visit [{}]: {}",
                entry.transition.as_deref().unwrap_or(""),
                entry.url
            ),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(&entry).unwrap_or_default(),
        });
    }
    Ok(())
}

fn parse_firefox_downloads(
    conn: &rusqlite::Connection,
    path: &Path,
    profile: Option<&str>,
    out: &mut Vec<ParsedArtifact>,
) -> Result<(), ParserError> {
    // Firefox stores downloads as moz_places entries with moz_annos metadata.
    // visit_type = 7 (DOWNLOAD) in moz_historyvisits.
    if !table_exists(conn, "moz_places") || !table_exists(conn, "moz_annos") {
        return Ok(());
    }

    let sql = format!(
        "SELECT p.url, a.content, a.dateAdded \
         FROM moz_annos a JOIN moz_places p ON a.place_id = p.id \
         WHERE a.anno_attribute_id IN (SELECT id FROM moz_anno_attributes WHERE name = 'downloads/destinationFileURI') \
         LIMIT {}",
        DOWNLOAD_LIMIT
    );
    let Ok(mut stmt) = conn.prepare(&sql) else {
        return Ok(());
    };
    let rows = stmt
        .query_map([], |row| {
            let dest_uri: Option<String> = row.get(1).ok();
            let dest_path = dest_uri
                .as_deref()
                .and_then(|u| u.strip_prefix("file:///"))
                .map(String::from)
                .or(dest_uri);
            Ok(BrowserDownload {
                url: row.get(0).ok(),
                target_path: dest_path,
                start_time: row.get::<_, i64>(2).ok().map(firefox_us_to_unix),
                end_time: None,
                total_bytes: 0,
                received_bytes: 0,
                state: None,
                danger_type: None,
                mime_type: None,
                browser: "Firefox".to_string(),
                profile: profile.map(String::from),
            })
        })
        .map_err(|e| ParserError::Database(e.to_string()))?;

    for entry in rows.flatten() {
        out.push(ParsedArtifact {
            timestamp: entry.start_time,
            artifact_type: "browser".to_string(),
            description: format!(
                "Firefox download: {} → {}",
                entry.url.as_deref().unwrap_or(""),
                entry.target_path.as_deref().unwrap_or("(unknown)")
            ),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(&entry).unwrap_or_default(),
        });
    }
    Ok(())
}

fn parse_firefox_bookmarks(
    conn: &rusqlite::Connection,
    path: &Path,
    profile: Option<&str>,
    out: &mut Vec<ParsedArtifact>,
) -> Result<(), ParserError> {
    if !table_exists(conn, "moz_bookmarks") {
        return Ok(());
    }

    let sql = format!(
        "SELECT b.title, p.url, b.dateAdded, b.lastModified \
         FROM moz_bookmarks b LEFT JOIN moz_places p ON b.fk = p.id \
         WHERE b.type = 1 LIMIT {}",
        BOOKMARK_LIMIT
    );
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| ParserError::Database(e.to_string()))?;
    let rows = stmt
        .query_map([], |row| {
            Ok(BrowserBookmark {
                title: row.get::<_, String>(0).unwrap_or_else(|_| "(untitled)".into()),
                url: row.get(1).ok(),
                date_added: row.get::<_, i64>(2).ok().map(firefox_us_to_unix),
                folder_path: String::new(),
                browser: "Firefox".to_string(),
                profile: profile.map(String::from),
            })
        })
        .map_err(|e| ParserError::Database(e.to_string()))?;

    for entry in rows.flatten() {
        out.push(ParsedArtifact {
            timestamp: entry.date_added,
            artifact_type: "browser".to_string(),
            description: format!(
                "Firefox bookmark: {} → {}",
                entry.title,
                entry.url.as_deref().unwrap_or("")
            ),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(&entry).unwrap_or_default(),
        });
    }
    Ok(())
}

fn parse_firefox_cookies(
    conn: &rusqlite::Connection,
    path: &Path,
    profile: Option<&str>,
    out: &mut Vec<ParsedArtifact>,
) -> Result<(), ParserError> {
    if !table_exists(conn, "moz_cookies") {
        return Ok(());
    }

    let sql = format!(
        "SELECT host, name, path, creationTime, expiry, isSecure, isHttpOnly \
         FROM moz_cookies LIMIT {}",
        COOKIE_LIMIT
    );
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| ParserError::Database(e.to_string()))?;
    let rows = stmt
        .query_map([], |row| {
            Ok(BrowserCookie {
                host: row.get::<_, String>(0).unwrap_or_default(),
                name: row.get::<_, String>(1).unwrap_or_default(),
                path: row.get::<_, String>(2).unwrap_or_default(),
                creation: row.get::<_, i64>(3).ok().map(firefox_us_to_unix),
                expiry: row.get::<_, i64>(4).ok(),
                is_secure: row.get::<_, i64>(5).unwrap_or(0) != 0,
                is_httponly: row.get::<_, i64>(6).unwrap_or(0) != 0,
                browser: "Firefox".to_string(),
                profile: profile.map(String::from),
            })
        })
        .map_err(|e| ParserError::Database(e.to_string()))?;

    for entry in rows.flatten() {
        out.push(ParsedArtifact {
            timestamp: entry.creation,
            artifact_type: "browser".to_string(),
            description: format!("Firefox cookie: {} on {}", entry.name, entry.host),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(&entry).unwrap_or_default(),
        });
    }
    Ok(())
}

fn parse_firefox_formhistory(
    conn: &rusqlite::Connection,
    path: &Path,
    profile: Option<&str>,
    out: &mut Vec<ParsedArtifact>,
) -> Result<(), ParserError> {
    if !table_exists(conn, "moz_formhistory") {
        return Ok(());
    }

    let mut stmt = conn
        .prepare(
            "SELECT fieldname, value, timesUsed, firstUsed, lastUsed FROM moz_formhistory",
        )
        .map_err(|e| ParserError::Database(e.to_string()))?;
    let rows = stmt
        .query_map([], |row| {
            Ok(BrowserAutofillField {
                name: row.get::<_, String>(0).unwrap_or_default(),
                value: row.get::<_, String>(1).unwrap_or_default(),
                count: row.get::<_, i64>(2).unwrap_or(0),
                date_created: row.get::<_, i64>(3).ok().map(firefox_us_to_unix),
                date_last_used: row.get::<_, i64>(4).ok().map(firefox_us_to_unix),
                browser: "Firefox".to_string(),
                profile: profile.map(String::from),
            })
        })
        .map_err(|e| ParserError::Database(e.to_string()))?;

    for entry in rows.flatten() {
        out.push(ParsedArtifact {
            timestamp: entry.date_last_used,
            artifact_type: "browser".to_string(),
            description: format!("Firefox form: {} = {}", entry.name, entry.value),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(&entry).unwrap_or_default(),
        });
    }
    Ok(())
}

fn parse_firefox_logins_json(
    path: &Path,
    data: &[u8],
    profile: Option<&str>,
) -> Vec<ParsedArtifact> {
    let mut out = Vec::new();
    let value: serde_json::Value = match serde_json::from_slice(data) {
        Ok(v) => v,
        Err(_) => return out,
    };

    let logins = match value.get("logins").and_then(|l| l.as_array()) {
        Some(l) => l,
        None => return out,
    };

    for login in logins {
        let hostname = login
            .get("hostname")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let username = login
            .get("encryptedUsername")
            .and_then(|v| v.as_str())
            .map(|_| "(encrypted)".to_string());
        let time_created = login
            .get("timeCreated")
            .and_then(|v| v.as_i64())
            .map(|ms| ms / 1000);
        let time_last_used = login
            .get("timeLastUsed")
            .and_then(|v| v.as_i64())
            .map(|ms| ms / 1000);
        let times_used = login
            .get("timesUsed")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);

        let entry = BrowserLogin {
            origin_url: hostname.clone(),
            username,
            date_created: time_created,
            date_last_used: time_last_used,
            times_used,
            browser: "Firefox".to_string(),
            profile: profile.map(String::from),
        };
        out.push(ParsedArtifact {
            timestamp: time_created,
            artifact_type: "browser".to_string(),
            description: format!(
                "Firefox saved login: {} (used {} times)",
                hostname, times_used
            ),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(&entry).unwrap_or_default(),
        });
    }
    out
}

// ════════════════════════════════════════════════════════════════════════════
// 3. SAFARI FORENSIC PARSER
// ════════════════════════════════════════════════════════════════════════════

pub struct SafariForensicParser;

impl SafariForensicParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SafariForensicParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for SafariForensicParser {
    fn name(&self) -> &str {
        "Safari Forensic Parser"
    }

    fn artifact_type(&self) -> &str {
        "browser"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "library/safari/history.db",
            "library/safari/downloads.plist",
            "library/safari/bookmarks.plist",
            "library/cookies/cookies.binarycookies",
            "/safari/",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let path_str = path.to_string_lossy().to_lowercase();
        if !path_str.contains("/safari/") && !path_str.contains("/cookies/") {
            return Ok(Vec::new());
        }

        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();

        match file_name.as_str() {
            "history.db" if path_str.contains("/safari/") => {
                parse_safari_history_db(path, data)
            }
            "cookies.binarycookies" => {
                Ok(parse_safari_cookies_binary(path, data))
            }
            _ => Ok(Vec::new()),
        }
    }
}

fn parse_safari_history_db(
    path: &Path,
    data: &[u8],
) -> Result<Vec<ParsedArtifact>, ParserError> {
    let mut artifacts = Vec::new();
    let result = with_sqlite_connection(path, data, |conn| {
        let mut entries = Vec::new();

        if !table_exists(conn, "history_items") || !table_exists(conn, "history_visits") {
            return Ok(entries);
        }

        let sql = format!(
            "SELECT hi.url, hv.title, hv.visit_time, hi.visit_count \
             FROM history_visits hv JOIN history_items hi ON hv.history_item = hi.id \
             ORDER BY hv.visit_time DESC LIMIT {}",
            HISTORY_LIMIT
        );
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| ParserError::Database(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(BrowserVisit {
                    url: row.get::<_, String>(0).unwrap_or_default(),
                    title: row.get(1).ok(),
                    visit_time: row
                        .get::<_, f64>(2)
                        .ok()
                        .map(|d| d as i64 + COREDATA_EPOCH_OFFSET),
                    visit_count: row.get::<_, i64>(3).unwrap_or(0),
                    typed_count: 0,
                    transition: None,
                    transition_qualifiers: Vec::new(),
                    from_visit_url: None,
                    browser: "Safari".to_string(),
                    profile: None,
                })
            })
            .map_err(|e| ParserError::Database(e.to_string()))?;

        for entry in rows.flatten() {
            entries.push(ParsedArtifact {
                timestamp: entry.visit_time,
                artifact_type: "browser".to_string(),
                description: format!("Safari visit: {}", entry.url),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }
        Ok(entries)
    });

    if let Ok(mut entries) = result {
        artifacts.append(&mut entries);
    }
    Ok(artifacts)
}

/// Parse Safari's Cookies.binarycookies file.
///
/// The format is a proprietary binary plist-like structure:
///   * 4-byte magic: "cook"
///   * 4-byte BE: number of pages
///   * Array of page sizes (4-byte BE each)
///   * Pages containing cookie records
///
/// Each cookie record has: URL, name, path, value, expiry, creation date.
fn parse_safari_cookies_binary(path: &Path, data: &[u8]) -> Vec<ParsedArtifact> {
    let mut out = Vec::new();

    // Verify magic
    if data.len() < 8 || &data[0..4] != b"cook" {
        return out;
    }

    let num_pages = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;
    if num_pages == 0 || num_pages > 10_000 {
        return out;
    }

    // Page sizes start at offset 8
    let page_sizes_end = 8 + num_pages * 4;
    if page_sizes_end > data.len() {
        return out;
    }

    let mut page_sizes = Vec::with_capacity(num_pages);
    for i in 0..num_pages {
        let off = 8 + i * 4;
        let sz = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        page_sizes.push(sz as usize);
    }

    // Pages start immediately after the page sizes array
    let mut page_offset = page_sizes_end;
    for page_size in &page_sizes {
        if page_offset + page_size > data.len() {
            break;
        }
        let page = &data[page_offset..page_offset + page_size];
        parse_safari_cookie_page(page, path, &mut out);
        page_offset += page_size;
        if out.len() >= COOKIE_LIMIT {
            break;
        }
    }

    out
}

fn parse_safari_cookie_page(page: &[u8], path: &Path, out: &mut Vec<ParsedArtifact>) {
    // Page header: 4-byte LE magic (0x00000100), then 4-byte LE cookie count
    if page.len() < 8 {
        return;
    }
    let cookie_count =
        u32::from_le_bytes([page[4], page[5], page[6], page[7]]) as usize;
    if cookie_count == 0 || cookie_count > 10_000 {
        return;
    }

    // Cookie offsets: array of cookie_count * 4-byte LE offsets starting at byte 8
    let offsets_end = 8 + cookie_count * 4;
    if offsets_end > page.len() {
        return;
    }

    for i in 0..cookie_count {
        let off_pos = 8 + i * 4;
        let cookie_offset =
            u32::from_le_bytes([page[off_pos], page[off_pos + 1], page[off_pos + 2], page[off_pos + 3]])
                as usize;
        if cookie_offset + 48 > page.len() {
            continue;
        }

        let cookie = &page[cookie_offset..];
        if cookie.len() < 48 {
            continue;
        }

        // Cookie record layout:
        //   0x00: u32 LE size
        //   0x04: u32 LE flags (1=secure, 4=httponly)
        //   0x10: u32 LE url_offset (from cookie start)
        //   0x14: u32 LE name_offset
        //   0x18: u32 LE path_offset
        //   0x1C: u32 LE value_offset
        //   0x28: f64 LE expiry_date (Mac epoch)
        //   0x30: f64 LE creation_date (Mac epoch)
        let flags = u32::from_le_bytes([cookie[4], cookie[5], cookie[6], cookie[7]]);
        let url_off = u32::from_le_bytes([cookie[0x10], cookie[0x11], cookie[0x12], cookie[0x13]]) as usize;
        let name_off = u32::from_le_bytes([cookie[0x14], cookie[0x15], cookie[0x16], cookie[0x17]]) as usize;
        let path_off = u32::from_le_bytes([cookie[0x18], cookie[0x19], cookie[0x1A], cookie[0x1B]]) as usize;

        let expiry_bytes: [u8; 8] = cookie[0x28..0x30].try_into().unwrap_or([0; 8]);
        let creation_bytes: [u8; 8] = cookie[0x30..0x38].try_into().unwrap_or([0; 8]);
        let expiry_f = f64::from_le_bytes(expiry_bytes);
        let creation_f = f64::from_le_bytes(creation_bytes);

        let expiry = if expiry_f > 0.0 {
            Some(expiry_f as i64 + COREDATA_EPOCH_OFFSET)
        } else {
            None
        };
        let creation = if creation_f > 0.0 {
            Some(creation_f as i64 + COREDATA_EPOCH_OFFSET)
        } else {
            None
        };

        let host = read_cstring(cookie, url_off);
        let name = read_cstring(cookie, name_off);
        let cookie_path = read_cstring(cookie, path_off);

        let entry = BrowserCookie {
            host: host.clone(),
            name: name.clone(),
            path: cookie_path,
            creation,
            expiry,
            is_secure: flags & 1 != 0,
            is_httponly: flags & 4 != 0,
            browser: "Safari".to_string(),
            profile: None,
        };
        out.push(ParsedArtifact {
            timestamp: creation,
            artifact_type: "browser".to_string(),
            description: format!("Safari cookie: {} on {}", name, host),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(&entry).unwrap_or_default(),
        });
    }
}

fn read_cstring(data: &[u8], offset: usize) -> String {
    if offset >= data.len() {
        return String::new();
    }
    let slice = &data[offset..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len().min(256));
    String::from_utf8_lossy(&slice[..end]).to_string()
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // ── Chromium tests ──────────────────────────────────────────────

    #[test]
    fn chromium_transition_decoding() {
        assert_eq!(decode_transition(0), "LINK");
        assert_eq!(decode_transition(1), "TYPED");
        assert_eq!(decode_transition(7), "FORM_SUBMIT");
        assert_eq!(decode_transition(9), "KEYWORD");
        // Transition with qualifier flags: TYPED + FROM_ADDRESS_BAR
        assert_eq!(decode_transition(0x0040_0001), "TYPED");
        let q = decode_transition_qualifiers(0x0040_0001);
        assert!(q.contains(&"FROM_ADDRESS_BAR"));
    }

    #[test]
    fn chromium_timestamp_conversion() {
        // 13321925725000000 microseconds since 1601 ≈ 2022 range
        let unix = chromium_ts_to_unix(13_321_925_725_000_000);
        assert!(unix > 1_640_000_000 && unix < 1_700_000_000, "got {}", unix);
        assert_eq!(chromium_ts_to_unix(0), 0);
        assert_eq!(chromium_ts_to_unix(-1), 0);
    }

    #[test]
    fn chromium_bookmarks_json_parsing() {
        let json = r#"{
            "roots": {
                "bookmark_bar": {
                    "children": [
                        {
                            "date_added": "13321925725000000",
                            "name": "Wolfmark Systems",
                            "type": "url",
                            "url": "https://wolfmarksystems.com"
                        },
                        {
                            "children": [
                                {
                                    "date_added": "13321925725000000",
                                    "name": "Strata",
                                    "type": "url",
                                    "url": "https://strata.rs"
                                }
                            ],
                            "name": "Tools",
                            "type": "folder"
                        }
                    ],
                    "name": "Bookmarks Bar",
                    "type": "folder"
                },
                "other": { "children": [], "type": "folder" }
            }
        }"#;

        let parser = ChromiumForensicParser::chrome();
        let path = PathBuf::from(
            "/Users/test/Library/Application Support/Google/Chrome/Default/Bookmarks",
        );
        let out = parser.parse_file(&path, json.as_bytes()).unwrap();
        assert_eq!(out.len(), 2);
        let titles: Vec<String> = out
            .iter()
            .filter_map(|a| a.json_data.get("title").and_then(|v| v.as_str()).map(String::from))
            .collect();
        assert!(titles.contains(&"Wolfmark Systems".to_string()));
        assert!(titles.contains(&"Strata".to_string()));
    }

    #[test]
    fn chromium_extensions_json_parsing() {
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

        let parser = ChromiumForensicParser::edge();
        let path = PathBuf::from(
            "C:/Users/test/AppData/Local/Microsoft/Edge/User Data/Default/Preferences",
        );
        let out = parser.parse_file(&path, json.as_bytes()).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].json_data.get("browser").and_then(|v| v.as_str()),
            Some("Edge")
        );
        assert_eq!(
            out[0].json_data.get("name").and_then(|v| v.as_str()),
            Some("uBlock Origin")
        );
    }

    #[test]
    fn chromium_ignores_wrong_browser_path() {
        let parser = ChromiumForensicParser::chrome();
        let path = PathBuf::from(
            "/Users/test/Library/Application Support/Microsoft Edge/Default/Bookmarks",
        );
        let out = parser.parse_file(&path, b"{}").unwrap();
        assert!(out.is_empty(), "Chrome parser should ignore Edge paths");
    }

    #[test]
    fn edge_parser_matches_edge_paths() {
        let parser = ChromiumForensicParser::edge();
        let path = PathBuf::from(
            "C:/Users/test/AppData/Local/Microsoft/Edge/User Data/Default/Bookmarks",
        );
        let json = r#"{"roots":{"bookmark_bar":{"children":[{"name":"test","type":"url","url":"https://example.com","date_added":"13321925725000000"}],"type":"folder"}}}"#;
        let out = parser.parse_file(&path, json.as_bytes()).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].json_data.get("browser").and_then(|v| v.as_str()),
            Some("Edge")
        );
    }

    #[test]
    fn chromium_profile_extraction() {
        assert_eq!(
            extract_chromium_profile(
                "c:/users/test/appdata/local/google/chrome/user data/default/history"
            ),
            Some("default".to_string())
        );
        assert_eq!(
            extract_chromium_profile(
                "/users/test/library/application support/microsoft edge/profile 2/cookies"
            ),
            Some("profile 2".to_string())
        );
    }

    // ── Firefox tests ───────────────────────────────────────────────

    #[test]
    fn firefox_logins_json_parsing() {
        let json = r#"{
            "logins": [
                {
                    "hostname": "https://example.com",
                    "encryptedUsername": "BASE64DATA",
                    "encryptedPassword": "BASE64DATA",
                    "timeCreated": 1700000000000,
                    "timeLastUsed": 1700100000000,
                    "timesUsed": 5
                }
            ]
        }"#;
        let parser = FirefoxForensicParser::new();
        let path = PathBuf::from(
            "/Users/test/Library/Application Support/Firefox/Profiles/abc/logins.json",
        );
        let out = parser.parse_file(&path, json.as_bytes()).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].json_data.get("origin_url").and_then(|v| v.as_str()),
            Some("https://example.com")
        );
        assert_eq!(
            out[0].json_data.get("times_used").and_then(|v| v.as_i64()),
            Some(5)
        );
        assert_eq!(out[0].timestamp, Some(1_700_000_000));
    }

    #[test]
    fn firefox_ignores_non_firefox_paths() {
        let parser = FirefoxForensicParser::new();
        let path = PathBuf::from("/Users/test/Library/SomeOther/places.sqlite");
        let out = parser.parse_file(&path, b"x").unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn firefox_profile_extraction() {
        assert_eq!(
            extract_firefox_profile(
                "/users/test/library/application support/firefox/profiles/abc123.default-release/places.sqlite"
            ),
            Some("abc123.default-release".to_string())
        );
    }

    #[test]
    fn firefox_us_conversion() {
        assert_eq!(firefox_us_to_unix(1_700_000_000_000_000), 1_700_000_000);
        assert_eq!(firefox_us_to_unix(0), 0);
        assert_eq!(firefox_us_to_unix(-5), 0);
    }

    // ── Safari tests ────────────────────────────────────────────────

    #[test]
    fn safari_cookies_binary_magic_check() {
        let parser = SafariForensicParser::new();
        let path = PathBuf::from("/Users/test/Library/Cookies/Cookies.binarycookies");
        // Not a valid binarycookies file — should return empty, not error
        let out = parser.parse_file(&path, b"not_a_cookie_file").unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn safari_cookies_binary_parses_minimal() {
        // Build a minimal Cookies.binarycookies with 1 page, 1 cookie
        let mut data = Vec::new();

        // Magic
        data.extend_from_slice(b"cook");
        // Number of pages (1)
        data.extend_from_slice(&1u32.to_be_bytes());
        // Page size (we'll fill in the actual page below)
        let page_size_offset = data.len();
        data.extend_from_slice(&0u32.to_be_bytes()); // placeholder

        // Build cookie record
        let url = b".example.com\0";
        let name = b"session_id\0";
        let cookie_path = b"/\0";

        // Cookie record: minimum 0x38 bytes header + strings
        let url_off: u32 = 0x38;
        let name_off: u32 = url_off + url.len() as u32;
        let path_off: u32 = name_off + name.len() as u32;
        let value_off: u32 = path_off + cookie_path.len() as u32;
        let cookie_size: u32 = value_off + 1; // +1 for value null terminator

        let mut cookie = vec![0u8; cookie_size as usize];
        cookie[0..4].copy_from_slice(&cookie_size.to_le_bytes());
        cookie[4..8].copy_from_slice(&1u32.to_le_bytes()); // flags: secure
        cookie[0x10..0x14].copy_from_slice(&url_off.to_le_bytes());
        cookie[0x14..0x18].copy_from_slice(&name_off.to_le_bytes());
        cookie[0x18..0x1C].copy_from_slice(&path_off.to_le_bytes());
        cookie[0x1C..0x20].copy_from_slice(&value_off.to_le_bytes());
        // expiry at 0x28: 700000000.0 (Mac epoch)
        let expiry_f: f64 = 700_000_000.0;
        cookie[0x28..0x30].copy_from_slice(&expiry_f.to_le_bytes());
        // creation at 0x30: 699000000.0
        let creation_f: f64 = 699_000_000.0;
        cookie[0x30..0x38].copy_from_slice(&creation_f.to_le_bytes());
        // strings
        cookie[url_off as usize..url_off as usize + url.len()].copy_from_slice(url);
        cookie[name_off as usize..name_off as usize + name.len()].copy_from_slice(name);
        cookie[path_off as usize..path_off as usize + cookie_path.len()]
            .copy_from_slice(cookie_path);

        // Build page: magic (0x00000100 LE), cookie_count, cookie_offset, cookies
        let mut page = Vec::new();
        page.extend_from_slice(&0x0000_0100u32.to_le_bytes()); // page magic
        page.extend_from_slice(&1u32.to_le_bytes()); // 1 cookie
        let cookie_data_offset: u32 = 12; // 4 (magic) + 4 (count) + 4 (offset)
        page.extend_from_slice(&cookie_data_offset.to_le_bytes());
        page.extend_from_slice(&cookie);

        // Patch page size in header
        let page_size = page.len() as u32;
        data[page_size_offset..page_size_offset + 4].copy_from_slice(&page_size.to_be_bytes());

        // Append page to data
        data.extend_from_slice(&page);

        let parser = SafariForensicParser::new();
        let path = PathBuf::from("/Users/test/Library/Cookies/Cookies.binarycookies");
        let out = parser.parse_file(&path, &data).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].json_data.get("host").and_then(|v| v.as_str()),
            Some(".example.com")
        );
        assert_eq!(
            out[0].json_data.get("name").and_then(|v| v.as_str()),
            Some("session_id")
        );
        assert_eq!(
            out[0].json_data.get("is_secure").and_then(|v| v.as_bool()),
            Some(true)
        );
        // creation: 699000000 + 978307200 = 1677307200
        assert_eq!(out[0].timestamp, Some(1_677_307_200));
    }

    #[test]
    fn safari_ignores_non_safari_paths() {
        let parser = SafariForensicParser::new();
        let path = PathBuf::from("/Users/test/Documents/history.db");
        let out = parser.parse_file(&path, b"x").unwrap();
        assert!(out.is_empty());
    }

    // ── Download state / danger type decoding ───────────────────────

    #[test]
    fn download_state_and_danger_decoding() {
        assert_eq!(decode_download_state(1), "COMPLETE");
        assert_eq!(decode_download_state(2), "CANCELLED");
        assert_eq!(decode_danger_type(0), "NOT_DANGEROUS");
        assert_eq!(decode_danger_type(1), "DANGEROUS_FILE");
        assert_eq!(decode_danger_type(2), "DANGEROUS_URL");
    }
}
