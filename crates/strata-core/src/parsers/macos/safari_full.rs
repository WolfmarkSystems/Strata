//! Safari full artifact parser — Bookmarks, TopSites, RecentlyClosedTabs,
//! Downloads.plist, and Searches stored under ~/Library/Safari.
//!
//! Forensic value:
//! Safari is the default browser on macOS/iOS, so its artifacts often contain
//! the most complete picture of the user's web activity. Where the existing
//! `SafariParser` covers History.db / Cookies.binarycookies / Downloads.db,
//! this parser covers the *plist*-based companion artifacts that mac_apt
//! enumerates separately:
//!   * Bookmarks.plist (binary plist tree of folders + URLs)
//!   * TopSites.plist (frequently-visited domains)
//!   * RecentlyClosedTabs.plist (recently-closed tab URLs)
//!   * Downloads.plist (legacy/synced download metadata)
//!   * History.plist (legacy pre-Yosemite Safari history file)
//!   * UserNotificationPermissions.plist (web push permissions)
//!
//! Each artifact is emitted as a `ParsedArtifact` containing the structured
//! plist contents so downstream consumers (Sigma, reports) get the full data.

use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::plist_utils::parse_plist_data;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// macOS Core Data / CFAbsoluteTime epoch: 2001-01-01 00:00:00 UTC.
const COREDATA_EPOCH_OFFSET: i64 = 978_307_200;

/// Maximum recursion depth for the bookmark tree walker. Bookmarks.plist is a
/// nested tree of `WebBookmarkTypeList` containers; we cap traversal to prevent
/// pathological inputs from blowing the stack.
const MAX_BOOKMARK_DEPTH: usize = 16;

/// Hard cap on bookmark entries returned per file. Real bookmark databases are
/// typically a few hundred entries; this guards against runaway parsing.
const MAX_BOOKMARK_ENTRIES: usize = 50_000;

#[derive(Debug, Default, Clone, Copy)]
enum SafariFullKind {
    #[default]
    Bookmarks,
    TopSites,
    RecentlyClosed,
    DownloadsPlist,
    HistoryPlist,
    NotificationPermissions,
}

impl SafariFullKind {
    fn from_path(path: &Path) -> Option<Self> {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();
        match name.as_str() {
            "bookmarks.plist" => Some(SafariFullKind::Bookmarks),
            "topsites.plist" => Some(SafariFullKind::TopSites),
            "recentlyclosedtabs.plist" => Some(SafariFullKind::RecentlyClosed),
            "downloads.plist" => Some(SafariFullKind::DownloadsPlist),
            "history.plist" => Some(SafariFullKind::HistoryPlist),
            "usernotificationpermissions.plist" => Some(SafariFullKind::NotificationPermissions),
            _ => None,
        }
    }

}

pub struct SafariFullParser;

impl SafariFullParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SafariFullParser {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SafariBookmark {
    pub title: String,
    pub url: Option<String>,
    pub uuid: Option<String>,
    pub parent_path: String,
    pub depth: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SafariTopSite {
    pub title: Option<String>,
    pub url: String,
    pub pinned: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SafariClosedTab {
    pub title: Option<String>,
    pub url: Option<String>,
    pub last_visited: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SafariDownloadPlistEntry {
    pub url: Option<String>,
    pub local_path: Option<String>,
    pub bytes_total: Option<i64>,
    pub bytes_loaded: Option<i64>,
    pub started: Option<i64>,
    pub completed: Option<i64>,
}

impl ArtifactParser for SafariFullParser {
    fn name(&self) -> &str {
        "Safari Full Artifacts"
    }

    fn artifact_type(&self) -> &str {
        "browser"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "bookmarks.plist",
            "topsites.plist",
            "recentlyclosedtabs.plist",
            "downloads.plist",
            "history.plist",
            "usernotificationpermissions.plist",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let Some(kind) = SafariFullKind::from_path(path) else {
            return Ok(Vec::new());
        };

        // Only handle Safari plists — guard against arbitrary plists that
        // happen to share the filename (e.g. a `Bookmarks.plist` from a
        // non-Safari app).
        let path_str = path.to_string_lossy().to_lowercase();
        if !path_str.contains("safari") {
            return Ok(Vec::new());
        }

        let plist_val = parse_plist_data(data)?;

        match kind {
            SafariFullKind::Bookmarks => Ok(parse_bookmarks(path, &plist_val)),
            SafariFullKind::TopSites => Ok(parse_top_sites(path, &plist_val)),
            SafariFullKind::RecentlyClosed => Ok(parse_recently_closed(path, &plist_val)),
            SafariFullKind::DownloadsPlist => Ok(parse_downloads_plist(path, &plist_val)),
            SafariFullKind::HistoryPlist => Ok(parse_history_plist(path, &plist_val)),
            SafariFullKind::NotificationPermissions => Ok(parse_notifications(path, &plist_val)),
        }
    }
}

fn parse_bookmarks(path: &Path, plist_val: &plist::Value) -> Vec<ParsedArtifact> {
    let mut out = Vec::new();
    walk_bookmark_node(plist_val, path, "/", 0, &mut out);
    out
}

fn walk_bookmark_node(
    node: &plist::Value,
    path: &Path,
    parent_path: &str,
    depth: usize,
    out: &mut Vec<ParsedArtifact>,
) {
    if depth > MAX_BOOKMARK_DEPTH || out.len() >= MAX_BOOKMARK_ENTRIES {
        return;
    }
    let Some(dict) = node.as_dictionary() else {
        return;
    };

    let bookmark_type = dict
        .get("WebBookmarkType")
        .and_then(|v| v.as_string())
        .unwrap_or("");

    match bookmark_type {
        "WebBookmarkTypeList" => {
            // Folder — recurse into Children with an extended parent_path.
            let title = dict
                .get("Title")
                .and_then(|v| v.as_string())
                .unwrap_or("BookmarksBar");
            let new_parent = if parent_path == "/" {
                format!("/{}", title)
            } else {
                format!("{}/{}", parent_path, title)
            };
            if let Some(children) = dict.get("Children").and_then(|v| v.as_array()) {
                for child in children {
                    walk_bookmark_node(child, path, &new_parent, depth + 1, out);
                }
            }
        }
        "WebBookmarkTypeLeaf" => {
            let url = dict
                .get("URLString")
                .and_then(|v| v.as_string())
                .map(|s| s.to_string());
            let title = dict
                .get("URIDictionary")
                .and_then(|v| v.as_dictionary())
                .and_then(|d| d.get("title"))
                .and_then(|v| v.as_string())
                .unwrap_or("untitled")
                .to_string();
            let uuid = dict
                .get("WebBookmarkUUID")
                .and_then(|v| v.as_string())
                .map(|s| s.to_string());

            let bm = SafariBookmark {
                title: title.clone(),
                url: url.clone(),
                uuid,
                parent_path: parent_path.to_string(),
                depth,
            };

            out.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "browser".to_string(),
                description: format!(
                    "Safari bookmark: {} -> {}",
                    title,
                    url.as_deref().unwrap_or("(folder)")
                ),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(bm).unwrap_or_default(),
            });
        }
        _ => {
            // Unknown node type — try to recurse into Children if present so
            // we don't drop nested data on a malformed root.
            if let Some(children) = dict.get("Children").and_then(|v| v.as_array()) {
                for child in children {
                    walk_bookmark_node(child, path, parent_path, depth + 1, out);
                }
            }
        }
    }
}

fn parse_top_sites(path: &Path, plist_val: &plist::Value) -> Vec<ParsedArtifact> {
    let mut out = Vec::new();
    let Some(dict) = plist_val.as_dictionary() else {
        return out;
    };

    // TopSites.plist contains a `TopSites` array of dicts with TopSiteURLString
    // and TopSiteTitle keys. The optional `BannedURLStrings` is excluded — only
    // current top sites are surfaced here.
    if let Some(items) = dict.get("TopSites").and_then(|v| v.as_array()) {
        for item in items {
            let item_dict = match item.as_dictionary() {
                Some(d) => d,
                None => continue,
            };
            let url = item_dict
                .get("TopSiteURLString")
                .and_then(|v| v.as_string())
                .map(|s| s.to_string());
            let title = item_dict
                .get("TopSiteTitle")
                .and_then(|v| v.as_string())
                .map(|s| s.to_string());
            let pinned = item_dict
                .get("TopSiteIsPinned")
                .and_then(|v| v.as_boolean())
                .unwrap_or(false);
            let Some(url) = url else { continue };
            let entry = SafariTopSite {
                title: title.clone(),
                url: url.clone(),
                pinned,
            };
            out.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "browser".to_string(),
                description: format!(
                    "Safari top site: {} ({})",
                    title.as_deref().unwrap_or(""),
                    url
                ),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(entry).unwrap_or_default(),
            });
        }
    }
    out
}

fn parse_recently_closed(path: &Path, plist_val: &plist::Value) -> Vec<ParsedArtifact> {
    let mut out = Vec::new();
    let Some(dict) = plist_val.as_dictionary() else {
        return out;
    };

    let key_candidates = ["ClosedTabOrWindowPersistentStates", "RecentlyClosedTabs"];
    for key in key_candidates {
        let Some(items) = dict.get(key).and_then(|v| v.as_array()) else {
            continue;
        };
        for item in items {
            let item_dict = match item.as_dictionary() {
                Some(d) => d,
                None => continue,
            };
            let url = item_dict
                .get("PersistentStateURLString")
                .or_else(|| item_dict.get("URLString"))
                .and_then(|v| v.as_string())
                .map(|s| s.to_string());
            let title = item_dict
                .get("PersistentStateTitle")
                .or_else(|| item_dict.get("Title"))
                .and_then(|v| v.as_string())
                .map(|s| s.to_string());
            let last_visited = item_dict
                .get("DateClosed")
                .and_then(|v| v.as_real())
                .map(|d| d as i64 + COREDATA_EPOCH_OFFSET);

            let entry = SafariClosedTab {
                title: title.clone(),
                url: url.clone(),
                last_visited,
            };
            out.push(ParsedArtifact {
                timestamp: last_visited,
                artifact_type: "browser".to_string(),
                description: format!(
                    "Safari recently closed: {}",
                    url.as_deref().unwrap_or("(unknown)")
                ),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(entry).unwrap_or_default(),
            });
        }
    }
    out
}

fn parse_downloads_plist(path: &Path, plist_val: &plist::Value) -> Vec<ParsedArtifact> {
    let mut out = Vec::new();
    let Some(dict) = plist_val.as_dictionary() else {
        return out;
    };

    let Some(history) = dict.get("DownloadHistory").and_then(|v| v.as_array()) else {
        return out;
    };

    for item in history {
        let item_dict = match item.as_dictionary() {
            Some(d) => d,
            None => continue,
        };
        let url = item_dict
            .get("DownloadEntryURL")
            .and_then(|v| v.as_string())
            .map(|s| s.to_string());
        let local_path = item_dict
            .get("DownloadEntryPath")
            .and_then(|v| v.as_string())
            .map(|s| s.to_string());
        let bytes_total = item_dict
            .get("DownloadEntryProgressTotalToLoad")
            .and_then(|v| v.as_signed_integer());
        let bytes_loaded = item_dict
            .get("DownloadEntryProgressBytesSoFar")
            .and_then(|v| v.as_signed_integer());

        let entry = SafariDownloadPlistEntry {
            url: url.clone(),
            local_path: local_path.clone(),
            bytes_total,
            bytes_loaded,
            started: None,
            completed: None,
        };
        out.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "browser".to_string(),
            description: format!(
                "Safari download entry: {} -> {}",
                url.as_deref().unwrap_or("(unknown URL)"),
                local_path.as_deref().unwrap_or("(unknown path)")
            ),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        });
    }
    out
}

fn parse_history_plist(path: &Path, plist_val: &plist::Value) -> Vec<ParsedArtifact> {
    // Pre-Yosemite Safari stored History.plist with WebHistoryDates as the
    // top-level array of {"" : url, "title": ...} dicts. Modern macOS uses
    // History.db (covered by SafariParser).
    let mut out = Vec::new();
    let Some(dict) = plist_val.as_dictionary() else {
        return out;
    };
    let Some(history) = dict.get("WebHistoryDates").and_then(|v| v.as_array()) else {
        return out;
    };

    for item in history {
        let item_dict = match item.as_dictionary() {
            Some(d) => d,
            None => continue,
        };
        let url = item_dict
            .get("")
            .and_then(|v| v.as_string())
            .map(|s| s.to_string());
        let title = item_dict
            .get("title")
            .or_else(|| item_dict.get("displayTitle"))
            .and_then(|v| v.as_string())
            .map(|s| s.to_string());
        let last_visited = item_dict
            .get("lastVisitedDate")
            .and_then(|v| v.as_string())
            .and_then(|s| s.parse::<f64>().ok())
            .map(|d| d as i64 + COREDATA_EPOCH_OFFSET);
        let visit_count = item_dict
            .get("visitCount")
            .and_then(|v| v.as_signed_integer())
            .unwrap_or(0);
        out.push(ParsedArtifact {
            timestamp: last_visited,
            artifact_type: "browser".to_string(),
            description: format!(
                "Safari legacy history: {} ({} visits)",
                url.as_deref().unwrap_or("(unknown)"),
                visit_count
            ),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::json!({
                "url": url,
                "title": title,
                "visit_count": visit_count,
                "last_visited": last_visited,
            }),
        });
    }
    out
}

fn parse_notifications(path: &Path, plist_val: &plist::Value) -> Vec<ParsedArtifact> {
    let mut out = Vec::new();
    let Some(dict) = plist_val.as_dictionary() else {
        return out;
    };
    // The plist contains domain -> { "permission": "Allowed"/"Denied", ... }
    for (domain, value) in dict {
        let Some(value_dict) = value.as_dictionary() else {
            continue;
        };
        let permission = value_dict
            .get("permission")
            .and_then(|v| v.as_string())
            .unwrap_or("unknown")
            .to_string();
        out.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "browser".to_string(),
            description: format!("Safari push permission: {} = {}", domain, permission),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::json!({
                "domain": domain,
                "permission": permission,
            }),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn safari_path(name: &str) -> PathBuf {
        PathBuf::from(format!(
            "/Users/test/Library/Safari/{}",
            name
        ))
    }

    #[test]
    fn parses_a_safari_bookmark_tree() {
        // Build a small Bookmarks.plist as XML and feed it to the parser.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>WebBookmarkType</key>
    <string>WebBookmarkTypeList</string>
    <key>Title</key>
    <string>BookmarksBar</string>
    <key>Children</key>
    <array>
        <dict>
            <key>WebBookmarkType</key>
            <string>WebBookmarkTypeLeaf</string>
            <key>URLString</key>
            <string>https://wolfmarksystems.com</string>
            <key>URIDictionary</key>
            <dict>
                <key>title</key>
                <string>Wolfmark Systems</string>
            </dict>
            <key>WebBookmarkUUID</key>
            <string>UUID-1</string>
        </dict>
        <dict>
            <key>WebBookmarkType</key>
            <string>WebBookmarkTypeList</string>
            <key>Title</key>
            <string>Tools</string>
            <key>Children</key>
            <array>
                <dict>
                    <key>WebBookmarkType</key>
                    <string>WebBookmarkTypeLeaf</string>
                    <key>URLString</key>
                    <string>https://strata.rs</string>
                    <key>URIDictionary</key>
                    <dict>
                        <key>title</key>
                        <string>Strata</string>
                    </dict>
                </dict>
            </array>
        </dict>
    </array>
</dict>
</plist>"#;
        let parser = SafariFullParser::new();
        let path = safari_path("Bookmarks.plist");
        let out = parser.parse_file(&path, xml.as_bytes()).unwrap();
        assert_eq!(out.len(), 2, "expected two leaf bookmarks");
        let titles: Vec<String> = out
            .iter()
            .filter_map(|a| a.json_data.get("title").and_then(|v| v.as_str()).map(String::from))
            .collect();
        assert!(titles.contains(&"Wolfmark Systems".to_string()));
        assert!(titles.contains(&"Strata".to_string()));
    }

    #[test]
    fn parses_top_sites() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>TopSites</key>
    <array>
        <dict>
            <key>TopSiteURLString</key>
            <string>https://apple.com</string>
            <key>TopSiteTitle</key>
            <string>Apple</string>
            <key>TopSiteIsPinned</key>
            <true/>
        </dict>
        <dict>
            <key>TopSiteURLString</key>
            <string>https://news.ycombinator.com</string>
            <key>TopSiteTitle</key>
            <string>Hacker News</string>
        </dict>
    </array>
</dict>
</plist>"#;
        let parser = SafariFullParser::new();
        let path = safari_path("TopSites.plist");
        let out = parser.parse_file(&path, xml.as_bytes()).unwrap();
        assert_eq!(out.len(), 2);
        let pinned = out
            .iter()
            .find(|a| {
                a.json_data
                    .get("title")
                    .and_then(|v| v.as_str())
                    == Some("Apple")
            })
            .unwrap();
        assert_eq!(
            pinned.json_data.get("pinned").and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn parses_legacy_history_plist() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>WebHistoryDates</key>
    <array>
        <dict>
            <key></key>
            <string>https://example.com</string>
            <key>title</key>
            <string>Example</string>
            <key>visitCount</key>
            <integer>5</integer>
            <key>lastVisitedDate</key>
            <string>700000000</string>
        </dict>
    </array>
</dict>
</plist>"#;
        let parser = SafariFullParser::new();
        let path = safari_path("History.plist");
        let out = parser.parse_file(&path, xml.as_bytes()).unwrap();
        assert_eq!(out.len(), 1);
        let entry = &out[0];
        assert_eq!(
            entry.json_data.get("url").and_then(|v| v.as_str()),
            Some("https://example.com")
        );
        // 700000000 + 978307200 = 1678307200
        assert_eq!(entry.timestamp, Some(1_678_307_200));
    }

    #[test]
    fn parses_downloads_plist_entries() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>DownloadHistory</key>
    <array>
        <dict>
            <key>DownloadEntryURL</key>
            <string>https://example.com/file.zip</string>
            <key>DownloadEntryPath</key>
            <string>~/Downloads/file.zip</string>
            <key>DownloadEntryProgressTotalToLoad</key>
            <integer>1024</integer>
            <key>DownloadEntryProgressBytesSoFar</key>
            <integer>1024</integer>
        </dict>
    </array>
</dict>
</plist>"#;
        let parser = SafariFullParser::new();
        let path = safari_path("Downloads.plist");
        let out = parser.parse_file(&path, xml.as_bytes()).unwrap();
        assert_eq!(out.len(), 1);
        let entry = &out[0];
        assert_eq!(
            entry.json_data.get("url").and_then(|v| v.as_str()),
            Some("https://example.com/file.zip")
        );
        assert_eq!(
            entry.json_data.get("bytes_total").and_then(|v| v.as_i64()),
            Some(1024)
        );
    }

    #[test]
    fn ignores_non_safari_paths() {
        // A bookmarks.plist for some other app should be ignored entirely.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>WebBookmarkType</key>
    <string>WebBookmarkTypeList</string>
    <key>Children</key>
    <array/>
</dict>
</plist>"#;
        let parser = SafariFullParser::new();
        let path = PathBuf::from("/Users/test/Library/SomeOtherApp/Bookmarks.plist");
        let out = parser.parse_file(&path, xml.as_bytes()).unwrap();
        assert!(out.is_empty(), "non-Safari paths must produce no output");
    }
}
