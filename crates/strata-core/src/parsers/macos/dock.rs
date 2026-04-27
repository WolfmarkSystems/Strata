//! macOS Dock parser.
//!
//! Reads `~/Library/Preferences/com.apple.dock.plist` and extracts:
//!
//!   * `persistent-apps` — pinned application icons (left side of dock)
//!   * `recent-apps` — most-recently-used apps (right side of dock)
//!   * `persistent-others` — pinned files/folders/stacks (right of separator)
//!   * `recent-others` — recent documents/folders bubble
//!
//! Forensic value:
//! The dock plist is one of the few places where macOS records both *pinned*
//! application choices and *recent* document/folder access in a single artifact.
//! Examiners use it to prove an app was deliberately added to the dock and to
//! place a user in front of a particular file.

use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::plist_utils::parse_plist_data;
use plist::Value;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct MacosDockParser;

impl MacosDockParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MacosDockParser {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DockItem {
    /// Section the item belongs to: persistent-apps | recent-apps |
    /// persistent-others | recent-others
    pub section: String,
    pub label: Option<String>,
    pub bundle_id: Option<String>,
    pub file_url: Option<String>,
    pub file_path: Option<String>,
    pub guid: Option<i64>,
}

impl ArtifactParser for MacosDockParser {
    fn name(&self) -> &str {
        "macOS Dock"
    }

    fn artifact_type(&self) -> &str {
        "user_activity"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["com.apple.dock.plist"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let lc_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();
        if lc_name != "com.apple.dock.plist" {
            return Ok(Vec::new());
        }

        let plist_val = parse_plist_data(data)?;
        let dict = match plist_val.as_dictionary() {
            Some(d) => d,
            None => return Ok(Vec::new()),
        };

        let sections = [
            "persistent-apps",
            "recent-apps",
            "persistent-others",
            "recent-others",
        ];

        let mut artifacts = Vec::new();
        for section in sections {
            let Some(items) = dict.get(section).and_then(|v| v.as_array()) else {
                continue;
            };
            for item in items {
                if let Some(parsed) = parse_dock_item(item, section) {
                    let label = parsed.label.clone().unwrap_or_else(|| "(unlabeled)".into());
                    artifacts.push(ParsedArtifact {
                        timestamp: None,
                        artifact_type: "user_activity".to_string(),
                        description: format!("Dock {}: {}", section, label),
                        source_path: path.to_string_lossy().to_string(),
                        json_data: serde_json::to_value(parsed).unwrap_or_default(),
                    });
                }
            }
        }
        Ok(artifacts)
    }
}

fn parse_dock_item(item: &Value, section: &str) -> Option<DockItem> {
    let item_dict = item.as_dictionary()?;
    let tile_data = item_dict.get("tile-data").and_then(|v| v.as_dictionary());

    let label = tile_data
        .and_then(|d| d.get("file-label"))
        .and_then(|v| v.as_string())
        .map(String::from);
    let bundle_id = tile_data
        .and_then(|d| d.get("bundle-identifier"))
        .and_then(|v| v.as_string())
        .map(String::from);
    let guid = item_dict
        .get("GUID")
        .and_then(|v| v.as_signed_integer())
        .or_else(|| {
            item_dict
                .get("GUID")
                .and_then(|v| v.as_unsigned_integer())
                .map(|u| u as i64)
        });

    // file-data is a CFURL dict; the URL string is in `_CFURLString` and
    // looks like `file:///Applications/Safari.app/`.
    let file_url = tile_data
        .and_then(|d| d.get("file-data"))
        .and_then(|v| v.as_dictionary())
        .and_then(|d| d.get("_CFURLString"))
        .and_then(|v| v.as_string())
        .map(String::from);

    let file_path = file_url.as_deref().map(decode_file_url);

    Some(DockItem {
        section: section.to_string(),
        label,
        bundle_id,
        file_url,
        file_path,
        guid,
    })
}

/// Decode `file://` URLs into a plain filesystem path. Strips the scheme,
/// optional host, and percent-decodes `%20` etc. Best-effort — invalid
/// percent escapes are kept literally.
fn decode_file_url(url: &str) -> String {
    let stripped = url
        .strip_prefix("file://localhost")
        .or_else(|| url.strip_prefix("file://"))
        .unwrap_or(url);

    let mut out = String::with_capacity(stripped.len());
    let bytes = stripped.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8 as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn dock_path() -> PathBuf {
        PathBuf::from("/Users/test/Library/Preferences/com.apple.dock.plist")
    }

    fn build_minimal_dock_plist() -> &'static str {
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>persistent-apps</key>
    <array>
        <dict>
            <key>GUID</key>
            <integer>1234567890</integer>
            <key>tile-data</key>
            <dict>
                <key>file-label</key>
                <string>Safari</string>
                <key>bundle-identifier</key>
                <string>com.apple.Safari</string>
                <key>file-data</key>
                <dict>
                    <key>_CFURLString</key>
                    <string>file:///Applications/Safari.app/</string>
                </dict>
            </dict>
        </dict>
    </array>
    <key>recent-apps</key>
    <array>
        <dict>
            <key>GUID</key>
            <integer>987654321</integer>
            <key>tile-data</key>
            <dict>
                <key>file-label</key>
                <string>Strata</string>
                <key>bundle-identifier</key>
                <string>dev.wolfmark.strata</string>
                <key>file-data</key>
                <dict>
                    <key>_CFURLString</key>
                    <string>file:///Applications/Strata%20Tree.app/</string>
                </dict>
            </dict>
        </dict>
    </array>
</dict>
</plist>"#
    }

    #[test]
    fn parses_persistent_and_recent_apps() {
        let parser = MacosDockParser::new();
        let out = parser
            .parse_file(&dock_path(), build_minimal_dock_plist().as_bytes())
            .unwrap();
        assert_eq!(out.len(), 2);
        let labels: Vec<String> = out
            .iter()
            .filter_map(|a| {
                a.json_data
                    .get("label")
                    .and_then(|v| v.as_str())
                    .map(String::from)
            })
            .collect();
        assert!(labels.contains(&"Safari".to_string()));
        assert!(labels.contains(&"Strata".to_string()));
    }

    #[test]
    fn decodes_percent_encoded_file_urls() {
        let parser = MacosDockParser::new();
        let out = parser
            .parse_file(&dock_path(), build_minimal_dock_plist().as_bytes())
            .unwrap();
        let strata = out
            .iter()
            .find(|a| a.json_data.get("label").and_then(|v| v.as_str()) == Some("Strata"))
            .unwrap();
        let path = strata
            .json_data
            .get("file_path")
            .and_then(|v| v.as_str())
            .unwrap();
        assert!(path.contains("Strata Tree.app"), "got {}", path);
    }

    #[test]
    fn ignores_unrelated_plist_filenames() {
        let parser = MacosDockParser::new();
        let out = parser
            .parse_file(
                &PathBuf::from("/tmp/com.apple.finder.plist"),
                build_minimal_dock_plist().as_bytes(),
            )
            .unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn returns_empty_for_unrelated_plist_data() {
        let parser = MacosDockParser::new();
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>foo</key><string>bar</string></dict></plist>"#;
        let out = parser.parse_file(&dock_path(), xml.as_bytes()).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn extracts_bundle_id_and_guid() {
        let parser = MacosDockParser::new();
        let out = parser
            .parse_file(&dock_path(), build_minimal_dock_plist().as_bytes())
            .unwrap();
        let safari = out
            .iter()
            .find(|a| a.json_data.get("label").and_then(|v| v.as_str()) == Some("Safari"))
            .unwrap();
        assert_eq!(
            safari.json_data.get("bundle_id").and_then(|v| v.as_str()),
            Some("com.apple.Safari")
        );
        assert_eq!(
            safari.json_data.get("guid").and_then(|v| v.as_i64()),
            Some(1_234_567_890)
        );
    }
}
