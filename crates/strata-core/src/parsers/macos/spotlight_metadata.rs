//! Spotlight metadata parser.
//!
//! macOS stores rich file metadata in two places:
//!
//!   1. Per-volume `.Spotlight-V100/Store-V2/store.db` (the central index — the
//!      existing `SpotlightParser` already detects this).
//!   2. Per-file `com.apple.metadata:_kMDItem*` extended attributes serialised
//!      as binary plists.
//!
//! This parser focuses on the second source: the per-file `kMDItem*` plist
//! blobs. They typically contain `kMDItemWhereFroms` (URL the file was
//! downloaded from), `kMDItemDownloadedDate`, `kMDItemUserTags`, and
//! `kMDItemAuthors`.  When carved from disk or extracted from extended
//! attributes, they look like a small binary plist on their own.

use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::plist_utils::parse_plist_data;
use plist::Value;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct SpotlightMetadataParser;

impl SpotlightMetadataParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SpotlightMetadataParser {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SpotlightMetadataEntry {
    pub source_xattr: String,
    pub where_froms: Vec<String>,
    pub downloaded_date: Option<i64>,
    pub user_tags: Vec<String>,
    pub authors: Vec<String>,
    pub content_type: Option<String>,
    pub display_name: Option<String>,
    pub last_used_date: Option<i64>,
    pub item_keywords: Vec<String>,
}

impl ArtifactParser for SpotlightMetadataParser {
    fn name(&self) -> &str {
        "Spotlight Metadata (xattr)"
    }

    fn artifact_type(&self) -> &str {
        "metadata"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "com.apple.metadata_kmditemwherefroms",
            "com.apple.metadata_kmditemdownloadeddate",
            "com.apple.metadata_kmditemusertags",
            "com.apple.metadata_kmditemkeywords",
            ".com.apple.metadata.plist",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let path_str = path.to_string_lossy().to_lowercase();

        // Accept any file whose name *or* path contains the kMDItem prefix.
        // This covers both the dumped extended-attribute file and the rare
        // .com.apple.metadata side files.
        let is_metadata = path_str.contains("com.apple.metadata") || path_str.contains("kmditem");
        if !is_metadata {
            return Ok(Vec::new());
        }

        let plist_val = parse_plist_data(data)?;
        let entry = build_metadata_entry(&path_str, &plist_val);
        let description = format_description(&entry);

        Ok(vec![ParsedArtifact {
            timestamp: entry.downloaded_date.or(entry.last_used_date),
            artifact_type: "metadata".to_string(),
            description,
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(entry).unwrap_or_default(),
        }])
    }
}

fn build_metadata_entry(path_str: &str, value: &Value) -> SpotlightMetadataEntry {
    let mut entry = SpotlightMetadataEntry {
        source_xattr: detect_xattr_kind(path_str).to_string(),
        where_froms: Vec::new(),
        downloaded_date: None,
        user_tags: Vec::new(),
        authors: Vec::new(),
        content_type: None,
        display_name: None,
        last_used_date: None,
        item_keywords: Vec::new(),
    };

    // The plist may itself be either a single value (when the xattr was a
    // single key) or a dict of kMDItem* keys.
    match value {
        Value::Array(arr) => {
            // Likely a kMDItemWhereFroms array (sequence of URLs/strings).
            entry.where_froms = collect_strings(arr);
        }
        Value::String(s) => {
            entry.where_froms.push(s.clone());
        }
        Value::Date(d) => {
            // Single date xattr — almost certainly kMDItemDownloadedDate.
            entry.downloaded_date = Some(date_to_unix(d));
        }
        Value::Dictionary(dict) => {
            for (key, val) in dict.iter() {
                match key.as_str() {
                    "kMDItemWhereFroms" => {
                        if let Some(arr) = val.as_array() {
                            entry.where_froms = collect_strings(arr);
                        }
                    }
                    "kMDItemDownloadedDate" => {
                        entry.downloaded_date = first_date(val);
                    }
                    "kMDItemUserTags" => {
                        if let Some(arr) = val.as_array() {
                            entry.user_tags = collect_strings(arr);
                        }
                    }
                    "kMDItemAuthors" => {
                        if let Some(arr) = val.as_array() {
                            entry.authors = collect_strings(arr);
                        }
                    }
                    "kMDItemContentType" => {
                        if let Some(s) = val.as_string() {
                            entry.content_type = Some(s.to_string());
                        }
                    }
                    "kMDItemDisplayName" => {
                        if let Some(s) = val.as_string() {
                            entry.display_name = Some(s.to_string());
                        }
                    }
                    "kMDItemLastUsedDate" => {
                        entry.last_used_date = first_date(val);
                    }
                    "kMDItemKeywords" => {
                        if let Some(arr) = val.as_array() {
                            entry.item_keywords = collect_strings(arr);
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
    entry
}

fn collect_strings(arr: &[Value]) -> Vec<String> {
    arr.iter()
        .filter_map(|v| v.as_string().map(String::from))
        .collect()
}

fn first_date(val: &Value) -> Option<i64> {
    if let Some(d) = val.as_date() {
        return Some(date_to_unix(&d));
    }
    if let Some(arr) = val.as_array() {
        for inner in arr {
            if let Some(d) = inner.as_date() {
                return Some(date_to_unix(&d));
            }
        }
    }
    None
}

fn date_to_unix(date: &plist::Date) -> i64 {
    let st: std::time::SystemTime = (*date).into();
    st.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn detect_xattr_kind(path_str: &str) -> &'static str {
    if path_str.contains("kmditemwherefroms") {
        "kMDItemWhereFroms"
    } else if path_str.contains("kmditemdownloadeddate") {
        "kMDItemDownloadedDate"
    } else if path_str.contains("kmditemusertags") {
        "kMDItemUserTags"
    } else if path_str.contains("kmditemkeywords") {
        "kMDItemKeywords"
    } else {
        "com.apple.metadata"
    }
}

fn format_description(entry: &SpotlightMetadataEntry) -> String {
    if !entry.where_froms.is_empty() {
        format!(
            "Spotlight metadata: downloaded from {}",
            entry.where_froms.join(", ")
        )
    } else if !entry.user_tags.is_empty() {
        format!("Spotlight tags: {}", entry.user_tags.join(", "))
    } else if let Some(name) = &entry.display_name {
        format!("Spotlight display name: {}", name)
    } else {
        "Spotlight metadata extended attribute".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn parses_where_froms_array() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
    <string>https://wolfmarksystems.com/release/strata.zip</string>
    <string>https://wolfmarksystems.com/</string>
</array>
</plist>"#;
        let parser = SpotlightMetadataParser::new();
        let path = PathBuf::from("/tmp/com.apple.metadata_kMDItemWhereFroms");
        let out = parser.parse_file(&path, xml.as_bytes()).unwrap();
        assert_eq!(out.len(), 1);
        let from: Vec<String> = out[0]
            .json_data
            .get("where_froms")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(from.len(), 2);
        assert!(from[0].starts_with("https://wolfmarksystems.com"));
    }

    #[test]
    fn parses_full_metadata_dict() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>kMDItemWhereFroms</key>
    <array>
        <string>https://example.com/file.zip</string>
    </array>
    <key>kMDItemUserTags</key>
    <array>
        <string>Important</string>
        <string>Red</string>
    </array>
    <key>kMDItemDisplayName</key>
    <string>file.zip</string>
    <key>kMDItemContentType</key>
    <string>com.pkware.zip-archive</string>
</dict>
</plist>"#;
        let parser = SpotlightMetadataParser::new();
        let path = PathBuf::from("/tmp/.com.apple.metadata.plist");
        let out = parser.parse_file(&path, xml.as_bytes()).unwrap();
        assert_eq!(out.len(), 1);
        let json = &out[0].json_data;
        assert_eq!(
            json.get("display_name").and_then(|v| v.as_str()),
            Some("file.zip")
        );
        assert_eq!(
            json.get("content_type").and_then(|v| v.as_str()),
            Some("com.pkware.zip-archive")
        );
        let tags: Vec<String> = json
            .get("user_tags")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(tags, vec!["Important", "Red"]);
    }

    #[test]
    fn ignores_non_metadata_paths() {
        let parser = SpotlightMetadataParser::new();
        let path = PathBuf::from("/tmp/random.txt");
        let out = parser.parse_file(&path, b"hello").unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn xattr_kind_classified_from_path() {
        assert_eq!(
            detect_xattr_kind("/tmp/com.apple.metadata_kmditemwherefroms"),
            "kMDItemWhereFroms"
        );
        assert_eq!(
            detect_xattr_kind("/tmp/.com.apple.metadata.plist"),
            "com.apple.metadata"
        );
    }
}
