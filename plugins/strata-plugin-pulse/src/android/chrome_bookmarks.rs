//! Chrome Bookmarks — Android Chrome bookmark extraction (JSON).
//!
//! ALEAPP reference: `scripts/artifacts/chromeBookmarks.py`. Source path:
//! `/data/data/com.android.chrome/app_chrome/Default/Bookmarks`.
//!
//! This file is JSON, not SQLite. Contains `roots.bookmark_bar.children`
//! and `roots.other.children` arrays with `{url, name, date_added}`.

use crate::android::helpers::build_record;
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &[
    "app_chrome/default/bookmarks",
    "app_sbrowser/default/bookmarks",
];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let data = match std::fs::read_to_string(path) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let json: serde_json::Value = match serde_json::from_str(&data) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    if let Some(roots) = json.get("roots") {
        for key in &["bookmark_bar", "other", "synced"] {
            if let Some(folder) = roots.get(key) {
                extract_bookmarks(folder, path, &mut out);
            }
        }
    }
    out
}

fn extract_bookmarks(node: &serde_json::Value, path: &Path, out: &mut Vec<ArtifactRecord>) {
    if let Some(children) = node.get("children").and_then(|c| c.as_array()) {
        for child in children {
            let url = child.get("url").and_then(|v| v.as_str()).unwrap_or("");
            let name = child.get("name").and_then(|v| v.as_str()).unwrap_or("(untitled)");
            let date_added = child
                .get("date_added")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<i64>().ok());
            if !url.is_empty() {
                // Chrome date_added is WebKit timestamp (microseconds since 1601)
                let ts = date_added.map(|us| us / 1_000_000 - 11_644_473_600);
                let title = format!("Chrome bookmark: {}", name);
                let detail = format!(
                    "Chrome bookmark name='{}' url='{}'",
                    name, url
                );
                out.push(build_record(
                    ArtifactCategory::WebActivity,
                    "Chrome Bookmark",
                    title,
                    detail,
                    path,
                    ts,
                    ForensicValue::Low,
                    false,
                ));
            }
            // Recurse into sub-folders
            extract_bookmarks(child, path, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bookmarks_file() -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let json = r#"{
            "roots": {
                "bookmark_bar": {
                    "children": [
                        {"name": "Example", "url": "https://example.com", "date_added": "13252108800000000"},
                        {"name": "News", "url": "https://news.com", "date_added": "13252108900000000"},
                        {"name": "Folder", "children": [
                            {"name": "Nested", "url": "https://nested.com", "date_added": "13252109000000000"}
                        ]}
                    ]
                },
                "other": {
                    "children": []
                }
            }
        }"#;
        std::fs::write(tmp.path(), json).unwrap();
        tmp
    }

    #[test]
    fn parses_bookmarks_including_nested() {
        let f = make_bookmarks_file();
        let r = parse(f.path());
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|a| a.subcategory == "Chrome Bookmark"));
    }

    #[test]
    fn name_and_url_in_detail() {
        let f = make_bookmarks_file();
        let r = parse(f.path());
        assert!(r.iter().any(|a| a.detail.contains("name='Example'") && a.detail.contains("url='https://example.com'")));
    }

    #[test]
    fn nested_bookmark_found() {
        let f = make_bookmarks_file();
        let r = parse(f.path());
        assert!(r.iter().any(|a| a.detail.contains("name='Nested'")));
    }

    #[test]
    fn invalid_json_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "not valid json").unwrap();
        assert!(parse(tmp.path()).is_empty());
    }
}
