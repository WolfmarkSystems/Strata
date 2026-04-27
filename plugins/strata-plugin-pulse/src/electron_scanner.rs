//! Electron / WebView2 generic LevelDB + IndexedDB scanner (PULSE-10).
//!
//! Modern desktop apps (WhatsApp, Teams, Slack, Discord, Signal, VS
//! Code, Notion) store data in Chromium-style LevelDB and IndexedDB.
//! This scanner carves JSON fragments containing forensically
//! interesting keys without needing a full LevelDB decoder.
//!
//! MITRE: T1552.003 (credentials in files), T1005.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use std::path::Path;

const INTERESTING_KEYS: &[&str] = &[
    "message",
    "content",
    "text",
    "body",
    "timestamp",
    "time",
    "date",
    "ts",
    "from",
    "author",
    "sender",
    "userId",
    "to",
    "recipient",
    "channel",
    "filename",
    "url",
    "uri",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElectronArtifact {
    pub app_name: String,
    pub store_type: String,
    pub content: String,
    pub keys_found: Vec<String>,
    pub source_path: String,
    pub offset: u64,
}

pub fn detect_app(path: &Path) -> &'static str {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    if lower.contains("/whatsapp/") || lower.contains("\\whatsapp\\") {
        "WhatsApp"
    } else if lower.contains("/slack/") || lower.contains("\\slack\\") {
        "Slack"
    } else if lower.contains("/discord/") || lower.contains("\\discord\\") {
        "Discord"
    } else if lower.contains("/signal/") || lower.contains("\\signal\\") {
        "Signal"
    } else if lower.contains("/microsoft/teams/") || lower.contains("\\microsoft\\teams\\") {
        "Teams"
    } else if lower.contains("/code/") || lower.contains("\\code\\") {
        "VS Code"
    } else if lower.contains("/notion/") || lower.contains("\\notion\\") {
        "Notion"
    } else {
        "Electron App (unknown)"
    }
}

pub fn detect_store(path: &Path) -> Option<&'static str> {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    if lower.contains("local storage/leveldb/") || lower.contains("local storage\\leveldb\\") {
        Some("LevelDB")
    } else if lower.contains("/indexeddb/") || lower.contains("\\indexeddb\\") {
        Some("IndexedDB")
    } else {
        None
    }
}

pub fn carve(
    bytes: &[u8],
    source_path: &str,
    app_name: &str,
    store_type: &str,
) -> Vec<ElectronArtifact> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'{' {
            i += 1;
            continue;
        }
        let mut depth = 0i32;
        let mut in_str = false;
        let mut escape = false;
        let mut end = i;
        let limit = (i + 8192).min(bytes.len());
        while end < limit {
            let c = bytes[end];
            if escape {
                escape = false;
                end += 1;
                continue;
            }
            if in_str {
                if c == b'\\' {
                    escape = true;
                } else if c == b'"' {
                    in_str = false;
                }
            } else if c == b'"' {
                in_str = true;
            } else if c == b'{' {
                depth += 1;
            } else if c == b'}' {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            end += 1;
        }
        if depth != 0 || end >= bytes.len() {
            i += 1;
            continue;
        }
        let candidate = &bytes[i..=end];
        if let Ok(s) = std::str::from_utf8(candidate) {
            let keys: Vec<String> = INTERESTING_KEYS
                .iter()
                .filter(|k| s.contains(&format!("\"{}\"", k)))
                .map(|k| (*k).to_string())
                .collect();
            if !keys.is_empty() {
                let truncated: String = s.chars().take(1024).collect();
                out.push(ElectronArtifact {
                    app_name: app_name.to_string(),
                    store_type: store_type.to_string(),
                    content: truncated,
                    keys_found: keys,
                    source_path: source_path.to_string(),
                    offset: i as u64,
                });
            }
            if out.len() >= 10_000 {
                break;
            }
        }
        i = end + 1;
    }
    out
}

pub fn is_electron_data_path(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    (name.ends_with(".ldb") || name.ends_with(".log")) && detect_store(path).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_app_recognises_known_apps() {
        assert_eq!(detect_app(Path::new("/x/Slack/storage/x.ldb")), "Slack");
        assert_eq!(detect_app(Path::new("/x/Notion/leveldb/y.ldb")), "Notion");
        assert_eq!(
            detect_app(Path::new("/x/Unknown/file.ldb")),
            "Electron App (unknown)"
        );
    }

    #[test]
    fn detect_store_matches_leveldb_and_indexeddb() {
        assert_eq!(
            detect_store(Path::new("/x/Slack/Local Storage/leveldb/000003.ldb")),
            Some("LevelDB")
        );
        assert_eq!(
            detect_store(Path::new("/x/App/IndexedDB/store.leveldb/LOG")),
            Some("IndexedDB")
        );
        assert!(detect_store(Path::new("/x/random.log")).is_none());
    }

    #[test]
    fn carve_extracts_json_with_interesting_keys() {
        let body = br#"prefix {"message":"hello","timestamp":"2024-06-01T12:00:00Z"} tail"#;
        let hits = carve(body, "/x", "App", "LevelDB");
        assert_eq!(hits.len(), 1);
        assert!(hits[0].keys_found.contains(&"message".to_string()));
        assert!(hits[0].keys_found.contains(&"timestamp".to_string()));
    }

    #[test]
    fn carve_skips_json_without_interesting_keys() {
        let body = br#"{"nothing":"boring","size":42}"#;
        assert!(carve(body, "/x", "App", "LevelDB").is_empty());
    }

    #[test]
    fn is_electron_data_path_matches_ldb_in_known_store() {
        assert!(is_electron_data_path(Path::new(
            "/x/Slack/Local Storage/leveldb/000003.ldb"
        )));
        assert!(!is_electron_data_path(Path::new("/x/unrelated.ldb")));
    }
}
