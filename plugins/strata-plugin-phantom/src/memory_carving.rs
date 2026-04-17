//! Memory image string + pattern carving (MEM-1).
//!
//! MITRE: T1005, T1552.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use std::fs;
use std::io::Read;
use std::path::Path;
use strata_plugin_sdk::Artifact;

pub const MAX_ARTIFACTS: usize = 10_000;
pub const SCAN_MIN_FILE_SIZE: u64 = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryStringArtifact {
    pub pattern_type: String,
    pub value: String,
    pub offset: u64,
    pub occurrence_count: usize,
    pub context: Option<String>,
}

pub fn is_memory_image_path(path: &Path) -> bool {
    let name = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(
        name.as_str(),
        "raw" | "mem" | "vmem" | "dmp" | "lime" | "bin"
    )
}

pub fn classify_token(token: &str) -> Option<&'static str> {
    if token.ends_with(".onion") && token.len() >= 22 {
        return Some("OnionUrl");
    }
    if token.starts_with("http://") || token.starts_with("https://") {
        return Some("Url");
    }
    if is_ipv4(token) {
        return Some("Ipv4");
    }
    if token.contains('@') && token.contains('.') && token.len() <= 254 {
        return Some("Email");
    }
    let lower = token.to_ascii_lowercase();
    if (lower.contains("password=")
        || lower.contains("passwd=")
        || lower.contains("secret=")
        || lower.contains("api_key="))
        && token.len() >= 10
    {
        return Some("Credential");
    }
    if token.starts_with("HKEY_") {
        return Some("RegistryKey");
    }
    let b = token.as_bytes();
    if b.len() >= 4
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && (b[2] == b'\\' || b[2] == b'/')
        && (token.to_ascii_lowercase().contains("\\appdata\\")
            || token.to_ascii_lowercase().contains("\\temp\\")
            || token.to_ascii_lowercase().contains("\\downloads\\")
            || token.to_ascii_lowercase().ends_with(".exe")
            || token.to_ascii_lowercase().ends_with(".dll"))
    {
        return Some("WindowsPath");
    }
    None
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| {
        !p.is_empty()
            && p.chars().all(|c| c.is_ascii_digit())
            && p.parse::<u16>().map(|n| n <= 255).unwrap_or(false)
    })
}

pub fn carve(bytes: &[u8]) -> Vec<MemoryStringArtifact> {
    let mut out = Vec::new();
    let mut seen: std::collections::BTreeMap<(String, String), usize> =
        std::collections::BTreeMap::new();
    let mut current_start: usize = 0;
    let mut current: Vec<u8> = Vec::new();
    for (i, &b) in bytes.iter().enumerate() {
        if (0x20..=0x7E).contains(&b) {
            if current.is_empty() {
                current_start = i;
            }
            current.push(b);
            continue;
        }
        emit_run(&current, current_start, &mut seen, &mut out, bytes);
        current.clear();
        if seen.len() >= MAX_ARTIFACTS {
            break;
        }
    }
    emit_run(&current, current_start, &mut seen, &mut out, bytes);
    // Collapse occurrences.
    for ((pattern, value), count) in &seen {
        if let Some(existing) = out
            .iter_mut()
            .find(|a| a.pattern_type == *pattern && a.value == *value)
        {
            existing.occurrence_count = *count;
        }
    }
    out
}

fn emit_run(
    current: &[u8],
    start: usize,
    seen: &mut std::collections::BTreeMap<(String, String), usize>,
    out: &mut Vec<MemoryStringArtifact>,
    bytes: &[u8],
) {
    if current.len() < 8 {
        return;
    }
    let Ok(s) = std::str::from_utf8(current) else {
        return;
    };
    for token in s.split_whitespace() {
        let Some(pattern) = classify_token(token) else {
            continue;
        };
        let key = (pattern.to_string(), token.to_string());
        let entry = seen.entry(key.clone()).or_insert(0);
        *entry += 1;
        if *entry == 1 && out.len() < MAX_ARTIFACTS {
            let context = if pattern == "Credential" {
                let ctx_start = start.saturating_sub(50);
                let ctx_end = (start + current.len() + 50).min(bytes.len());
                std::str::from_utf8(&bytes[ctx_start..ctx_end])
                    .ok()
                    .map(String::from)
            } else {
                None
            };
            out.push(MemoryStringArtifact {
                pattern_type: pattern.to_string(),
                value: token.to_string(),
                offset: start as u64,
                occurrence_count: 1,
                context,
            });
        }
    }
}

pub fn scan(path: &Path) -> Vec<Artifact> {
    if !is_memory_image_path(path) {
        return Vec::new();
    }
    let Ok(meta) = fs::metadata(path) else {
        return Vec::new();
    };
    if meta.len() < SCAN_MIN_FILE_SIZE {
        return Vec::new();
    }
    let Ok(mut f) = fs::File::open(path) else {
        return Vec::new();
    };
    // Cap at 256 MiB for tests / practical scan budget.
    let cap = meta.len().min(256 * 1024 * 1024) as usize;
    let mut buf = vec![0u8; cap];
    if f.read_exact(&mut buf).is_err() {
        return Vec::new();
    }
    let hits = carve(&buf);
    hits.into_iter()
        .map(|h| {
            let mut a = Artifact::new("Memory String", &path.to_string_lossy());
            a.add_field(
                "title",
                &format!(
                    "Memory {}: {}",
                    h.pattern_type,
                    h.value.chars().take(80).collect::<String>()
                ),
            );
            a.add_field("file_type", "Memory String");
            a.add_field("pattern_type", &h.pattern_type);
            a.add_field("value", &h.value);
            a.add_field("offset", &format!("0x{:X}", h.offset));
            a.add_field("occurrence_count", &h.occurrence_count.to_string());
            if let Some(c) = &h.context {
                a.add_field("context", c);
            }
            a.add_field("mitre", "T1005");
            match h.pattern_type.as_str() {
                "OnionUrl" | "Credential" => {
                    a.add_field("forensic_value", "High");
                    a.add_field("suspicious", "true");
                    if h.pattern_type == "Credential" {
                        a.add_field("mitre_secondary", "T1552");
                    }
                }
                _ => a.add_field("forensic_value", "Medium"),
            }
            a
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_token_recognises_onion_and_ipv4() {
        assert_eq!(
            classify_token("3g2upl4pq6kufc4m.onion"),
            Some("OnionUrl")
        );
        assert_eq!(classify_token("10.0.0.5"), Some("Ipv4"));
        assert_eq!(
            classify_token("https://example.com/x"),
            Some("Url")
        );
        assert!(classify_token("just-text").is_none());
    }

    #[test]
    fn classify_token_detects_credential_patterns() {
        assert_eq!(classify_token("password=hunter2"), Some("Credential"));
        assert_eq!(classify_token("api_key=abcd1234"), Some("Credential"));
    }

    #[test]
    fn carve_extracts_unique_strings_with_counts() {
        let mut body = Vec::new();
        body.extend_from_slice(b"abcdefgh 10.0.0.5 junk");
        body.push(0u8);
        body.extend_from_slice(b"  10.0.0.5 again 192.0.2.1  ");
        let hits = carve(&body);
        assert!(hits.iter().any(|h| h.value == "10.0.0.5" && h.occurrence_count >= 2));
        assert!(hits.iter().any(|h| h.value == "192.0.2.1"));
    }

    #[test]
    fn is_memory_image_path_matches_expected_extensions() {
        for ext in ["raw", "mem", "vmem", "dmp", "lime", "bin"] {
            assert!(is_memory_image_path(Path::new(&format!("/x/img.{}", ext))));
        }
        assert!(!is_memory_image_path(Path::new("/x/img.txt")));
    }

    #[test]
    fn scan_skips_small_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tiny.raw");
        fs::write(&path, b"too small").expect("w");
        assert!(scan(&path).is_empty());
    }
}
