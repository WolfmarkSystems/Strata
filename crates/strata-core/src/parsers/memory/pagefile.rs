use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use std::path::Path;

/// Maximum bytes to scan for strings. CLAUDE.md: "never load an entire
/// evidence image into memory" — we cap at 1 MiB even if more data is
/// available. The `data` slice passed to `parse_file` is already bounded
/// by the caller, but we enforce the cap here as a defense-in-depth
/// measure.
const MAX_SCAN_BYTES: usize = 1_048_576;

/// Minimum printable Unicode run length to be considered interesting.
const MIN_STRING_LEN: usize = 8;

/// Maximum number of extracted strings to keep (prevent huge output).
const MAX_STRINGS: usize = 500;

pub struct PagefileParser;

impl Default for PagefileParser {
    fn default() -> Self {
        Self::new()
    }
}

impl PagefileParser {
    pub fn new() -> Self {
        Self
    }
}

impl ArtifactParser for PagefileParser {
    fn name(&self) -> &str {
        "Windows Pagefile Parser"
    }

    fn artifact_type(&self) -> &str {
        "pagefile"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["pagefile.sys", "swapfile.sys"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let file_name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();
        if !file_name.contains("pagefile") && !file_name.contains("swapfile") {
            return Ok(Vec::new());
        }

        let file_size = data.len();
        let is_swapfile = file_name.contains("swapfile");

        // Bounded read: scan at most MAX_SCAN_BYTES
        let scan_len = file_size.min(MAX_SCAN_BYTES);
        let scan_slice = &data[..scan_len];

        let strings = extract_interesting_strings(scan_slice);

        let urls: Vec<&str> = strings
            .iter()
            .filter(|s| is_url(s))
            .map(|s| s.as_str())
            .collect();

        let credential_patterns: Vec<&str> = strings
            .iter()
            .filter(|s| is_credential_pattern(s))
            .map(|s| s.as_str())
            .collect();

        let file_paths: Vec<&str> = strings
            .iter()
            .filter(|s| is_file_path(s))
            .map(|s| s.as_str())
            .collect();

        let file_type = if is_swapfile {
            "Windows Store App Swap File"
        } else {
            "Windows Page File"
        };

        let description = format!(
            "CRITICAL: {} detected ({} bytes). Scanned first {} bytes — found {} URLs, {} credential patterns, {} file paths",
            file_type,
            file_size,
            scan_len,
            urls.len(),
            credential_patterns.len(),
            file_paths.len(),
        );

        let json = serde_json::json!({
            "file_name": file_name,
            "file_size": file_size,
            "file_type": file_type,
            "scanned_bytes": scan_len,
            "forensic_value": "Critical",
            "forensic_note": "Pagefile contains pages swapped out of RAM — may include passwords, session tokens, chat messages, document fragments, and encryption keys that were in memory at any point during the session",
            "extracted_strings": {
                "total_interesting": strings.len(),
                "urls": urls,
                "credential_patterns": credential_patterns,
                "file_paths": file_paths,
            }
        });

        Ok(vec![ParsedArtifact {
            timestamp: None,
            artifact_type: "pagefile".to_string(),
            description,
            source_path: path.to_string_lossy().to_string(),
            json_data: json,
        }])
    }
}

/// Extract printable ASCII+Unicode strings of at least `MIN_STRING_LEN` chars.
///
/// Scans for both:
/// - ASCII runs (bytes 0x20..=0x7E)
/// - UTF-16LE runs (printable char followed by 0x00)
fn extract_interesting_strings(data: &[u8]) -> Vec<String> {
    let mut result = Vec::new();

    // Pass 1: ASCII strings
    let mut current = String::new();
    for &byte in data {
        if byte >= 0x20 && byte <= 0x7E {
            current.push(byte as char);
        } else {
            if current.len() >= MIN_STRING_LEN && is_interesting(&current) {
                result.push(std::mem::take(&mut current));
                if result.len() >= MAX_STRINGS {
                    return result;
                }
            }
            current.clear();
        }
    }
    if current.len() >= MIN_STRING_LEN && is_interesting(&current) {
        result.push(current);
    }

    // Pass 2: UTF-16LE strings
    if data.len() >= 2 {
        let mut utf16_buf = Vec::new();
        let mut i = 0;
        while i + 1 < data.len() && result.len() < MAX_STRINGS {
            let lo = data[i];
            let hi = data[i + 1];
            // Printable BMP character in UTF-16LE
            if hi == 0 && lo >= 0x20 && lo <= 0x7E {
                utf16_buf.push(u16::from_le_bytes([lo, hi]));
            } else {
                if utf16_buf.len() >= MIN_STRING_LEN {
                    let s = String::from_utf16_lossy(&utf16_buf);
                    if is_interesting(&s) {
                        result.push(s);
                    }
                }
                utf16_buf.clear();
            }
            i += 2;
        }
        if utf16_buf.len() >= MIN_STRING_LEN {
            let s = String::from_utf16_lossy(&utf16_buf);
            if is_interesting(&s) {
                result.push(s);
            }
        }
    }

    result
}

/// Filter for strings that carry forensic value (not just random printable noise).
fn is_interesting(s: &str) -> bool {
    is_url(s) || is_credential_pattern(s) || is_file_path(s) || is_email(s)
}

fn is_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://") || s.starts_with("ftp://")
}

fn is_credential_pattern(s: &str) -> bool {
    let lower = s.to_lowercase();
    lower.contains("password") || lower.contains("passwd")
        || lower.contains("token=") || lower.contains("api_key")
        || lower.contains("apikey") || lower.contains("secret=")
        || lower.contains("session_id") || lower.contains("authorization:")
        || lower.contains("bearer ") || lower.contains("basic ")
}

fn is_file_path(s: &str) -> bool {
    (s.len() > 3 && s.chars().nth(1) == Some(':') && s.chars().nth(2) == Some('\\'))
        || s.starts_with("\\\\")
        || s.starts_with("/home/")
        || s.starts_with("/Users/")
        || s.starts_with("/tmp/")
        || s.starts_with("/var/")
}

fn is_email(s: &str) -> bool {
    let at_pos = s.find('@');
    let dot_pos = s.rfind('.');
    matches!((at_pos, dot_pos), (Some(a), Some(d)) if a > 0 && d > a + 1 && d < s.len() - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pagefile_with_strings() -> Vec<u8> {
        let mut data = vec![0u8; 4096];
        // Embed some ASCII strings
        let url = b"https://evil.example.com/exfil?data=secret123";
        data[100..100 + url.len()].copy_from_slice(url);

        let cred = b"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9";
        data[300..300 + cred.len()].copy_from_slice(cred);

        let file_path = b"C:\\Users\\suspect\\Documents\\plan.docx";
        data[500..500 + file_path.len()].copy_from_slice(file_path);

        // Embed a UTF-16LE string
        let utf16_str = "password=hunter2!!";
        let utf16_bytes: Vec<u8> = utf16_str
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        data[800..800 + utf16_bytes.len()].copy_from_slice(&utf16_bytes);

        data
    }

    #[test]
    fn detects_pagefile_and_extracts_strings() {
        let parser = PagefileParser::new();
        let data = make_pagefile_with_strings();
        let path = Path::new("/evidence/C/pagefile.sys");
        let result = parser.parse_file(path, &data).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].description.contains("CRITICAL"));

        let urls = result[0].json_data["extracted_strings"]["urls"]
            .as_array()
            .unwrap();
        assert!(urls.iter().any(|u| u.as_str().unwrap().contains("evil.example.com")));
    }

    #[test]
    fn extracts_credential_patterns() {
        let parser = PagefileParser::new();
        let data = make_pagefile_with_strings();
        let path = Path::new("/evidence/C/pagefile.sys");
        let result = parser.parse_file(path, &data).unwrap();
        let creds = result[0].json_data["extracted_strings"]["credential_patterns"]
            .as_array()
            .unwrap();
        assert!(creds.iter().any(|c| c.as_str().unwrap().contains("Bearer")));
    }

    #[test]
    fn extracts_file_paths() {
        let parser = PagefileParser::new();
        let data = make_pagefile_with_strings();
        let path = Path::new("/evidence/C/pagefile.sys");
        let result = parser.parse_file(path, &data).unwrap();
        let paths = result[0].json_data["extracted_strings"]["file_paths"]
            .as_array()
            .unwrap();
        assert!(paths.iter().any(|p| p.as_str().unwrap().contains("plan.docx")));
    }

    #[test]
    fn extracts_utf16_strings() {
        let parser = PagefileParser::new();
        let data = make_pagefile_with_strings();
        let path = Path::new("/evidence/C/pagefile.sys");
        let result = parser.parse_file(path, &data).unwrap();
        let creds = result[0].json_data["extracted_strings"]["credential_patterns"]
            .as_array()
            .unwrap();
        assert!(creds.iter().any(|c| c.as_str().unwrap().contains("password=hunter2")));
    }

    #[test]
    fn respects_scan_byte_cap() {
        let parser = PagefileParser::new();
        let data = make_pagefile_with_strings();
        let path = Path::new("/evidence/C/pagefile.sys");
        let result = parser.parse_file(path, &data).unwrap();
        let scanned = result[0].json_data["scanned_bytes"].as_u64().unwrap();
        assert!(scanned <= MAX_SCAN_BYTES as u64);
    }

    #[test]
    fn detects_swapfile() {
        let parser = PagefileParser::new();
        let data = vec![0u8; 1024];
        let path = Path::new("/evidence/C/swapfile.sys");
        let result = parser.parse_file(path, &data).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].description.contains("Store App Swap File"));
    }

    #[test]
    fn skips_non_pagefile_filename() {
        let parser = PagefileParser::new();
        let data = vec![0u8; 1024];
        let path = Path::new("/evidence/C/hiberfil.sys");
        let result = parser.parse_file(path, &data).unwrap();
        assert!(result.is_empty());
    }
}
