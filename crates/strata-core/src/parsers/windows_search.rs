use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Maximum bytes to scan for indexed content. Windows.edb can exceed
/// 10 GB — we cap at 8 MiB to stay bounded per CLAUDE.md rules.
const MAX_SCAN_BYTES: usize = 8 * 1024 * 1024;

/// Minimum run of printable characters to consider a "content snippet".
const MIN_SNIPPET_LEN: usize = 20;

/// Maximum number of file path extractions to keep.
const MAX_PATHS: usize = 2000;

/// Maximum number of content snippets.
const MAX_SNIPPETS: usize = 500;

pub struct WindowsSearchParser;

impl Default for WindowsSearchParser {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsSearchParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchIndexEntry {
    pub document_id: Option<i64>,
    pub file_path: Option<String>,
    pub file_name: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub keywords: Vec<String>,
    pub modified_time: Option<i64>,
    pub created_time: Option<i64>,
    pub accessed_time: Option<i64>,
    pub size: i64,
    pub content_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchHistoryEntry {
    pub query: String,
    pub timestamp: Option<i64>,
    pub user: Option<String>,
    pub search_count: i32,
}

impl ArtifactParser for WindowsSearchParser {
    fn name(&self) -> &str {
        "Windows Search Index Parser"
    }

    fn artifact_type(&self) -> &str {
        "windows_search"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["Windows.edb"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let source = path.to_string_lossy().to_string();
        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let filename_lower = filename.to_lowercase();

        if !filename_lower.contains("windows.edb") {
            return Ok(Vec::new());
        }

        if data.len() < 668 {
            return Ok(vec![ParsedArtifact {
                timestamp: None,
                artifact_type: "windows_search".to_string(),
                description: format!(
                    "Windows Search index detected but too small to parse ({} bytes): {}",
                    data.len(),
                    filename
                ),
                source_path: source,
                json_data: serde_json::json!({
                    "file_name": filename,
                    "file_size": data.len(),
                    "forensic_value": "Critical",
                    "forensic_note": "File too small — may be a stub or partially wiped"
                }),
            }]);
        }

        let mut artifacts = Vec::new();
        let scan_len = data.len().min(MAX_SCAN_BYTES);
        let scan_data = &data[..scan_len];

        // Detect ESE header
        let page_size = u32::from_le_bytes(
            data.get(236..240)
                .and_then(|b| b.try_into().ok())
                .unwrap_or([0, 0, 0, 0]),
        );
        let db_state = u32::from_le_bytes(
            data.get(344..348)
                .and_then(|b| b.try_into().ok())
                .unwrap_or([0, 0, 0, 0]),
        );
        let state_name = match db_state {
            1 => "JustCreated",
            2 => "DirtyShutdown",
            3 => "CleanShutdown",
            4 => "BeingConverted",
            5 => "ForceDetach",
            _ => "Unknown",
        };

        // Detect which SystemIndex tables are present
        let has_gthr = find_ascii(scan_data, b"SystemIndex_Gthr");
        let has_property_store = find_ascii(scan_data, b"SystemIndex_PropertyStore");
        let has_gthr_pth = find_ascii(scan_data, b"SystemIndex_GthrPth");

        // Extract indexed file paths (drive:\path patterns in the data)
        let indexed_paths = extract_indexed_paths(scan_data);

        // Extract content snippets — fragments of indexed document text
        let content_snippets = extract_content_snippets(scan_data);

        // Extract email-like strings (indicates Outlook content was indexed)
        let email_refs = extract_email_references(scan_data);

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "windows_search".to_string(),
            description: format!(
                "CRITICAL: Windows Search Index (Windows.edb) — {} bytes, state={}, \
                 scanned {} bytes, found {} indexed paths, {} content snippets, {} email references",
                data.len(),
                state_name,
                scan_len,
                indexed_paths.len(),
                content_snippets.len(),
                email_refs.len(),
            ),
            source_path: source.clone(),
            json_data: serde_json::json!({
                "file_name": filename,
                "file_size": data.len(),
                "ese_page_size": page_size,
                "database_state": state_name,
                "scanned_bytes": scan_len,
                "tables_detected": {
                    "SystemIndex_Gthr": has_gthr,
                    "SystemIndex_GthrPth": has_gthr_pth,
                    "SystemIndex_PropertyStore": has_property_store,
                },
                "forensic_value": "Critical",
                "forensic_note": "Windows Search indexes the content and metadata of files, emails, and messages. Content persists in the index even after source files are deleted — this is one of the most forensically valuable artifacts on a Windows system.",
            }),
        });

        if !indexed_paths.is_empty() {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "windows_search_paths".to_string(),
                description: format!(
                    "Windows Search: {} indexed file paths recovered from Windows.edb",
                    indexed_paths.len()
                ),
                source_path: source.clone(),
                json_data: serde_json::json!({
                    "indexed_file_count": indexed_paths.len(),
                    "indexed_files": indexed_paths,
                    "forensic_note": "These paths were indexed by Windows Search — the files existed at the time of indexing even if since deleted"
                }),
            });
        }

        if !content_snippets.is_empty() {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "windows_search_content".to_string(),
                description: format!(
                    "Windows Search: {} content snippets recovered from indexed documents",
                    content_snippets.len()
                ),
                source_path: source.clone(),
                json_data: serde_json::json!({
                    "snippet_count": content_snippets.len(),
                    "snippets": content_snippets,
                    "forensic_note": "Document text indexed by Windows Search — may include content from deleted files, emails, and messages"
                }),
            });
        }

        if !email_refs.is_empty() {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "windows_search_emails".to_string(),
                description: format!(
                    "Windows Search: {} email address references in index",
                    email_refs.len()
                ),
                source_path: source,
                json_data: serde_json::json!({
                    "email_count": email_refs.len(),
                    "email_addresses": email_refs,
                    "forensic_note": "Email addresses found in Windows Search index — indicates Outlook or other mail clients were indexed"
                }),
            });
        }

        Ok(artifacts)
    }
}

/// Check if a byte pattern exists in the data.
fn find_ascii(data: &[u8], needle: &[u8]) -> bool {
    data.windows(needle.len()).any(|w| w == needle)
}

/// Extract Windows file paths from raw ESE page data.
///
/// Scans for patterns like `C:\`, `D:\`, `\\` (UNC paths) in both
/// ASCII and UTF-16LE encodings.
fn extract_indexed_paths(data: &[u8]) -> Vec<String> {
    let mut paths = Vec::new();

    // ASCII paths: X:\something
    extract_paths_ascii(data, &mut paths);

    // UTF-16LE paths: X.:.\.s.o.m.e.t.h.i.n.g
    extract_paths_utf16(data, &mut paths);

    // Dedup while preserving order
    let mut seen = std::collections::HashSet::new();
    paths.retain(|p| seen.insert(p.clone()));

    paths.truncate(MAX_PATHS);
    paths
}

fn extract_paths_ascii(data: &[u8], out: &mut Vec<String>) {
    let mut i = 0;
    while i + 3 < data.len() && out.len() < MAX_PATHS {
        // Look for X:\ pattern
        if data[i].is_ascii_alphabetic() && data[i + 1] == b':' && data[i + 2] == b'\\' {
            let start = i;
            let mut end = i + 3;
            while end < data.len() && is_path_char(data[end]) {
                end += 1;
            }
            if end - start >= 6 {
                let path = String::from_utf8_lossy(&data[start..end]).to_string();
                if is_plausible_path(&path) {
                    out.push(path);
                }
            }
            i = end;
        } else {
            i += 1;
        }
    }
}

fn extract_paths_utf16(data: &[u8], out: &mut Vec<String>) {
    let mut i = 0;
    while i + 6 < data.len() && out.len() < MAX_PATHS {
        // Look for X.:.\ in UTF-16LE (letter, 0x00, colon, 0x00, backslash, 0x00)
        if data[i].is_ascii_alphabetic()
            && i + 5 < data.len()
            && data[i + 1] == 0
            && data[i + 2] == b':'
            && data[i + 3] == 0
            && data[i + 4] == b'\\'
            && data[i + 5] == 0
        {
            let start = i;
            let mut end = i + 6;
            while end + 1 < data.len()
                && (is_path_char(data[end]) || data[end] > 0x7F)
                && data[end + 1] == 0
            {
                end += 2;
            }
            let chars: Vec<u16> = data[start..end]
                .chunks(2)
                .filter_map(|c| {
                    if c.len() == 2 {
                        Some(u16::from_le_bytes([c[0], c[1]]))
                    } else {
                        None
                    }
                })
                .collect();
            if chars.len() >= 4 {
                let path = String::from_utf16_lossy(&chars);
                if is_plausible_path(&path) {
                    out.push(path);
                }
            }
            i = end;
        } else {
            i += 1;
        }
    }
}

fn is_path_char(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || b == b'\\'
        || b == b'/'
        || b == b'.'
        || b == b'-'
        || b == b'_'
        || b == b' '
        || b == b'('
        || b == b')'
        || b == b'~'
}

fn is_plausible_path(s: &str) -> bool {
    // Must contain at least one backslash beyond the root
    s.matches('\\').count() >= 2
        && !s.contains('\0')
        && s.len() < 500
}

/// Extract text snippets that look like document content.
fn extract_content_snippets(data: &[u8]) -> Vec<String> {
    let mut snippets = Vec::new();
    let mut current = String::new();

    for &byte in data.iter().take(MAX_SCAN_BYTES) {
        if (0x20..=0x7E).contains(&byte) {
            current.push(byte as char);
        } else {
            if current.len() >= MIN_SNIPPET_LEN && is_content_snippet(&current) {
                snippets.push(std::mem::take(&mut current));
                if snippets.len() >= MAX_SNIPPETS {
                    return snippets;
                }
            }
            current.clear();
        }
    }
    if current.len() >= MIN_SNIPPET_LEN && is_content_snippet(&current) {
        snippets.push(current);
    }
    snippets
}

/// Filter for strings that look like actual document content rather than
/// binary noise or ESE internal metadata.
fn is_content_snippet(s: &str) -> bool {
    // Must contain spaces (prose-like content)
    let space_count = s.chars().filter(|c| *c == ' ').count();
    if space_count < 3 {
        return false;
    }
    // Must have a reasonable ratio of alpha characters
    let alpha_count = s.chars().filter(|c| c.is_alphabetic()).count();
    alpha_count > s.len() / 2
}

/// Extract email addresses from the index data.
fn extract_email_references(data: &[u8]) -> Vec<String> {
    let mut emails = Vec::new();
    let text = String::from_utf8_lossy(&data[..data.len().min(MAX_SCAN_BYTES)]);

    // Simple email pattern scan
    let mut i = 0;
    let chars: Vec<char> = text.chars().collect();
    while i < chars.len() && emails.len() < 200 {
        if chars[i] == '@' && i > 1 {
            // Walk backwards to find start of local part
            let mut start = i - 1;
            while start > 0 && is_email_char(chars[start - 1]) {
                start -= 1;
            }
            // Walk forward to find end of domain
            let mut end = i + 1;
            while end < chars.len() && is_email_char(chars[end]) {
                end += 1;
            }
            let candidate: String = chars[start..end].iter().collect();
            if is_plausible_email(&candidate) && !emails.contains(&candidate) {
                emails.push(candidate);
            }
            i = end;
        } else {
            i += 1;
        }
    }
    emails
}

fn is_email_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '+'
}

fn is_plausible_email(s: &str) -> bool {
    let at_pos = s.find('@');
    let dot_pos = s.rfind('.');
    match (at_pos, dot_pos) {
        (Some(a), Some(d)) => {
            a > 0
                && d > a + 1
                && d < s.len() - 1
                && !s.starts_with('.')
                && !s.ends_with('.')
                && s.len() >= 5
                && s.len() < 254
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_windows_edb() -> Vec<u8> {
        let mut data = vec![0u8; 4096];

        // ESE header — page size at offset 236
        data[236..240].copy_from_slice(&4096u32.to_le_bytes());
        // Database state at offset 344 = CleanShutdown (3)
        data[344..348].copy_from_slice(&3u32.to_le_bytes());

        // Embed table names
        let table1 = b"SystemIndex_Gthr";
        data[800..800 + table1.len()].copy_from_slice(table1);
        let table2 = b"SystemIndex_PropertyStore";
        data[900..900 + table2.len()].copy_from_slice(table2);

        // Embed an indexed file path (ASCII)
        let path1 = b"C:\\Users\\suspect\\Documents\\evidence.docx";
        data[1200..1200 + path1.len()].copy_from_slice(path1);

        // Embed another path
        let path2 = b"C:\\Users\\suspect\\Desktop\\financials.xlsx";
        data[1400..1400 + path2.len()].copy_from_slice(path2);

        // Embed a content snippet (prose-like)
        let snippet = b"The meeting notes from last Tuesday show that the package was delivered to the warehouse on Monday evening";
        data[2000..2000 + snippet.len()].copy_from_slice(snippet);

        // Embed an email address
        let email = b"suspect@example.com";
        data[2500..2500 + email.len()].copy_from_slice(email);

        data
    }

    #[test]
    fn parses_windows_edb_header_and_tables() {
        let parser = WindowsSearchParser::new();
        let data = make_windows_edb();
        let path = Path::new("/evidence/C/ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.edb");
        let result = parser.parse_file(path, &data).unwrap();
        assert!(!result.is_empty());
        let main = &result[0];
        assert!(main.description.contains("CRITICAL"));
        assert!(main.description.contains("CleanShutdown"));
        assert_eq!(main.json_data["ese_page_size"], 4096);
        assert_eq!(main.json_data["tables_detected"]["SystemIndex_Gthr"], true);
        assert_eq!(
            main.json_data["tables_detected"]["SystemIndex_PropertyStore"],
            true
        );
    }

    #[test]
    fn extracts_indexed_file_paths() {
        let parser = WindowsSearchParser::new();
        let data = make_windows_edb();
        let path = Path::new("/evidence/Windows.edb");
        let result = parser.parse_file(path, &data).unwrap();
        let paths_artifact = result
            .iter()
            .find(|a| a.artifact_type == "windows_search_paths");
        assert!(paths_artifact.is_some());
        let paths = paths_artifact.unwrap().json_data["indexed_files"]
            .as_array()
            .unwrap();
        assert!(paths.iter().any(|p| p.as_str().unwrap().contains("evidence.docx")));
        assert!(paths.iter().any(|p| p.as_str().unwrap().contains("financials.xlsx")));
    }

    #[test]
    fn extracts_content_snippets() {
        let parser = WindowsSearchParser::new();
        let data = make_windows_edb();
        let path = Path::new("/evidence/Windows.edb");
        let result = parser.parse_file(path, &data).unwrap();
        let content_artifact = result
            .iter()
            .find(|a| a.artifact_type == "windows_search_content");
        assert!(content_artifact.is_some());
        let snippets = content_artifact.unwrap().json_data["snippets"]
            .as_array()
            .unwrap();
        assert!(snippets.iter().any(|s| s.as_str().unwrap().contains("meeting notes")));
    }

    #[test]
    fn extracts_email_references() {
        let parser = WindowsSearchParser::new();
        let data = make_windows_edb();
        let path = Path::new("/evidence/Windows.edb");
        let result = parser.parse_file(path, &data).unwrap();
        let email_artifact = result
            .iter()
            .find(|a| a.artifact_type == "windows_search_emails");
        assert!(email_artifact.is_some());
        let emails = email_artifact.unwrap().json_data["email_addresses"]
            .as_array()
            .unwrap();
        assert!(emails.iter().any(|e| e.as_str().unwrap() == "suspect@example.com"));
    }

    #[test]
    fn skips_non_windows_edb() {
        let parser = WindowsSearchParser::new();
        let data = vec![0u8; 1024];
        let path = Path::new("/evidence/random.edb");
        let result = parser.parse_file(path, &data).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn handles_undersized_file() {
        let parser = WindowsSearchParser::new();
        let data = vec![0u8; 100];
        let path = Path::new("/evidence/Windows.edb");
        let result = parser.parse_file(path, &data).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].description.contains("too small"));
    }

    #[test]
    fn utf16_path_extraction() {
        let mut data = vec![0u8; 4096];
        // ESE header
        data[236..240].copy_from_slice(&4096u32.to_le_bytes());
        data[344..348].copy_from_slice(&3u32.to_le_bytes());

        // Embed UTF-16LE path: C:\Users\test\file.txt
        let utf16_path = "C:\\Users\\test\\file.txt";
        let utf16_bytes: Vec<u8> = utf16_path
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        data[1000..1000 + utf16_bytes.len()].copy_from_slice(&utf16_bytes);

        let parser = WindowsSearchParser::new();
        let path = Path::new("/evidence/Windows.edb");
        let result = parser.parse_file(path, &data).unwrap();
        let paths_artifact = result
            .iter()
            .find(|a| a.artifact_type == "windows_search_paths");
        assert!(paths_artifact.is_some());
        let paths = paths_artifact.unwrap().json_data["indexed_files"]
            .as_array()
            .unwrap();
        assert!(paths.iter().any(|p| p.as_str().unwrap().contains("file.txt")));
    }
}
