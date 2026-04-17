//! Windows 11 Notepad TabState parser (W-15).
//!
//! Parses `{GUID}.bin` files under
//! `%LOCALAPPDATA%\Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\
//! LocalState\TabState\`. Skips `{GUID}.0.bin` / `{GUID}.1.bin`
//! transient write files.
//!
//! The format is a custom proprietary binary. We take a pragmatic
//! approach: scan for UTF-16LE ASCII runs ≥ 4 chars, largest run wins
//! as the tab text; scan for a Windows-path-shaped run to identify a
//! saved-file association.
//!
//! MITRE: T1059 (command and scripting), T1552.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotepadTab {
    pub tab_guid: String,
    pub unsaved_content: bool,
    pub content: Option<String>,
    pub file_path: Option<String>,
    pub content_length: usize,
    pub suspicious_pattern: Option<String>,
}

pub fn parse(bytes: &[u8], guid: &str) -> NotepadTab {
    let runs = extract_utf16le_runs(bytes, 4);
    let file_path = runs.iter().find(|s| looks_like_windows_path(s)).cloned();
    // Largest non-path run is the content candidate.
    let content = runs
        .iter()
        .filter(|s| !looks_like_windows_path(s))
        .max_by_key(|s| s.len())
        .cloned();
    let content_length = content.as_deref().map(|s| s.len()).unwrap_or(0);
    let unsaved_content = file_path.is_none() && content_length > 0;
    let suspicious_pattern =
        content.as_deref().and_then(classify_suspicious).map(|s| s.to_string());
    NotepadTab {
        tab_guid: guid.to_string(),
        unsaved_content,
        content,
        file_path,
        content_length,
        suspicious_pattern,
    }
}

pub fn extract_utf16le_runs(bytes: &[u8], min_chars: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 2 <= bytes.len() {
        let start = i;
        let mut run: Vec<u8> = Vec::new();
        while i + 2 <= bytes.len() {
            let lo = bytes[i];
            let hi = bytes[i + 1];
            if hi != 0x00 || !(0x20..=0x7E).contains(&lo) {
                break;
            }
            run.push(lo);
            i += 2;
        }
        if run.len() >= min_chars {
            if let Ok(s) = std::str::from_utf8(&run) {
                out.push(s.to_string());
            }
        }
        if i == start {
            i += 2;
        }
    }
    out
}

fn looks_like_windows_path(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\'
}

fn classify_suspicious(text: &str) -> Option<&'static str> {
    let lc = text.to_ascii_lowercase();
    if lc.contains("-encodedcommand") || has_long_base64(text) {
        return Some("encoded-command");
    }
    if lc.contains("invoke-") || lc.contains("iex ") {
        return Some("powershell");
    }
    if lc.contains("http://") || lc.contains("https://") {
        return Some("url");
    }
    if lc.contains("password") || lc.contains("passwd") || lc.contains("api_key")
        || lc.contains("secret")
    {
        return Some("credential");
    }
    None
}

fn has_long_base64(s: &str) -> bool {
    let mut run: usize = 0;
    let mut best: usize = 0;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' {
            run += 1;
            if run > best {
                best = run;
            }
        } else {
            run = 0;
        }
    }
    best >= 32
}

pub fn is_tabstate_path(path: &Path) -> bool {
    let normalised = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let is_tabstate = normalised
        .contains("microsoft.windowsnotepad_8wekyb3d8bbwe/localstate/tabstate/");
    if !is_tabstate {
        return false;
    }
    if !normalised.ends_with(".bin") {
        return false;
    }
    // Exclude .0.bin / .1.bin transient writes.
    !(normalised.ends_with(".0.bin") || normalised.ends_with(".1.bin"))
}

pub fn tab_guid_from_path(path: &Path) -> String {
    let name = path
        .to_string_lossy()
        .replace('\\', "/");
    name.rsplit('/').next().unwrap_or("").trim_end_matches(".bin").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for u in s.encode_utf16() {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out
    }

    #[test]
    fn extract_utf16le_runs_picks_up_ascii_text() {
        let mut blob = vec![0u8; 16];
        blob.extend_from_slice(&utf16("hello world"));
        blob.extend_from_slice(&[0u8; 8]);
        let runs = extract_utf16le_runs(&blob, 4);
        assert!(runs.iter().any(|s| s == "hello world"));
    }

    #[test]
    fn parse_identifies_unsaved_content() {
        let mut blob = vec![0u8; 8];
        blob.extend_from_slice(&utf16("secret draft content"));
        blob.extend_from_slice(&[0u8; 16]);
        let tab = parse(&blob, "ABC-GUID");
        assert!(tab.unsaved_content);
        assert_eq!(tab.content.as_deref(), Some("secret draft content"));
        assert!(tab.file_path.is_none());
    }

    #[test]
    fn parse_identifies_saved_file_path() {
        let mut blob = vec![0u8; 8];
        blob.extend_from_slice(&utf16("C:\\Users\\alice\\notes.txt"));
        blob.extend_from_slice(&[0u8; 8]);
        blob.extend_from_slice(&utf16("some body"));
        let tab = parse(&blob, "DEF-GUID");
        assert_eq!(tab.file_path.as_deref(), Some("C:\\Users\\alice\\notes.txt"));
        assert!(!tab.unsaved_content);
    }

    #[test]
    fn classify_suspicious_flags_powershell_and_creds() {
        let mut blob = vec![0u8; 8];
        blob.extend_from_slice(&utf16("password=hunter2 and iex foo"));
        let tab = parse(&blob, "G");
        assert!(tab.suspicious_pattern.is_some());
    }

    #[test]
    fn is_tabstate_path_filters_transient_writes() {
        assert!(is_tabstate_path(Path::new(
            "C:\\Users\\a\\AppData\\Local\\Packages\\Microsoft.WindowsNotepad_8wekyb3d8bbwe\\LocalState\\TabState\\GUID.bin"
        )));
        assert!(!is_tabstate_path(Path::new(
            "C:\\Users\\a\\AppData\\Local\\Packages\\Microsoft.WindowsNotepad_8wekyb3d8bbwe\\LocalState\\TabState\\GUID.0.bin"
        )));
        assert!(!is_tabstate_path(Path::new("/tmp/unrelated.bin")));
    }
}
