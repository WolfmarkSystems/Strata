//! Windows Search Index (ESE) string-carving parser (X-2).
//!
//! Location: `C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb`.
//! Format: Extensible Storage Engine (ESE / JET Blue) database.
//!
//! ## Implementation choice
//! Full ESE catalog walking + long-value decoding requires either the
//! `libesedb` C bindings or the unpublished `frnsc-esedb` crate — neither
//! is available in the Strata workspace today. Per SPRINT X-2 we take the
//! **string-carving fallback**: validate the ESE file magic, then scan
//! the raw bytes for UTF-16LE runs that look like Windows paths. This
//! proves the file's presence and surfaces the indexed paths (the
//! highest-value piece of user-activity evidence inside Windows.edb)
//! without shipping a half-implemented binary decoder.
//!
//! Upgrading to full ESE parsing is a follow-up; the carving fallback
//! is intentionally conservative so a future deep parser can replace it
//! without disturbing consumers.
//!
//! ## Carving rules
//! * UTF-16LE ASCII run, minimum 10 characters.
//! * Must contain either `\` or `/` to qualify as a path.
//! * Must start with a drive letter + colon, or a UNC prefix, or a
//!   relative fragment that is file-extension shaped.
//! * Hard cap: 10 000 records per database to bound memory.
//!
//! ## MITRE ATT&CK
//! * **T1083** — File and Directory Discovery (the user's own index
//!   over their filesystem is exactly the knowledge T1083 measures).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use std::path::Path;

/// ESE file magic at offset 4. Little-endian `0x89ABCDEF`.
const ESE_MAGIC_OFFSET: usize = 4;
const ESE_MAGIC: [u8; 4] = [0xEF, 0xCD, 0xAB, 0x89];

/// Minimum character count for a carved UTF-16LE run to be retained.
const MIN_CARVED_CHARS: usize = 10;

/// Hard cap on records surfaced per database.
const MAX_RECORDS: usize = 10_000;

/// One record carved from a `Windows.edb` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchIndexEntry {
    /// Carved path as a UTF-8 string (converted from UTF-16LE in place).
    pub item_path: String,
    /// File offset of the UTF-16LE run within the database. Useful for
    /// cross-referencing against a full ESE parse later.
    pub file_offset: u64,
    /// Length of the decoded path in characters.
    pub path_length: usize,
}

/// True when the bytes look like an ESE database by header magic.
pub fn has_ese_magic(bytes: &[u8]) -> bool {
    bytes.len() >= ESE_MAGIC_OFFSET + ESE_MAGIC.len()
        && bytes[ESE_MAGIC_OFFSET..ESE_MAGIC_OFFSET + ESE_MAGIC.len()] == ESE_MAGIC
}

/// Parse a `Windows.edb` (or any ESE blob) and return carved path
/// entries. Empty vec on magic mismatch. Never panics.
pub fn parse(_path: &Path, bytes: &[u8]) -> Vec<SearchIndexEntry> {
    if !has_ese_magic(bytes) {
        return Vec::new();
    }
    carve_utf16le_paths(bytes)
}

/// Scan `bytes` for UTF-16LE runs that look like Windows paths.
///
/// Public for testability — callers can feed synthetic byte slices
/// directly without needing an ESE file magic.
pub fn carve_utf16le_paths(bytes: &[u8]) -> Vec<SearchIndexEntry> {
    let mut out = Vec::new();
    // We walk 16-bit-aligned positions. A UTF-16LE ASCII character is
    // `[0x20..0x7F, 0x00]` or `[0x00, 0x00]` (null terminator). We
    // collect a run until we hit a non-matching pair.
    let mut i: usize = 0;
    while i + 2 <= bytes.len() {
        if out.len() >= MAX_RECORDS {
            break;
        }
        let start = i;
        let mut run: Vec<u8> = Vec::new();
        while i + 2 <= bytes.len() {
            let lo = bytes[i];
            let hi = bytes[i + 1];
            if hi != 0x00 {
                break;
            }
            if !(0x20..=0x7E).contains(&lo) {
                break;
            }
            run.push(lo);
            i += 2;
        }
        if run.len() >= MIN_CARVED_CHARS {
            if let Ok(text) = std::str::from_utf8(&run) {
                if looks_like_path(text) {
                    out.push(SearchIndexEntry {
                        item_path: text.to_string(),
                        file_offset: start as u64,
                        path_length: text.len(),
                    });
                }
            }
        }
        // Skip the byte that broke the run so we don't infinite-loop
        // on stretches of non-text bytes.
        if i == start {
            i += 2;
        }
    }
    out
}

fn looks_like_path(s: &str) -> bool {
    if !(s.contains('\\') || s.contains('/')) {
        return false;
    }
    let bytes = s.as_bytes();
    // `C:\...` or `\\server\...` or `/path/...`.
    if bytes.len() >= 3 && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/') {
        return bytes[0].is_ascii_alphabetic();
    }
    if s.starts_with("\\\\") || s.starts_with("//") {
        return true;
    }
    // POSIX-absolute path with at least two path segments.
    if s.starts_with('/') && s[1..].contains('/') {
        return true;
    }
    // Relative path with a filename that has an extension.
    if let Some(dot) = s.rfind('.') {
        let ext = &s[dot + 1..];
        if !ext.is_empty() && ext.len() <= 6 && ext.chars().all(|c| c.is_ascii_alphanumeric()) {
            return true;
        }
    }
    false
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le(s: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(s.len() * 2);
        for ch in s.encode_utf16() {
            out.extend_from_slice(&ch.to_le_bytes());
        }
        out
    }

    fn build_ese_blob(payloads: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        // 4 bytes checksum, then magic.
        out.extend_from_slice(&[0u8; ESE_MAGIC_OFFSET]);
        out.extend_from_slice(&ESE_MAGIC);
        out.extend_from_slice(&[0u8; 248]);
        for p in payloads {
            out.extend_from_slice(&utf16le(p));
            out.extend_from_slice(&[0u8; 8]);
        }
        out
    }

    #[test]
    fn parse_returns_empty_on_missing_magic() {
        let blob = vec![0u8; 64];
        let records = parse(Path::new("/tmp/nowhere.edb"), &blob);
        assert!(records.is_empty());
    }

    #[test]
    fn parse_returns_empty_on_short_input() {
        let blob = vec![0u8; 3];
        let records = parse(Path::new("/tmp/nowhere.edb"), &blob);
        assert!(records.is_empty());
    }

    #[test]
    fn carves_drive_letter_paths_from_valid_ese() {
        let blob = build_ese_blob(&[
            "C:\\Users\\alice\\Documents\\report.docx",
            "D:\\Downloads\\installer.exe",
            "\\\\fileserver\\share\\archive.zip",
        ]);
        let records = parse(Path::new("/tmp/Windows.edb"), &blob);
        assert_eq!(records.len(), 3);
        assert!(records
            .iter()
            .any(|r| r.item_path == "C:\\Users\\alice\\Documents\\report.docx"));
        assert!(records
            .iter()
            .any(|r| r.item_path == "\\\\fileserver\\share\\archive.zip"));
    }

    #[test]
    fn ignores_runs_without_slash_or_valid_extension() {
        let blob = build_ese_blob(&["HelloThereNoPath", "AlsoNoSlashOrExt", "C:\\Real\\Path.txt"]);
        let records = parse(Path::new("/tmp/Windows.edb"), &blob);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].item_path, "C:\\Real\\Path.txt");
    }

    #[test]
    fn ignores_runs_shorter_than_minimum() {
        let blob = build_ese_blob(&["C:\\a.t"]);
        let records = parse(Path::new("/tmp/Windows.edb"), &blob);
        assert!(records.is_empty());
    }

    #[test]
    fn has_ese_magic_detects_header() {
        let mut blob = vec![0u8; 8];
        blob[4..8].copy_from_slice(&ESE_MAGIC);
        assert!(has_ese_magic(&blob));
        blob[7] = 0;
        assert!(!has_ese_magic(&blob));
    }

    #[test]
    fn looks_like_path_only_accepts_real_paths() {
        assert!(looks_like_path("C:\\Windows\\System32\\cmd.exe"));
        assert!(looks_like_path("/usr/local/bin/ls"));
        assert!(looks_like_path("folder\\file.pdf"));
        assert!(!looks_like_path("no slash here"));
        assert!(!looks_like_path("Hello world!"));
    }
}
