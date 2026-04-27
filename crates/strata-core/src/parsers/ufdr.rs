//! UFDR (Cellebrite Universal Forensic Extraction Device Report) parser.
//!
//! A UFDR file is a ZIP container produced by Cellebrite Reader and friends.
//! Inside the archive you typically find:
//!
//! ```text
//! report.xml         -- the index of every extracted file with metadata
//! files/             -- subfolder containing the actual extracted bytes
//! ufed.xml           -- (sometimes) device manifest with model/IMEI/etc.
//! ```
//!
//! `report.xml` is the source of truth for *original* device paths. Each
//! `<file>` element carries a `path="..."` attribute that names the original
//! on-device location (for example `/data/data/com.whatsapp/databases/msgstore.db`),
//! while the actual bytes are stored at a flat archive location like
//! `files/Image/photo_001.jpg`.
//!
//! This parser:
//!
//!   1. Detects whether a given byte buffer is a UFDR ZIP (PK\x03\x04 magic + a
//!      `report.xml` entry).
//!   2. Parses `report.xml` extracting `(archive_path, original_path, hash,
//!      size, mtime)` tuples.
//!   3. Returns one `ParsedArtifact` per `<file>` so downstream plugins can
//!      reason over the original device hierarchy without untar/unzip.
//!   4. Optionally, callers can wrap a UFDR archive in a `UfdrEvidenceSource`
//!      (see `open_ufdr_archive` below) which exposes the *reconstructed*
//!      VFS — original device paths as the directory tree, with bytes pulled
//!      from the flat ZIP layout on demand.
//!
//! The XML grammar is intentionally permissive — different Cellebrite Reader
//! versions emit slightly different attribute names. We accept any of:
//!
//!   * `<file path="..." extraction="..." size="..." md5="..." sha256="...">`
//!   * `<File path="..." Size="..." MD5="..." SHA256="...">`
//!   * `<file LocalPath="..." Path="..." MD5="...">`
//!
//! Reference:
//!   https://blog.dfir.science/2018/02/cellebrite-ufdr-format-deep-dive/

use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::path::Path;
use zip::ZipArchive;

const UFDR_LIMIT: usize = 50_000;

pub struct UfdrParser;

impl UfdrParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for UfdrParser {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UfdrFileEntry {
    /// Path inside the UFDR ZIP archive (e.g. `files/Image/photo.jpg`).
    pub archive_path: String,
    /// Original device path as recorded in `report.xml` (e.g.
    /// `/data/data/com.whatsapp/databases/msgstore.db`).
    pub original_path: String,
    pub size: Option<u64>,
    pub md5: Option<String>,
    pub sha256: Option<String>,
    /// Source category from the UFDR (`Image`, `Database`, `Audio`, ...).
    pub category: Option<String>,
    /// File modification time as recorded in the report (Unix seconds).
    pub mtime: Option<i64>,
}

impl ArtifactParser for UfdrParser {
    fn name(&self) -> &str {
        "Cellebrite UFDR"
    }

    fn artifact_type(&self) -> &str {
        "mobile_extraction"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![".ufdr", "report.xml", "ufdr.xml"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let lc = path.to_string_lossy().to_lowercase();

        // Two ingest paths:
        //   * caller passed the .ufdr ZIP container directly
        //   * caller passed the bare report.xml that lives inside one
        if lc.ends_with(".ufdr") || looks_like_zip(data) {
            let entries = parse_ufdr_zip(data)?;
            return Ok(entries_to_artifacts(path, &entries));
        }

        if lc.ends_with("report.xml") || lc.ends_with("ufdr.xml") {
            let entries = parse_report_xml(&String::from_utf8_lossy(data));
            return Ok(entries_to_artifacts(path, &entries));
        }

        Ok(Vec::new())
    }
}

fn looks_like_zip(data: &[u8]) -> bool {
    data.len() >= 4 && &data[..4] == b"PK\x03\x04"
}

/// Open the ZIP, locate `report.xml`, parse it, and return entries.
pub fn parse_ufdr_zip(data: &[u8]) -> Result<Vec<UfdrFileEntry>, ParserError> {
    let cursor = Cursor::new(data);
    let mut archive =
        ZipArchive::new(cursor).map_err(|e| ParserError::Parse(format!("UFDR open: {}", e)))?;

    // Find report.xml inside the archive (it lives at the root in mainline
    // UFDRs but some exports nest it under `Reports/report.xml`).
    let report_name = (0..archive.len())
        .filter_map(|i| archive.by_index(i).ok().map(|f| f.name().to_string()))
        .find(|name| {
            let lc = name.to_lowercase();
            lc.ends_with("report.xml") || lc.ends_with("ufdr.xml")
        });
    let Some(report_name) = report_name else {
        return Err(ParserError::Parse(
            "UFDR archive does not contain report.xml".to_string(),
        ));
    };

    let mut entry = archive
        .by_name(&report_name)
        .map_err(|e| ParserError::Parse(format!("UFDR report.xml read: {}", e)))?;
    let mut xml = String::new();
    entry
        .read_to_string(&mut xml)
        .map_err(|e| ParserError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;

    Ok(parse_report_xml(&xml))
}

/// Hand-rolled lenient parser for `report.xml`.
///
/// We avoid pulling in a full XML library because (a) we only need attributes
/// out of `<file>` elements and (b) UFDR XML is generated and predictable.
/// The parser walks `<file ... />` and `<file ... > ... </file>` elements,
/// extracts the attributes that match any of the recognised name spellings,
/// and stops once `UFDR_LIMIT` entries are collected.
pub fn parse_report_xml(xml: &str) -> Vec<UfdrFileEntry> {
    let mut entries = Vec::new();
    let bytes = xml.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() && entries.len() < UFDR_LIMIT {
        // Find next '<file' or '<File'
        let lower_window = if idx + 6 < bytes.len() {
            &bytes[idx..]
        } else {
            break;
        };
        let next = find_file_tag(lower_window);
        let Some(rel) = next else { break };
        let abs = idx + rel;
        // Locate the end of the opening tag '>'
        let Some(end_tag) = find_byte(&bytes[abs..], b'>') else {
            break;
        };
        let tag_slice = &xml[abs..abs + end_tag + 1];
        let attrs = extract_attributes(tag_slice);
        if let Some(entry) = build_entry_from_attrs(&attrs) {
            entries.push(entry);
        }
        idx = abs + end_tag + 1;
    }
    entries
}

/// Locate the next opening `<file ` or `<File ` tag (case-insensitive on the
/// 4-letter element name only). Returns the byte offset relative to the slice.
fn find_file_tag(haystack: &[u8]) -> Option<usize> {
    let len = haystack.len();
    let mut i = 0;
    while i + 5 < len {
        if haystack[i] == b'<'
            && (haystack[i + 1] == b'f' || haystack[i + 1] == b'F')
            && (haystack[i + 2] == b'i' || haystack[i + 2] == b'I')
            && (haystack[i + 3] == b'l' || haystack[i + 3] == b'L')
            && (haystack[i + 4] == b'e' || haystack[i + 4] == b'E')
        {
            // Must be followed by whitespace or '/' or '>'
            let next = haystack[i + 5];
            if next == b' ' || next == b'\t' || next == b'\n' || next == b'/' || next == b'>' {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn find_byte(haystack: &[u8], byte: u8) -> Option<usize> {
    haystack.iter().position(|b| *b == byte)
}

/// Extract `key="value"` pairs from a tag fragment. Lenient: tolerates
/// single-quoted values and self-closing slashes. Returns lowercased keys.
fn extract_attributes(tag: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let bytes = tag.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Skip until next alphanumeric char (start of an attribute name).
        while i < bytes.len() && !bytes[i].is_ascii_alphanumeric() && bytes[i] != b'_' {
            i += 1;
        }
        let key_start = i;
        while i < bytes.len()
            && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b':')
        {
            i += 1;
        }
        if key_start == i {
            break;
        }
        let key = tag[key_start..i].to_lowercase();

        // Expect '='
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            // Bare attribute (no value) — skip.
            continue;
        }
        i += 1;
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let quote = bytes[i];
        if quote != b'"' && quote != b'\'' {
            continue;
        }
        i += 1;
        let val_start = i;
        while i < bytes.len() && bytes[i] != quote {
            i += 1;
        }
        let value = decode_xml_entities(&tag[val_start..i]);
        out.insert(key, value);
        if i < bytes.len() {
            i += 1;
        }
    }
    out
}

fn decode_xml_entities(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

fn build_entry_from_attrs(attrs: &HashMap<String, String>) -> Option<UfdrFileEntry> {
    // Original device path can show up under several names depending on the
    // Cellebrite Reader version that emitted the report.
    let original_path = attrs
        .get("path")
        .or_else(|| attrs.get("originalpath"))
        .or_else(|| attrs.get("devicepath"))
        .or_else(|| attrs.get("deviceabsolutepath"))?
        .clone();
    if original_path.is_empty() {
        return None;
    }

    // Inside-archive path. Many UFDRs emit `LocalPath="files/..."` for the
    // disk extraction copy.
    let archive_path = attrs
        .get("localpath")
        .or_else(|| attrs.get("extraction"))
        .or_else(|| attrs.get("file"))
        .cloned()
        .unwrap_or_else(|| original_path.clone());

    let size = attrs
        .get("size")
        .or_else(|| attrs.get("filesize"))
        .and_then(|s| s.parse::<u64>().ok());

    let md5 = attrs.get("md5").cloned();
    let sha256 = attrs
        .get("sha256")
        .or_else(|| attrs.get("sha-256"))
        .cloned();

    let category = attrs.get("category").or_else(|| attrs.get("type")).cloned();

    let mtime = attrs
        .get("modifytime")
        .or_else(|| attrs.get("modified"))
        .or_else(|| attrs.get("mtime"))
        .and_then(|s| s.parse::<i64>().ok());

    Some(UfdrFileEntry {
        archive_path,
        original_path,
        size,
        md5,
        sha256,
        category,
        mtime,
    })
}

fn entries_to_artifacts(path: &Path, entries: &[UfdrFileEntry]) -> Vec<ParsedArtifact> {
    let source = path.to_string_lossy().to_string();
    entries
        .iter()
        .map(|e| ParsedArtifact {
            timestamp: e.mtime,
            artifact_type: "mobile_extraction".to_string(),
            description: format!("UFDR file: {}", e.original_path),
            source_path: source.clone(),
            json_data: serde_json::to_value(e).unwrap_or_default(),
        })
        .collect()
}

// ────────────────────────────────────────────────────────────────────────────
// Reconstructed UFDR file map (used by callers that want to mount the archive
// as an EvidenceSource-like view of original device paths).
// ────────────────────────────────────────────────────────────────────────────

/// In-memory reconstruction of a UFDR archive: original-device-path → archive
/// entry. The caller owns the underlying ZIP bytes; this struct is only the
/// path index.
#[derive(Debug, Default, Clone)]
pub struct UfdrFileMap {
    /// Map: original device path → UfdrFileEntry
    pub by_original: HashMap<String, UfdrFileEntry>,
}

impl UfdrFileMap {
    pub fn from_zip_bytes(data: &[u8]) -> Result<Self, ParserError> {
        let entries = parse_ufdr_zip(data)?;
        let mut by_original = HashMap::with_capacity(entries.len());
        for entry in entries {
            by_original.insert(entry.original_path.clone(), entry);
        }
        Ok(Self { by_original })
    }

    pub fn lookup(&self, original_path: &str) -> Option<&UfdrFileEntry> {
        self.by_original.get(original_path)
    }

    pub fn len(&self) -> usize {
        self.by_original.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_original.is_empty()
    }

    /// List all reconstructed device paths under `prefix`. The match is case
    /// sensitive, simple `starts_with` — Pulse uses this to enumerate files
    /// under app-private directories like `/data/data/com.whatsapp/`.
    pub fn list_under(&self, prefix: &str) -> Vec<&UfdrFileEntry> {
        self.by_original
            .values()
            .filter(|e| e.original_path.starts_with(prefix))
            .collect()
    }
}

/// Read the bytes for a single device path out of a UFDR archive.
///
/// `archive_data` is the full UFDR ZIP buffer; `original_path` is the device
/// path the caller wants. Returns the bytes from the matching `<file>`
/// element's `LocalPath` (or `extraction`) entry inside the archive.
pub fn read_ufdr_file(
    archive_data: &[u8],
    map: &UfdrFileMap,
    original_path: &str,
) -> Result<Vec<u8>, ParserError> {
    let entry = map
        .lookup(original_path)
        .ok_or_else(|| ParserError::Vfs(format!("UFDR: no entry for {}", original_path)))?;
    let cursor = Cursor::new(archive_data);
    let mut archive = ZipArchive::new(cursor).map_err(|e| ParserError::Parse(e.to_string()))?;
    let mut zf = archive
        .by_name(&entry.archive_path)
        .map_err(|e| ParserError::Vfs(format!("UFDR: archive entry missing: {}", e)))?;
    let mut buf = Vec::with_capacity(zf.size() as usize);
    zf.read_to_end(&mut buf).map_err(ParserError::Io)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use zip::write::{FileOptions, ZipWriter};

    fn build_sample_report_xml() -> String {
        r#"<?xml version="1.0" encoding="utf-8"?>
<report>
    <files>
        <file path="/data/data/com.whatsapp/databases/msgstore.db"
              LocalPath="files/Database/msgstore.db"
              size="1048576"
              md5="abcd1234abcd1234abcd1234abcd1234"
              sha256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
              category="Database" />
        <file path="/sdcard/DCIM/Camera/photo_001.jpg"
              LocalPath="files/Image/photo_001.jpg"
              size="2048"
              md5="11111111111111111111111111111111"
              category="Image" />
        <file Path="/data/data/com.facebook/cache/profile.bin"
              LocalPath="files/Cache/profile.bin"
              Size="42"
              MD5="22222222222222222222222222222222" />
    </files>
</report>"#
            .to_string()
    }

    fn build_sample_ufdr_zip() -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut zip = ZipWriter::new(cursor);
            let opts: FileOptions<()> =
                FileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zip.start_file("report.xml", opts).unwrap();
            zip.write_all(build_sample_report_xml().as_bytes()).unwrap();

            zip.start_file("files/Database/msgstore.db", opts).unwrap();
            zip.write_all(b"FAKE-WHATSAPP-SQLITE-CONTENT").unwrap();

            zip.start_file("files/Image/photo_001.jpg", opts).unwrap();
            zip.write_all(b"\xFF\xD8\xFF\xE0FAKE-JPEG").unwrap();

            zip.finish().unwrap();
        }
        buf
    }

    #[test]
    fn parses_report_xml_with_three_files() {
        let xml = build_sample_report_xml();
        let entries = parse_report_xml(&xml);
        assert_eq!(entries.len(), 3);
        assert_eq!(
            entries[0].original_path,
            "/data/data/com.whatsapp/databases/msgstore.db"
        );
        assert_eq!(entries[0].size, Some(1_048_576));
        assert_eq!(
            entries[0].md5.as_deref(),
            Some("abcd1234abcd1234abcd1234abcd1234")
        );
        assert_eq!(entries[1].category.as_deref(), Some("Image"));
    }

    #[test]
    fn parses_zip_container_and_extracts_entries() {
        let buf = build_sample_ufdr_zip();
        let entries = parse_ufdr_zip(&buf).unwrap();
        assert_eq!(entries.len(), 3);
        let whatsapp = entries
            .iter()
            .find(|e| e.original_path.contains("whatsapp"))
            .unwrap();
        assert_eq!(whatsapp.archive_path, "files/Database/msgstore.db");
    }

    #[test]
    fn ufdr_file_map_lookup_round_trip() {
        let buf = build_sample_ufdr_zip();
        let map = UfdrFileMap::from_zip_bytes(&buf).unwrap();
        assert_eq!(map.len(), 3);
        let entry = map
            .lookup("/sdcard/DCIM/Camera/photo_001.jpg")
            .expect("photo entry");
        assert_eq!(entry.archive_path, "files/Image/photo_001.jpg");
    }

    #[test]
    fn read_ufdr_file_returns_archive_bytes() {
        let buf = build_sample_ufdr_zip();
        let map = UfdrFileMap::from_zip_bytes(&buf).unwrap();
        let bytes = read_ufdr_file(&buf, &map, "/sdcard/DCIM/Camera/photo_001.jpg").unwrap();
        assert_eq!(&bytes[..3], b"\xFF\xD8\xFF");
    }

    #[test]
    fn list_under_filters_by_prefix() {
        let buf = build_sample_ufdr_zip();
        let map = UfdrFileMap::from_zip_bytes(&buf).unwrap();
        let whatsapp = map.list_under("/data/data/com.whatsapp/");
        assert_eq!(whatsapp.len(), 1);
    }

    #[test]
    fn artifact_parser_recognises_ufdr_extension() {
        let parser = UfdrParser::new();
        let buf = build_sample_ufdr_zip();
        let path = PathBuf::from("/cases/sample.ufdr");
        let artifacts = parser.parse_file(&path, &buf).unwrap();
        assert_eq!(artifacts.len(), 3);
    }

    #[test]
    fn artifact_parser_recognises_bare_report_xml() {
        let parser = UfdrParser::new();
        let xml = build_sample_report_xml();
        let path = PathBuf::from("/tmp/report.xml");
        let artifacts = parser.parse_file(&path, xml.as_bytes()).unwrap();
        assert_eq!(artifacts.len(), 3);
    }

    #[test]
    fn missing_report_xml_errors_cleanly() {
        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut zip = ZipWriter::new(cursor);
            let opts: FileOptions<()> = FileOptions::default();
            zip.start_file("README.txt", opts).unwrap();
            zip.write_all(b"not a ufdr").unwrap();
            zip.finish().unwrap();
        }
        let err = parse_ufdr_zip(&buf).unwrap_err();
        match err {
            ParserError::Parse(msg) => assert!(msg.contains("report.xml")),
            other => panic!("expected Parse error, got {:?}", other),
        }
    }
}
