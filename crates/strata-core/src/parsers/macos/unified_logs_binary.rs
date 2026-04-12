use crate::parser::{ParsedArtifact, ParserError};
use crate::parsers::macos::unified_logs::UnifiedLogEntry;
use std::path::Path;

/// Simple binary decoder for .tracev3 files (macOS Unified Logs)
/// This is a complex format, here we implement a basic chunk-based recovery
pub fn parse_tracev3(
    path: &Path,
    data: &[u8],
    out: &mut Vec<ParsedArtifact>,
) -> Result<(), ParserError> {
    if data.len() < 16 || &data[0..4] != b"vt03" {
        return Ok(()); // Not a tracev3 file
    }

    // tracev3 is composed of chunks.
    // Header (vt03), then many catalogs, chunks, and data blocks.

    let mut offset = 0;
    while offset + 12 <= data.len() {
        let tag = &data[offset..offset + 4];
        let size = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap()) as usize;

        if size == 0 || offset + size > data.len() {
            break;
        }

        // Tag examples:
        // 0x1000 - Header
        // 0x6001 - Catalog
        // 0x6002 - Chunk

        match tag {
            b"\x00\x10\x00\x00" => { // Header
                 // Parse header info if needed
            }
            b"\x01\x60\x00\x00" => { // Catalog
                 // Catalogs contain the string templates and subsystem names
            }
            b"\x02\x60\x00\x00" => {
                // Chunk
                // Chunks contain the actual fire-hose events
                parse_log_chunk(path, &data[offset..offset + size], out);
            }
            _ => {}
        }

        offset += size;
    }

    Ok(())
}

fn parse_log_chunk(path: &Path, _chunk_data: &[u8], out: &mut Vec<ParsedArtifact>) {
    // In a real implementation, we would decode the firehose protocol here.
    // For now, we record that we found binary log chunks in this file.
    let entry = UnifiedLogEntry {
        timestamp: None,
        subsystem: Some("binary_logs".to_string()),
        category: None,
        message: Some(format!(
            "Detected binary tracev3 log chunks in: {}",
            path.display()
        )),
        process: None,
        pid: None,
        tid: None,
        activity_id: None,
        thread: None,
    };

    out.push(ParsedArtifact {
        timestamp: None,
        artifact_type: "system_log".to_string(),
        description: "macOS Unified Log (Binary TraceV3)".to_string(),
        source_path: path.to_string_lossy().to_string(),
        json_data: serde_json::to_value(&entry).unwrap_or_default(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_tracev3_header() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"vt03");  // magic
        buf.extend_from_slice(&64_u32.to_le_bytes()); // size of this chunk
        buf.extend_from_slice(&[0u8; 56]); // padding to 64 bytes
        buf
    }

    fn build_chunk(tag: &[u8; 4], payload_size: usize) -> Vec<u8> {
        let total = 8 + payload_size;
        let mut buf = Vec::new();
        buf.extend_from_slice(tag);
        buf.extend_from_slice(&(total as u32).to_le_bytes());
        buf.resize(total, 0);
        buf
    }

    #[test]
    fn parses_tracev3_with_chunk() {
        let mut data = build_tracev3_header();
        data.extend_from_slice(&build_chunk(b"\x02\x60\x00\x00", 24)); // Chunk tag
        let mut out = Vec::new();
        parse_tracev3(Path::new("test.tracev3"), &data, &mut out).unwrap();
        assert!(!out.is_empty());
        assert!(out[0].description.contains("TraceV3"));
    }

    #[test]
    fn rejects_non_tracev3_magic() {
        let data = b"NOT_A_TRACEV3_FILE_AT_ALL";
        let mut out = Vec::new();
        parse_tracev3(Path::new("bad.tracev3"), data, &mut out).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn handles_empty_data() {
        let mut out = Vec::new();
        parse_tracev3(Path::new("empty"), b"", &mut out).unwrap();
        assert!(out.is_empty());
    }
}
