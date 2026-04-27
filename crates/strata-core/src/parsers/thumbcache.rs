use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Windows Thumbcache Parser
/// Path: %LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_*.db
///
/// Thumbnail caches prove files existed on a system even after deletion.
/// CRITICAL for CSAM and IP theft cases — thumbnails persist after file deletion.
///
/// Format: CMMM header (magic 0x434D4D4D), followed by cache entries.
/// Each entry: header with hash, size, data offset, then thumbnail image data.
pub struct ThumbcacheParser;

impl Default for ThumbcacheParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ThumbcacheParser {
    pub fn new() -> Self {
        Self
    }
}

/// CMMM magic bytes for thumbcache files
const CMMM_MAGIC: [u8; 4] = [0x43, 0x4D, 0x4D, 0x4D]; // "CMMM"

#[derive(Debug, Serialize, Deserialize)]
pub struct ThumbcacheHeader {
    pub version: u32,
    pub cache_type: String,
    pub first_entry_offset: u32,
    pub first_available_offset: u32,
    pub entry_count: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThumbcacheEntry {
    pub cache_entry_hash: String,
    pub data_size: u32,
    pub header_size: u32,
    pub data_offset: u64,
    pub identifier_size: u32,
    pub padding_size: u32,
    pub data_checksum: Option<String>,
    pub header_checksum: Option<String>,
    pub image_format: Option<String>,
    pub entry_index: usize,
}

impl ArtifactParser for ThumbcacheParser {
    fn name(&self) -> &str {
        "Windows Thumbcache Parser"
    }

    fn artifact_type(&self) -> &str {
        "thumbnail_cache"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "thumbcache_32.db",
            "thumbcache_96.db",
            "thumbcache_256.db",
            "thumbcache_1024.db",
            "thumbcache_2560.db",
            "thumbcache_sr.db",
            "thumbcache_wide.db",
            "thumbcache_exif.db",
            "thumbcache_wide_alternate.db",
            "thumbcache_custom_stream.db",
            "iconcache_32.db",
            "iconcache_48.db",
            "iconcache_96.db",
            "iconcache_256.db",
            "iconcache_1024.db",
            "iconcache_2560.db",
            "iconcache_wide.db",
            "iconcache_exif.db",
            "iconcache_sr.db",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();
        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        // Determine cache type from filename
        let cache_type = if filename.contains("thumbcache") {
            "thumbnail"
        } else if filename.contains("iconcache") {
            "icon"
        } else {
            "unknown"
        };

        // Validate CMMM header
        if data.len() < 24 || data[0..4] != CMMM_MAGIC {
            if !data.is_empty() {
                artifacts.push(ParsedArtifact {
                    timestamp: None,
                    artifact_type: "thumbnail_cache".to_string(),
                    description: format!(
                        "Thumbcache file (no CMMM header): {} ({} bytes)",
                        filename,
                        data.len()
                    ),
                    source_path: source,
                    json_data: serde_json::json!({
                        "filename": filename,
                        "size_bytes": data.len(),
                        "cache_type": cache_type,
                        "note": "File does not contain valid CMMM header",
                    }),
                });
            }
            return Ok(artifacts);
        }

        // Parse CMMM header
        let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let cache_type_code = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let first_entry_offset = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let first_available_offset = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let entry_count = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);

        let cache_type_str = match cache_type_code {
            0x00 => "thumbcache_32",
            0x01 => "thumbcache_96",
            0x02 => "thumbcache_256",
            0x03 => "thumbcache_1024",
            0x04 => "thumbcache_sr",
            0x05 => "thumbcache_wide",
            0x06 => "thumbcache_exif",
            0x07 => "thumbcache_wide_alternate",
            0x08 => "thumbcache_custom_stream",
            _ => cache_type,
        };

        let header = ThumbcacheHeader {
            version,
            cache_type: cache_type_str.to_string(),
            first_entry_offset,
            first_available_offset,
            entry_count,
        };

        // Summary artifact for the cache file itself
        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "thumbnail_cache_header".to_string(),
            description: format!(
                "Thumbcache: {} (v{}, {} entries, {} bytes)",
                cache_type_str,
                version,
                entry_count,
                data.len()
            ),
            source_path: source.clone(),
            json_data: serde_json::to_value(&header).unwrap_or_default(),
        });

        // Parse cache entries
        let mut offset = first_entry_offset as usize;
        let mut entry_index = 0;
        let max_entries = entry_count.min(10000) as usize; // Safety limit

        while offset + 48 <= data.len() && entry_index < max_entries {
            // Check for CMMM entry marker
            if data[offset..offset + 4] != CMMM_MAGIC {
                // Try to find next entry
                offset += 4;
                continue;
            }

            // Entry structure (Windows 7+ / Vista varies):
            // 0x00: CMMM magic (4 bytes)
            // 0x04: entry size (4 bytes)
            // 0x08: entry hash (8 bytes)
            // 0x10: identifier string size (4 bytes)
            // 0x14: padding size (4 bytes)
            // 0x18: data size (4 bytes)
            // 0x1C: unknown (4 bytes)
            // 0x20: data checksum (8 bytes)
            // 0x28: header checksum (8 bytes)

            let entry_size = u32::from_le_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);

            if entry_size == 0 || entry_size as usize > data.len() - offset {
                break;
            }

            let cache_entry_hash = format!(
                "{:016X}",
                u64::from_le_bytes([
                    data[offset + 8],
                    data[offset + 9],
                    data[offset + 10],
                    data[offset + 11],
                    data[offset + 12],
                    data[offset + 13],
                    data[offset + 14],
                    data[offset + 15],
                ])
            );

            let identifier_size = u32::from_le_bytes([
                data[offset + 16],
                data[offset + 17],
                data[offset + 18],
                data[offset + 19],
            ]);
            let padding_size = u32::from_le_bytes([
                data[offset + 20],
                data[offset + 21],
                data[offset + 22],
                data[offset + 23],
            ]);
            let data_size = u32::from_le_bytes([
                data[offset + 24],
                data[offset + 25],
                data[offset + 26],
                data[offset + 27],
            ]);

            // Detect image format from data if present
            let data_start = offset + 48 + identifier_size as usize + padding_size as usize;
            let image_format = if data_size > 4 && data_start + 4 <= data.len() {
                detect_image_format(&data[data_start..])
            } else {
                None
            };

            let entry = ThumbcacheEntry {
                cache_entry_hash: cache_entry_hash.clone(),
                data_size,
                header_size: 48,
                data_offset: data_start as u64,
                identifier_size,
                padding_size,
                data_checksum: None,
                header_checksum: None,
                image_format: image_format.clone(),
                entry_index,
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "thumbnail_entry".to_string(),
                description: format!(
                    "Thumbnail: hash={} size={} format={}",
                    cache_entry_hash,
                    data_size,
                    image_format.as_deref().unwrap_or("unknown"),
                ),
                source_path: source.clone(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });

            offset += entry_size as usize;
            entry_index += 1;
        }

        Ok(artifacts)
    }
}

/// Detect image format from the first few bytes of thumbnail data.
fn detect_image_format(data: &[u8]) -> Option<String> {
    if data.len() < 4 {
        return None;
    }
    // JPEG
    if data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
        return Some("JPEG".to_string());
    }
    // PNG
    if data.len() >= 8 && data[0..8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
        return Some("PNG".to_string());
    }
    // BMP
    if data[0] == 0x42 && data[1] == 0x4D {
        return Some("BMP".to_string());
    }
    // GIF
    if data.len() >= 6 && &data[0..3] == b"GIF" {
        return Some("GIF".to_string());
    }
    // EMF
    if data.len() >= 4 && data[0..4] == [0x01, 0x00, 0x00, 0x00] {
        return Some("EMF".to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn build_cmmm_header(
        version: u32,
        cache_type: u32,
        first_entry: u32,
        first_avail: u32,
        count: u32,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&CMMM_MAGIC);
        buf.extend_from_slice(&version.to_le_bytes());
        buf.extend_from_slice(&cache_type.to_le_bytes());
        buf.extend_from_slice(&first_entry.to_le_bytes());
        buf.extend_from_slice(&first_avail.to_le_bytes());
        buf.extend_from_slice(&count.to_le_bytes());
        buf
    }

    fn build_cmmm_entry(
        hash: u64,
        identifier_size: u32,
        padding_size: u32,
        data_size: u32,
    ) -> Vec<u8> {
        let entry_total = 48 + identifier_size + padding_size + data_size;
        let mut buf = Vec::new();
        buf.extend_from_slice(&CMMM_MAGIC);
        buf.extend_from_slice(&entry_total.to_le_bytes());
        buf.extend_from_slice(&hash.to_le_bytes());
        buf.extend_from_slice(&identifier_size.to_le_bytes());
        buf.extend_from_slice(&padding_size.to_le_bytes());
        buf.extend_from_slice(&data_size.to_le_bytes());
        buf.extend_from_slice(&0_u32.to_le_bytes());
        buf.extend_from_slice(&0_u64.to_le_bytes());
        buf.extend_from_slice(&0_u64.to_le_bytes());
        buf.resize(buf.len() + identifier_size as usize, 0);
        buf.resize(buf.len() + padding_size as usize, 0);
        if data_size >= 3 {
            buf.push(0xFF);
            buf.push(0xD8);
            buf.push(0xFF);
            buf.resize(buf.len() + (data_size as usize - 3), 0);
        } else {
            buf.resize(buf.len() + data_size as usize, 0);
        }
        buf
    }

    #[test]
    fn parses_valid_cmmm_header() {
        let mut data = build_cmmm_header(21, 0x02, 24, 200, 1);
        let entry = build_cmmm_entry(0xDEADBEEF_CAFEBABE, 0, 0, 10);
        data.extend_from_slice(&entry);
        let parser = ThumbcacheParser::new();
        let artifacts = parser
            .parse_file(Path::new("thumbcache_256.db"), &data)
            .unwrap();
        let header_art = artifacts
            .iter()
            .find(|a| a.artifact_type == "thumbnail_cache_header")
            .unwrap();
        assert!(header_art.description.contains("v21"));
        assert!(header_art.description.contains("1 entries"));
        let entry_art = artifacts
            .iter()
            .find(|a| a.artifact_type == "thumbnail_entry")
            .unwrap();
        assert!(entry_art.description.contains("DEADBEEFCAFEBABE"));
        assert!(entry_art.description.contains("JPEG"));
    }

    #[test]
    fn handles_invalid_magic() {
        let data = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ];
        let parser = ThumbcacheParser::new();
        let artifacts = parser
            .parse_file(Path::new("thumbcache_96.db"), &data)
            .unwrap();
        assert_eq!(artifacts.len(), 1);
        assert!(artifacts[0].description.contains("no CMMM header"));
    }

    #[test]
    fn handles_empty_data() {
        let parser = ThumbcacheParser::new();
        let artifacts = parser
            .parse_file(Path::new("thumbcache_32.db"), &[])
            .unwrap();
        assert!(artifacts.is_empty());
    }

    #[test]
    fn detect_image_format_works() {
        assert_eq!(
            detect_image_format(&[0xFF, 0xD8, 0xFF, 0xE0]),
            Some("JPEG".to_string())
        );
        assert_eq!(
            detect_image_format(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
            Some("PNG".to_string())
        );
        assert_eq!(
            detect_image_format(&[0x42, 0x4D, 0x00, 0x00]),
            Some("BMP".to_string())
        );
        assert_eq!(
            detect_image_format(&[0x47, 0x49, 0x46, 0x38, 0x39, 0x61]),
            Some("GIF".to_string())
        );
        assert_eq!(detect_image_format(&[0x00, 0x00]), None);
    }

    #[test]
    fn target_patterns_cover_common_sizes() {
        let parser = ThumbcacheParser::new();
        let patterns = parser.target_patterns();
        assert!(patterns.contains(&"thumbcache_256.db"));
        assert!(patterns.contains(&"thumbcache_1024.db"));
        assert!(patterns.contains(&"iconcache_256.db"));
    }
}
