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
