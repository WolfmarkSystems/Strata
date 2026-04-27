use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Volume Shadow Copy (VSS) Parser
///
/// Parses VSS catalog and store files to enumerate shadow copies
/// and extract metadata about available restore points.
///
/// Files:
///   - {GUID}{GUID} files in System Volume Information
///   - VSS catalog entries contain snapshot metadata
///
/// Forensic value: Shadow copies contain previous versions of files,
/// including files that have been deleted from the live volume.
/// Attackers often delete shadow copies (vssadmin delete shadows)
/// to prevent recovery — the absence of VSS data IS evidence (T1490).
///
/// Current capability: Enumerate shadow copies and extract metadata.
/// Full file extraction from VSS requires NTFS-level raw access.
pub struct VssExtractionParser;

impl Default for VssExtractionParser {
    fn default() -> Self {
        Self::new()
    }
}

impl VssExtractionParser {
    pub fn new() -> Self {
        Self
    }
}

/// VSS catalog header magic: "MICROSOFT_VSS_CATALOG"
const VSS_CATALOG_MAGIC: &[u8] = b"MICROSOFT_VSS_CATALOG";

/// VSS snapshot set GUID header pattern
const VSS_SNAP_MAGIC: &[u8; 16] = &[
    0x6B, 0x87, 0x08, 0x38, 0x76, 0xB1, 0x48, 0x4B, 0xB8, 0xD2, 0x1E, 0x25, 0x82, 0x44, 0xBE, 0xC8,
];

#[derive(Debug, Serialize, Deserialize)]
pub struct VssCatalogEntry {
    pub snapshot_id: Option<String>,
    pub snapshot_set_id: Option<String>,
    pub creation_time: Option<i64>,
    pub volume_name: Option<String>,
    pub originating_machine: Option<String>,
    pub service_machine: Option<String>,
    pub provider_id: Option<String>,
    pub snapshot_attributes: Option<u32>,
    pub snapshot_count: Option<u32>,
    pub catalog_offset: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VssStoreInfo {
    pub store_file: String,
    pub store_size: usize,
    pub block_count_estimate: usize,
    pub has_catalog: bool,
    pub shadow_copies_found: usize,
}

impl ArtifactParser for VssExtractionParser {
    fn name(&self) -> &str {
        "Volume Shadow Copy Parser"
    }

    fn artifact_type(&self) -> &str {
        "volume_shadow"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "{3808876b-c176-4e48-b8d2-1e258244bec8}*",
            "System Volume Information",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();
        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        if data.len() < 128 {
            return Ok(artifacts);
        }

        // Check for VSS catalog
        let has_catalog = data
            .windows(VSS_CATALOG_MAGIC.len())
            .any(|w| w == VSS_CATALOG_MAGIC);

        // Check for VSS snapshot store header
        let _has_snap_header = data.len() >= 16 && &data[0..16] == VSS_SNAP_MAGIC;

        // Scan for GUID patterns that indicate VSS entries
        let mut shadow_entries = Vec::new();
        let mut offset = 0;

        while offset + 128 <= data.len() {
            // Look for VSS catalog entry signature
            if offset + 16 <= data.len() && &data[offset..offset + 16] == VSS_SNAP_MAGIC {
                // Parse VSS entry at this offset
                let entry = parse_vss_catalog_entry(data, offset);
                shadow_entries.push(entry);
                offset += 128;
            } else {
                offset += 16; // Align to 16-byte boundary
            }

            if shadow_entries.len() >= 1000 {
                break;
            }
        }

        // Also scan for FILETIME patterns near GUID-like structures
        // to find creation timestamps of shadow copies
        let guid_count = count_guids_in_data(data);

        let store_info = VssStoreInfo {
            store_file: filename.clone(),
            store_size: data.len(),
            block_count_estimate: data.len() / 16384, // 16KB blocks typical
            has_catalog,
            shadow_copies_found: shadow_entries.len(),
        };

        // Summary artifact
        let mut desc = format!(
            "VSS Store: {} ({} bytes, {} shadow copies detected, ~{} blocks)",
            filename,
            data.len(),
            shadow_entries.len(),
            store_info.block_count_estimate,
        );
        if has_catalog {
            desc.push_str(" [HAS_CATALOG]");
        }
        if shadow_entries.is_empty() && guid_count > 0 {
            desc.push_str(&format!(" [{} GUID references]", guid_count));
        }

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "vss_store".to_string(),
            description: desc,
            source_path: source.clone(),
            json_data: serde_json::to_value(&store_info).unwrap_or_default(),
        });

        // Individual shadow copy entries
        for entry in &shadow_entries {
            let mut desc = format!(
                "VSS Shadow Copy: {} (created: {})",
                entry.snapshot_id.as_deref().unwrap_or("unknown"),
                entry
                    .creation_time
                    .map(|t| format!("epoch {}", t))
                    .unwrap_or_else(|| "unknown".to_string()),
            );
            if let Some(ref vol) = entry.volume_name {
                desc.push_str(&format!(" [vol: {}]", vol));
            }

            artifacts.push(ParsedArtifact {
                timestamp: entry.creation_time,
                artifact_type: "vss_snapshot".to_string(),
                description: desc,
                source_path: source.clone(),
                json_data: serde_json::to_value(entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}

fn parse_vss_catalog_entry(data: &[u8], offset: usize) -> VssCatalogEntry {
    let snapshot_id = if offset + 32 <= data.len() {
        Some(format_guid(&data[offset + 16..offset + 32]))
    } else {
        None
    };

    let snapshot_set_id = if offset + 48 <= data.len() {
        Some(format_guid(&data[offset + 32..offset + 48]))
    } else {
        None
    };

    // FILETIME at offset + 48
    let creation_time = if offset + 56 <= data.len() {
        let ft = u64::from_le_bytes([
            data[offset + 48],
            data[offset + 49],
            data[offset + 50],
            data[offset + 51],
            data[offset + 52],
            data[offset + 53],
            data[offset + 54],
            data[offset + 55],
        ]);
        if ft > 0 {
            let unix_epoch_ft: u64 = 116_444_736_000_000_000;
            if ft > unix_epoch_ft {
                Some(((ft - unix_epoch_ft) / 10_000_000) as i64)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    VssCatalogEntry {
        snapshot_id,
        snapshot_set_id,
        creation_time,
        volume_name: None,
        originating_machine: None,
        service_machine: None,
        provider_id: None,
        snapshot_attributes: None,
        snapshot_count: None,
        catalog_offset: offset,
    }
}

fn format_guid(data: &[u8]) -> String {
    if data.len() < 16 {
        return "invalid".to_string();
    }
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
        u16::from_le_bytes([data[4], data[5]]),
        u16::from_le_bytes([data[6], data[7]]),
        data[8],
        data[9],
        data[10],
        data[11],
        data[12],
        data[13],
        data[14],
        data[15],
    )
}

fn count_guids_in_data(data: &[u8]) -> usize {
    // Count patterns that look like GUID bytes (16 bytes, non-zero, plausible)
    let mut count = 0;
    let mut offset = 0;
    while offset + 16 <= data.len() {
        let chunk = &data[offset..offset + 16];
        // A GUID-like pattern: not all zeros, not all 0xFF, has some variety
        let zero_count = chunk.iter().filter(|&&b| b == 0).count();
        let ff_count = chunk.iter().filter(|&&b| b == 0xFF).count();
        if zero_count < 8 && ff_count < 8 {
            // Check if it has the version nibble (typically 4 in byte 7)
            if chunk[7] & 0xF0 == 0x40 {
                count += 1;
            }
        }
        offset += 16;
    }
    count
}
