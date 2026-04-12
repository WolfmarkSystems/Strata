use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use std::path::Path;

/// Windows hibernation file signature: "hibr" + rest of PO_MEMORY_IMAGE.
const HIBR_SIGNATURE: &[u8] = b"hibr";

/// Alternate signature used by some Windows versions.
const RSTR_SIGNATURE: &[u8] = b"RSTR";

/// Alternate signature for Windows 10+ fast startup.
const WAKE_SIGNATURE: &[u8] = b"wake";

/// Minimum header size needed for parsing (first 8 KiB is enough for
/// the PO_MEMORY_IMAGE header fields we care about).
const MIN_HEADER_SIZE: usize = 8192;

pub struct HiberfilParser;

impl Default for HiberfilParser {
    fn default() -> Self {
        Self::new()
    }
}

impl HiberfilParser {
    pub fn new() -> Self {
        Self
    }
}

impl ArtifactParser for HiberfilParser {
    fn name(&self) -> &str {
        "Windows Hibernation File Parser"
    }

    fn artifact_type(&self) -> &str {
        "hiberfil"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["hiberfil.sys"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let file_name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();
        if !file_name.contains("hiberfil") {
            return Ok(Vec::new());
        }

        if data.len() < 8 {
            return Ok(vec![ParsedArtifact {
                timestamp: None,
                artifact_type: "hiberfil".to_string(),
                description: format!("Hibernation file detected (too small to parse): {}", file_name),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::json!({
                    "file_name": file_name,
                    "file_size": data.len(),
                    "forensic_note": "File too small — may be zeroed or partially wiped",
                    "forensic_value": "Critical"
                }),
            }]);
        }

        let signature = &data[0..4];
        let sig_type = if signature == HIBR_SIGNATURE {
            "hibr"
        } else if signature == RSTR_SIGNATURE {
            "RSTR"
        } else if signature == WAKE_SIGNATURE {
            "wake"
        } else {
            return Ok(vec![ParsedArtifact {
                timestamp: None,
                artifact_type: "hiberfil".to_string(),
                description: format!(
                    "File named hiberfil.sys but signature mismatch: {:02X}{:02X}{:02X}{:02X}",
                    data[0], data[1], data[2], data[3]
                ),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::json!({
                    "file_name": file_name,
                    "file_size": data.len(),
                    "signature_bytes": format!("{:02X}{:02X}{:02X}{:02X}", data[0], data[1], data[2], data[3]),
                    "valid_signature": false,
                    "forensic_note": "Signature does not match known hiberfil formats — file may be corrupted, wiped, or not a hibernation file",
                    "forensic_value": "Medium"
                }),
            }]);
        };

        let mut json = serde_json::json!({
            "file_name": file_name,
            "file_size": data.len(),
            "signature": sig_type,
            "valid_signature": true,
            "forensic_value": "Critical",
            "forensic_note": "Hibernation file contains a full memory snapshot — may include encryption keys, passwords, chat messages, and open documents at time of hibernation"
        });

        if data.len() >= MIN_HEADER_SIZE {
            let header = parse_header(data);
            if let Some(ref h) = header {
                json["header"] = serde_json::json!({
                    "page_size": h.page_size,
                    "image_type": h.image_type,
                    "system_time": h.system_time,
                    "num_pages": h.num_pages,
                    "highest_physical_page": h.highest_physical_page,
                    "first_boot_restore_page_count": h.first_boot_restore_page_count,
                });

                if let Some(win_ver) = windows_version_hint(h) {
                    json["windows_version_hint"] = serde_json::Value::String(win_ver);
                }
            }
        }

        let description = match sig_type {
            "hibr" => format!(
                "CRITICAL: Windows hibernation file (PO_MEMORY_IMAGE) — full RAM snapshot. Size: {} bytes",
                data.len()
            ),
            "RSTR" => format!(
                "CRITICAL: Windows resume hibernation file (RSTR). Size: {} bytes",
                data.len()
            ),
            "wake" => format!(
                "CRITICAL: Windows Fast Startup hibernation file. Size: {} bytes",
                data.len()
            ),
            _ => format!("Hibernation file detected. Size: {} bytes", data.len()),
        };

        Ok(vec![ParsedArtifact {
            timestamp: None,
            artifact_type: "hiberfil".to_string(),
            description,
            source_path: path.to_string_lossy().to_string(),
            json_data: json,
        }])
    }
}

struct HiberfilHeader {
    page_size: u32,
    image_type: u32,
    system_time: u64,
    num_pages: u64,
    highest_physical_page: u64,
    first_boot_restore_page_count: u32,
}

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
}

fn read_u64_le(data: &[u8], offset: usize) -> Option<u64> {
    data.get(offset..offset + 8)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_le_bytes)
}

/// Parse the PO_MEMORY_IMAGE header.
///
/// Windows hiberfil.sys layout (offsets are approximate and version-dependent):
/// - 0x00: Signature (4 bytes) — "hibr", "RSTR", "wake"
/// - 0x04: Version (4 bytes)
/// - 0x08–0x0F: Checksum (varies)
/// - 0x18: SystemTime (8 bytes, FILETIME)
/// - 0x20: NumPages / PageCount (8 bytes on 64-bit)
/// - 0x28: HighestPhysicalPage (8 bytes)
/// - 0x30: FirstBootRestorePageCount (4 bytes)
/// - 0x58: ImageType (4 bytes)
/// - 0x60: PageSize (4 bytes, typically 4096)
fn parse_header(data: &[u8]) -> Option<HiberfilHeader> {
    if data.len() < MIN_HEADER_SIZE {
        return None;
    }

    Some(HiberfilHeader {
        page_size: read_u32_le(data, 0x60).unwrap_or(4096),
        image_type: read_u32_le(data, 0x58).unwrap_or(0),
        system_time: read_u64_le(data, 0x18).unwrap_or(0),
        num_pages: read_u64_le(data, 0x20).unwrap_or(0),
        highest_physical_page: read_u64_le(data, 0x28).unwrap_or(0),
        first_boot_restore_page_count: read_u32_le(data, 0x30).unwrap_or(0),
    })
}

/// Guess Windows version from image_type and page characteristics.
fn windows_version_hint(h: &HiberfilHeader) -> Option<String> {
    if h.page_size == 0 {
        return None;
    }
    match h.image_type {
        0 => Some("Full hibernation (Windows Vista+)".to_string()),
        1 => Some("Full hibernation with kernel context".to_string()),
        2 => Some("Fast Startup / Hybrid Boot (Windows 8+)".to_string()),
        _ => Some(format!("Unknown image type: {}", h.image_type)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hibr_data() -> Vec<u8> {
        let mut data = vec![0u8; MIN_HEADER_SIZE];
        // Signature: "hibr"
        data[0..4].copy_from_slice(b"hibr");
        // PageSize at offset 0x60 = 4096
        data[0x60..0x64].copy_from_slice(&4096u32.to_le_bytes());
        // ImageType at offset 0x58 = 0 (full hibernation)
        data[0x58..0x5C].copy_from_slice(&0u32.to_le_bytes());
        // NumPages at offset 0x20 = 1_048_576
        data[0x20..0x28].copy_from_slice(&1_048_576u64.to_le_bytes());
        // HighestPhysicalPage at offset 0x28 = 2_097_152
        data[0x28..0x30].copy_from_slice(&2_097_152u64.to_le_bytes());
        data
    }

    #[test]
    fn parses_valid_hibr_signature() {
        let parser = HiberfilParser::new();
        let data = make_hibr_data();
        let path = Path::new("/evidence/C/hiberfil.sys");
        let result = parser.parse_file(path, &data).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].description.contains("CRITICAL"));
        assert!(result[0].description.contains("PO_MEMORY_IMAGE"));
        assert_eq!(result[0].json_data["signature"], "hibr");
        assert_eq!(result[0].json_data["valid_signature"], true);
    }

    #[test]
    fn extracts_header_metadata() {
        let parser = HiberfilParser::new();
        let data = make_hibr_data();
        let path = Path::new("/evidence/C/hiberfil.sys");
        let result = parser.parse_file(path, &data).unwrap();
        let header = &result[0].json_data["header"];
        assert_eq!(header["page_size"], 4096);
        assert_eq!(header["num_pages"], 1_048_576);
        assert_eq!(header["highest_physical_page"], 2_097_152);
    }

    #[test]
    fn detects_rstr_signature() {
        let parser = HiberfilParser::new();
        let mut data = vec![0u8; MIN_HEADER_SIZE];
        data[0..4].copy_from_slice(b"RSTR");
        let path = Path::new("/evidence/C/hiberfil.sys");
        let result = parser.parse_file(path, &data).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].description.contains("RSTR"));
        assert_eq!(result[0].json_data["signature"], "RSTR");
    }

    #[test]
    fn detects_wake_signature() {
        let parser = HiberfilParser::new();
        let mut data = vec![0u8; MIN_HEADER_SIZE];
        data[0..4].copy_from_slice(b"wake");
        let path = Path::new("/evidence/C/hiberfil.sys");
        let result = parser.parse_file(path, &data).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].description.contains("Fast Startup"));
    }

    #[test]
    fn flags_invalid_signature() {
        let parser = HiberfilParser::new();
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00];
        let path = Path::new("/evidence/C/hiberfil.sys");
        let result = parser.parse_file(path, &data).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].json_data["valid_signature"], false);
        assert!(result[0].description.contains("signature mismatch"));
    }

    #[test]
    fn skips_non_hiberfil_filename() {
        let parser = HiberfilParser::new();
        let data = make_hibr_data();
        let path = Path::new("/evidence/C/pagefile.sys");
        let result = parser.parse_file(path, &data).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn handles_undersized_data() {
        let parser = HiberfilParser::new();
        let data = vec![0u8; 4];
        let path = Path::new("/evidence/C/hiberfil.sys");
        let result = parser.parse_file(path, &data).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].description.contains("too small"));
    }
}
