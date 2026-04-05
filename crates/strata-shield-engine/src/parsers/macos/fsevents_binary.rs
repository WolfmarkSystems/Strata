use crate::parser::{ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;
use flate2::read::GzDecoder;
use std::io::Read;

#[derive(Debug, Serialize, Deserialize)]
pub struct FsEventRecord {
    pub path: String,
    pub event_id: u64,
    pub flags: u32,
    pub flags_human: Vec<String>,
}

pub fn parse_fsevents_binary(path: &Path, data: &[u8], out: &mut Vec<ParsedArtifact>) -> Result<(), ParserError> {
    // FSEvents files are gzip compressed
    let mut decoder = GzDecoder::new(data);
    let mut decompressed = Vec::new();
    if decoder.read_to_end(&mut decompressed).is_err() {
        return Ok(()); // Probably not a valid gzip or fsevents file
    }

    if decompressed.len() < 12 {
        return Ok(());
    }

    // Header: D64 (legacy) or D65 (modern)
    let magic = &decompressed[0..4];
    if magic != b"1SLD" && magic != b"2SLD" {
        // D64/D65 is usually the 4th-7th bytes if the file starts with a different header
        // For standard .fseventsd files, it often starts with the page header
    }

    // FSEvents structure is a sequence of records:
    // [C-String Path] + [u64 EventID] + [u32 Flags] + [optional u32 NodeID for D65]
    
    let mut offset = 12; // Skip page header
    while offset < decompressed.len() {
        // Find null terminator for path
        let mut name_end = offset;
        while name_end < decompressed.len() && decompressed[name_end] != 0 {
            name_end += 1;
        }

        if name_end >= decompressed.len() { break; }

        let path_str = String::from_utf8_lossy(&decompressed[offset..name_end]).to_string();
        offset = name_end + 1;

        if offset + 12 > decompressed.len() { break; }

        let event_id = u64::from_le_bytes(decompressed[offset..offset+8].try_into().unwrap());
        let flags = u32::from_le_bytes(decompressed[offset+8..offset+12].try_into().unwrap());
        
        let record = FsEventRecord {
            path: path_str.clone(),
            event_id,
            flags,
            flags_human: map_fsevent_flags(flags),
        };

        out.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "macos_fsevents".to_string(),
            description: format!("FSEvent: {} on {}", record.flags_human.join("|"), record.path),
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(record).unwrap_or_default(),
        });

        offset += 12; // u64 + u32
        // D65 has an extra 8 bytes for node_id
        if magic == b"2SLD" && offset + 8 <= decompressed.len() {
            offset += 8;
        }
    }

    Ok(())
}

fn map_fsevent_flags(f: u32) -> Vec<String> {
    let mut flags = Vec::new();
    if f & 0x00000001 != 0 { flags.push("MustScanSubDirs".to_string()); }
    if f & 0x00000002 != 0 { flags.push("UserDropped".to_string()); }
    if f & 0x00000004 != 0 { flags.push("KernelDropped".to_string()); }
    if f & 0x00000008 != 0 { flags.push("EventIdsWrapped".to_string()); }
    if f & 0x00000010 != 0 { flags.push("HistoryDone".to_string()); }
    if f & 0x00000020 != 0 { flags.push("RootChanged".to_string()); }
    if f & 0x00000040 != 0 { flags.push("Mount".to_string()); }
    if f & 0x00000080 != 0 { flags.push("Unmount".to_string()); }
    if f & 0x00000100 != 0 { flags.push("Created".to_string()); }
    if f & 0x00000200 != 0 { flags.push("Removed".to_string()); }
    if f & 0x00000400 != 0 { flags.push("InodeMetaMod".to_string()); }
    if f & 0x00000800 != 0 { flags.push("Renamed".to_string()); }
    if f & 0x00001000 != 0 { flags.push("Modified".to_string()); }
    if f & 0x00002000 != 0 { flags.push("Exchange".to_string()); }
    if f & 0x00004000 != 0 { flags.push("FinderInfoMod".to_string()); }
    if f & 0x00008000 != 0 { flags.push("FolderCreated".to_string()); }
    if f & 0x00010000 != 0 { flags.push("PermissionMod".to_string()); }
    if f & 0x00020000 != 0 { flags.push("ExtendedAttrMod".to_string()); }
    if f & 0x00040000 != 0 { flags.push("ExtendedAttrRemoved".to_string()); }
    if f & 0x00100000 != 0 { flags.push("DocumentRevision".to_string()); }
    flags
}
