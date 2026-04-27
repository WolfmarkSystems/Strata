//! Windows LNK (Shell Link) parser — MS-SHLLINK.
//!
//! Location: `%AppData%\Microsoft\Windows\Recent\*.lnk`,
//! `%AppData%\Microsoft\Office\Recent\*.lnk`.
//!
//! Research reference: dfir-toolkit/lnk2bodyfile (MIT) — studied for
//! approach; implementation written independently from the MS-SHLLINK
//! specification.
//!
//! ## File shape
//!
//! ```text
//! offset 0x00  u32  header_size == 0x0000004C
//! offset 0x04  GUID 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46
//! offset 0x14  u32  LinkFlags
//! offset 0x18  u32  FileAttributes
//! offset 0x1C  FILETIME  CreationTime
//! offset 0x24  FILETIME  AccessTime
//! offset 0x2C  FILETIME  WriteTime
//! offset 0x34  u32  FileSize
//! offset 0x38  u32  IconIndex
//! offset 0x3C  u32  ShowCommand
//! offset 0x40  u16  HotKey
//! offset 0x44  u16  reserved
//! offset 0x46  u32  reserved
//! offset 0x4C  [+optional structures per LinkFlags]
//! ```
//!
//! LinkFlags bits we honour:
//! * `0x00000001` HasLinkTargetIDList — IDList at offset 0x4C
//! * `0x00000002` HasLinkInfo
//! * `0x00000004` HasName (StringData Description)
//! * `0x00000008` HasRelativePath
//! * `0x00000010` HasWorkingDir
//! * `0x00000020` HasArguments
//! * `0x00000040` HasIconLocation
//! * `0x00000080` IsUnicode (StringData uses UTF-16LE)
//! * `0x00000100` ForceNoLinkInfo
//!
//! ## MITRE ATT&CK
//! * **T1547.009** — shortcut modification for persistence.
//! * **T1070.006** — indicator removal via timestamp manipulation.
//!
//! `suspicious=true` when target resolves inside a Temp / AppData /
//! Downloads directory — common malware staging pattern.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};

/// Expected header size.
const LNK_HEADER_SIZE: u32 = 0x4C;
/// Standard LNK class identifier.
const LNK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];
const FILETIME_EPOCH_DELTA: i64 = 11_644_473_600;

mod link_flags {
    pub const HAS_LINK_TARGET_IDLIST: u32 = 0x0000_0001;
    pub const HAS_LINK_INFO: u32 = 0x0000_0002;
    pub const HAS_NAME: u32 = 0x0000_0004;
    pub const HAS_RELATIVE_PATH: u32 = 0x0000_0008;
    pub const HAS_WORKING_DIR: u32 = 0x0000_0010;
    pub const HAS_ARGUMENTS: u32 = 0x0000_0020;
    pub const HAS_ICON_LOCATION: u32 = 0x0000_0040;
    pub const IS_UNICODE: u32 = 0x0000_0080;
    pub const FORCE_NO_LINK_INFO: u32 = 0x0000_0100;
}

/// Decoded LNK file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LnkFile {
    /// The file/folder the LNK points to. Best-effort: prefers
    /// LinkInfo BasePath; falls back to RelativePath.
    pub target_path: String,
    /// Working-directory override, when present.
    pub working_directory: Option<String>,
    /// Command-line arguments.
    pub arguments: Option<String>,
    /// Target-file creation time (FILETIME → UTC).
    pub target_created: Option<DateTime<Utc>>,
    /// Target-file last-access time.
    pub target_accessed: Option<DateTime<Utc>>,
    /// Target-file last-write time.
    pub target_modified: Option<DateTime<Utc>>,
    /// Target file size in bytes at the time the LNK was written.
    pub target_size: u64,
    /// LinkFlags bits (useful for downstream heuristics).
    pub link_flags: u32,
    /// Volume drive type descriptor: `"Fixed"`, `"Removable"`,
    /// `"Network"`, `"CDRom"`, `"Ram"`, `"NoRoot"`, or `"Unknown"`.
    pub drive_type: String,
    /// Volume serial number as hex, when recovered.
    pub drive_serial: Option<String>,
    /// Volume label, when recovered.
    pub volume_label: Option<String>,
    /// NetBIOS machine name that wrote the LNK — reveals origin
    /// machine even when the file itself has been moved.
    pub machine_id: Option<String>,
    /// DROID volume ID (GUID) — part of the Distributed Link
    /// Tracking service record.
    pub droid_volume_id: Option<String>,
    /// DROID file ID (GUID) — tracks the target file across renames
    /// and volume changes. Often the only surviving provenance
    /// indicator after a target is deleted.
    pub droid_file_id: Option<String>,
}

/// Parse a LNK file body.
pub fn parse(bytes: &[u8]) -> Option<LnkFile> {
    let header_size = read_u32_le(bytes, 0)?;
    if header_size != LNK_HEADER_SIZE {
        return None;
    }
    let clsid = bytes.get(4..20)?;
    if clsid != LNK_CLSID {
        return None;
    }
    let link_flags = read_u32_le(bytes, 0x14)?;
    let created = read_filetime(bytes, 0x1C);
    let accessed = read_filetime(bytes, 0x24);
    let modified = read_filetime(bytes, 0x2C);
    let target_size = read_u32_le(bytes, 0x34)? as u64;
    let mut cursor: usize = LNK_HEADER_SIZE as usize;
    // Skip optional IDList (LinkTargetIDList).
    if link_flags & link_flags::HAS_LINK_TARGET_IDLIST != 0 {
        let id_list_size = read_u16_le(bytes, cursor)? as usize;
        cursor = cursor.checked_add(2)?.checked_add(id_list_size)?;
    }
    let mut target_path = String::new();
    let mut working_directory = None;
    let mut arguments = None;
    let mut drive_type = "Unknown".to_string();
    let mut drive_serial = None;
    let mut volume_label = None;
    let mut droid_volume_id = None;
    let mut droid_file_id = None;
    if link_flags & link_flags::HAS_LINK_INFO != 0
        && link_flags & link_flags::FORCE_NO_LINK_INFO == 0
    {
        if let Some(info) = parse_link_info(bytes, cursor) {
            target_path = info.base_path;
            drive_type = info.drive_type;
            drive_serial = info.drive_serial;
            volume_label = info.volume_label;
            cursor = info.end;
        } else {
            return None;
        }
    }
    let is_unicode = link_flags & link_flags::IS_UNICODE != 0;
    if link_flags & link_flags::HAS_NAME != 0 {
        if let Some((_name, next)) = read_string_data(bytes, cursor, is_unicode) {
            cursor = next;
        }
    }
    if link_flags & link_flags::HAS_RELATIVE_PATH != 0 {
        if let Some((rel, next)) = read_string_data(bytes, cursor, is_unicode) {
            if target_path.is_empty() {
                target_path = rel;
            }
            cursor = next;
        }
    }
    if link_flags & link_flags::HAS_WORKING_DIR != 0 {
        if let Some((wd, next)) = read_string_data(bytes, cursor, is_unicode) {
            working_directory = Some(wd);
            cursor = next;
        }
    }
    if link_flags & link_flags::HAS_ARGUMENTS != 0 {
        if let Some((args, next)) = read_string_data(bytes, cursor, is_unicode) {
            arguments = Some(args);
            cursor = next;
        }
    }
    if link_flags & link_flags::HAS_ICON_LOCATION != 0 {
        if let Some((_icon, next)) = read_string_data(bytes, cursor, is_unicode) {
            cursor = next;
        }
    }
    // ExtraData blocks — walk each, recording machine_id + DROIDs.
    let mut machine_id = None;
    while cursor + 4 <= bytes.len() {
        let size = read_u32_le(bytes, cursor)? as usize;
        if size < 4 {
            break;
        }
        let sig = read_u32_le(bytes, cursor + 4).unwrap_or(0);
        let block_end = cursor.checked_add(size)?;
        if block_end > bytes.len() {
            break;
        }
        if sig == 0xA000_0009 {
            // TrackerDataBlock: length + version (8 bytes) then 16-byte
            // machine_id C-string padded, then two 16-byte GUIDs.
            let data_start = cursor + 8;
            let mid_off = data_start.checked_add(8)?;
            if let Some(mid) = bytes.get(mid_off..mid_off + 16) {
                let nul = mid.iter().position(|b| *b == 0).unwrap_or(mid.len());
                if let Ok(s) = std::str::from_utf8(&mid[..nul]) {
                    machine_id = Some(s.to_string());
                }
            }
            let droid_off = mid_off + 16;
            if let Some(vol) = bytes.get(droid_off..droid_off + 16) {
                droid_volume_id = Some(format_guid(vol));
            }
            let file_off = droid_off + 16;
            if let Some(fid) = bytes.get(file_off..file_off + 16) {
                droid_file_id = Some(format_guid(fid));
            }
        }
        cursor = block_end;
    }
    Some(LnkFile {
        target_path,
        working_directory,
        arguments,
        target_created: created,
        target_accessed: accessed,
        target_modified: modified,
        target_size,
        link_flags,
        drive_type,
        drive_serial,
        volume_label,
        machine_id,
        droid_volume_id,
        droid_file_id,
    })
}

struct LinkInfo {
    base_path: String,
    drive_type: String,
    drive_serial: Option<String>,
    volume_label: Option<String>,
    end: usize,
}

fn parse_link_info(bytes: &[u8], start: usize) -> Option<LinkInfo> {
    let link_info_size = read_u32_le(bytes, start)? as usize;
    let _header_size = read_u32_le(bytes, start + 4)?;
    let flags = read_u32_le(bytes, start + 8)?;
    let volume_id_offset = read_u32_le(bytes, start + 12)? as usize;
    let local_base_path_offset = read_u32_le(bytes, start + 16)? as usize;
    let _cnr_offset = read_u32_le(bytes, start + 20)?;
    let _cpsn_offset = read_u32_le(bytes, start + 24)?;
    let mut drive_type = "Unknown".to_string();
    let mut drive_serial = None;
    let mut volume_label = None;
    if flags & 0x0000_0001 != 0 && volume_id_offset > 0 {
        let vol_start = start + volume_id_offset;
        if vol_start + 16 <= bytes.len() {
            let _vol_size = read_u32_le(bytes, vol_start)?;
            let drive_type_raw = read_u32_le(bytes, vol_start + 4)?;
            let serial = read_u32_le(bytes, vol_start + 8)?;
            let label_offset = read_u32_le(bytes, vol_start + 12)? as usize;
            drive_type = drive_type_name(drive_type_raw).to_string();
            drive_serial = Some(format!("{:08X}", serial));
            if label_offset > 0 {
                let label_start = vol_start + label_offset;
                if let Some(s) = read_cstring(bytes, label_start) {
                    volume_label = Some(s);
                }
            }
        }
    }
    let mut base_path = String::new();
    if flags & 0x0000_0001 != 0 && local_base_path_offset > 0 {
        let base_start = start + local_base_path_offset;
        if let Some(s) = read_cstring(bytes, base_start) {
            base_path = s;
        }
    }
    Some(LinkInfo {
        base_path,
        drive_type,
        drive_serial,
        volume_label,
        end: start + link_info_size,
    })
}

fn drive_type_name(raw: u32) -> &'static str {
    match raw {
        0 => "Unknown",
        1 => "NoRoot",
        2 => "Removable",
        3 => "Fixed",
        4 => "Network",
        5 => "CDRom",
        6 => "Ram",
        _ => "Unknown",
    }
}

fn read_string_data(bytes: &[u8], pos: usize, unicode: bool) -> Option<(String, usize)> {
    let count = read_u16_le(bytes, pos)? as usize;
    if count == 0 {
        return Some((String::new(), pos + 2));
    }
    if unicode {
        let byte_len = count.checked_mul(2)?;
        let end = pos.checked_add(2)?.checked_add(byte_len)?;
        if end > bytes.len() {
            return None;
        }
        let slice = &bytes[pos + 2..end];
        let mut code_units = Vec::with_capacity(count);
        for chunk in slice.chunks_exact(2) {
            let Ok(arr) = <[u8; 2]>::try_from(chunk) else {
                return None;
            };
            code_units.push(u16::from_le_bytes(arr));
        }
        let s = String::from_utf16_lossy(&code_units);
        Some((s, end))
    } else {
        let end = pos.checked_add(2)?.checked_add(count)?;
        if end > bytes.len() {
            return None;
        }
        let s = String::from_utf8_lossy(&bytes[pos + 2..end]).to_string();
        Some((s, end))
    }
}

fn read_cstring(bytes: &[u8], start: usize) -> Option<String> {
    if start >= bytes.len() {
        return None;
    }
    let rest = &bytes[start..];
    let end = rest.iter().position(|b| *b == 0).unwrap_or(rest.len());
    Some(String::from_utf8_lossy(&rest[..end]).to_string())
}

fn read_u16_le(buf: &[u8], off: usize) -> Option<u16> {
    let slice = buf.get(off..off.checked_add(2)?)?;
    let arr: [u8; 2] = slice.try_into().ok()?;
    Some(u16::from_le_bytes(arr))
}

fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let slice = buf.get(off..off.checked_add(4)?)?;
    let arr: [u8; 4] = slice.try_into().ok()?;
    Some(u32::from_le_bytes(arr))
}

fn read_u64_le(buf: &[u8], off: usize) -> Option<u64> {
    let slice = buf.get(off..off.checked_add(8)?)?;
    let arr: [u8; 8] = slice.try_into().ok()?;
    Some(u64::from_le_bytes(arr))
}

fn read_filetime(buf: &[u8], off: usize) -> Option<DateTime<Utc>> {
    let ft = read_u64_le(buf, off)?;
    if ft == 0 {
        return None;
    }
    let secs_since_1601 = (ft / 10_000_000) as i64;
    let unix_secs = secs_since_1601.checked_sub(FILETIME_EPOCH_DELTA)?;
    let nanos = ((ft % 10_000_000) * 100) as u32;
    DateTime::<Utc>::from_timestamp(unix_secs, nanos)
}

fn format_guid(bytes: &[u8]) -> String {
    if bytes.len() != 16 {
        return String::new();
    }
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        bytes[3], bytes[2], bytes[1], bytes[0],
        bytes[5], bytes[4],
        bytes[7], bytes[6],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

/// True when the target looks like a malware staging location.
pub fn is_suspicious_target(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("\\temp\\")
        || lower.contains("\\appdata\\")
        || lower.contains("\\downloads\\")
        || lower.contains("/tmp/")
        || lower.contains("\\users\\public\\")
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_filetime(unix_secs: i64) -> [u8; 8] {
        let since_1601 = unix_secs + FILETIME_EPOCH_DELTA;
        ((since_1601 as u64) * 10_000_000).to_le_bytes()
    }

    fn build_minimal_lnk(target: &str) -> Vec<u8> {
        let mut out = Vec::new();
        // Header size.
        out.extend_from_slice(&LNK_HEADER_SIZE.to_le_bytes());
        // CLSID.
        out.extend_from_slice(&LNK_CLSID);
        // LinkFlags: HasLinkInfo only.
        out.extend_from_slice(&link_flags::HAS_LINK_INFO.to_le_bytes());
        // FileAttributes.
        out.extend_from_slice(&0u32.to_le_bytes());
        // FILETIMEs.
        out.extend_from_slice(&encode_filetime(1_717_243_200));
        out.extend_from_slice(&encode_filetime(1_717_243_260));
        out.extend_from_slice(&encode_filetime(1_717_243_300));
        // FileSize, IconIndex, ShowCommand, HotKey + 2x Reserved.
        out.extend_from_slice(&1024u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        // LinkInfo:
        //   size (fixed up later), header_size=0x1C, flags=1, vol_off=0x1C,
        //   base_path_off=0x2C, cnr_off=0, cpsn_off=0.
        let link_info_start = out.len();
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0x1Cu32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&0x1Cu32.to_le_bytes());
        out.extend_from_slice(&0x2Du32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        // VolumeID at offset 0x1C: size=0x11, drive_type=3 (Fixed),
        // serial=0xDEADBEEF, label_off=0x10, label="".
        out.extend_from_slice(&0x11u32.to_le_bytes());
        out.extend_from_slice(&3u32.to_le_bytes());
        out.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        out.extend_from_slice(&0x10u32.to_le_bytes());
        out.push(0);
        // LocalBasePath at offset 0x2D: C-string target.
        out.extend_from_slice(target.as_bytes());
        out.push(0);
        // Patch up link_info_size.
        let link_info_size = (out.len() - link_info_start) as u32;
        out[link_info_start..link_info_start + 4].copy_from_slice(&link_info_size.to_le_bytes());
        // Terminator ExtraData block.
        out.extend_from_slice(&0u32.to_le_bytes());
        out
    }

    #[test]
    fn parse_empty_returns_none() {
        assert!(parse(&[]).is_none());
    }

    #[test]
    fn parse_wrong_clsid_returns_none() {
        let mut blob = vec![0u8; 0x4C];
        blob[..4].copy_from_slice(&LNK_HEADER_SIZE.to_le_bytes());
        // CLSID stays zero -> mismatch.
        blob.resize(0x100, 0);
        assert!(parse(&blob).is_none());
    }

    #[test]
    fn parse_minimal_lnk_extracts_target_and_times() {
        let blob = build_minimal_lnk("C:\\Users\\alice\\report.docx");
        let lnk = parse(&blob).expect("parse");
        assert_eq!(lnk.target_path, "C:\\Users\\alice\\report.docx");
        assert_eq!(lnk.drive_type, "Fixed");
        assert_eq!(lnk.drive_serial.as_deref(), Some("DEADBEEF"));
        assert_eq!(lnk.target_size, 1024);
        assert_eq!(
            lnk.target_created.map(|d| d.timestamp()),
            Some(1_717_243_200)
        );
        assert_eq!(
            lnk.target_accessed.map(|d| d.timestamp()),
            Some(1_717_243_260)
        );
        assert_eq!(
            lnk.target_modified.map(|d| d.timestamp()),
            Some(1_717_243_300)
        );
    }

    #[test]
    fn parse_truncated_returns_none() {
        let blob = build_minimal_lnk("C:\\a\\b");
        let trunc = &blob[..0x40];
        assert!(parse(trunc).is_none());
    }

    #[test]
    fn is_suspicious_target_flags_staging_paths() {
        assert!(is_suspicious_target(
            "C:\\Users\\alice\\AppData\\Local\\Temp\\dropper.exe"
        ));
        assert!(is_suspicious_target(
            "C:\\Users\\alice\\Downloads\\suspicious.exe"
        ));
        assert!(is_suspicious_target("C:\\Users\\Public\\foo.exe"));
        assert!(!is_suspicious_target("C:\\Program Files\\App\\app.exe"));
    }

    #[test]
    fn format_guid_reorders_fields() {
        let raw = [
            0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E,
            0x8F, 0x90,
        ];
        let g = format_guid(&raw);
        assert_eq!(g, "D4C3B2A1-F6E5-1807-293A-4B5C6D7E8F90");
    }
}
