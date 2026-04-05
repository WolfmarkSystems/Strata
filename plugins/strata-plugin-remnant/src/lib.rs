pub mod regions;
pub mod signatures;

use serde_json::json;
use strata_plugin_sdk::{
    Artifact, ArtifactCategory, ArtifactRecord, ForensicValue, PluginCapability, PluginContext,
    PluginOutput, PluginResult, PluginSummary, PluginType, StrataPlugin,
};

pub struct RemnantPlugin {
    name: String,
    version: String,
}

impl Default for RemnantPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Suspicious PE imports that indicate process injection or hollowing techniques.
const SUSPICIOUS_IMPORTS: &[&str] = &[
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtCreateThreadEx",
];

impl RemnantPlugin {
    pub fn new() -> Self {
        Self {
            name: "Strata Remnant".to_string(),
            version: "2.0.0".to_string(),
        }
    }

    // ── PE Executable analysis (.exe/.dll) ──────────────────────────────

    fn analyze_pe(data: &[u8]) -> serde_json::Value {
        if data.len() < 0x40 {
            return json!({"error": "File too small for PE header"});
        }

        // Read e_lfanew — offset to PE signature
        let e_lfanew = u32::from_le_bytes(
            data[0x3C..0x40].try_into().unwrap_or([0; 4]),
        ) as usize;

        if e_lfanew + 8 > data.len() || data.get(e_lfanew..e_lfanew + 4) != Some(b"PE\x00\x00") {
            return json!({"error": "Invalid PE signature", "e_lfanew": e_lfanew});
        }

        // Compilation timestamp at PE header + 8
        let ts_offset = e_lfanew + 8;
        let compilation_ts = if ts_offset + 4 <= data.len() {
            u32::from_le_bytes(data[ts_offset..ts_offset + 4].try_into().unwrap_or([0; 4]))
        } else {
            0
        };

        // Check if timestamp is in the future (suspicious — possible timestomping)
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        let future_ts = compilation_ts > now_epoch;

        // Scan for imported DLLs and suspicious imports by searching the data
        // for null-terminated ASCII strings that look like DLL names and API names.
        let mut import_count = 0u32;
        let mut suspicious_found: Vec<String> = Vec::new();

        // Simple heuristic: scan for ".dll" references (case-insensitive)
        let data_lower: Vec<u8> = data.iter().map(|b| b.to_ascii_lowercase()).collect();
        let dll_marker = b".dll";
        let mut pos = 0;
        while pos + 4 < data_lower.len() {
            if &data_lower[pos..pos + 4] == dll_marker {
                import_count += 1;
                pos += 4;
            } else {
                pos += 1;
            }
        }

        // Scan for suspicious API imports
        for &api in SUSPICIOUS_IMPORTS {
            let api_bytes = api.as_bytes();
            if data
                .windows(api_bytes.len())
                .any(|w| w == api_bytes)
            {
                suspicious_found.push(api.to_string());
            }
        }

        // Check for version info resource (VS_VERSION_INFO)
        let has_version_info = data
            .windows(b"VS_VERSION_INFO".len())
            .any(|w| w == b"VS_VERSION_INFO");

        json!({
            "compilation_ts": compilation_ts,
            "compilation_utc": format_unix_ts(compilation_ts as i64),
            "import_count": import_count,
            "suspicious_imports": suspicious_found,
            "has_version_info": has_version_info,
            "future_timestamp": future_ts,
        })
    }

    // ── SQLite database analysis ────────────────────────────────────────

    fn analyze_sqlite(data: &[u8], path: &str) -> serde_json::Value {
        // Verify header
        if data.len() < 16 || &data[..16] != b"SQLite format 3\x00" {
            return json!({"error": "Invalid SQLite header"});
        }

        // Open the database read-only
        let conn = match rusqlite::Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ) {
            Ok(c) => c,
            Err(e) => return json!({"error": format!("Cannot open database: {}", e)}),
        };

        // Enumerate tables
        let mut tables: Vec<String> = Vec::new();
        if let Ok(mut stmt) = conn.prepare("SELECT name FROM sqlite_master WHERE type='table'") {
            if let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(0)) {
                for name in rows.flatten() {
                    tables.push(name);
                }
            }
        }

        // Detect database type from table names
        let tables_lower: Vec<String> = tables.iter().map(|t| t.to_lowercase()).collect();
        let db_type = if tables_lower.iter().any(|t| t == "moz_places") {
            "Firefox Browser History"
        } else if tables_lower.iter().any(|t| t == "urls")
            || tables_lower.iter().any(|t| t == "visits")
        {
            "Chrome/Edge Browser History"
        } else if tables_lower.iter().any(|t| t == "message")
            && tables_lower.iter().any(|t| t == "handle")
        {
            "iMessage Database"
        } else if tables_lower.iter().any(|t| t == "messages")
            || tables_lower.iter().any(|t| t == "chat")
        {
            "WhatsApp/Messenger Database"
        } else if tables_lower.iter().any(|t| t == "sms")
            || tables_lower.iter().any(|t| t == "mmssms")
        {
            "SMS Database"
        } else {
            "Unknown SQLite Database"
        };

        // Count rows in each table
        let mut row_counts = serde_json::Map::new();
        for table in &tables {
            // Sanitize table name to prevent injection (only allow alphanumeric and underscore)
            let safe_name: String = table
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if safe_name.is_empty() {
                continue;
            }
            let query = format!("SELECT COUNT(*) FROM \"{}\"", safe_name);
            if let Ok(count) = conn.query_row(&query, [], |row| row.get::<_, i64>(0)) {
                row_counts.insert(table.clone(), json!(count));
            }
        }

        json!({
            "db_type": db_type,
            "tables": tables,
            "row_counts": row_counts,
        })
    }

    // ── JPEG/TIFF EXIF analysis ─────────────────────────────────────────

    fn analyze_image_exif(data: &[u8]) -> serde_json::Value {
        let mut make = String::new();
        let mut model = String::new();
        let mut datetime = String::new();
        let mut has_gps = false;
        let mut software = String::new();
        let mut exif_found = false;

        // Search for EXIF APP1 marker (0xFF 0xE1) in JPEG data
        for i in 0..data.len().saturating_sub(10) {
            if data[i] == 0xFF && data[i + 1] == 0xE1 {
                // Check for "Exif\0\0" after the 2-byte length field
                let marker_start = i + 4; // skip FF E1 + 2-byte length
                if marker_start + 6 <= data.len()
                    && &data[marker_start..marker_start + 6] == b"Exif\x00\x00"
                {
                    exif_found = true;
                    let tiff_start = marker_start + 6;
                    if tiff_start + 8 > data.len() {
                        break;
                    }

                    // Determine byte order
                    let little_endian = &data[tiff_start..tiff_start + 2] == b"II";
                    let read_u16 = if little_endian {
                        |d: &[u8], o: usize| -> u16 {
                            u16::from_le_bytes(d[o..o + 2].try_into().unwrap_or([0; 2]))
                        }
                    } else {
                        |d: &[u8], o: usize| -> u16 {
                            u16::from_be_bytes(d[o..o + 2].try_into().unwrap_or([0; 2]))
                        }
                    };
                    let read_u32 = if little_endian {
                        |d: &[u8], o: usize| -> u32 {
                            u32::from_le_bytes(d[o..o + 4].try_into().unwrap_or([0; 4]))
                        }
                    } else {
                        |d: &[u8], o: usize| -> u32 {
                            u32::from_be_bytes(d[o..o + 4].try_into().unwrap_or([0; 4]))
                        }
                    };

                    // Read IFD0 offset
                    let ifd0_offset = read_u32(data, tiff_start + 4) as usize;
                    let ifd0_abs = tiff_start + ifd0_offset;
                    if ifd0_abs + 2 > data.len() {
                        break;
                    }

                    let entry_count = read_u16(data, ifd0_abs) as usize;
                    for e in 0..entry_count {
                        let entry_off = ifd0_abs + 2 + e * 12;
                        if entry_off + 12 > data.len() {
                            break;
                        }
                        let tag = read_u16(data, entry_off);
                        let count = read_u32(data, entry_off + 4) as usize;
                        let value_off_raw = read_u32(data, entry_off + 8) as usize;

                        // For strings > 4 bytes, value_off_raw is offset from TIFF start
                        let value_abs = if count > 4 {
                            tiff_start + value_off_raw
                        } else {
                            entry_off + 8
                        };

                        match tag {
                            0x010F => {
                                // Make
                                if value_abs + count <= data.len() {
                                    make = extract_ascii(data, value_abs, count);
                                }
                            }
                            0x0110 => {
                                // Model
                                if value_abs + count <= data.len() {
                                    model = extract_ascii(data, value_abs, count);
                                }
                            }
                            0x0131 => {
                                // Software
                                if value_abs + count <= data.len() {
                                    software = extract_ascii(data, value_abs, count);
                                }
                            }
                            0x0132 => {
                                // DateTime "YYYY:MM:DD HH:MM:SS"
                                if value_abs + count <= data.len() {
                                    datetime = extract_ascii(data, value_abs, count);
                                }
                            }
                            0x8825 => {
                                // GPS IFD pointer
                                has_gps = true;
                            }
                            _ => {}
                        }
                    }
                }
                break;
            }
        }

        json!({
            "exif_present": exif_found,
            "make": make,
            "model": model,
            "datetime": datetime,
            "has_gps": has_gps,
            "software": software,
        })
    }

    // ── Recycle Bin $I file parsing ───────────────────────────────────────

    fn parse_recycle_bin_entry(path: &str, data: &[u8]) -> Vec<Artifact> {
        let mut results = Vec::new();

        // $I files: magic(8) + file_size(8) + deletion_time(8) + original_path(UTF-16LE from 24)
        if data.len() < 28 {
            return results;
        }

        let _magic = u64::from_le_bytes(data[0..8].try_into().unwrap_or([0; 8]));
        let file_size = u64::from_le_bytes(data[8..16].try_into().unwrap_or([0; 8]));
        let deletion_ft = u64::from_le_bytes(data[16..24].try_into().unwrap_or([0; 8]));
        let deletion_unix = filetime_to_unix(deletion_ft);

        // Read original path as UTF-16LE from offset 24
        let path_bytes = &data[24..];
        let utf16_units: Vec<u16> = path_bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&u| u != 0)
            .collect();
        let original_path = String::from_utf16_lossy(&utf16_units);

        let original_filename = original_path
            .rsplit('\\')
            .next()
            .unwrap_or(&original_path);

        let detail = format!(
            "Original: {} | Deleted: {} | Size: {} bytes",
            original_path,
            format_unix_ts(deletion_unix),
            file_size
        );

        let mut artifact = Artifact::new("Recycle Bin Entry", path);
        artifact.add_field("title", original_filename);
        artifact.add_field("detail", &detail);
        artifact.add_field("original_path", &original_path);
        artifact.add_field("deletion_time", &deletion_unix.to_string());
        artifact.add_field("file_size", &file_size.to_string());
        artifact.add_field("mitre", "T1070.004");
        artifact.add_field("suspicious", "true");
        artifact.timestamp = Some(deletion_unix as u64);

        results.push(artifact);
        results
    }

    // ── Anti-forensic tool detection ───────────────────────────────────────

    fn detect_anti_forensic_tools(path: &str, name: &str) -> Vec<Artifact> {
        let mut results = Vec::new();
        let name_upper = name.to_uppercase();

        let detections: Vec<(&str, &str)> = vec![
            // (condition-matched title, mitre technique)
        ];
        let _ = detections; // suppress unused warning

        let mut matched: Vec<(String, String)> = Vec::new();

        if name_upper.contains("SDELETE.EXE") {
            matched.push(("SDelete detected".to_string(), "T1070".to_string()));
        }
        if name_upper.contains("CCLEANER") {
            matched.push(("CCleaner detected".to_string(), "T1070".to_string()));
        }
        if path.contains("Eraser 6") {
            matched.push(("Eraser detected".to_string(), "T1070".to_string()));
        }
        if name_upper.contains("VSSADMIN.EXE") {
            matched.push((
                "VSS admin tool \u{2014} may have deleted shadow copies".to_string(),
                "T1490".to_string(),
            ));
        }
        if path.contains("EFSTMPWP") {
            matched.push(("cipher.exe /w artifact".to_string(), "T1070".to_string()));
        }

        // Event ID 1102 detection: Security.evtx may contain log-cleared events
        if name_upper == "SECURITY.EVTX" {
            matched.push((
                "Security log \u{2014} check for Event 1102 (log cleared)".to_string(),
                "T1070".to_string(),
            ));
        }

        for (title, mitre) in matched {
            let mut artifact = Artifact::new("Anti-Forensic Activity", path);
            artifact.add_field("title", &title);
            artifact.add_field("detail", &title);
            artifact.add_field("mitre", &mitre);
            artifact.add_field("suspicious", "true");
            artifact.add_field("forensic_value", "Critical");
            results.push(artifact);
        }

        results
    }

    // ── SQLite WAL file detection ──────────────────────────────────────────

    fn detect_sqlite_wal(path: &str, name: &str, data: &[u8]) -> Option<Artifact> {
        if !name.ends_with("-wal") {
            return None;
        }
        if data.len() < 4 {
            return None;
        }

        let magic = u32::from_be_bytes(data[0..4].try_into().unwrap_or([0; 4]));
        if magic != 0x377f0682 && magic != 0x377f0683 {
            return None;
        }

        let mut artifact = Artifact::new("SQLite WAL Recovery", path);
        artifact.add_field("title", &format!("WAL file: {}", name));
        artifact.add_field("detail", "May contain deleted records");
        Some(artifact)
    }

    // ── LNK (Windows shortcut) analysis ─────────────────────────────────

    fn analyze_lnk(data: &[u8]) -> serde_json::Value {
        if data.len() < 0x4C {
            return json!({"error": "File too small for LNK header"});
        }

        // Verify LNK magic
        if data[0..4] != [0x4C, 0x00, 0x00, 0x00] {
            return json!({"error": "Invalid LNK magic"});
        }

        // Flags at 0x14
        let flags = u32::from_le_bytes(data[0x14..0x18].try_into().unwrap_or([0; 4]));
        let has_link_info = (flags & 0x02) != 0;
        let has_target_id_list = (flags & 0x01) != 0;

        // Creation time FILETIME at 0x1C (u64 LE)
        let creation_ft =
            u64::from_le_bytes(data[0x1C..0x24].try_into().unwrap_or([0; 8]));
        // Modification time FILETIME at 0x24
        let modification_ft =
            u64::from_le_bytes(data[0x24..0x2C].try_into().unwrap_or([0; 8]));
        // Target file size at 0x34
        let target_size =
            u32::from_le_bytes(data[0x34..0x38].try_into().unwrap_or([0; 4]));

        let creation_unix = filetime_to_unix(creation_ft);
        let modification_unix = filetime_to_unix(modification_ft);

        // Attempt to extract target path from LinkInfo section
        let mut target_path = String::new();
        if has_link_info {
            // After the 0x4C header, optionally skip TargetIDList
            let mut offset = 0x4C_usize;
            if has_target_id_list && offset + 2 <= data.len() {
                let id_list_size =
                    u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap_or([0; 2]))
                        as usize;
                offset += 2 + id_list_size;
            }

            // LinkInfo structure
            if offset + 4 <= data.len() {
                let link_info_size =
                    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4]))
                        as usize;
                if link_info_size > 0 && offset + link_info_size <= data.len() {
                    // LocalBasePath offset is at LinkInfo + 16
                    if offset + 20 <= data.len() {
                        let local_base_off = u32::from_le_bytes(
                            data[offset + 16..offset + 20].try_into().unwrap_or([0; 4]),
                        ) as usize;
                        let path_abs = offset + local_base_off;
                        if path_abs < data.len() {
                            target_path = extract_ascii(data, path_abs, data.len() - path_abs);
                        }
                    }
                }
            }
        }

        json!({
            "target_path": target_path,
            "creation_time": creation_unix,
            "creation_time_utc": format_unix_ts(creation_unix),
            "modification_time": modification_unix,
            "modification_time_utc": format_unix_ts(modification_unix),
            "target_size": target_size,
            "has_link_info": has_link_info,
        })
    }
    // ── $UsnJrnl Change Journal detection ─────────────────────────────────

    fn detect_usnjrnl(path: &std::path::Path, name: &str, path_str: &str) -> Vec<Artifact> {
        let mut results = Vec::new();
        let lower_name = name.to_lowercase();

        if lower_name == "$usnjrnl" || path_str.to_lowercase().contains("$extend/$usnjrnl") || lower_name == "$j" {
            let mut artifact = Artifact::new("NTFS Artifact", &path.to_string_lossy());
            artifact.add_field("category", "$UsnJrnl Change Journal");
            artifact.add_field("file_type", "$UsnJrnl Change Journal");
            artifact.add_field("title", &format!("$UsnJrnl: {}", path.display()));
            artifact.add_field(
                "detail",
                "NTFS change journal found \u{2014} records every file operation (create, delete, rename, modify). USN_RECORD_V2 structure: RecordLength(u32), MajorVersion(u16), FileReferenceNumber(u64), ParentFileRef(u64), TimeStamp(FILETIME), Reason(u32 flags), FileName(UTF-16LE)",
            );
            artifact.add_field("forensic_value", "Critical");
            results.push(artifact);
        }

        results
    }

    // ── $UsnJrnl binary record parsing (USN_RECORD_V2) ───────────────────

    fn parse_usnjrnl_records(data: &[u8]) -> Vec<Artifact> {
        let mut results = Vec::new();
        let mut offset = 0usize;
        let max_records = 10000; // Cap for performance

        while offset + 60 <= data.len() && results.len() < max_records {
            // Skip zero-filled regions (common in $UsnJrnl)
            if data[offset..offset + 4].iter().all(|&b| b == 0) {
                offset += 8;
                continue;
            }

            let record_len = u32::from_le_bytes(
                data[offset..offset + 4].try_into().unwrap_or([0; 4]),
            ) as usize;

            if !(60..=4096).contains(&record_len) || offset + record_len > data.len() {
                offset += 8;
                continue;
            }

            let major = u16::from_le_bytes(
                data[offset + 4..offset + 6].try_into().unwrap_or([0; 2]),
            );
            if major != 2 {
                offset += record_len.max(8);
                continue;
            }

            let file_ref =
                u64::from_le_bytes(data[offset + 8..offset + 16].try_into().unwrap_or([0; 8]));
            let parent_ref =
                u64::from_le_bytes(data[offset + 16..offset + 24].try_into().unwrap_or([0; 8]));
            let timestamp_ft =
                u64::from_le_bytes(data[offset + 32..offset + 40].try_into().unwrap_or([0; 8]));
            let reason =
                u32::from_le_bytes(data[offset + 40..offset + 44].try_into().unwrap_or([0; 4]));
            let name_len = u16::from_le_bytes(
                data[offset + 56..offset + 58].try_into().unwrap_or([0; 2]),
            ) as usize;
            let name_off = u16::from_le_bytes(
                data[offset + 58..offset + 60].try_into().unwrap_or([0; 2]),
            ) as usize;

            // Extract filename (UTF-16LE)
            let filename = if name_len > 0
                && name_off > 0
                && offset + name_off + name_len <= data.len()
            {
                let name_bytes = &data[offset + name_off..offset + name_off + name_len];
                String::from_utf16_lossy(
                    &name_bytes
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect::<Vec<_>>(),
                )
            } else {
                String::new()
            };

            if filename.is_empty() {
                offset += record_len;
                continue;
            }

            // Convert FILETIME to unix seconds
            let unix_ts = if timestamp_ft > 116_444_736_000_000_000 {
                Some((timestamp_ft - 116_444_736_000_000_000) / 10_000_000)
            } else {
                None
            };

            let reason_str = Self::usn_reason_to_string(reason);

            // Detect suspicious patterns
            let is_delete = reason & 0x200 != 0;
            let lower_name = filename.to_lowercase();
            let is_exe = lower_name.ends_with(".exe")
                || lower_name.ends_with(".dll")
                || lower_name.ends_with(".ps1")
                || lower_name.ends_with(".bat");
            let is_rename = reason & 0x1000 != 0;
            let is_suspicious = (is_delete && is_exe) || is_rename;

            let mut artifact = Artifact::new("$UsnJrnl Entry", &filename);
            artifact.timestamp = unix_ts;
            artifact.add_field("subcategory", "$UsnJrnl Entry");
            artifact.add_field("title", &format!("{} [{}]", filename, reason_str));
            artifact.add_field(
                "detail",
                &format!(
                    "File: {} | Reason: {} (0x{:08X}) | FileRef: {} | ParentRef: {} | Time: {}",
                    filename,
                    reason_str,
                    reason,
                    file_ref,
                    parent_ref,
                    unix_ts
                        .map(|t| t.to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                ),
            );
            if is_suspicious {
                artifact.add_field("suspicious", "true");
            }
            artifact.add_field("mitre", "T1070.004");
            results.push(artifact);

            offset += record_len;
        }
        results
    }

    /// Map USN reason flags to human-readable strings.
    fn usn_reason_to_string(reason: u32) -> String {
        let mut flags = Vec::new();
        if reason & 0x00000001 != 0 {
            flags.push("DATA_OVERWRITE");
        }
        if reason & 0x00000002 != 0 {
            flags.push("DATA_EXTEND");
        }
        if reason & 0x00000004 != 0 {
            flags.push("DATA_TRUNCATION");
        }
        if reason & 0x00000100 != 0 {
            flags.push("FILE_CREATE");
        }
        if reason & 0x00000200 != 0 {
            flags.push("FILE_DELETE");
        }
        if reason & 0x00000800 != 0 {
            flags.push("SECURITY_CHANGE");
        }
        if reason & 0x00001000 != 0 {
            flags.push("RENAME_OLD_NAME");
        }
        if reason & 0x00002000 != 0 {
            flags.push("RENAME_NEW_NAME");
        }
        if reason & 0x80000000 != 0 {
            flags.push("CLOSE");
        }
        if flags.is_empty() {
            "UNKNOWN".to_string()
        } else {
            flags.join(" | ")
        }
    }
}

// ── Helper functions ────────────────────────────────────────────────────

/// Convert Windows FILETIME (100-ns intervals since 1601-01-01) to Unix seconds.
fn filetime_to_unix(ft: u64) -> i64 {
    if ft == 0 {
        return 0;
    }
    ((ft as i128 - 116_444_736_000_000_000i128) / 10_000_000) as i64
}

/// Format a Unix timestamp as a UTC string.
fn format_unix_ts(ts: i64) -> String {
    if ts <= 0 {
        return String::new();
    }
    // Simple UTC formatting without chrono
    let secs_per_day: i64 = 86400;
    let days = ts / secs_per_day;
    let remaining = ts % secs_per_day;
    let hours = remaining / 3600;
    let minutes = (remaining % 3600) / 60;
    let seconds = remaining % 60;

    // Days since Unix epoch to Y/M/D (simplified Gregorian)
    let mut y = 1970i64;
    let mut d = days;
    loop {
        let year_days = if is_leap(y) { 366 } else { 365 };
        if d < year_days {
            break;
        }
        d -= year_days;
        y += 1;
    }
    let month_days: [i64; 12] = if is_leap(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut m = 0usize;
    while m < 12 && d >= month_days[m] {
        d -= month_days[m];
        m += 1;
    }
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m + 1,
        d + 1,
        hours,
        minutes,
        seconds
    )
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

/// Extract a null-terminated ASCII string from data.
fn extract_ascii(data: &[u8], offset: usize, max_len: usize) -> String {
    let end = (offset + max_len).min(data.len());
    let slice = &data[offset..end];
    let null_pos = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..null_pos]).trim().to_string()
}

/// Build a human-readable summary from analysis JSON.
fn build_analysis_summary(sig_name: &str, analysis: &serde_json::Value) -> String {
    match sig_name {
        "PE Executable" => {
            let ts = analysis.get("compilation_utc").and_then(|v| v.as_str()).unwrap_or("unknown");
            let imports = analysis.get("import_count").and_then(|v| v.as_u64()).unwrap_or(0);
            let suspicious: Vec<String> = analysis
                .get("suspicious_imports")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();
            let future = analysis.get("future_timestamp").and_then(|v| v.as_bool()).unwrap_or(false);
            let mut s = format!("PE compiled {} | {} DLL refs", ts, imports);
            if !suspicious.is_empty() {
                s.push_str(&format!(" | SUSPICIOUS IMPORTS: {}", suspicious.join(", ")));
            }
            if future {
                s.push_str(" | WARNING: future compilation timestamp");
            }
            s
        }
        "SQLite Database" => {
            let db_type = analysis.get("db_type").and_then(|v| v.as_str()).unwrap_or("Unknown");
            let tables: Vec<String> = analysis
                .get("tables")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();
            format!("{} | {} tables: {}", db_type, tables.len(), tables.join(", "))
        }
        "JPEG" | "TIFF LE" | "TIFF BE" => {
            let make = analysis.get("make").and_then(|v| v.as_str()).unwrap_or("");
            let model = analysis.get("model").and_then(|v| v.as_str()).unwrap_or("");
            let dt = analysis.get("datetime").and_then(|v| v.as_str()).unwrap_or("");
            let gps = analysis.get("has_gps").and_then(|v| v.as_bool()).unwrap_or(false);
            let mut s = String::new();
            if !make.is_empty() || !model.is_empty() {
                s.push_str(format!("Camera: {} {} ", make, model).trim());
            }
            if !dt.is_empty() {
                s.push_str(&format!(" | Taken: {}", dt));
            }
            if gps {
                s.push_str(" | GPS DATA PRESENT");
            }
            if s.is_empty() {
                "No EXIF data found".to_string()
            } else {
                s.trim().to_string()
            }
        }
        "LNK Shortcut" => {
            let target = analysis.get("target_path").and_then(|v| v.as_str()).unwrap_or("");
            let created = analysis.get("creation_time_utc").and_then(|v| v.as_str()).unwrap_or("");
            let modified = analysis.get("modification_time_utc").and_then(|v| v.as_str()).unwrap_or("");
            let size = analysis.get("target_size").and_then(|v| v.as_u64()).unwrap_or(0);
            let mut s = String::new();
            if !target.is_empty() {
                s.push_str(&format!("Target: {}", target));
            }
            if !created.is_empty() {
                s.push_str(&format!(" | Created: {}", created));
            }
            if !modified.is_empty() {
                s.push_str(&format!(" | Modified: {}", modified));
            }
            if size > 0 {
                s.push_str(&format!(" | Size: {} bytes", size));
            }
            if s.is_empty() {
                "LNK file (no target info extracted)".to_string()
            } else {
                s.trim().to_string()
            }
        }
        _ => String::new(),
    }
}

impl StrataPlugin for RemnantPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn supported_inputs(&self) -> Vec<String> {
        vec!["*".to_string()]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Carver
    }

    fn capabilities(&self) -> Vec<PluginCapability> {
        vec![
            PluginCapability::FileCarving,
            PluginCapability::DeletedFileRecovery,
        ]
    }

    fn description(&self) -> &str {
        "Deep file carving and deleted artifact recovery with content analysis"
    }

    fn run(&self, ctx: PluginContext) -> PluginResult {
        let mut results = Vec::new();
        let root = std::path::Path::new(&ctx.root_path);

        // Walk indexed files and identify carved artifacts by signature
        if root.is_dir() {
            if let Ok(entries) = std::fs::read_dir(root) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Ok(data) = std::fs::read(&path) {
                            if data.len() >= 4 {
                                for sig in &signatures::get_default_signatures() {
                                    if data.starts_with(&sig.header) {
                                        let mut artifact =
                                            Artifact::new("Carved Files", &path.to_string_lossy());
                                        artifact.add_field("file_type", &sig.name);
                                        artifact.add_field("extension", &sig.extension);
                                        artifact.add_field("size", &data.len().to_string());
                                        artifact.add_field(
                                            "title",
                                            &format!("Carved: {} ({})", sig.name, sig.extension),
                                        );

                                        // ── Content analysis based on file type ──
                                        let analysis = match sig.name.as_str() {
                                            "PE Executable" => {
                                                Self::analyze_pe(&data)
                                            }
                                            "SQLite Database" => {
                                                Self::analyze_sqlite(
                                                    &data,
                                                    &path.to_string_lossy(),
                                                )
                                            }
                                            "JPEG" | "TIFF LE" | "TIFF BE" => {
                                                Self::analyze_image_exif(&data)
                                            }
                                            "LNK Shortcut" => {
                                                Self::analyze_lnk(&data)
                                            }
                                            _ => serde_json::Value::Null,
                                        };

                                        if !analysis.is_null() {
                                            artifact.add_field(
                                                "analysis",
                                                &analysis.to_string(),
                                            );
                                            let summary = build_analysis_summary(
                                                &sig.name,
                                                &analysis,
                                            );
                                            if !summary.is_empty() {
                                                artifact.add_field("detail", &summary);
                                            }
                                        }

                                        results.push(artifact);
                                        break;
                                    }
                                }

                                // ── v2.0 detections ─────────────────────────
                                let path_str = path.to_string_lossy();
                                let file_name = path
                                    .file_name()
                                    .map(|n| n.to_string_lossy().to_string())
                                    .unwrap_or_default();

                                // Recycle Bin $I file parsing
                                if path_str.contains("$Recycle.Bin")
                                    && file_name.starts_with("$I")
                                {
                                    results
                                        .extend(Self::parse_recycle_bin_entry(&path_str, &data));
                                }

                                // Anti-forensic tool detection
                                let af_artifacts =
                                    Self::detect_anti_forensic_tools(&path_str, &file_name);
                                if !af_artifacts.is_empty() {
                                    results.extend(af_artifacts);
                                }

                                // SQLite WAL recovery
                                if file_name.ends_with("-wal") {
                                    if let Some(wal_artifact) =
                                        Self::detect_sqlite_wal(&path_str, &file_name, &data)
                                    {
                                        results.push(wal_artifact);
                                    }
                                }

                                // $UsnJrnl Change Journal detection
                                results.extend(Self::detect_usnjrnl(&path, &file_name, &path_str));

                                // $UsnJrnl binary record parsing
                                let lower_file_name = file_name.to_lowercase();
                                if lower_file_name == "$j"
                                    || lower_file_name == "$usnjrnl"
                                    || path_str.to_lowercase().contains("$extend/$usnjrnl")
                                {
                                    results.extend(Self::parse_usnjrnl_records(&data));
                                }
                            }
                        }
                    }
                }
            }
        }

        if results.is_empty() {
            let mut artifact = Artifact::new("Carved Files", "remnant");
            artifact.add_field("status", "Remnant v2.0.0 ready");
            artifact.add_field("title", "Remnant carving engine active");
            results.push(artifact);
        }

        Ok(results)
    }

    fn execute(
        &self,
        context: PluginContext,
    ) -> Result<PluginOutput, strata_plugin_sdk::PluginError> {
        let start = std::time::Instant::now();
        let artifacts_raw = self.run(context)?;

        let mut records = Vec::new();
        for artifact in &artifacts_raw {
            let artifact_category = &artifact.category;

            // ── v2.0: Handle new artifact types first ──────────────────
            if artifact_category == "Recycle Bin Entry" {
                let mitre = artifact.data.get("mitre").cloned();
                records.push(ArtifactRecord {
                    category: ArtifactCategory::DeletedRecovered,
                    subcategory: "Recycle Bin Entry".to_string(),
                    timestamp: artifact.timestamp.map(|t| t as i64),
                    title: artifact
                        .data
                        .get("title")
                        .cloned()
                        .unwrap_or_else(|| artifact.source.clone()),
                    detail: artifact
                        .data
                        .get("detail")
                        .cloned()
                        .unwrap_or_default(),
                    source_path: artifact.source.clone(),
                    forensic_value: ForensicValue::High,
                    mitre_technique: mitre,
                    is_suspicious: true,
                    raw_data: None,
                });
                continue;
            }

            if artifact_category == "Anti-Forensic Activity" {
                let mitre = artifact.data.get("mitre").cloned();
                records.push(ArtifactRecord {
                    category: ArtifactCategory::DeletedRecovered,
                    subcategory: "Anti-Forensic Activity".to_string(),
                    timestamp: artifact.timestamp.map(|t| t as i64),
                    title: artifact
                        .data
                        .get("title")
                        .cloned()
                        .unwrap_or_else(|| artifact.source.clone()),
                    detail: artifact
                        .data
                        .get("detail")
                        .cloned()
                        .unwrap_or_default(),
                    source_path: artifact.source.clone(),
                    forensic_value: ForensicValue::Critical,
                    mitre_technique: mitre,
                    is_suspicious: true,
                    raw_data: None,
                });
                continue;
            }

            if artifact_category == "SQLite WAL Recovery" {
                records.push(ArtifactRecord {
                    category: ArtifactCategory::DeletedRecovered,
                    subcategory: "SQLite WAL Recovery".to_string(),
                    timestamp: artifact.timestamp.map(|t| t as i64),
                    title: artifact
                        .data
                        .get("title")
                        .cloned()
                        .unwrap_or_else(|| artifact.source.clone()),
                    detail: artifact
                        .data
                        .get("detail")
                        .cloned()
                        .unwrap_or_default(),
                    source_path: artifact.source.clone(),
                    forensic_value: ForensicValue::High,
                    mitre_technique: None,
                    is_suspicious: false,
                    raw_data: None,
                });
                continue;
            }

            if artifact_category == "NTFS Artifact" {
                records.push(ArtifactRecord {
                    category: ArtifactCategory::SystemActivity,
                    subcategory: "$UsnJrnl Change Journal".to_string(),
                    timestamp: artifact.timestamp.map(|t| t as i64),
                    title: artifact
                        .data
                        .get("title")
                        .cloned()
                        .unwrap_or_else(|| artifact.source.clone()),
                    detail: artifact
                        .data
                        .get("detail")
                        .cloned()
                        .unwrap_or_default(),
                    source_path: artifact.source.clone(),
                    forensic_value: ForensicValue::Critical,
                    mitre_technique: None,
                    is_suspicious: false,
                    raw_data: None,
                });
                continue;
            }

            if artifact_category == "$UsnJrnl Entry" {
                let is_suspicious = artifact.data.get("suspicious").map(|v| v == "true").unwrap_or(false);
                let mitre = artifact.data.get("mitre").cloned();
                records.push(ArtifactRecord {
                    category: ArtifactCategory::DeletedRecovered,
                    subcategory: "$UsnJrnl Entry".to_string(),
                    timestamp: artifact.timestamp.map(|t| t as i64),
                    title: artifact
                        .data
                        .get("title")
                        .cloned()
                        .unwrap_or_else(|| artifact.source.clone()),
                    detail: artifact
                        .data
                        .get("detail")
                        .cloned()
                        .unwrap_or_default(),
                    source_path: artifact.source.clone(),
                    forensic_value: if is_suspicious {
                        ForensicValue::Critical
                    } else {
                        ForensicValue::High
                    },
                    mitre_technique: mitre,
                    is_suspicious,
                    raw_data: None,
                });
                continue;
            }

            // ── Original carved-file logic ─────────────────────────────
            let file_type = artifact.data.get("file_type").cloned().unwrap_or_default();
            let is_exe = file_type.contains("PE") || file_type.contains("Executable");
            let is_db = file_type.contains("SQLite");
            let is_lnk = file_type.contains("LNK");

            // Determine forensic value and suspicion from analysis data
            let analysis_str = artifact.data.get("analysis").cloned().unwrap_or_default();
            let analysis: serde_json::Value =
                serde_json::from_str(&analysis_str).unwrap_or(serde_json::Value::Null);

            let has_suspicious_imports = analysis
                .get("suspicious_imports")
                .and_then(|v| v.as_array())
                .map(|a| !a.is_empty())
                .unwrap_or(false);
            let has_future_ts = analysis
                .get("future_timestamp")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let has_gps = analysis
                .get("has_gps")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let is_suspicious = is_exe || has_suspicious_imports || has_future_ts;

            let category = if is_exe {
                ArtifactCategory::ExecutionHistory
            } else if is_db || is_lnk {
                ArtifactCategory::UserActivity
            } else {
                ArtifactCategory::DeletedRecovered
            };

            let forensic_value = if has_suspicious_imports || has_future_ts {
                ForensicValue::Critical
            } else if is_exe || has_gps || is_lnk || is_db {
                ForensicValue::High
            } else {
                ForensicValue::Medium
            };

            let detail = artifact
                .data
                .get("detail")
                .cloned()
                .unwrap_or_else(|| {
                    format!(
                        "Type: {} Size: {}",
                        file_type,
                        artifact.data.get("size").cloned().unwrap_or_default()
                    )
                });

            let mitre = if has_suspicious_imports {
                Some("T1055".to_string()) // Process Injection
            } else if has_future_ts {
                Some("T1070.006".to_string()) // Timestomping
            } else if is_exe {
                Some("T1564".to_string()) // Hidden Artifacts
            } else {
                None
            };

            records.push(ArtifactRecord {
                category,
                subcategory: format!("Carved {}", file_type),
                timestamp: artifact.timestamp.map(|t| t as i64),
                title: artifact
                    .data
                    .get("title")
                    .cloned()
                    .unwrap_or_else(|| artifact.source.clone()),
                detail,
                source_path: artifact.source.clone(),
                forensic_value,
                mitre_technique: mitre,
                is_suspicious,
                raw_data: if analysis.is_null() {
                    None
                } else {
                    Some(analysis.clone())
                },
            });
        }

        let suspicious_count = records.iter().filter(|r| r.is_suspicious).count();
        let total = records.len();

        Ok(PluginOutput {
            plugin_name: self.name().to_string(),
            plugin_version: self.version().to_string(),
            executed_at: String::new(),
            duration_ms: start.elapsed().as_millis() as u64,
            artifacts: records,
            summary: PluginSummary {
                total_artifacts: total,
                suspicious_count,
                categories_populated: vec![
                    "Deleted & Recovered".to_string(),
                    "Execution History".to_string(),
                    "User Activity".to_string(),
                    "File/Folder Opening".to_string(),
                    "Media".to_string(),
                ],
                headline: format!("Carved {} files ({} suspicious)", total, suspicious_count),
            },
            warnings: vec![],
        })
    }
}

#[no_mangle]
pub extern "C" fn create_plugin_remnant() -> *mut std::ffi::c_void {
    let plugin: Box<dyn StrataPlugin> = Box::new(RemnantPlugin::new());
    let plugin_holder = Box::new(plugin);
    Box::into_raw(plugin_holder) as *mut std::ffi::c_void
}
