use super::scalpel::{read_prefix, DEFAULT_BINARY_MAX_BYTES};
use crate::errors::ForensicError;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct LnkFile {
    pub target_path: Option<String>,
    pub working_directory: Option<String>,
    pub arguments: Option<String>,
    pub description: Option<String>,
    pub icon_location: Option<String>,
    pub flags: LnkFlags,
    pub file_attributes: LnkFileAttributes,
    pub creation_time: Option<i64>,
    pub access_time: Option<i64>,
    pub write_time: Option<i64>,
    pub target_size: Option<u64>,
    pub drive_serial: Option<u32>,
    pub drive_type: Option<String>,
    pub machine_id: Option<String>,
    pub target_id_list: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct LnkFlags {
    pub has_link_target_id_list: bool,
    pub has_link_info: bool,
    pub has_name: bool,
    pub has_relative_path: bool,
    pub has_working_dir: bool,
    pub has_arguments: bool,
    pub has_icon_location: bool,
    pub is_unicode: bool,
    pub force_no_link_info: bool,
    pub has_exp_string: bool,
    pub run_in_separate_process: bool,
    pub has_darwin_id: bool,
    pub run_as_user: bool,
    pub has_exp_icon: bool,
    pub no_pf_alias_target: bool,
    pub force_unc_name: bool,
    pub run_with_shim_layer: bool,
    pub force_file_system: bool,
    pub has_long_name: bool,
    pub no_chiron: bool,
    pub has_re_separator: bool,
}

#[derive(Debug, Clone, Default)]
pub struct LnkFileAttributes {
    pub readonly: bool,
    pub hidden: bool,
    pub system: bool,
    pub directory: bool,
    pub archive: bool,
    pub device: bool,
    pub normal: bool,
    pub temporary: bool,
    pub sparse_file: bool,
    pub reparse_point: bool,
    pub compressed: bool,
    pub offline: bool,
    pub not_content_indexed: bool,
    pub encrypted: bool,
}

#[derive(Debug, Clone)]
pub struct LnkShortcutRecord {
    pub path: String,
    pub target_path: Option<String>,
    pub arguments: Option<String>,
    pub working_directory: Option<String>,
    pub description: Option<String>,
    pub created_unix: Option<i64>,
    pub modified_unix: Option<i64>,
    pub access_time_unix: Option<i64>,
    pub write_time_unix: Option<i64>,
    pub drive_type: Option<String>,
    pub drive_serial: Option<u32>,
    pub machine_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LnkInputShape {
    Missing,
    Empty,
    Directory,
    LnkFile,
    JsonArray,
    JsonObject,
    CsvText,
    LineText,
    Unknown,
}

impl LnkInputShape {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Empty => "empty",
            Self::Directory => "directory",
            Self::LnkFile => "lnk-file",
            Self::JsonArray => "json-array",
            Self::JsonObject => "json-object",
            Self::CsvText => "csv-text",
            Self::LineText => "line-text",
            Self::Unknown => "unknown",
        }
    }
}

pub fn detect_lnk_input_shape(path: &Path) -> LnkInputShape {
    if !path.exists() {
        return LnkInputShape::Missing;
    }
    if path.is_dir() {
        return LnkInputShape::Directory;
    }
    if path
        .extension()
        .and_then(|v| v.to_str())
        .map(|v| v.eq_ignore_ascii_case("lnk"))
        .unwrap_or(false)
    {
        return LnkInputShape::LnkFile;
    }

    let Ok(bytes) = strata_fs::read(path) else {
        return LnkInputShape::Unknown;
    };
    if bytes.is_empty() {
        return LnkInputShape::Empty;
    }
    if bytes.len() >= 4 && &bytes[0..4] == b"\x4C\x00\x00\x00" {
        return LnkInputShape::LnkFile;
    }
    let text = String::from_utf8_lossy(&bytes);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return LnkInputShape::Empty;
    }
    if trimmed.starts_with('[') {
        return LnkInputShape::JsonArray;
    }
    if trimmed.starts_with('{') {
        return LnkInputShape::JsonObject;
    }
    let first = trimmed
        .lines()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if first.contains("target_path")
        || first.contains("working_directory")
        || first.contains("write_time")
        || first.contains("path")
    {
        return LnkInputShape::CsvText;
    }
    LnkInputShape::LineText
}

pub fn parse_lnk_shortcuts_from_path(path: &Path, limit: usize) -> Vec<LnkShortcutRecord> {
    if !path.exists() || limit == 0 {
        return Vec::new();
    }

    let mut rows = if path.is_dir() {
        let mut out = Vec::new();
        walk_for_lnk(path, &mut out);
        out
    } else if path
        .extension()
        .and_then(|v| v.to_str())
        .map(|v| v.eq_ignore_ascii_case("lnk"))
        .unwrap_or(false)
    {
        parse_lnk_row_from_file(path)
            .into_iter()
            .collect::<Vec<_>>()
    } else if let Ok(bytes) = strata_fs::read(path) {
        if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
            parse_lnk_rows_json_value(&value)
        } else {
            parse_lnk_csv_or_lines(String::from_utf8_lossy(&bytes).as_ref())
        }
    } else {
        Vec::new()
    };

    if rows.is_empty() && path.is_file() {
        rows = parse_lnk_text_fallback(path);
    }

    let mut dedupe = BTreeSet::<String>::new();
    rows.retain(|row| {
        let key = format!(
            "{}|{}|{}|{}",
            row.path,
            row.target_path.as_deref().unwrap_or(""),
            row.write_time_unix
                .map(|v| v.to_string())
                .unwrap_or_default(),
            row.arguments.as_deref().unwrap_or("")
        );
        dedupe.insert(key)
    });

    rows.sort_by(|a, b| {
        let a_ts = a
            .write_time_unix
            .or(a.modified_unix)
            .or(a.created_unix)
            .unwrap_or_default();
        let b_ts = b
            .write_time_unix
            .or(b.modified_unix)
            .or(b.created_unix)
            .unwrap_or_default();
        b_ts.cmp(&a_ts).then_with(|| a.path.cmp(&b.path))
    });
    rows.truncate(limit);
    rows
}

pub fn parse_lnk_text_fallback(path: &Path) -> Vec<LnkShortcutRecord> {
    if !path.exists() {
        return Vec::new();
    }
    let Ok(content) = strata_fs::read_to_string(path) else {
        return Vec::new();
    };
    parse_lnk_csv_or_lines(&content)
}

pub fn parse_lnk(path: &Path) -> Result<LnkFile, ForensicError> {
    let data = read_prefix(path, DEFAULT_BINARY_MAX_BYTES)?;
    parse_lnk_bytes(&data)
}

fn walk_for_lnk(dir: &Path, out: &mut Vec<LnkShortcutRecord>) {
    let Ok(entries) = strata_fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let entry_path = entry.path();
        if entry_path.is_dir() {
            walk_for_lnk(&entry_path, out);
            continue;
        }
        if !entry_path
            .extension()
            .and_then(|v| v.to_str())
            .map(|v| v.eq_ignore_ascii_case("lnk"))
            .unwrap_or(false)
        {
            continue;
        }
        if let Some(row) = parse_lnk_row_from_file(&entry_path) {
            out.push(row);
        }
    }
}

fn parse_lnk_row_from_file(path: &Path) -> Option<LnkShortcutRecord> {
    let parsed = parse_lnk(path).ok()?;
    let meta = strata_fs::metadata(path).ok();
    let created = meta
        .as_ref()
        .and_then(|v| v.created().ok())
        .and_then(system_time_to_unix);
    let modified = meta
        .as_ref()
        .and_then(|v| v.modified().ok())
        .and_then(system_time_to_unix);
    Some(LnkShortcutRecord {
        path: path.to_string_lossy().to_string(),
        target_path: parsed.target_path.map(|v| v.replace('/', "\\")),
        arguments: parsed.arguments,
        working_directory: parsed.working_directory.map(|v| v.replace('/', "\\")),
        description: parsed.description,
        created_unix: created,
        modified_unix: modified,
        access_time_unix: parsed.access_time,
        write_time_unix: parsed.write_time,
        drive_type: parsed.drive_type,
        drive_serial: parsed.drive_serial,
        machine_id: parsed.machine_id,
    })
}

fn parse_lnk_rows_json_value(value: &Value) -> Vec<LnkShortcutRecord> {
    if let Some(arr) = value.as_array() {
        return parse_lnk_rows_json(arr);
    }
    if let Some(obj) = value.as_object() {
        if let Some(arr) = obj
            .get("records")
            .or_else(|| obj.get("entries"))
            .or_else(|| obj.get("shortcuts"))
            .and_then(Value::as_array)
        {
            return parse_lnk_rows_json(arr);
        }
    }
    Vec::new()
}

fn parse_lnk_rows_json(rows: &[Value]) -> Vec<LnkShortcutRecord> {
    let mut out = Vec::new();
    for row in rows {
        let Some(obj) = row.as_object() else {
            continue;
        };
        let path = obj
            .get("path")
            .and_then(Value::as_str)
            .map(|v| v.trim().replace('/', "\\"))
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "lnk-record".to_string());
        let target_path = obj
            .get("target_path")
            .or_else(|| obj.get("target"))
            .and_then(Value::as_str)
            .map(|v| v.trim().replace('/', "\\"))
            .filter(|v| !v.is_empty());
        let arguments = obj
            .get("arguments")
            .or_else(|| obj.get("args"))
            .and_then(Value::as_str)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        let working_directory = obj
            .get("working_directory")
            .or_else(|| obj.get("working_dir"))
            .and_then(Value::as_str)
            .map(|v| v.trim().replace('/', "\\"))
            .filter(|v| !v.is_empty());
        let description = obj
            .get("description")
            .and_then(Value::as_str)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        let created_unix = obj
            .get("created_unix")
            .and_then(value_to_i64)
            .or_else(|| obj.get("created").and_then(value_to_i64));
        let modified_unix = obj
            .get("modified_unix")
            .and_then(value_to_i64)
            .or_else(|| obj.get("modified").and_then(value_to_i64));
        let access_time_unix = obj
            .get("access_time_unix")
            .and_then(value_to_i64)
            .or_else(|| obj.get("access_time").and_then(value_to_i64));
        let write_time_unix = obj
            .get("write_time_unix")
            .and_then(value_to_i64)
            .or_else(|| obj.get("write_time").and_then(value_to_i64))
            .or_else(|| {
                obj.get("write_time_utc")
                    .and_then(Value::as_str)
                    .and_then(parse_utc_to_unix)
            });
        let drive_type = obj
            .get("drive_type")
            .and_then(Value::as_str)
            .map(|v| v.to_string());
        let drive_serial = obj
            .get("drive_serial")
            .and_then(Value::as_u64)
            .and_then(|v| u32::try_from(v).ok());
        let machine_id = obj
            .get("machine_id")
            .and_then(Value::as_str)
            .map(|v| v.to_string());
        out.push(LnkShortcutRecord {
            path,
            target_path,
            arguments,
            working_directory,
            description,
            created_unix,
            modified_unix,
            access_time_unix,
            write_time_unix,
            drive_type,
            drive_serial,
            machine_id,
        });
    }
    out
}

fn parse_lnk_csv_or_lines(content: &str) -> Vec<LnkShortcutRecord> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut lines = trimmed.lines();
    let first = lines.next().unwrap_or_default().trim().to_string();
    let has_header = first.to_ascii_lowercase().contains("path")
        || first.to_ascii_lowercase().contains("target")
        || first.to_ascii_lowercase().contains("write_time");
    let mut rows = Vec::new();
    if has_header {
        rows.extend(lines.map(|v| v.to_string()));
    } else {
        rows.push(first);
        rows.extend(lines.map(|v| v.to_string()));
    }

    for row in rows {
        let clean = row.trim();
        if clean.is_empty() {
            continue;
        }
        let parts = if clean.contains('|') {
            clean
                .split('|')
                .map(|v| v.trim().to_string())
                .collect::<Vec<_>>()
        } else {
            clean
                .split(',')
                .map(|v| v.trim().to_string())
                .collect::<Vec<_>>()
        };
        if parts.is_empty() {
            continue;
        }

        let mut item = LnkShortcutRecord {
            path: "lnk-record".to_string(),
            target_path: None,
            arguments: None,
            working_directory: None,
            description: None,
            created_unix: None,
            modified_unix: None,
            access_time_unix: None,
            write_time_unix: None,
            drive_type: None,
            drive_serial: None,
            machine_id: None,
        };

        if has_header {
            // Header order expectation: path,target_path,arguments,working_directory,write_time,created,modified
            if let Some(v) = parts.first() {
                if !v.is_empty() {
                    item.path = v.replace('/', "\\");
                }
            }
            if let Some(v) = parts.get(1) {
                let normalized = v.replace('/', "\\");
                if !normalized.is_empty() {
                    item.target_path = Some(normalized);
                }
            }
            if let Some(v) = parts.get(2) {
                if !v.is_empty() {
                    item.arguments = Some(v.to_string());
                }
            }
            if let Some(v) = parts.get(3) {
                let normalized = v.replace('/', "\\");
                if !normalized.is_empty() {
                    item.working_directory = Some(normalized);
                }
            }
            if let Some(v) = parts.get(4) {
                item.write_time_unix = v.parse::<i64>().ok().or_else(|| parse_utc_to_unix(v));
            }
            item.created_unix = parts.get(5).and_then(|v| v.parse::<i64>().ok());
            item.modified_unix = parts.get(6).and_then(|v| v.parse::<i64>().ok());
        } else {
            item.write_time_unix = parts.first().and_then(|v| {
                v.parse::<i64>()
                    .ok()
                    .or_else(|| parse_utc_to_unix(v.as_str()))
            });
            if let Some(v) = parts.get(1) {
                item.path = v.replace('/', "\\");
            }
            item.target_path = parts
                .get(2)
                .map(|v| v.replace('/', "\\"))
                .filter(|v| !v.is_empty());
            if let Some(v) = parts.get(3) {
                if !v.is_empty() {
                    item.arguments = Some(v.to_string());
                }
            }
            if let Some(v) = parts.get(4) {
                if !v.is_empty() {
                    item.working_directory = Some(v.replace('/', "\\"));
                }
            }
        }
        out.push(item);
    }
    out
}

fn value_to_i64(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|v| i64::try_from(v).ok()))
        .or_else(|| value.as_str().and_then(|v| v.parse::<i64>().ok()))
}

fn parse_utc_to_unix(value: &str) -> Option<i64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    chrono::DateTime::parse_from_rfc3339(trimmed)
        .map(|v| v.timestamp())
        .ok()
        .or_else(|| trimmed.parse::<i64>().ok())
}

fn system_time_to_unix(value: std::time::SystemTime) -> Option<i64> {
    value
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|v| i64::try_from(v.as_secs()).ok())
}

fn parse_lnk_bytes(data: &[u8]) -> Result<LnkFile, ForensicError> {
    if data.len() < 4 {
        return Err(ForensicError::UnsupportedImageFormat(
            "LNK file too small".to_string(),
        ));
    }

    if &data[0..4] != b"\x4C\x00\x00\x00" {
        return Err(ForensicError::UnsupportedImageFormat(
            "Invalid LNK signature".to_string(),
        ));
    }

    let mut lnk = LnkFile {
        target_path: None,
        working_directory: None,
        arguments: None,
        description: None,
        icon_location: None,
        flags: LnkFlags::default(),
        file_attributes: LnkFileAttributes::default(),
        creation_time: None,
        access_time: None,
        write_time: None,
        target_size: None,
        drive_serial: None,
        drive_type: None,
        machine_id: None,
        target_id_list: Vec::new(),
    };

    let parsed_header_size = le_u32_at(data, 0).unwrap_or(0) as usize;
    let header_size = if (0x4C..=data.len()).contains(&parsed_header_size) {
        parsed_header_size
    } else {
        0x4C
    };

    if data.len() < 0x38 {
        return Ok(lnk);
    }

    lnk.flags = parse_flags(le_u32_at(data, 0x14).unwrap_or(0));

    let file_attributes = le_u32_at(data, 0x18).unwrap_or(0);
    lnk.file_attributes = parse_file_attributes(file_attributes);

    lnk.creation_time = read_filetime(data.get(0x1C..0x24).unwrap_or(&[]));
    lnk.access_time = read_filetime(data.get(0x24..0x2C).unwrap_or(&[]));
    lnk.write_time = read_filetime(data.get(0x2C..0x34).unwrap_or(&[]));

    lnk.target_size = le_u32_at(data, 0x34).map(|v| v as u64);

    let mut offset = header_size + 0x4C;
    if header_size >= 0x4C {
        offset = header_size;
    }

    if lnk.flags.has_link_target_id_list && offset + 2 <= data.len() {
        let id_list_size = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        let id_list_end = offset + id_list_size;
        while offset + 2 < id_list_end && offset + 2 < data.len() {
            let item_id_size = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;

            if item_id_size == 0 {
                break;
            }

            if offset + item_id_size <= data.len() && item_id_size > 2 {
                let item_data = &data[offset + 2..offset + item_id_size];
                if let Some(item) = parse_shell_item(item_data) {
                    lnk.target_id_list.push(item);
                }
            }

            offset += item_id_size;
        }
    }

    if lnk.flags.has_link_info && offset + 4 <= data.len() {
        let link_info_size = parse_link_info_block(data, offset, &mut lnk);
        if link_info_size > 0 {
            offset += link_info_size;
        }
    }

    if lnk.flags.has_name && offset + 2 <= data.len() {
        let (value, next_offset) = read_string_data(data, offset, lnk.flags.is_unicode);
        lnk.description = value;
        offset = next_offset;
    }

    if lnk.flags.has_working_dir && offset + 2 <= data.len() {
        let (value, next_offset) = read_string_data(data, offset, lnk.flags.is_unicode);
        lnk.working_directory = value;
        offset = next_offset;
    }

    if lnk.flags.has_arguments && offset + 2 <= data.len() {
        let (value, next_offset) = read_string_data(data, offset, lnk.flags.is_unicode);
        lnk.arguments = value;
        offset = next_offset;
    }

    if lnk.flags.has_icon_location && offset + 2 <= data.len() {
        let (value, _next_offset) = read_string_data(data, offset, lnk.flags.is_unicode);
        lnk.icon_location = value;
    }

    Ok(lnk)
}

fn parse_flags(flags: u32) -> LnkFlags {
    LnkFlags {
        has_link_target_id_list: flags & 0x00000001 != 0,
        has_link_info: flags & 0x00000002 != 0,
        has_name: flags & 0x00000004 != 0,
        has_relative_path: flags & 0x00000008 != 0,
        has_working_dir: flags & 0x00000010 != 0,
        has_arguments: flags & 0x00000020 != 0,
        has_icon_location: flags & 0x00000040 != 0,
        is_unicode: flags & 0x00000080 != 0,
        force_no_link_info: flags & 0x00000100 != 0,
        has_exp_string: flags & 0x00000200 != 0,
        run_in_separate_process: flags & 0x00000400 != 0,
        has_darwin_id: flags & 0x00001000 != 0,
        run_as_user: flags & 0x00002000 != 0,
        has_exp_icon: flags & 0x00004000 != 0,
        no_pf_alias_target: flags & 0x00008000 != 0,
        force_unc_name: flags & 0x00010000 != 0,
        run_with_shim_layer: flags & 0x00020000 != 0,
        force_file_system: flags & 0x00040000 != 0,
        has_long_name: flags & 0x00080000 != 0,
        no_chiron: flags & 0x00100000 != 0,
        has_re_separator: false,
    }
}

fn parse_file_attributes(attr: u32) -> LnkFileAttributes {
    LnkFileAttributes {
        readonly: attr & 0x00000001 != 0,
        hidden: attr & 0x00000002 != 0,
        system: attr & 0x00000004 != 0,
        directory: attr & 0x00000010 != 0,
        archive: attr & 0x00000020 != 0,
        device: attr & 0x00000040 != 0,
        normal: attr & 0x00000080 != 0,
        temporary: attr & 0x00000100 != 0,
        sparse_file: attr & 0x00000200 != 0,
        reparse_point: attr & 0x00000400 != 0,
        compressed: attr & 0x00000800 != 0,
        offline: attr & 0x00001000 != 0,
        not_content_indexed: attr & 0x00002000 != 0,
        encrypted: attr & 0x00004000 != 0,
    }
}

fn parse_link_info_block(data: &[u8], offset: usize, lnk: &mut LnkFile) -> usize {
    let Some(link_info_size) = le_u32_at(data, offset).map(|v| v as usize) else {
        return 0;
    };
    if link_info_size == 0 || offset + link_info_size > data.len() {
        return 0;
    }
    let link_info_end = offset + link_info_size;
    let link_info_header_size = le_u32_at(data, offset + 4).unwrap_or(0) as usize;
    let link_info_flags = le_u32_at(data, offset + 8).unwrap_or(0);
    let volume_id_offset = le_u32_at(data, offset + 12).unwrap_or(0) as usize;
    let local_base_path_offset = le_u32_at(data, offset + 16).unwrap_or(0) as usize;

    if (link_info_flags & 0x01) != 0 && volume_id_offset > 0 {
        let volume_start = offset + volume_id_offset;
        if volume_start + 16 <= link_info_end {
            if let Some(drive_type_raw) = le_u32_at(data, volume_start + 4) {
                lnk.drive_type = Some(map_drive_type(drive_type_raw));
            }
            lnk.drive_serial = le_u32_at(data, volume_start + 8).or(lnk.drive_serial);
        }
    }

    if local_base_path_offset > 0 {
        let base_start = offset + local_base_path_offset;
        if base_start < link_info_end {
            if let Some(base_path) = read_c_string(&data[base_start..link_info_end]) {
                if !base_path.is_empty() {
                    lnk.target_path = Some(base_path);
                }
            }
        }
    }

    if lnk.target_path.is_none() && link_info_header_size >= 0x24 {
        let local_base_path_offset_unicode = le_u32_at(data, offset + 28).unwrap_or(0) as usize;
        if local_base_path_offset_unicode > 0 {
            let unicode_start = offset + local_base_path_offset_unicode;
            if unicode_start < link_info_end {
                if let Some(path) = read_utf16_c_string(&data[unicode_start..link_info_end]) {
                    if !path.is_empty() {
                        lnk.target_path = Some(path);
                    }
                }
            }
        }
    }

    link_info_size
}

fn map_drive_type(raw: u32) -> String {
    match raw {
        0 => "Unknown",
        1 => "NoRootDir",
        2 => "Removable",
        3 => "Fixed",
        4 => "Remote",
        5 => "CDROM",
        6 => "RAMDisk",
        _ => "Unknown",
    }
    .to_string()
}

fn read_c_string(data: &[u8]) -> Option<String> {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    if end == 0 {
        return None;
    }
    let value = String::from_utf8_lossy(&data[..end]).trim().to_string();
    if value.is_empty() {
        return None;
    }
    Some(value)
}

fn read_utf16_c_string(data: &[u8]) -> Option<String> {
    let mut units = Vec::new();
    for chunk in data.chunks(2) {
        if chunk.len() != 2 {
            break;
        }
        let value = u16::from_le_bytes([chunk[0], chunk[1]]);
        if value == 0 {
            break;
        }
        units.push(value);
    }
    if units.is_empty() {
        return None;
    }
    let text = String::from_utf16(&units).ok()?.trim().to_string();
    if text.is_empty() {
        return None;
    }
    Some(text)
}

fn read_string_data(data: &[u8], offset: usize, is_unicode: bool) -> (Option<String>, usize) {
    if offset + 2 > data.len() {
        return (None, offset);
    }
    let chars = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
    let value_start = offset + 2;
    let byte_len = if is_unicode {
        chars.saturating_mul(2)
    } else {
        chars
    };
    let value_end = value_start.saturating_add(byte_len);
    if value_end > data.len() {
        return (None, data.len());
    }

    let value = if is_unicode {
        let raw = String::from_utf16_lossy(&collect_u16_array(&data[value_start..value_end]));
        raw.trim_end_matches('\0').trim().to_string()
    } else {
        String::from_utf8_lossy(&data[value_start..value_end])
            .trim_end_matches('\0')
            .trim()
            .to_string()
    };
    let parsed = if value.is_empty() { None } else { Some(value) };
    (parsed, value_end)
}

fn read_filetime(data: &[u8]) -> Option<i64> {
    if data.len() < 8 {
        return None;
    }

    let ft = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);

    if ft == 0 {
        return None;
    }

    Some((ft / 10_000_000) as i64 - 11644473600)
}

fn parse_shell_item(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }

    let shell_item_type = data[0];

    match shell_item_type {
        0x1F => Some("Desktop".to_string()),
        0x2F => Some("My Computer".to_string()),
        0x31 => Some("Network".to_string()),
        0x32 => Some("Network".to_string()),
        0x35 | 0x36 => {
            if data.len() >= 22 {
                let name_len = data[20] as usize;
                if data.len() >= 22 + name_len {
                    Some(String::from_utf8_lossy(&data[22..22 + name_len]).to_string())
                } else {
                    Some(format!("Drive-{}", data[19] as char))
                }
            } else {
                Some("Drive".to_string())
            }
        }
        0x00 => Some("Root".to_string()),
        0x01 => Some("Volume".to_string()),
        0x2E => {
            if data.len() > 12 {
                let name_offset = 12;
                let name_len = data[name_offset] as usize;
                if data.len() > name_offset + 1 + name_len {
                    Some(
                        String::from_utf8_lossy(&data[name_offset + 1..name_offset + 1 + name_len])
                            .to_string(),
                    )
                } else {
                    Some("Folder".to_string())
                }
            } else {
                Some("Folder".to_string())
            }
        }
        0x46 => Some("Network Share".to_string()),
        _ => Some(format!("Type-{:02X}", shell_item_type)),
    }
}

fn collect_u16_array(data: &[u8]) -> Vec<u16> {
    data.chunks(2)
        .filter_map(|chunk| {
            if chunk.len() == 2 {
                Some(u16::from_le_bytes([chunk[0], chunk[1]]))
            } else {
                None
            }
        })
        .collect()
}

fn le_u32_at(data: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 > data.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_filetime(unix: i64) -> u64 {
        ((unix + 11_644_473_600) as u64) * 10_000_000
    }

    #[test]
    fn parse_lnk_bytes_extracts_mac_times_and_volume_serial() {
        let target = b"C:\\Windows\\System32\\cmd.exe\0";
        let link_info_size = 0x2Cusize + target.len();
        let total_size = 0x4Cusize + link_info_size;
        let mut data = vec![0u8; total_size];

        // Shell Link header
        data[0..4].copy_from_slice(&0x4Cu32.to_le_bytes());
        data[0x14..0x18].copy_from_slice(&0x00000002u32.to_le_bytes()); // HasLinkInfo
        data[0x1C..0x24].copy_from_slice(&to_filetime(1_700_000_000).to_le_bytes());
        data[0x24..0x2C].copy_from_slice(&to_filetime(1_700_000_100).to_le_bytes());
        data[0x2C..0x34].copy_from_slice(&to_filetime(1_700_000_200).to_le_bytes());
        data[0x34..0x38].copy_from_slice(&4096u32.to_le_bytes());

        // LinkInfo block
        let li = 0x4Cusize;
        data[li..li + 4].copy_from_slice(&(link_info_size as u32).to_le_bytes());
        data[li + 4..li + 8].copy_from_slice(&0x1Cu32.to_le_bytes()); // LinkInfoHeaderSize
        data[li + 8..li + 12].copy_from_slice(&0x00000001u32.to_le_bytes()); // VolumeIDAndLocalBasePath
        data[li + 12..li + 16].copy_from_slice(&0x1Cu32.to_le_bytes()); // VolumeIDOffset
        data[li + 16..li + 20].copy_from_slice(&0x2Cu32.to_le_bytes()); // LocalBasePathOffset

        // VolumeID
        let vol = li + 0x1C;
        data[vol..vol + 4].copy_from_slice(&0x10u32.to_le_bytes());
        data[vol + 4..vol + 8].copy_from_slice(&3u32.to_le_bytes()); // Fixed
        data[vol + 8..vol + 12].copy_from_slice(&0xA1B2C3D4u32.to_le_bytes());
        data[vol + 12..vol + 16].copy_from_slice(&0x10u32.to_le_bytes());

        data[li + 0x2C..li + 0x2C + target.len()].copy_from_slice(target);

        let parsed = parse_lnk_bytes(&data).expect("parse");
        assert_eq!(parsed.creation_time, Some(1_700_000_000));
        assert_eq!(parsed.access_time, Some(1_700_000_100));
        assert_eq!(parsed.write_time, Some(1_700_000_200));
        assert_eq!(parsed.drive_serial, Some(0xA1B2C3D4));
        assert_eq!(parsed.drive_type.as_deref(), Some("Fixed"));
        assert_eq!(
            parsed.target_path.as_deref(),
            Some("C:\\Windows\\System32\\cmd.exe")
        );
    }

    #[test]
    fn detect_lnk_input_shape_supports_directory_json_csv() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("links");
        let lnk = temp.path().join("sample.lnk");
        let json = temp.path().join("lnk.json");
        let csv = temp.path().join("lnk.csv");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&lnk, b"\x4C\x00\x00\x00").unwrap();
        std::fs::write(
            &json,
            r#"{"records":[{"path":"C:/Users/lab/Desktop/cmd.lnk","target_path":"C:/Windows/System32/cmd.exe","write_time_unix":1700004000}]}"#,
        )
        .unwrap();
        std::fs::write(
            &csv,
            "path,target_path,arguments,working_directory,write_time,created,modified\nC:\\Users\\lab\\Desktop\\cmd.lnk,C:\\Windows\\System32\\cmd.exe,/c whoami,C:\\Windows\\System32,1700004000,1700003900,1700003950\n",
        )
        .unwrap();

        assert_eq!(detect_lnk_input_shape(&dir), LnkInputShape::Directory);
        assert_eq!(detect_lnk_input_shape(&lnk), LnkInputShape::LnkFile);
        assert_eq!(detect_lnk_input_shape(&json), LnkInputShape::JsonObject);
        assert_eq!(detect_lnk_input_shape(&csv), LnkInputShape::CsvText);
    }

    #[test]
    fn parse_lnk_shortcuts_from_path_parses_json_rows() {
        let temp = tempfile::tempdir().unwrap();
        let json = temp.path().join("lnk.json");
        std::fs::write(
            &json,
            r#"{"records":[{"path":"C:/Users/lab/Desktop/cmd.lnk","target_path":"C:/Windows/System32/cmd.exe","arguments":"/c whoami","working_directory":"C:/Windows/System32","write_time_unix":1700005000}]}"#,
        )
        .unwrap();

        let rows = parse_lnk_shortcuts_from_path(&json, 20);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].path, r"C:\Users\lab\Desktop\cmd.lnk");
        assert_eq!(
            rows[0].target_path.as_deref(),
            Some(r"C:\Windows\System32\cmd.exe")
        );
        assert_eq!(rows[0].write_time_unix, Some(1_700_005_000));
    }

    #[test]
    fn parse_lnk_text_fallback_handles_partial_rows() {
        let temp = tempfile::tempdir().unwrap();
        let txt = temp.path().join("lnk.txt");
        std::fs::write(
            &txt,
            "1700001000|C:/Users/lab/Desktop/cmd.lnk|C:/Windows/System32/cmd.exe|/c whoami|C:/Windows/System32\n1700000000|C:/Users/lab/Desktop/notepad.lnk|C:/Windows/System32/notepad.exe||\n",
        )
        .unwrap();

        let rows = parse_lnk_text_fallback(&txt);
        assert_eq!(rows.len(), 2);
        assert!(rows
            .iter()
            .any(|v| { v.target_path.as_deref() == Some(r"C:\Windows\System32\notepad.exe") }));
    }
}
