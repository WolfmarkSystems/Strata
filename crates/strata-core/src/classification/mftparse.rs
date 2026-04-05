use crate::errors::ForensicError;
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;

const ATTR_STANDARD_INFORMATION: u32 = 0x10;
const ATTR_FILE_NAME: u32 = 0x30;
const ATTR_DATA: u32 = 0x80;
const ATTR_END: u32 = 0xFFFF_FFFF;
const FILETIME_UNIX_EPOCH_OFFSET: i64 = 11_644_473_600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MftInputShape {
    Missing,
    Empty,
    BinaryRaw,
    JsonArray,
    JsonObject,
    CsvDelimited,
    LineText,
    Unknown,
}

impl MftInputShape {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Empty => "empty",
            Self::BinaryRaw => "binary-raw",
            Self::JsonArray => "json-array",
            Self::JsonObject => "json-object",
            Self::CsvDelimited => "csv-delimited",
            Self::LineText => "line-text",
            Self::Unknown => "unknown",
        }
    }
}

pub fn detect_mft_input_shape(path: &Path) -> MftInputShape {
    if !path.exists() {
        return MftInputShape::Missing;
    }
    let Ok(bytes) = strata_fs::read(path) else {
        return MftInputShape::Unknown;
    };
    if bytes.is_empty() {
        return MftInputShape::Empty;
    }
    if bytes.len() >= 4 && &bytes[0..4] == b"FILE" {
        return MftInputShape::BinaryRaw;
    }
    let text = String::from_utf8_lossy(&bytes);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return MftInputShape::Empty;
    }
    if trimmed.starts_with('[') {
        return MftInputShape::JsonArray;
    }
    if trimmed.starts_with('{') {
        return MftInputShape::JsonObject;
    }
    let first_line = trimmed
        .lines()
        .next()
        .unwrap_or(trimmed)
        .to_ascii_lowercase();
    if (first_line.contains("record")
        || first_line.contains("mft")
        || first_line.contains("file_name")
        || first_line.contains("full_path"))
        && (first_line.contains(',') || first_line.contains('|'))
    {
        return MftInputShape::CsvDelimited;
    }
    if first_line.contains(',') || first_line.contains('|') {
        return MftInputShape::CsvDelimited;
    }
    MftInputShape::LineText
}

pub fn detect_mft_entry(data: &[u8]) -> bool {
    data.len() >= 4 && &data[0..4] == b"FILE"
}

pub fn parse_mft_records_from_path(path: &Path, max_records: usize) -> Vec<MftRecord> {
    if max_records == 0 {
        return Vec::new();
    }
    let Ok(bytes) = strata_fs::read(path) else {
        return Vec::new();
    };
    let shape = detect_mft_input_shape(path);
    match shape {
        MftInputShape::Missing | MftInputShape::Empty => Vec::new(),
        MftInputShape::BinaryRaw => {
            let mut out = Vec::new();
            let record_sizes = [1024usize, 4096usize];
            for record_size in record_sizes {
                if bytes.len() < record_size {
                    continue;
                }
                out.clear();
                let mut offset = 0usize;
                while offset + 4 <= bytes.len() && out.len() < max_records {
                    let end = std::cmp::min(offset + record_size, bytes.len());
                    let chunk = &bytes[offset..end];
                    if detect_mft_entry(chunk) {
                        if let Ok(row) = parse_mft_record(chunk) {
                            out.push(row);
                        }
                    }
                    offset = offset.saturating_add(record_size);
                }
                if !out.is_empty() {
                    break;
                }
            }
            if out.is_empty() && detect_mft_entry(&bytes) {
                if let Ok(row) = parse_mft_record(&bytes) {
                    out.push(row);
                }
            }
            out
        }
        MftInputShape::JsonArray | MftInputShape::JsonObject => {
            if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                let mut out = parse_mft_records_json_value(&value);
                out.truncate(max_records);
                out
            } else {
                Vec::new()
            }
        }
        MftInputShape::CsvDelimited | MftInputShape::LineText | MftInputShape::Unknown => {
            let mut out = parse_mft_text_fallback(path);
            out.truncate(max_records);
            out
        }
    }
}

pub fn parse_mft_text_fallback(path: &Path) -> Vec<MftRecord> {
    let Ok(content) = strata_fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with('#') || lower.starts_with("//") || lower.starts_with("record_number") {
            continue;
        }

        let fields = if trimmed.contains('|') {
            trimmed
                .split('|')
                .map(|v| v.trim().to_string())
                .collect::<Vec<_>>()
        } else if trimmed.contains(',') {
            trimmed
                .split(',')
                .map(|v| v.trim().to_string())
                .collect::<Vec<_>>()
        } else {
            vec![trimmed.to_string()]
        };
        let record_number = fields
            .first()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or((idx + 1) as u64);
        let sequence_number = fields
            .get(1)
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(0);
        let path_field = fields
            .iter()
            .find(|v| v.contains('\\') || v.contains('/') || v.contains(':'))
            .cloned()
            .unwrap_or_else(|| format!("record_{}", record_number));
        let canonical_path = path_field.replace('/', "\\");
        let file_name = canonical_path
            .rsplit('\\')
            .next()
            .map(ToString::to_string)
            .filter(|v| !v.is_empty());
        let deleted = fields.iter().any(|v| {
            let l = v.to_ascii_lowercase();
            l == "deleted" || l == "true" || l == "1"
        });
        let ts = fields
            .iter()
            .find_map(|v| v.parse::<i64>().ok())
            .filter(|v| *v > 946_684_800);
        out.push(MftRecord {
            record_number,
            sequence_number,
            in_use: !deleted,
            deleted,
            file_name,
            modified_time: ts,
            ..MftRecord::default()
        });
    }
    out
}

fn parse_mft_records_json_value(value: &Value) -> Vec<MftRecord> {
    if let Some(rows) = value.as_array() {
        return rows.iter().map(parse_json_mft_record).collect();
    }
    if let Some(obj) = value.as_object() {
        for key in ["records", "entries", "rows"] {
            if let Some(rows) = obj.get(key).and_then(Value::as_array) {
                return rows.iter().map(parse_json_mft_record).collect();
            }
        }
        return vec![parse_json_mft_record(value)];
    }
    Vec::new()
}

pub fn parse_mft_record(data: &[u8]) -> Result<MftRecord, ForensicError> {
    if detect_mft_entry(data) {
        return Ok(parse_binary_mft_record(data));
    }

    if let Ok(v) = serde_json::from_slice::<Value>(data) {
        return Ok(parse_json_mft_record(&v));
    }

    Ok(MftRecord::default())
}

#[derive(Debug, Clone, Default)]
pub struct MftRecord {
    pub record_number: u64,
    pub sequence_number: u16,
    pub hard_link_count: u16,
    pub flags: u16,
    pub in_use: bool,
    pub deleted: bool,
    pub is_directory: bool,
    pub first_attribute_offset: u16,
    pub used_size: u32,
    pub allocated_size: u32,
    pub size: u32,
    pub file_name: Option<String>,
    pub short_name: Option<String>,
    pub parent_record_number: Option<u64>,
    pub file_name_namespace: Option<u8>,
    pub file_name_flags: Option<u32>,
    pub created_time: Option<i64>,
    pub modified_time: Option<i64>,
    pub mft_modified_time: Option<i64>,
    pub accessed_time: Option<i64>,
    pub timestamp_conflicts: Vec<String>,
    pub ads_streams: Vec<MftAdsStream>,
}

#[derive(Debug, Clone, Default)]
pub struct MftAttribute {
    pub attr_type: u32,
    pub size: u32,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MftAdsStream {
    pub name: String,
    pub size: u64,
    pub resident: bool,
}

#[derive(Debug, Clone, Default)]
pub struct MftPathResolution {
    pub record_number: u64,
    pub path: String,
    pub complete: bool,
    pub cycle_detected: bool,
}

pub fn reconstruct_mft_paths(records: &[MftRecord]) -> Vec<MftPathResolution> {
    let mut index: BTreeMap<u64, &MftRecord> = BTreeMap::new();
    for record in records {
        index.insert(record.record_number, record);
    }

    let mut memo: BTreeMap<u64, (String, bool, bool)> = BTreeMap::new();
    let mut out = Vec::new();
    for record_number in index.keys().copied() {
        let (path, complete, cycle_detected) =
            resolve_mft_path(record_number, &index, &mut memo, &mut HashSet::new());
        out.push(MftPathResolution {
            record_number,
            path,
            complete,
            cycle_detected,
        });
    }

    out.sort_by(|a, b| a.record_number.cmp(&b.record_number));
    out
}

fn resolve_mft_path(
    record_number: u64,
    index: &BTreeMap<u64, &MftRecord>,
    memo: &mut BTreeMap<u64, (String, bool, bool)>,
    visiting: &mut HashSet<u64>,
) -> (String, bool, bool) {
    if let Some(cached) = memo.get(&record_number) {
        return cached.clone();
    }
    let Some(record) = index.get(&record_number) else {
        return (String::new(), false, false);
    };

    let name = record
        .file_name
        .clone()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| format!("record_{}", record_number));

    if visiting.contains(&record_number) {
        return (name, false, true);
    }
    visiting.insert(record_number);

    let result = if record_number == 5 && record.file_name.as_deref().unwrap_or("").is_empty() {
        ("\\".to_string(), true, false)
    } else if let Some(parent) = record.parent_record_number {
        if parent == record_number {
            (name, false, true)
        } else if index.contains_key(&parent) {
            let (parent_path, parent_complete, parent_cycle) =
                resolve_mft_path(parent, index, memo, visiting);
            if parent_path == "\\" {
                (format!(r"\{}", name), parent_complete, parent_cycle)
            } else if !parent_path.is_empty() {
                (
                    format!(r"{}\{}", parent_path, name),
                    parent_complete,
                    parent_cycle,
                )
            } else {
                (name, false, parent_cycle)
            }
        } else {
            (name, false, false)
        }
    } else {
        (name, false, false)
    };

    visiting.remove(&record_number);
    memo.insert(record_number, result.clone());
    result
}

pub fn extract_mft_attributes(data: &[u8]) -> Vec<MftAttribute> {
    if detect_mft_entry(data) {
        return parse_binary_attributes(data);
    }

    let Ok(v) = serde_json::from_slice::<Value>(data) else {
        return Vec::new();
    };
    let Some(items) = v.get("attributes").and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .map(|x| MftAttribute {
            attr_type: x.get("attr_type").and_then(Value::as_u64).unwrap_or(0) as u32,
            size: x.get("size").and_then(Value::as_u64).unwrap_or(0) as u32,
            name: x
                .get("name")
                .and_then(Value::as_str)
                .map(ToString::to_string),
        })
        .collect()
}

fn parse_binary_mft_record(data: &[u8]) -> MftRecord {
    if data.len() < 0x30 {
        return MftRecord::default();
    }

    let sequence_number = le_u16_at(data, 0x10).unwrap_or(0);
    let hard_link_count = le_u16_at(data, 0x12).unwrap_or(0);
    let first_attribute_offset = le_u16_at(data, 0x14).unwrap_or(0);
    let flags = le_u16_at(data, 0x16).unwrap_or(0);
    let used_size = le_u32_at(data, 0x18).unwrap_or(0);
    let allocated_size = le_u32_at(data, 0x1c).unwrap_or(0);
    let record_number = le_u32_at(data, 0x2c).unwrap_or(0) as u64;
    let in_use = (flags & 0x0001) != 0;
    let is_directory = (flags & 0x0002) != 0;
    let deleted = !in_use;

    let mut file_name = None;
    let mut short_name = None;
    let mut si_created_time = None;
    let mut si_modified_time = None;
    let mut si_mft_modified_time = None;
    let mut si_accessed_time = None;
    let mut fn_created_time = None;
    let mut fn_modified_time = None;
    let mut fn_mft_modified_time = None;
    let mut fn_accessed_time = None;
    let mut best_data_size = None::<u32>;
    let mut parent_record_number = None::<u64>;
    let mut file_name_namespace = None::<u8>;
    let mut file_name_flags = None::<u32>;
    let mut ads_streams = Vec::<MftAdsStream>::new();

    for attr in parse_attr_headers(data, first_attribute_offset as usize) {
        match attr.attr_type {
            ATTR_STANDARD_INFORMATION => {
                if !attr.non_resident {
                    if let Some(content) =
                        resident_attr_content(data, attr.header_offset, attr.length)
                    {
                        if content.len() >= 32 {
                            si_created_time =
                                filetime_to_unix_i64(le_i64_at(content, 0x00).unwrap_or(0));
                            si_modified_time =
                                filetime_to_unix_i64(le_i64_at(content, 0x08).unwrap_or(0));
                            si_mft_modified_time =
                                filetime_to_unix_i64(le_i64_at(content, 0x10).unwrap_or(0));
                            si_accessed_time =
                                filetime_to_unix_i64(le_i64_at(content, 0x18).unwrap_or(0));
                        }
                    }
                }
            }
            ATTR_FILE_NAME => {
                if !attr.non_resident {
                    if let Some(parsed) = parse_file_name_attr_details(data, &attr) {
                        if parsed.name_namespace == Some(2) {
                            short_name = short_name.or(parsed.name.clone());
                        }
                        let replace_name = should_replace_file_name(
                            file_name.as_deref(),
                            file_name_namespace,
                            parsed.name.as_deref(),
                            parsed.name_namespace,
                        );
                        if replace_name {
                            file_name = parsed.name.clone();
                            file_name_namespace = parsed.name_namespace;
                            parent_record_number = parsed.parent_record_number;
                            file_name_flags = parsed.file_flags;
                        } else {
                            parent_record_number =
                                parent_record_number.or(parsed.parent_record_number);
                            file_name_flags = file_name_flags.or(parsed.file_flags);
                        }
                        fn_created_time = fn_created_time.or(parsed.created_time);
                        fn_modified_time = fn_modified_time.or(parsed.modified_time);
                        fn_mft_modified_time = fn_mft_modified_time.or(parsed.mft_modified_time);
                        fn_accessed_time = fn_accessed_time.or(parsed.accessed_time);
                        best_data_size = best_data_size.or(parsed.real_size);
                    } else {
                        file_name = parse_file_name_attr(data, &attr).or_else(|| {
                            resident_attr_content(data, attr.header_offset, attr.length).and_then(
                                |content| {
                                    if content.len() < 66 {
                                        return None;
                                    }
                                    let name_len = content[64] as usize;
                                    let byte_len = name_len.saturating_mul(2);
                                    if 66 + byte_len > content.len() {
                                        return None;
                                    }
                                    decode_utf16_name(&content[66..66 + byte_len])
                                },
                            )
                        });
                    }
                }
            }
            ATTR_DATA => {
                let stream_name = attr.header_name.clone().filter(|n| !n.trim().is_empty());
                let stream_size = if attr.non_resident {
                    le_u64_at(data, attr.header_offset + 48).unwrap_or(0)
                } else {
                    le_u32_at(data, attr.header_offset + 16).unwrap_or(0) as u64
                };

                if let Some(name) = stream_name {
                    upsert_ads_stream(&mut ads_streams, name, stream_size, !attr.non_resident);
                } else if attr.non_resident {
                    if stream_size <= u32::MAX as u64 {
                        best_data_size = Some(stream_size as u32);
                    }
                } else {
                    best_data_size = Some(best_data_size.unwrap_or(0).max(stream_size as u32));
                }
            }
            _ => {}
        }
    }

    let created_time = si_created_time.or(fn_created_time);
    let modified_time = si_modified_time.or(fn_modified_time);
    let mft_modified_time = si_mft_modified_time.or(fn_mft_modified_time);
    let accessed_time = si_accessed_time.or(fn_accessed_time);
    let timestamp_conflicts = collect_timestamp_conflicts(
        [
            si_created_time,
            si_modified_time,
            si_mft_modified_time,
            si_accessed_time,
        ],
        [
            fn_created_time,
            fn_modified_time,
            fn_mft_modified_time,
            fn_accessed_time,
        ],
    );

    MftRecord {
        record_number,
        sequence_number,
        hard_link_count,
        flags,
        in_use,
        deleted,
        is_directory,
        first_attribute_offset,
        used_size,
        allocated_size,
        size: best_data_size.unwrap_or(used_size),
        file_name,
        short_name,
        parent_record_number,
        file_name_namespace,
        file_name_flags,
        created_time,
        modified_time,
        mft_modified_time,
        accessed_time,
        timestamp_conflicts,
        ads_streams,
    }
}

fn parse_json_mft_record(v: &Value) -> MftRecord {
    MftRecord {
        record_number: v
            .get("record_number")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
        sequence_number: v
            .get("sequence_number")
            .and_then(Value::as_u64)
            .unwrap_or_default() as u16,
        hard_link_count: v
            .get("hard_link_count")
            .and_then(Value::as_u64)
            .unwrap_or_default() as u16,
        flags: v.get("flags").and_then(Value::as_u64).unwrap_or_default() as u16,
        in_use: v.get("in_use").and_then(Value::as_bool).unwrap_or_default(),
        deleted: v
            .get("deleted")
            .and_then(Value::as_bool)
            .or_else(|| {
                v.get("in_use")
                    .and_then(Value::as_bool)
                    .map(|in_use| !in_use)
            })
            .unwrap_or_default(),
        is_directory: v
            .get("is_directory")
            .and_then(Value::as_bool)
            .unwrap_or_default(),
        first_attribute_offset: v
            .get("first_attribute_offset")
            .and_then(Value::as_u64)
            .unwrap_or_default() as u16,
        used_size: v
            .get("used_size")
            .and_then(Value::as_u64)
            .unwrap_or_default() as u32,
        allocated_size: v
            .get("allocated_size")
            .and_then(Value::as_u64)
            .unwrap_or_default() as u32,
        size: v.get("size").and_then(Value::as_u64).unwrap_or_default() as u32,
        file_name: v
            .get("file_name")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        short_name: v
            .get("short_name")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        parent_record_number: v.get("parent_record_number").and_then(Value::as_u64),
        file_name_namespace: v
            .get("file_name_namespace")
            .and_then(Value::as_u64)
            .map(|v| v as u8),
        file_name_flags: v
            .get("file_name_flags")
            .and_then(Value::as_u64)
            .map(|v| v as u32),
        created_time: v.get("created_time").and_then(Value::as_i64),
        modified_time: v.get("modified_time").and_then(Value::as_i64),
        mft_modified_time: v.get("mft_modified_time").and_then(Value::as_i64),
        accessed_time: v.get("accessed_time").and_then(Value::as_i64),
        timestamp_conflicts: v
            .get("timestamp_conflicts")
            .and_then(Value::as_array)
            .map(|rows| {
                rows.iter()
                    .filter_map(|row| row.as_str().map(ToString::to_string))
                    .collect()
            })
            .unwrap_or_default(),
        ads_streams: v
            .get("ads_streams")
            .and_then(Value::as_array)
            .map(|rows| {
                rows.iter()
                    .filter_map(|row| {
                        Some(MftAdsStream {
                            name: row.get("name")?.as_str()?.to_string(),
                            size: row.get("size").and_then(Value::as_u64).unwrap_or(0),
                            resident: row.get("resident").and_then(Value::as_bool).unwrap_or(true),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

#[derive(Debug, Clone)]
struct AttrHeader {
    attr_type: u32,
    length: usize,
    non_resident: bool,
    header_offset: usize,
    header_name: Option<String>,
}

fn parse_attr_headers(data: &[u8], first_offset: usize) -> Vec<AttrHeader> {
    let mut out = Vec::new();
    if first_offset >= data.len() {
        return out;
    }

    let mut pos = first_offset;
    let mut iterations = 0usize;
    while pos + 8 <= data.len() {
        iterations += 1;
        if iterations > 4096 {
            break;
        }
        let Some(attr_type) = le_u32_at(data, pos) else {
            break;
        };
        if attr_type == ATTR_END {
            break;
        }
        let Some(len_u32) = le_u32_at(data, pos + 4) else {
            break;
        };
        let len = len_u32 as usize;
        if len < 8 || pos + len > data.len() {
            pos = pos.saturating_add(8);
            continue;
        }
        out.push(AttrHeader {
            attr_type,
            length: len,
            non_resident: data.get(pos + 8).copied().unwrap_or(0) != 0,
            header_offset: pos,
            header_name: parse_attr_header_name(data, pos, len),
        });
        pos += len;
    }

    out
}

fn upsert_ads_stream(streams: &mut Vec<MftAdsStream>, name: String, size: u64, resident: bool) {
    if let Some(existing) = streams
        .iter_mut()
        .find(|s| s.name.eq_ignore_ascii_case(name.as_str()))
    {
        existing.size = existing.size.max(size);
        existing.resident = existing.resident && resident;
        return;
    }
    streams.push(MftAdsStream {
        name,
        size,
        resident,
    });
}

fn collect_timestamp_conflicts(
    si_times: [Option<i64>; 4],
    fn_times: [Option<i64>; 4],
) -> Vec<String> {
    let mut out = Vec::new();
    let keys = [
        "created_time",
        "modified_time",
        "mft_modified_time",
        "accessed_time",
    ];
    for (index, key) in keys.iter().enumerate() {
        push_timestamp_conflict(&mut out, key, si_times[index], fn_times[index]);
    }
    out
}

fn push_timestamp_conflict(
    out: &mut Vec<String>,
    key: &str,
    left: Option<i64>,
    right: Option<i64>,
) {
    if let (Some(a), Some(b)) = (left, right) {
        if a != b {
            out.push(key.to_string());
        }
    }
}

fn parse_binary_attributes(data: &[u8]) -> Vec<MftAttribute> {
    if data.len() < 0x18 || !detect_mft_entry(data) {
        return Vec::new();
    }
    let first_offset = le_u16_at(data, 0x14).unwrap_or(0) as usize;
    parse_attr_headers(data, first_offset)
        .into_iter()
        .map(|h| MftAttribute {
            attr_type: h.attr_type,
            size: h.length as u32,
            name: h
                .header_name
                .or_else(|| Some(attr_type_name(h.attr_type).to_string())),
        })
        .collect()
}

fn resident_attr_content(data: &[u8], attr_offset: usize, attr_len: usize) -> Option<&[u8]> {
    if attr_offset + attr_len > data.len() || attr_len < 24 {
        return None;
    }
    let value_len = le_u32_at(data, attr_offset + 16)? as usize;
    let value_offset = le_u16_at(data, attr_offset + 20)? as usize;
    if value_offset > attr_len || value_len > attr_len {
        return None;
    }
    let start = attr_offset + value_offset;
    let end = start + value_len;
    if end > data.len() || end > attr_offset + attr_len {
        return None;
    }
    Some(&data[start..end])
}

fn parse_attr_header_name(data: &[u8], attr_offset: usize, attr_len: usize) -> Option<String> {
    if attr_offset + attr_len > data.len() || attr_len < 16 {
        return None;
    }
    let name_len_chars = data.get(attr_offset + 9).copied().unwrap_or(0) as usize;
    if name_len_chars == 0 {
        return None;
    }
    let name_offset = le_u16_at(data, attr_offset + 10)? as usize;
    let name_bytes_len = name_len_chars.saturating_mul(2);
    if name_offset == 0 || name_offset + name_bytes_len > attr_len {
        return None;
    }
    let start = attr_offset + name_offset;
    let end = start + name_bytes_len;
    if end > data.len() {
        return None;
    }
    decode_utf16_name(&data[start..end])
}

#[derive(Debug, Clone, Default)]
struct FileNameAttrParsed {
    name: Option<String>,
    parent_record_number: Option<u64>,
    name_namespace: Option<u8>,
    file_flags: Option<u32>,
    created_time: Option<i64>,
    modified_time: Option<i64>,
    mft_modified_time: Option<i64>,
    accessed_time: Option<i64>,
    real_size: Option<u32>,
}

fn parse_file_name_attr(data: &[u8], attr: &AttrHeader) -> Option<String> {
    parse_file_name_attr_details(data, attr)?.name
}

fn file_name_namespace_rank(ns: Option<u8>) -> u8 {
    match ns {
        Some(3) => 4, // Win32 + DOS
        Some(1) => 3, // Win32
        Some(0) => 2, // POSIX
        Some(2) => 1, // DOS (8.3)
        _ => 0,
    }
}

fn should_replace_file_name(
    current_name: Option<&str>,
    current_ns: Option<u8>,
    new_name: Option<&str>,
    new_ns: Option<u8>,
) -> bool {
    if current_name.is_none() {
        return new_name.is_some();
    }
    if new_name.is_none() {
        return false;
    }

    let current_rank = file_name_namespace_rank(current_ns);
    let new_rank = file_name_namespace_rank(new_ns);
    if new_rank > current_rank {
        return true;
    }
    if new_rank < current_rank {
        return false;
    }

    // For equal namespace preference, pick a longer (often non-8.3) name.
    let cur_len = current_name.unwrap_or_default().chars().count();
    let new_len = new_name.unwrap_or_default().chars().count();
    new_len > cur_len
}

fn parse_file_name_attr_details(data: &[u8], attr: &AttrHeader) -> Option<FileNameAttrParsed> {
    if attr.non_resident || attr.length < 0x18 || attr.header_offset + attr.length > data.len() {
        return None;
    }

    let value_offset = le_u16_at(data, attr.header_offset + 20)? as usize;
    let value_start = attr.header_offset.checked_add(value_offset)?;
    let attr_end = attr.header_offset + attr.length;

    if value_start + 66 > attr_end || value_start + 66 > data.len() {
        return None;
    }

    let name_len = data[value_start + 64] as usize;
    let byte_len = name_len.saturating_mul(2);
    let name_start = value_start + 66;
    let name_end = name_start.checked_add(byte_len)?;
    if name_end > attr_end || name_end > data.len() {
        return None;
    }

    let name = decode_utf16_name(&data[name_start..name_end]);
    let parent_ref = le_u64_at(data, value_start)?;
    let parent_record_number = Some(parent_ref & 0x0000_FFFF_FFFF_FFFFu64);
    let file_flags = le_u32_at(data, value_start + 56);
    let name_namespace = data.get(value_start + 65).copied();
    let created_time = filetime_to_unix_i64(le_i64_at(data, value_start + 8).unwrap_or(0));
    let modified_time = filetime_to_unix_i64(le_i64_at(data, value_start + 16).unwrap_or(0));
    let mft_modified_time = filetime_to_unix_i64(le_i64_at(data, value_start + 24).unwrap_or(0));
    let accessed_time = filetime_to_unix_i64(le_i64_at(data, value_start + 32).unwrap_or(0));
    let real_size = le_u64_at(data, value_start + 48)
        .filter(|v| *v <= u32::MAX as u64)
        .map(|v| v as u32);

    Some(FileNameAttrParsed {
        name,
        parent_record_number,
        name_namespace,
        file_flags,
        created_time,
        modified_time,
        mft_modified_time,
        accessed_time,
        real_size,
    })
}

fn attr_type_name(attr_type: u32) -> &'static str {
    match attr_type {
        0x10 => "STANDARD_INFORMATION",
        0x20 => "ATTRIBUTE_LIST",
        0x30 => "FILE_NAME",
        0x40 => "OBJECT_ID",
        0x50 => "SECURITY_DESCRIPTOR",
        0x60 => "VOLUME_NAME",
        0x70 => "VOLUME_INFORMATION",
        0x80 => "DATA",
        0x90 => "INDEX_ROOT",
        0xA0 => "INDEX_ALLOCATION",
        0xB0 => "BITMAP",
        0xC0 => "REPARSE_POINT",
        0xD0 => "EA_INFORMATION",
        0xE0 => "EA",
        0xF0 => "PROPERTY_SET",
        0x100 => "LOGGED_UTILITY_STREAM",
        _ => "UNKNOWN",
    }
}

fn decode_utf16_name(bytes: &[u8]) -> Option<String> {
    let mut units = Vec::new();
    for chunk in bytes.chunks(2) {
        if chunk.len() != 2 {
            break;
        }
        let u = u16::from_le_bytes([chunk[0], chunk[1]]);
        if u == 0 {
            break;
        }
        units.push(u);
    }
    let text = String::from_utf16(&units).ok()?;
    if text.is_empty() {
        return None;
    }
    Some(text)
}

fn filetime_to_unix_i64(filetime: i64) -> Option<i64> {
    if filetime <= 0 {
        return None;
    }
    let seconds = filetime / 10_000_000;
    if seconds < FILETIME_UNIX_EPOCH_OFFSET {
        return None;
    }
    Some(seconds - FILETIME_UNIX_EPOCH_OFFSET)
}

fn le_u16_at(data: &[u8], off: usize) -> Option<u16> {
    if off + 2 > data.len() {
        return None;
    }
    Some(u16::from_le_bytes([data[off], data[off + 1]]))
}

fn le_u32_at(data: &[u8], off: usize) -> Option<u32> {
    if off + 4 > data.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
    ]))
}

fn le_u64_at(data: &[u8], off: usize) -> Option<u64> {
    if off + 8 > data.len() {
        return None;
    }
    Some(u64::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
        data[off + 4],
        data[off + 5],
        data[off + 6],
        data[off + 7],
    ]))
}

fn le_i64_at(data: &[u8], off: usize) -> Option<i64> {
    if off + 8 > data.len() {
        return None;
    }
    Some(i64::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
        data[off + 4],
        data[off + 5],
        data[off + 6],
        data[off + 7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_mft_record() -> Vec<u8> {
        let mut data = vec![0u8; 1024];
        data[0..4].copy_from_slice(b"FILE");
        data[0x10..0x12].copy_from_slice(&2u16.to_le_bytes()); // sequence
        data[0x12..0x14].copy_from_slice(&1u16.to_le_bytes()); // links
        data[0x14..0x16].copy_from_slice(&0x30u16.to_le_bytes()); // first attr
        data[0x16..0x18].copy_from_slice(&0x0003u16.to_le_bytes()); // in-use + dir
        data[0x18..0x1c].copy_from_slice(&512u32.to_le_bytes()); // used size
        data[0x1c..0x20].copy_from_slice(&1024u32.to_le_bytes()); // alloc size
        data[0x2c..0x30].copy_from_slice(&123u32.to_le_bytes()); // record num

        // STANDARD_INFORMATION (resident)
        let mut pos = 0x30usize;
        data[pos..pos + 4].copy_from_slice(&ATTR_STANDARD_INFORMATION.to_le_bytes());
        data[pos + 4..pos + 8].copy_from_slice(&0x60u32.to_le_bytes());
        data[pos + 8] = 0; // resident
        data[pos + 16..pos + 20].copy_from_slice(&0x30u32.to_le_bytes()); // value len
        data[pos + 20..pos + 22].copy_from_slice(&0x18u16.to_le_bytes()); // value off
        let ft = (FILETIME_UNIX_EPOCH_OFFSET + 1_700_000_000) * 10_000_000i64;
        data[pos + 0x18..pos + 0x20].copy_from_slice(&ft.to_le_bytes());
        data[pos + 0x20..pos + 0x28].copy_from_slice(&(ft + 10_000_000).to_le_bytes());
        data[pos + 0x28..pos + 0x30].copy_from_slice(&(ft + 20_000_000).to_le_bytes());
        data[pos + 0x30..pos + 0x38].copy_from_slice(&(ft + 30_000_000).to_le_bytes());

        // FILE_NAME (resident)
        pos += 0x60;
        data[pos..pos + 4].copy_from_slice(&ATTR_FILE_NAME.to_le_bytes());
        data[pos + 4..pos + 8].copy_from_slice(&0x70u32.to_le_bytes());
        data[pos + 8] = 0;
        data[pos + 16..pos + 20].copy_from_slice(&0x52u32.to_le_bytes());
        data[pos + 20..pos + 22].copy_from_slice(&0x18u16.to_le_bytes());
        let name = "report.txt";
        data[pos + 0x18 + 64] = name.len() as u8;
        data[pos + 0x18 + 65] = 1;
        let mut name_bytes = Vec::new();
        for u in name.encode_utf16() {
            name_bytes.extend_from_slice(&u.to_le_bytes());
        }
        let name_start = pos + 0x18 + 66;
        data[name_start..name_start + name_bytes.len()].copy_from_slice(&name_bytes);

        // DATA (resident)
        pos += 0x70;
        data[pos..pos + 4].copy_from_slice(&ATTR_DATA.to_le_bytes());
        data[pos + 4..pos + 8].copy_from_slice(&0x30u32.to_le_bytes());
        data[pos + 8] = 0;
        data[pos + 16..pos + 20].copy_from_slice(&64u32.to_le_bytes()); // value len
        data[pos + 20..pos + 22].copy_from_slice(&0x18u16.to_le_bytes());

        // End marker
        pos += 0x30;
        data[pos..pos + 4].copy_from_slice(&ATTR_END.to_le_bytes());

        data
    }

    fn write_named_resident_data_attr(
        data: &mut [u8],
        pos: usize,
        name: &str,
        value_len: u32,
    ) -> usize {
        let name_bytes: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let name_offset = 0x18usize;
        let value_offset = name_offset + name_bytes.len();
        let attr_len = value_offset + value_len as usize;

        data[pos..pos + 4].copy_from_slice(&ATTR_DATA.to_le_bytes());
        data[pos + 4..pos + 8].copy_from_slice(&(attr_len as u32).to_le_bytes());
        data[pos + 8] = 0; // resident
        data[pos + 9] = name.encode_utf16().count() as u8;
        data[pos + 10..pos + 12].copy_from_slice(&(name_offset as u16).to_le_bytes());
        data[pos + 16..pos + 20].copy_from_slice(&value_len.to_le_bytes());
        data[pos + 20..pos + 22].copy_from_slice(&(value_offset as u16).to_le_bytes());
        data[pos + name_offset..pos + name_offset + name_bytes.len()].copy_from_slice(&name_bytes);

        pos + attr_len
    }

    #[test]
    fn parse_binary_mft_record_extracts_core_fields() {
        let data = make_test_mft_record();
        let record = parse_mft_record(&data).unwrap();
        assert_eq!(record.record_number, 123);
        assert_eq!(record.sequence_number, 2);
        assert_eq!(record.hard_link_count, 1);
        assert!(record.in_use);
        assert!(record.is_directory);
        assert_eq!(record.size, 64);
        assert_eq!(record.file_name.as_deref(), Some("report.txt"));
        assert_eq!(record.created_time, Some(1_700_000_000));
        assert_eq!(record.file_name_namespace, Some(1));
    }

    #[test]
    fn parse_binary_mft_record_extracts_ads_and_preserves_primary_size() {
        let mut data = make_test_mft_record();
        let mut pos = 0x130usize;
        pos = write_named_resident_data_attr(&mut data, pos, "Zone.Identifier", 5);
        pos = write_named_resident_data_attr(&mut data, pos, "zone.identifier", 15);
        data[pos..pos + 4].copy_from_slice(&ATTR_END.to_le_bytes());

        let record = parse_mft_record(&data).unwrap();
        assert_eq!(record.size, 64);
        assert_eq!(record.ads_streams.len(), 1);
        assert_eq!(
            record.ads_streams[0],
            MftAdsStream {
                name: "Zone.Identifier".to_string(),
                size: 15,
                resident: true,
            }
        );
    }

    #[test]
    fn extract_binary_mft_attributes_lists_attribute_types() {
        let data = make_test_mft_record();
        let attrs = extract_mft_attributes(&data);
        let kinds: Vec<u32> = attrs.iter().map(|a| a.attr_type).collect();
        assert!(kinds.contains(&ATTR_STANDARD_INFORMATION));
        assert!(kinds.contains(&ATTR_FILE_NAME));
        assert!(kinds.contains(&ATTR_DATA));
    }

    #[test]
    fn parse_json_mft_record_still_supported() {
        let json = br#"{
            "record_number": 77,
            "flags": 3,
            "size": 4096,
            "file_name": "from-json"
        }"#;
        let record = parse_mft_record(json).unwrap();
        assert_eq!(record.record_number, 77);
        assert_eq!(record.flags, 3);
        assert_eq!(record.size, 4096);
        assert_eq!(record.file_name.as_deref(), Some("from-json"));
        assert!(record.timestamp_conflicts.is_empty());
    }

    #[test]
    fn parse_json_mft_record_infers_deleted_from_in_use_false() {
        let json = br#"{
            "record_number": 88,
            "in_use": false,
            "short_name": "FROMJS~1.TXT",
            "ads_streams": [{"name":"Zone.Identifier","size":7,"resident":true}]
        }"#;
        let record = parse_mft_record(json).unwrap();
        assert!(record.deleted);
        assert_eq!(record.short_name.as_deref(), Some("FROMJS~1.TXT"));
        assert_eq!(record.ads_streams.len(), 1);
        assert_eq!(record.ads_streams[0].name, "Zone.Identifier");
    }

    #[test]
    fn parse_binary_mft_record_uses_non_resident_real_size() {
        let mut data = make_test_mft_record();
        let data_attr = 0x30usize + 0x60usize + 0x70usize;
        data[data_attr + 4..data_attr + 8].copy_from_slice(&0x50u32.to_le_bytes());
        data[data_attr + 8] = 1; // non-resident
        data[data_attr + 48..data_attr + 56].copy_from_slice(&12345u64.to_le_bytes()); // real size

        let end = data_attr + 0x50;
        data[end..end + 4].copy_from_slice(&ATTR_END.to_le_bytes());

        let record = parse_mft_record(&data).unwrap();
        assert_eq!(record.size, 12345);
    }

    #[test]
    fn parse_binary_mft_record_prefers_win32_name_over_dos_alias() {
        let mut data = make_test_mft_record();

        // First FILE_NAME at 0x90 becomes DOS alias.
        let first_fn = 0x30usize + 0x60usize;
        let first_value = first_fn + 0x18;
        let dos_name = "REP~1.TXT";
        data[first_value + 64] = dos_name.len() as u8;
        data[first_value + 65] = 2; // DOS namespace
        let dos_bytes: Vec<u8> = dos_name
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let first_name_start = first_value + 66;
        data[first_name_start..first_name_start + dos_bytes.len()].copy_from_slice(&dos_bytes);

        // Replace DATA attr with a second FILE_NAME attr (Win32), then append DATA.
        let second_fn = 0x100usize;
        data[second_fn..second_fn + 4].copy_from_slice(&ATTR_FILE_NAME.to_le_bytes());
        data[second_fn + 4..second_fn + 8].copy_from_slice(&0x70u32.to_le_bytes());
        data[second_fn + 8] = 0;
        data[second_fn + 16..second_fn + 20].copy_from_slice(&0x52u32.to_le_bytes());
        data[second_fn + 20..second_fn + 22].copy_from_slice(&0x18u16.to_le_bytes());

        let win32_name = "Report.txt";
        let second_value = second_fn + 0x18;
        data[second_value + 64] = win32_name.len() as u8;
        data[second_value + 65] = 1; // Win32 namespace
        let win32_bytes: Vec<u8> = win32_name
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let second_name_start = second_value + 66;
        data[second_name_start..second_name_start + win32_bytes.len()]
            .copy_from_slice(&win32_bytes);

        let data_attr = 0x170usize;
        data[data_attr..data_attr + 4].copy_from_slice(&ATTR_DATA.to_le_bytes());
        data[data_attr + 4..data_attr + 8].copy_from_slice(&0x30u32.to_le_bytes());
        data[data_attr + 8] = 0;
        data[data_attr + 16..data_attr + 20].copy_from_slice(&64u32.to_le_bytes());
        data[data_attr + 20..data_attr + 22].copy_from_slice(&0x18u16.to_le_bytes());

        let end = data_attr + 0x30;
        data[end..end + 4].copy_from_slice(&ATTR_END.to_le_bytes());

        let record = parse_mft_record(&data).unwrap();
        assert_eq!(record.file_name.as_deref(), Some("Report.txt"));
        assert_eq!(record.file_name_namespace, Some(1));
        assert_eq!(record.short_name.as_deref(), Some("REP~1.TXT"));
    }

    #[test]
    fn parse_binary_mft_record_uses_file_name_times_when_si_missing() {
        let mut data = make_test_mft_record();
        // Mark STANDARD_INFORMATION as end marker to simulate sparse/corrupt SI.
        data[0x30..0x34].copy_from_slice(&ATTR_END.to_le_bytes());
        // Move attribute start directly to FILE_NAME block.
        data[0x14..0x16].copy_from_slice(&0x90u16.to_le_bytes());

        let fn_pos = 0x90usize;
        let ft = (FILETIME_UNIX_EPOCH_OFFSET + 1_701_000_000) * 10_000_000i64;
        let value_start = fn_pos + 0x18;
        data[value_start + 8..value_start + 16].copy_from_slice(&ft.to_le_bytes());
        data[value_start + 16..value_start + 24].copy_from_slice(&(ft + 10_000_000).to_le_bytes());
        data[value_start + 24..value_start + 32].copy_from_slice(&(ft + 20_000_000).to_le_bytes());
        data[value_start + 32..value_start + 40].copy_from_slice(&(ft + 30_000_000).to_le_bytes());
        data[value_start + 48..value_start + 56].copy_from_slice(&777u64.to_le_bytes());
        data[value_start..value_start + 8].copy_from_slice(&55u64.to_le_bytes());
        data[value_start + 56..value_start + 60].copy_from_slice(&0x20u32.to_le_bytes());

        let record = parse_mft_record(&data).unwrap();
        assert_eq!(record.created_time, Some(1_701_000_000));
        assert_eq!(record.size, 777);
        assert_eq!(record.parent_record_number, Some(55));
        assert_eq!(record.file_name_flags, Some(0x20));
    }

    #[test]
    fn parse_binary_mft_record_flags_si_fn_timestamp_conflicts() {
        let mut data = make_test_mft_record();
        let fn_pos = 0x90usize;
        let value_start = fn_pos + 0x18;
        let fn_ft = (FILETIME_UNIX_EPOCH_OFFSET + 1_600_000_000) * 10_000_000i64;
        data[value_start + 8..value_start + 16].copy_from_slice(&fn_ft.to_le_bytes());
        data[value_start + 16..value_start + 24]
            .copy_from_slice(&(fn_ft + 10_000_000).to_le_bytes());
        data[value_start + 24..value_start + 32]
            .copy_from_slice(&(fn_ft + 20_000_000).to_le_bytes());
        data[value_start + 32..value_start + 40]
            .copy_from_slice(&(fn_ft + 30_000_000).to_le_bytes());

        let record = parse_mft_record(&data).unwrap();
        assert_eq!(record.created_time, Some(1_700_000_000)); // SI still preferred
        assert_eq!(record.timestamp_conflicts.len(), 4);
        assert!(record
            .timestamp_conflicts
            .iter()
            .any(|v| v == "created_time"));
        assert!(record
            .timestamp_conflicts
            .iter()
            .any(|v| v == "modified_time"));
        assert!(record
            .timestamp_conflicts
            .iter()
            .any(|v| v == "mft_modified_time"));
        assert!(record
            .timestamp_conflicts
            .iter()
            .any(|v| v == "accessed_time"));
    }

    #[test]
    fn extract_binary_mft_attributes_prefers_named_attribute_label() {
        let mut data = make_test_mft_record();
        let fn_pos = 0x30usize + 0x60usize;
        data[fn_pos + 9] = 4; // name chars
        data[fn_pos + 10..fn_pos + 12].copy_from_slice(&0x50u16.to_le_bytes());
        let name_bytes: Vec<u8> = "MAIN"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let start = fn_pos + 0x50;
        data[start..start + name_bytes.len()].copy_from_slice(&name_bytes);

        let attrs = extract_mft_attributes(&data);
        let file_name_attr = attrs
            .iter()
            .find(|a| a.attr_type == ATTR_FILE_NAME)
            .expect("FILE_NAME attr missing");
        assert_eq!(file_name_attr.name.as_deref(), Some("MAIN"));
    }

    #[test]
    fn parse_binary_mft_record_marks_deleted_when_not_in_use() {
        let mut data = make_test_mft_record();
        data[0x16..0x18].copy_from_slice(&0x0002u16.to_le_bytes()); // directory, not in-use
        let record = parse_mft_record(&data).unwrap();
        assert!(!record.in_use);
        assert!(record.deleted);
    }

    #[test]
    fn parse_binary_mft_record_tolerates_malformed_attribute_chain() {
        let mut data = vec![0u8; 512];
        data[0..4].copy_from_slice(b"FILE");
        data[0x14..0x16].copy_from_slice(&0x30u16.to_le_bytes()); // first attr
        data[0x16..0x18].copy_from_slice(&0x0001u16.to_le_bytes()); // in-use
        data[0x18..0x1c].copy_from_slice(&128u32.to_le_bytes()); // used size
        data[0x1c..0x20].copy_from_slice(&512u32.to_le_bytes()); // alloc size

        // Malformed attr header: impossible length, parser should skip forward safely.
        data[0x30..0x34].copy_from_slice(&ATTR_STANDARD_INFORMATION.to_le_bytes());
        data[0x34..0x38].copy_from_slice(&0xFFFFu32.to_le_bytes());

        // Valid DATA attr at next scan position.
        let pos = 0x38usize;
        data[pos..pos + 4].copy_from_slice(&ATTR_DATA.to_le_bytes());
        data[pos + 4..pos + 8].copy_from_slice(&0x30u32.to_le_bytes());
        data[pos + 8] = 0;
        data[pos + 16..pos + 20].copy_from_slice(&12u32.to_le_bytes());
        data[pos + 20..pos + 22].copy_from_slice(&0x18u16.to_le_bytes());
        data[pos + 0x30..pos + 0x34].copy_from_slice(&ATTR_END.to_le_bytes());

        let record = parse_mft_record(&data).unwrap();
        assert_eq!(record.size, 12);

        let attrs = extract_mft_attributes(&data);
        assert!(attrs.iter().any(|a| a.attr_type == ATTR_DATA));
    }

    #[test]
    fn reconstruct_mft_paths_parent_chain() {
        let records = vec![
            MftRecord {
                record_number: 5,
                file_name: None,
                parent_record_number: None,
                ..MftRecord::default()
            },
            MftRecord {
                record_number: 42,
                file_name: Some("Users".to_string()),
                parent_record_number: Some(5),
                ..MftRecord::default()
            },
            MftRecord {
                record_number: 43,
                file_name: Some("alice".to_string()),
                parent_record_number: Some(42),
                ..MftRecord::default()
            },
            MftRecord {
                record_number: 44,
                file_name: Some("doc.txt".to_string()),
                parent_record_number: Some(43),
                ..MftRecord::default()
            },
        ];
        let rows = reconstruct_mft_paths(&records);
        let doc = rows.iter().find(|r| r.record_number == 44).unwrap();
        assert_eq!(doc.path, r"\Users\alice\doc.txt");
        assert!(doc.complete);
        assert!(!doc.cycle_detected);
    }

    #[test]
    fn reconstruct_mft_paths_handles_missing_parent() {
        let records = vec![MftRecord {
            record_number: 10,
            file_name: Some("orphan.txt".to_string()),
            parent_record_number: Some(999),
            ..MftRecord::default()
        }];
        let rows = reconstruct_mft_paths(&records);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].path, "orphan.txt");
        assert!(!rows[0].complete);
        assert!(!rows[0].cycle_detected);
    }

    #[test]
    fn reconstruct_mft_paths_detects_cycles() {
        let records = vec![
            MftRecord {
                record_number: 20,
                file_name: Some("A".to_string()),
                parent_record_number: Some(21),
                ..MftRecord::default()
            },
            MftRecord {
                record_number: 21,
                file_name: Some("B".to_string()),
                parent_record_number: Some(20),
                ..MftRecord::default()
            },
        ];
        let rows = reconstruct_mft_paths(&records);
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| !r.complete));
        assert!(rows.iter().all(|r| r.cycle_detected));
    }

    #[test]
    fn detect_mft_input_shape_supports_binary_json_csv() {
        let temp = std::env::temp_dir().join(format!(
            "mft_shape_{}_{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();

        let bin = temp.join("sample.bin");
        let json = temp.join("sample.json");
        let csv = temp.join("sample.csv");
        std::fs::write(&bin, b"FILE\x00\x00\x00\x00").unwrap();
        std::fs::write(&json, r#"[{"record_number":1,"file_name":"a.txt"}]"#).unwrap();
        std::fs::write(&csv, "record_number,file_name\n1,a.txt\n").unwrap();

        assert_eq!(detect_mft_input_shape(&bin), MftInputShape::BinaryRaw);
        assert_eq!(detect_mft_input_shape(&json), MftInputShape::JsonArray);
        assert_eq!(detect_mft_input_shape(&csv), MftInputShape::CsvDelimited);

        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn parse_mft_records_from_path_parses_json_records() {
        let temp = std::env::temp_dir().join(format!(
            "mft_json_{}_{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        let json = temp.join("sample.json");
        std::fs::write(
            &json,
            r#"[{"record_number":42,"file_name":"demo.exe","modified_time":1700001000}]"#,
        )
        .unwrap();
        let rows = parse_mft_records_from_path(&json, 10);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].record_number, 42);
        assert_eq!(rows[0].file_name.as_deref(), Some("demo.exe"));
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn parse_mft_text_fallback_handles_partial_lines() {
        let temp = std::env::temp_dir().join(format!(
            "mft_text_{}_{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        let input = temp.join("sample.txt");
        std::fs::write(
            &input,
            "record_number,path,status\n1,C:/Windows/System32/cmd.exe,deleted\n",
        )
        .unwrap();
        let rows = parse_mft_text_fallback(&input);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].record_number, 1);
        assert!(rows[0].deleted);
        assert_eq!(rows[0].file_name.as_deref(), Some("cmd.exe"));
        let _ = std::fs::remove_dir_all(&temp);
    }
}
