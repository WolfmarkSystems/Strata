use crate::errors::ForensicError;
use serde_json::Value;
use std::path::Path;

use super::scalpel::{read_prefix, DEFAULT_BINARY_MAX_BYTES};

const REGF_HEADER_LEN: usize = 0x1000;
const HBIN_HEADER_LEN: usize = 0x20;
const MAX_HIVE_READ_BYTES: usize = 128 * 1024 * 1024;
const FILETIME_UNIX_EPOCH_OFFSET: u64 = 11_644_473_600;
const NK_FLAG_COMP_NAME: u16 = 0x0020;

#[derive(Debug, Clone, Default)]
pub struct RegistryHive {
    pub name: String,
    pub file_path: String,
    pub hive_type: HiveType,
    pub root_key_offset: u32,
    pub last_modified: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub enum HiveType {
    #[default]
    Unknown,
    System,
    Software,
    Security,
    Sam,
    Ntuser,
    Usrclass,
}

#[derive(Debug, Clone, Default)]
pub struct RegKey {
    pub name: String,
    pub offset: u32,
    pub parent_offset: u32,
    pub subkey_count: u32,
    pub value_count: u32,
    pub last_modified: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct RegValue {
    pub name: String,
    pub value_type: RegValueType,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub enum RegValueType {
    #[default]
    None,
    String,
    ExpandString,
    Binary,
    Dword,
    Qword,
    MultiString,
    Link,
}

#[derive(Debug, Clone, Default)]
pub struct SecurityDescriptor {
    pub owner: Option<String>,
    pub group: Option<String>,
    pub dacl: Vec<Ace>,
}

#[derive(Debug, Clone, Default)]
pub struct Ace {
    pub ace_type: String,
    pub trustee: String,
    pub permissions: String,
}

pub fn parse_registry_hive(data: &[u8]) -> Result<RegistryHive, ForensicError> {
    let is_regf = data.len() >= REGF_HEADER_LEN && &data[0..4] == b"regf";
    let mut root_key_offset = 0u32;
    let mut last_modified = None;
    let mut name = String::new();
    let mut hive_type = detect_hive_type(data, "");

    if is_regf {
        root_key_offset = le_u32_at(data, 0x24).unwrap_or(0);
        last_modified = parse_registry_timestamp(data.get(0x0c..0x14).unwrap_or(&[]));
        if let Some(root_name) = parse_nk_name_at(data, root_key_offset) {
            name = root_name;
            let by_name = detect_hive_type(data, &name);
            if !matches!(by_name, HiveType::Unknown) {
                hive_type = by_name;
            }
        }
    }

    Ok(RegistryHive {
        name,
        file_path: String::new(),
        hive_type,
        root_key_offset,
        last_modified,
    })
}

pub fn enumerate_registry_keys(hive: &RegistryHive) -> Result<Vec<RegKey>, ForensicError> {
    if let Some(data) = read_hive_bytes(hive) {
        let root_offset = if hive.root_key_offset > 0 {
            hive.root_key_offset
        } else {
            le_u32_at(&data, 0x24).unwrap_or(0)
        };
        if root_offset > 0 {
            let tree_keys = enumerate_registry_keys_from_tree(&data, root_offset);
            if !tree_keys.is_empty() {
                return Ok(tree_keys);
            }
        }

        let mut out = Vec::new();
        for_each_allocated_cell(&data, |rel_off, cell| {
            if let Some(key) = parse_nk_cell(cell, rel_off) {
                out.push(key);
            }
        });
        if !out.is_empty() {
            return Ok(out);
        }
    }

    // Backward-compatible fallback for existing sidecar JSON fixture format.
    let path = format!("{}.keys.json", hive.file_path);
    let Ok(data) = read_prefix(Path::new(&path), DEFAULT_BINARY_MAX_BYTES) else {
        return Ok(Vec::new());
    };
    let Ok(v) = serde_json::from_slice::<Value>(&data) else {
        return Ok(Vec::new());
    };
    let items = v.as_array().cloned().unwrap_or_default();
    Ok(items
        .into_iter()
        .map(|x| RegKey {
            name: s(&x, &["name"]),
            offset: n(&x, &["offset"]) as u32,
            parent_offset: n(&x, &["parent_offset"]) as u32,
            subkey_count: n(&x, &["subkey_count"]) as u32,
            value_count: n(&x, &["value_count"]) as u32,
            last_modified: opt_n(&x, &["last_modified"]),
        })
        .filter(|x| !x.name.is_empty() || x.offset > 0)
        .collect())
}

pub fn enumerate_key_values(
    hive: &RegistryHive,
    key_offset: u32,
) -> Result<Vec<RegValue>, ForensicError> {
    if let Some(data) = read_hive_bytes(hive) {
        let values = enumerate_key_values_from_binary(&data, key_offset)?;
        if !values.is_empty() {
            return Ok(values);
        }
    }

    // Backward-compatible fallback for existing sidecar JSON fixture format.
    let path = format!("{}.values.json", hive.file_path);
    let Ok(data) = read_prefix(Path::new(&path), DEFAULT_BINARY_MAX_BYTES) else {
        return Ok(Vec::new());
    };
    let Ok(v) = serde_json::from_slice::<Value>(&data) else {
        return Ok(Vec::new());
    };
    let items = v.as_array().cloned().unwrap_or_default();
    Ok(items
        .into_iter()
        .filter(|x| key_offset == 0 || n(x, &["key_offset", "offset"]) as u32 == key_offset)
        .map(|x| RegValue {
            name: s(&x, &["name"]),
            value_type: value_type_enum(s(&x, &["value_type", "type"])),
            data: bytes_from_value(x.get("data")),
        })
        .collect())
}

pub fn parse_registry_timestamp(data: &[u8]) -> Option<u64> {
    if data.len() < 8 {
        return None;
    }
    let filetime = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    filetime_to_unix(filetime)
}

pub fn extract_registry_security_descriptor(
    data: &[u8],
) -> Result<SecurityDescriptor, ForensicError> {
    let Ok(v) = serde_json::from_slice::<Value>(data) else {
        return Ok(SecurityDescriptor {
            owner: None,
            group: None,
            dacl: Vec::new(),
        });
    };
    let dacl = v
        .get("dacl")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|x| Ace {
                    ace_type: s(x, &["ace_type", "type"]),
                    trustee: s(x, &["trustee", "principal"]),
                    permissions: s(x, &["permissions", "access"]),
                })
                .filter(|x| !x.ace_type.is_empty() || !x.trustee.is_empty())
                .collect()
        })
        .unwrap_or_default();
    Ok(SecurityDescriptor {
        owner: v
            .get("owner")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        group: v
            .get("group")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        dacl,
    })
}

fn enumerate_key_values_from_binary(
    data: &[u8],
    key_offset: u32,
) -> Result<Vec<RegValue>, ForensicError> {
    let target_offset = if key_offset == 0 {
        le_u32_at(data, 0x24).unwrap_or(0)
    } else {
        key_offset
    };
    let Some(key_cell) = get_allocated_cell(data, target_offset) else {
        return Ok(Vec::new());
    };
    if key_cell.len() < 0x2c || &key_cell[0..2] != b"nk" {
        return Ok(Vec::new());
    }

    let value_count = le_u32_at(key_cell, 0x24).unwrap_or(0) as usize;
    let value_list_offset = le_u32_at(key_cell, 0x28).unwrap_or(0);
    if value_count == 0 {
        return Ok(Vec::new());
    }

    let Some(value_list_cell) = get_allocated_cell(data, value_list_offset) else {
        return Ok(Vec::new());
    };

    let mut out = Vec::new();
    for i in 0..value_count {
        let off = i * 4;
        if off + 4 > value_list_cell.len() {
            break;
        }
        let vk_offset = u32::from_le_bytes([
            value_list_cell[off],
            value_list_cell[off + 1],
            value_list_cell[off + 2],
            value_list_cell[off + 3],
        ]);
        let Some(vk_cell) = get_allocated_cell(data, vk_offset) else {
            continue;
        };
        if let Some(v) = parse_vk_cell(data, vk_cell) {
            out.push(v);
        }
    }

    Ok(out)
}

fn parse_vk_cell(hive_data: &[u8], cell: &[u8]) -> Option<RegValue> {
    if cell.len() < 0x14 || &cell[0..2] != b"vk" {
        return None;
    }

    let name_len = le_u16_at(cell, 0x02)? as usize;
    let data_size_raw = le_u32_at(cell, 0x04)?;
    let data_offset = le_u32_at(cell, 0x08)?;
    let reg_type = le_u32_at(cell, 0x0c)?;
    let flags = le_u16_at(cell, 0x10).unwrap_or(0);

    let name = if name_len == 0 {
        "@".to_string()
    } else if 0x14 + name_len <= cell.len() {
        decode_vk_name(&cell[0x14..0x14 + name_len], flags)
    } else {
        String::new()
    };

    let data_size = (data_size_raw & 0x7fff_ffff) as usize;
    let inline = (data_size_raw & 0x8000_0000) != 0 && data_size <= 4;
    let data = if inline {
        data_offset.to_le_bytes()[..data_size].to_vec()
    } else {
        read_vk_data(hive_data, data_offset, data_size)
    };

    Some(RegValue {
        name,
        value_type: value_type_from_u32(reg_type),
        data,
    })
}

fn enumerate_registry_keys_from_tree(data: &[u8], root_offset: u32) -> Vec<RegKey> {
    let mut out = Vec::new();
    let mut queue = std::collections::VecDeque::<u32>::new();
    let mut seen = std::collections::HashSet::<u32>::new();
    queue.push_back(root_offset);

    while let Some(offset) = queue.pop_front() {
        if !seen.insert(offset) {
            continue;
        }
        let Some(cell) = get_allocated_cell(data, offset) else {
            continue;
        };
        let Some(key) = parse_nk_cell(cell, offset) else {
            continue;
        };

        let subkey_count = le_u32_at(cell, 0x14).unwrap_or(0);
        let subkey_list_offset = le_u32_at(cell, 0x1c).unwrap_or(u32::MAX);
        if subkey_count > 0 && subkey_list_offset != u32::MAX {
            for child_offset in read_subkey_offsets_from_index(data, subkey_list_offset, 0) {
                queue.push_back(child_offset);
            }
        }

        out.push(key);
    }

    out.sort_by(|a, b| a.offset.cmp(&b.offset).then_with(|| a.name.cmp(&b.name)));
    out
}

fn read_subkey_offsets_from_index(data: &[u8], index_offset: u32, depth: usize) -> Vec<u32> {
    if depth > 8 {
        return Vec::new();
    }
    let Some(index_cell) = get_allocated_cell(data, index_offset) else {
        return Vec::new();
    };
    if index_cell.len() < 4 {
        return Vec::new();
    }

    let sig = &index_cell[0..2];
    let count = le_u16_at(index_cell, 0x02).unwrap_or(0) as usize;
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::<u32>::new();

    match sig {
        b"li" => {
            for idx in 0..count {
                let off = 0x04 + idx * 4;
                let Some(nk_offset) = le_u32_at(index_cell, off) else {
                    break;
                };
                if is_nk_cell_at(data, nk_offset) && seen.insert(nk_offset) {
                    out.push(nk_offset);
                }
            }
        }
        b"lf" | b"lh" => {
            for idx in 0..count {
                let off = 0x04 + idx * 8;
                let Some(first) = le_u32_at(index_cell, off) else {
                    break;
                };
                let Some(second) = le_u32_at(index_cell, off + 4) else {
                    break;
                };

                if is_nk_cell_at(data, first) && seen.insert(first) {
                    out.push(first);
                } else if is_nk_cell_at(data, second) && seen.insert(second) {
                    out.push(second);
                }
            }
        }
        b"ri" => {
            for idx in 0..count {
                let off = 0x04 + idx * 4;
                let Some(sub_index) = le_u32_at(index_cell, off) else {
                    break;
                };
                for nk in read_subkey_offsets_from_index(data, sub_index, depth + 1) {
                    if seen.insert(nk) {
                        out.push(nk);
                    }
                }
            }
        }
        _ => {}
    }

    out
}

fn is_nk_cell_at(data: &[u8], offset: u32) -> bool {
    matches!(
        get_allocated_cell(data, offset),
        Some(cell) if cell.len() >= 2 && &cell[0..2] == b"nk"
    )
}

fn read_vk_data(hive_data: &[u8], data_offset: u32, data_size: usize) -> Vec<u8> {
    if data_size == 0 {
        return Vec::new();
    }
    if let Some(cell_data) = get_allocated_cell(hive_data, data_offset) {
        if let Some(big_data) = read_big_data_cell(hive_data, cell_data, data_size) {
            return big_data;
        }
        let mut out = cell_data[..cell_data.len().min(data_size)].to_vec();
        out.truncate(data_size);
        return out;
    }

    let Some(abs) = hive_offset_to_abs(data_offset) else {
        return Vec::new();
    };
    if abs + data_size > hive_data.len() {
        return Vec::new();
    }
    hive_data[abs..abs + data_size].to_vec()
}

fn read_big_data_cell(hive_data: &[u8], cell_data: &[u8], data_size: usize) -> Option<Vec<u8>> {
    if cell_data.len() < 8 || &cell_data[0..2] != b"db" {
        return None;
    }
    let segment_count = le_u16_at(cell_data, 0x02)? as usize;
    let segment_list_offset = le_u32_at(cell_data, 0x04)?;
    if segment_count == 0 {
        return Some(Vec::new());
    }

    let list_cell = get_allocated_cell(hive_data, segment_list_offset)?;
    let mut out = Vec::with_capacity(data_size.min(1024 * 1024));

    for idx in 0..segment_count {
        let off = idx * 4;
        if off + 4 > list_cell.len() {
            break;
        }
        let segment_offset = u32::from_le_bytes([
            list_cell[off],
            list_cell[off + 1],
            list_cell[off + 2],
            list_cell[off + 3],
        ]);
        let Some(segment) = get_allocated_cell(hive_data, segment_offset) else {
            continue;
        };
        out.extend_from_slice(segment);
        if out.len() >= data_size {
            break;
        }
    }

    out.truncate(data_size);
    Some(out)
}

fn decode_vk_name(name_bytes: &[u8], flags: u16) -> String {
    if (flags & 0x0001) != 0 {
        String::from_utf8_lossy(name_bytes).to_string()
    } else {
        let mut units = Vec::new();
        for chunk in name_bytes.chunks(2) {
            if chunk.len() != 2 {
                break;
            }
            let u = u16::from_le_bytes([chunk[0], chunk[1]]);
            if u == 0 {
                break;
            }
            units.push(u);
        }
        String::from_utf16(&units).unwrap_or_default()
    }
}

fn for_each_allocated_cell<F: FnMut(u32, &[u8])>(data: &[u8], mut f: F) {
    if data.len() < REGF_HEADER_LEN {
        return;
    }

    let mut hbin = REGF_HEADER_LEN;
    while hbin + HBIN_HEADER_LEN <= data.len() {
        if &data[hbin..hbin + 4] != b"hbin" {
            break;
        }
        let Some(hbin_size) = le_u32_at(data, hbin + 8).map(|x| x as usize) else {
            break;
        };
        if hbin_size < HBIN_HEADER_LEN || hbin + hbin_size > data.len() {
            break;
        }

        let hbin_end = hbin + hbin_size;
        let mut cell_pos = hbin + HBIN_HEADER_LEN;
        while cell_pos + 4 <= hbin_end {
            let sz = i32::from_le_bytes([
                data[cell_pos],
                data[cell_pos + 1],
                data[cell_pos + 2],
                data[cell_pos + 3],
            ]);
            if sz == 0 {
                break;
            }

            let cell_size = sz.unsigned_abs() as usize;
            if cell_size < 4 || cell_pos + cell_size > hbin_end {
                break;
            }

            if sz < 0 {
                let rel = (cell_pos - REGF_HEADER_LEN) as u32;
                let cell = &data[cell_pos + 4..cell_pos + cell_size];
                f(rel, cell);
            }

            cell_pos += cell_size;
        }

        hbin += hbin_size;
    }
}

fn get_allocated_cell(data: &[u8], rel_offset: u32) -> Option<&[u8]> {
    let abs = hive_offset_to_abs(rel_offset)?;
    if abs + 4 > data.len() {
        return None;
    }
    let sz = i32::from_le_bytes([data[abs], data[abs + 1], data[abs + 2], data[abs + 3]]);
    if sz >= 0 {
        return None;
    }
    let cell_size = sz.unsigned_abs() as usize;
    if cell_size < 4 || abs + cell_size > data.len() {
        return None;
    }
    Some(&data[abs + 4..abs + cell_size])
}

fn parse_nk_cell(cell: &[u8], rel_offset: u32) -> Option<RegKey> {
    if cell.len() < 0x4c || &cell[0..2] != b"nk" {
        return None;
    }

    let nk_flags = le_u16_at(cell, 0x02).unwrap_or(0);
    let name_len = le_u16_at(cell, 0x48)? as usize;
    if 0x4c + name_len > cell.len() {
        return None;
    }

    let name_bytes = &cell[0x4c..0x4c + name_len];
    let name = if (nk_flags & NK_FLAG_COMP_NAME) != 0 {
        String::from_utf8_lossy(name_bytes).to_string()
    } else {
        let decoded = if looks_like_utf16le(name_bytes) {
            decode_utf16_lossy(name_bytes)
        } else {
            String::new()
        };
        if decoded.is_empty() {
            String::from_utf8_lossy(name_bytes).to_string()
        } else {
            decoded
        }
    };

    Some(RegKey {
        name,
        offset: rel_offset,
        parent_offset: le_u32_at(cell, 0x10).unwrap_or(0),
        subkey_count: le_u32_at(cell, 0x14).unwrap_or(0),
        value_count: le_u32_at(cell, 0x24).unwrap_or(0),
        last_modified: parse_registry_timestamp(cell.get(0x04..0x0c).unwrap_or(&[])),
    })
}

fn parse_nk_name_at(data: &[u8], rel_offset: u32) -> Option<String> {
    let cell = get_allocated_cell(data, rel_offset)?;
    let key = parse_nk_cell(cell, rel_offset)?;
    if key.name.is_empty() {
        return None;
    }
    Some(key.name)
}

fn hive_offset_to_abs(rel_offset: u32) -> Option<usize> {
    REGF_HEADER_LEN.checked_add(rel_offset as usize)
}

fn read_hive_bytes(hive: &RegistryHive) -> Option<Vec<u8>> {
    if hive.file_path.is_empty() {
        return None;
    }
    let path = Path::new(&hive.file_path);
    if !path.exists() {
        return None;
    }

    let len = std::fs::metadata(path).ok()?.len() as usize;
    if len == 0 {
        return None;
    }
    let limit = len.clamp(DEFAULT_BINARY_MAX_BYTES, MAX_HIVE_READ_BYTES);
    read_prefix(path, limit).ok()
}

fn detect_hive_type(data: &[u8], root_name: &str) -> HiveType {
    let root_lc = root_name.to_ascii_lowercase();
    if root_lc == "sam" || data.windows(3).any(|w| w == b"SAM") {
        return HiveType::Sam;
    }
    if root_lc == "software" || data.windows(8).any(|w| w == b"SOFTWARE") {
        return HiveType::Software;
    }
    if root_lc == "system" || data.windows(6).any(|w| w == b"SYSTEM") {
        return HiveType::System;
    }
    if root_lc == "security" || data.windows(8).any(|w| w == b"SECURITY") {
        return HiveType::Security;
    }
    if root_lc == "ntuser.dat" || root_lc == "ntuser" {
        return HiveType::Ntuser;
    }
    if root_lc == "usrclass.dat" || root_lc == "usrclass" {
        return HiveType::Usrclass;
    }
    HiveType::Unknown
}

fn value_type_from_u32(value: u32) -> RegValueType {
    match value {
        1 => RegValueType::String,
        2 => RegValueType::ExpandString,
        3 => RegValueType::Binary,
        4 => RegValueType::Dword,
        6 => RegValueType::Link,
        7 => RegValueType::MultiString,
        11 => RegValueType::Qword,
        _ => RegValueType::None,
    }
}

fn value_type_enum(value: String) -> RegValueType {
    match value.to_ascii_lowercase().as_str() {
        "string" => RegValueType::String,
        "expandstring" | "expand_string" => RegValueType::ExpandString,
        "binary" => RegValueType::Binary,
        "dword" => RegValueType::Dword,
        "qword" => RegValueType::Qword,
        "multistring" | "multi_string" => RegValueType::MultiString,
        "link" => RegValueType::Link,
        _ => RegValueType::None,
    }
}

fn bytes_from_value(value: Option<&Value>) -> Vec<u8> {
    match value {
        Some(Value::String(s)) => s.as_bytes().to_vec(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_u64)
            .filter(|x| *x <= 255)
            .map(|x| x as u8)
            .collect(),
        _ => Vec::new(),
    }
}

fn s(v: &Value, keys: &[&str]) -> String {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            return x.to_string();
        }
    }
    String::new()
}

fn n(v: &Value, keys: &[&str]) -> u64 {
    opt_n(v, keys).unwrap_or(0)
}

fn opt_n(v: &Value, keys: &[&str]) -> Option<u64> {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_u64) {
            return Some(x);
        }
        if let Some(x) = v.get(*k).and_then(Value::as_i64) {
            if x >= 0 {
                return Some(x as u64);
            }
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = x.parse::<u64>() {
                return Some(n);
            }
        }
    }
    None
}

fn decode_utf16_lossy(data: &[u8]) -> String {
    let mut units = Vec::new();
    for chunk in data.chunks(2) {
        if chunk.len() != 2 {
            break;
        }
        let u = u16::from_le_bytes([chunk[0], chunk[1]]);
        if u == 0 {
            break;
        }
        units.push(u);
    }
    String::from_utf16(&units).unwrap_or_default()
}

fn looks_like_utf16le(data: &[u8]) -> bool {
    if data.len() < 4 || !data.len().is_multiple_of(2) {
        return false;
    }
    // Typical UTF-16LE ASCII-like key names have at least one zero high-byte.
    data.chunks(2).any(|ch| ch.len() == 2 && ch[1] == 0)
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

fn filetime_to_unix(filetime: u64) -> Option<u64> {
    if filetime == 0 {
        return None;
    }
    let seconds = filetime / 10_000_000;
    if seconds < FILETIME_UNIX_EPOCH_OFFSET {
        return None;
    }
    Some(seconds - FILETIME_UNIX_EPOCH_OFFSET)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_hive() -> Vec<u8> {
        let mut data = vec![0u8; 0x3000];
        data[0..4].copy_from_slice(b"regf");
        // Last write FILETIME (2026-03-10-ish)
        let ft = (FILETIME_UNIX_EPOCH_OFFSET + 1_773_100_800u64) * 10_000_000u64;
        data[0x0c..0x14].copy_from_slice(&ft.to_le_bytes());
        // Root key cell offset (relative to first hbin data area)
        data[0x24..0x28].copy_from_slice(&0x20u32.to_le_bytes());

        // First hbin
        data[0x1000..0x1004].copy_from_slice(b"hbin");
        data[0x1008..0x100c].copy_from_slice(&0x1000u32.to_le_bytes());

        // Root NK cell at rel 0x20 (abs 0x1020)
        let nk_abs = 0x1020usize;
        let nk_size = 0x90i32;
        data[nk_abs..nk_abs + 4].copy_from_slice(&(-nk_size).to_le_bytes());
        let nk = nk_abs + 4;
        data[nk..nk + 2].copy_from_slice(b"nk");
        data[nk + 0x10..nk + 0x14].copy_from_slice(&u32::MAX.to_le_bytes()); // parent none
        data[nk + 0x14..nk + 0x18].copy_from_slice(&0u32.to_le_bytes()); // subkeys
        data[nk + 0x24..nk + 0x28].copy_from_slice(&1u32.to_le_bytes()); // value_count
        data[nk + 0x28..nk + 0x2c].copy_from_slice(&0x200u32.to_le_bytes()); // value list
        data[nk + 0x48..nk + 0x4a].copy_from_slice(&8u16.to_le_bytes()); // name len
        data[nk + 0x4c..nk + 0x54].copy_from_slice(b"SOFTWARE");

        // Value list cell (one u32 offset to vk at rel 0x300)
        let vlist_abs = 0x1200usize;
        data[vlist_abs..vlist_abs + 4].copy_from_slice(&(-8i32).to_le_bytes());
        data[vlist_abs + 4..vlist_abs + 8].copy_from_slice(&0x300u32.to_le_bytes());

        // VK cell at rel 0x300 (abs 0x1300), inline DWORD=42
        let vk_abs = 0x1300usize;
        data[vk_abs..vk_abs + 4].copy_from_slice(&(-0x30i32).to_le_bytes());
        let vk = vk_abs + 4;
        data[vk..vk + 2].copy_from_slice(b"vk");
        data[vk + 2..vk + 4].copy_from_slice(&4u16.to_le_bytes()); // name len
        data[vk + 4..vk + 8].copy_from_slice(&(0x8000_0004u32).to_le_bytes()); // inline 4 bytes
        data[vk + 8..vk + 12].copy_from_slice(&42u32.to_le_bytes()); // inline data
        data[vk + 12..vk + 16].copy_from_slice(&4u32.to_le_bytes()); // REG_DWORD
        data[vk + 16..vk + 18].copy_from_slice(&1u16.to_le_bytes()); // ascii name flag
        data[vk + 20..vk + 24].copy_from_slice(b"Test");

        data
    }

    #[test]
    fn extract_registry_security_descriptor_parses_json() {
        let data = br#"{
            "owner": "SYSTEM",
            "group": "Administrators",
            "dacl": [
                {"ace_type":"allow","trustee":"BUILTIN\\Administrators","permissions":"full"}
            ]
        }"#;
        let sd = extract_registry_security_descriptor(data).unwrap();
        assert_eq!(sd.owner.as_deref(), Some("SYSTEM"));
        assert_eq!(sd.group.as_deref(), Some("Administrators"));
        assert_eq!(sd.dacl.len(), 1);
        assert_eq!(sd.dacl[0].permissions, "full");
    }

    #[test]
    fn parse_registry_hive_reads_regf_header_and_root() {
        let hive_bytes = make_test_hive();
        let hive = parse_registry_hive(&hive_bytes).unwrap();
        assert_eq!(hive.root_key_offset, 0x20);
        assert!(hive.last_modified.is_some());
        assert_eq!(hive.name, "SOFTWARE");
        assert!(matches!(hive.hive_type, HiveType::Software));
    }

    #[test]
    fn parse_registry_timestamp_converts_filetime() {
        let ft = (FILETIME_UNIX_EPOCH_OFFSET + 1_700_000_000u64) * 10_000_000u64;
        let ts = parse_registry_timestamp(&ft.to_le_bytes()).unwrap();
        assert_eq!(ts, 1_700_000_000u64);
    }

    #[test]
    fn enumerate_binary_registry_keys_and_values() {
        let dir = tempfile::tempdir().unwrap();
        let hive_path = dir.path().join("SOFTWARE");
        std::fs::write(&hive_path, make_test_hive()).unwrap();

        let hive = RegistryHive {
            name: "SOFTWARE".to_string(),
            file_path: hive_path.display().to_string(),
            hive_type: HiveType::Software,
            root_key_offset: 0x20,
            last_modified: None,
        };

        let keys = enumerate_registry_keys(&hive).unwrap();
        assert!(keys.iter().any(|k| k.name == "SOFTWARE"));

        let values = enumerate_key_values(&hive, 0x20).unwrap();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].name, "Test");
        assert!(matches!(values[0].value_type, RegValueType::Dword));
        assert_eq!(values[0].data, 42u32.to_le_bytes().to_vec());
    }

    #[test]
    fn enumerate_key_values_uses_root_when_offset_zero() {
        let dir = tempfile::tempdir().unwrap();
        let hive_path = dir.path().join("SOFTWARE");
        std::fs::write(&hive_path, make_test_hive()).unwrap();

        let hive = RegistryHive {
            name: "SOFTWARE".to_string(),
            file_path: hive_path.display().to_string(),
            hive_type: HiveType::Software,
            root_key_offset: 0x20,
            last_modified: None,
        };

        let values = enumerate_key_values(&hive, 0).unwrap();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].name, "Test");
    }

    #[test]
    fn parse_registry_hive_handles_utf16_nk_names() {
        let mut hive = make_test_hive();
        let nk = 0x1020usize + 4usize;
        hive[nk + 0x02..nk + 0x04].copy_from_slice(&0u16.to_le_bytes()); // not compressed
        let name_units: Vec<u8> = "SOFT"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        hive[nk + 0x48..nk + 0x4a].copy_from_slice(&(name_units.len() as u16).to_le_bytes());
        hive[nk + 0x4c..nk + 0x4c + name_units.len()].copy_from_slice(&name_units);

        let parsed = parse_registry_hive(&hive).unwrap();
        assert_eq!(parsed.name, "SOFT");
    }

    #[test]
    fn enumerate_key_values_reads_big_data_db_cell() {
        let mut hive = make_test_hive();

        // Repoint root value list to a new vk with db-backed payload.
        let nk = 0x1020usize + 4usize;
        hive[nk + 0x28..nk + 0x2c].copy_from_slice(&0x240u32.to_le_bytes());

        // Value list cell at rel 0x240 -> one vk at rel 0x340
        let vlist_abs = 0x1240usize;
        hive[vlist_abs..vlist_abs + 4].copy_from_slice(&(-8i32).to_le_bytes());
        hive[vlist_abs + 4..vlist_abs + 8].copy_from_slice(&0x340u32.to_le_bytes());

        // VK at rel 0x340 (db-backed data)
        let vk_abs = 0x1340usize;
        hive[vk_abs..vk_abs + 4].copy_from_slice(&(-0x40i32).to_le_bytes());
        let vk = vk_abs + 4;
        hive[vk..vk + 2].copy_from_slice(b"vk");
        hive[vk + 2..vk + 4].copy_from_slice(&3u16.to_le_bytes()); // name len
        hive[vk + 4..vk + 8].copy_from_slice(&6u32.to_le_bytes()); // data size
        hive[vk + 8..vk + 12].copy_from_slice(&0x380u32.to_le_bytes()); // data offset -> db
        hive[vk + 12..vk + 16].copy_from_slice(&3u32.to_le_bytes()); // REG_BINARY
        hive[vk + 16..vk + 18].copy_from_slice(&1u16.to_le_bytes()); // ascii name
        hive[vk + 20..vk + 23].copy_from_slice(b"Big");

        // DB cell at rel 0x380 -> list at rel 0x3C0, one segment at rel 0x400
        let db_abs = 0x1380usize;
        hive[db_abs..db_abs + 4].copy_from_slice(&(-0x10i32).to_le_bytes());
        let db = db_abs + 4;
        hive[db..db + 2].copy_from_slice(b"db");
        hive[db + 2..db + 4].copy_from_slice(&1u16.to_le_bytes()); // one segment
        hive[db + 4..db + 8].copy_from_slice(&0x3C0u32.to_le_bytes());

        // Segment list cell
        let list_abs = 0x13C0usize;
        hive[list_abs..list_abs + 4].copy_from_slice(&(-8i32).to_le_bytes());
        hive[list_abs + 4..list_abs + 8].copy_from_slice(&0x400u32.to_le_bytes());

        // Segment cell payload
        let seg_abs = 0x1400usize;
        hive[seg_abs..seg_abs + 4].copy_from_slice(&(-12i32).to_le_bytes()); // 8 bytes payload
        hive[seg_abs + 4..seg_abs + 12].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

        let dir = tempfile::tempdir().unwrap();
        let hive_path = dir.path().join("SOFTWARE");
        std::fs::write(&hive_path, hive).unwrap();

        let hive = RegistryHive {
            name: "SOFTWARE".to_string(),
            file_path: hive_path.display().to_string(),
            hive_type: HiveType::Software,
            root_key_offset: 0x20,
            last_modified: None,
        };

        let values = enumerate_key_values(&hive, 0x20).unwrap();
        let big = values
            .iter()
            .find(|v| v.name == "Big")
            .expect("Big value missing");
        assert_eq!(big.data, vec![1, 2, 3, 4, 5, 6]);
    }

    fn add_linked_subkey_li(hive: &mut [u8], subkey_name: &str) {
        let root_nk = 0x1020usize + 4usize;
        hive[root_nk + 0x14..root_nk + 0x18].copy_from_slice(&1u32.to_le_bytes()); // subkey count
        hive[root_nk + 0x1c..root_nk + 0x20].copy_from_slice(&0x260u32.to_le_bytes()); // index

        // LI index at rel 0x260 (abs 0x1260) with one child offset -> rel 0x500
        let li_abs = 0x1260usize;
        hive[li_abs..li_abs + 4].copy_from_slice(&(-12i32).to_le_bytes());
        let li = li_abs + 4;
        hive[li..li + 2].copy_from_slice(b"li");
        hive[li + 2..li + 4].copy_from_slice(&1u16.to_le_bytes());
        hive[li + 4..li + 8].copy_from_slice(&0x500u32.to_le_bytes());

        // Child NK at rel 0x500 (abs 0x1500)
        let child_abs = 0x1500usize;
        hive[child_abs..child_abs + 4].copy_from_slice(&(-0x90i32).to_le_bytes());
        let child = child_abs + 4;
        hive[child..child + 2].copy_from_slice(b"nk");
        hive[child + 0x02..child + 0x04].copy_from_slice(&NK_FLAG_COMP_NAME.to_le_bytes());
        hive[child + 0x10..child + 0x14].copy_from_slice(&0x20u32.to_le_bytes()); // parent root
        hive[child + 0x14..child + 0x18].copy_from_slice(&0u32.to_le_bytes()); // no subkeys
        hive[child + 0x24..child + 0x28].copy_from_slice(&0u32.to_le_bytes()); // no values
        hive[child + 0x48..child + 0x4a].copy_from_slice(&(subkey_name.len() as u16).to_le_bytes());
        hive[child + 0x4c..child + 0x4c + subkey_name.len()]
            .copy_from_slice(subkey_name.as_bytes());
    }

    #[test]
    fn enumerate_registry_keys_traverses_linked_subkeys_from_root() {
        let dir = tempfile::tempdir().unwrap();
        let hive_path = dir.path().join("SOFTWARE");
        let mut hive_bytes = make_test_hive();
        add_linked_subkey_li(&mut hive_bytes, "Child");
        std::fs::write(&hive_path, hive_bytes).unwrap();

        let hive = RegistryHive {
            name: "SOFTWARE".to_string(),
            file_path: hive_path.display().to_string(),
            hive_type: HiveType::Software,
            root_key_offset: 0x20,
            last_modified: None,
        };

        let keys = enumerate_registry_keys(&hive).unwrap();
        assert!(keys.iter().any(|k| k.name == "SOFTWARE"));
        let child = keys
            .iter()
            .find(|k| k.name == "Child")
            .expect("child missing");
        assert_eq!(child.parent_offset, 0x20);
    }

    #[test]
    fn enumerate_registry_keys_supports_lf_index_format() {
        let dir = tempfile::tempdir().unwrap();
        let hive_path = dir.path().join("SOFTWARE");
        let mut hive_bytes = make_test_hive();
        add_linked_subkey_li(&mut hive_bytes, "Leaf");

        // Replace LI index with LF index entry where second u32 is child nk offset.
        let li_abs = 0x1260usize;
        hive_bytes[li_abs..li_abs + 4].copy_from_slice(&(-16i32).to_le_bytes());
        let lf = li_abs + 4;
        hive_bytes[lf..lf + 2].copy_from_slice(b"lf");
        hive_bytes[lf + 2..lf + 4].copy_from_slice(&1u16.to_le_bytes());
        hive_bytes[lf + 4..lf + 8].copy_from_slice(&0xAABB_CCDDu32.to_le_bytes()); // hash/name hint
        hive_bytes[lf + 8..lf + 12].copy_from_slice(&0x500u32.to_le_bytes()); // child nk

        std::fs::write(&hive_path, hive_bytes).unwrap();
        let hive = RegistryHive {
            name: "SOFTWARE".to_string(),
            file_path: hive_path.display().to_string(),
            hive_type: HiveType::Software,
            root_key_offset: 0x20,
            last_modified: None,
        };

        let keys = enumerate_registry_keys(&hive).unwrap();
        assert!(keys.iter().any(|k| k.name == "Leaf"));
    }
}
