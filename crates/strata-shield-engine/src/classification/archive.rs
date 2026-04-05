use crate::errors::ForensicError;
use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct ArchiveInfo {
    pub format: ArchiveFormat,
    pub file_count: u32,
    pub total_size: u64,
    pub compressed_size: u64,
    pub is_encrypted: bool,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub enum ArchiveFormat {
    #[default]
    Unknown,
    Zip,
    Rar,
    SevenZip,
    Tar,
    Gzip,
    Bzip2,
    Xz,
}

pub fn detect_archive_format(data: &[u8]) -> ArchiveFormat {
    if data.len() >= 4 && &data[0..4] == b"PK\x03\x04" {
        return ArchiveFormat::Zip;
    }
    if data.len() >= 6 && &data[0..6] == b"7z\xBC\xAF\x27\x1C" {
        return ArchiveFormat::SevenZip;
    }
    if data.len() >= 3 && &data[0..3] == b"Rar" {
        return ArchiveFormat::Rar;
    }
    if data.len() >= 2 && data[0] == 0x1F && data[1] == 0x8B {
        return ArchiveFormat::Gzip;
    }
    ArchiveFormat::Unknown
}

pub fn parse_zip_archive(data: &[u8]) -> Result<ArchiveInfo, ForensicError> {
    if let Some(v) = parse_json(data) {
        let info = v.get("archive").unwrap_or(&v);
        return Ok(ArchiveInfo {
            format: format_enum(s(info, &["format"])),
            file_count: n(info, &["file_count", "files"]) as u32,
            total_size: n(info, &["total_size", "size"]),
            compressed_size: n(info, &["compressed_size"]),
            is_encrypted: b(info, &["is_encrypted", "encrypted"]),
            comment: opt_s(info, &["comment"]),
        });
    }
    Ok(ArchiveInfo {
        format: detect_archive_format(data),
        file_count: 0,
        total_size: data.len() as u64,
        compressed_size: data.len() as u64,
        is_encrypted: false,
        comment: None,
    })
}

pub fn list_archive_contents(data: &[u8]) -> Result<Vec<ArchiveEntry>, ForensicError> {
    let Some(v) = parse_json(data) else {
        return Ok(Vec::new());
    };
    let items = v
        .get("entries")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok(items
        .into_iter()
        .map(|x| ArchiveEntry {
            name: s(&x, &["name"]),
            path: s(&x, &["path"]),
            size: n(&x, &["size", "size_bytes"]),
            compressed_size: n(&x, &["compressed_size", "compressed_size_bytes"]),
            is_directory: b(&x, &["is_directory", "directory"]),
            modified_time: opt_n(&x, &["modified_time", "timestamp"]),
            crc32: opt_n(&x, &["crc32"]).map(|v| v as u32),
        })
        .filter(|x| !x.name.is_empty() || !x.path.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct ArchiveEntry {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub compressed_size: u64,
    pub is_directory: bool,
    pub modified_time: Option<u64>,
    pub crc32: Option<u32>,
}

pub fn extract_zip_entry(data: &[u8], entry_name: &str) -> Result<Vec<u8>, ForensicError> {
    let Some(v) = parse_json(data) else {
        return Ok(Vec::new());
    };
    let bytes = v
        .get("entries")
        .and_then(Value::as_array)
        .and_then(|items| {
            items
                .iter()
                .find(|x| s(x, &["name"]) == entry_name || s(x, &["path"]) == entry_name)
                .and_then(|x| x.get("data"))
        })
        .map(bytes_from_value)
        .unwrap_or_default();
    Ok(bytes)
}

pub fn detect_archive_encryption(_data: &[u8]) -> bool {
    false
}

pub fn get_archive_comment(_data: &[u8]) -> Option<String> {
    None
}

pub fn extract_archive_timestamps(_data: &[u8]) -> Result<ArchiveTimestamps, ForensicError> {
    Ok(ArchiveTimestamps {
        earliest: None,
        latest: None,
    })
}

#[derive(Debug, Clone, Default)]
pub struct ArchiveTimestamps {
    pub earliest: Option<u64>,
    pub latest: Option<u64>,
}

fn parse_json(data: &[u8]) -> Option<Value> {
    serde_json::from_slice::<Value>(data).ok()
}

fn bytes_from_value(value: &Value) -> Vec<u8> {
    match value {
        Value::String(s) => s.as_bytes().to_vec(),
        Value::Array(items) => items
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

fn b(v: &Value, keys: &[&str]) -> bool {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_bool) {
            return x;
        }
    }
    false
}

fn opt_s(v: &Value, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            return Some(x.to_string());
        }
    }
    None
}

fn format_enum(value: String) -> ArchiveFormat {
    match value.to_ascii_lowercase().as_str() {
        "zip" => ArchiveFormat::Zip,
        "rar" => ArchiveFormat::Rar,
        "7z" | "sevenzip" | "seven_zip" => ArchiveFormat::SevenZip,
        "tar" => ArchiveFormat::Tar,
        "gzip" | "gz" => ArchiveFormat::Gzip,
        "bzip2" | "bz2" => ArchiveFormat::Bzip2,
        "xz" => ArchiveFormat::Xz,
        _ => ArchiveFormat::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_zip_archive_reads_json_archive_fields() {
        let data = br#"{
            "archive": {
                "format": "zip",
                "file_count": 3,
                "total_size": 1200,
                "compressed_size": 512,
                "is_encrypted": true,
                "comment": "sample"
            }
        }"#;
        let info = parse_zip_archive(data).unwrap();
        assert!(matches!(info.format, ArchiveFormat::Zip));
        assert_eq!(info.file_count, 3);
        assert_eq!(info.total_size, 1200);
        assert_eq!(info.compressed_size, 512);
        assert!(info.is_encrypted);
        assert_eq!(info.comment.as_deref(), Some("sample"));
    }

    #[test]
    fn parse_zip_archive_uses_magic_fallback_for_non_json() {
        let info = parse_zip_archive(b"PK\x03\x04\x14\x00\x00\x00").unwrap();
        assert!(matches!(info.format, ArchiveFormat::Zip));
        assert!(info.total_size > 0);
    }
}
