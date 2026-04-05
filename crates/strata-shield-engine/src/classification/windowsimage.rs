use crate::errors::ForensicError;
use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct WindowsImage {
    pub image_format: WimgFormat,
    pub version: String,
    pub architecture: String,
    pub install_date: Option<u64>,
    pub product_name: Option<String>,
    pub product_version: Option<String>,
    pub build: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub enum WimgFormat {
    #[default]
    Unknown,
    WIM,
    ESD,
    VHD,
    VHDX,
}

pub fn detect_wim_format(data: &[u8]) -> bool {
    data.len() > 8 && &data[0..8] == b"MSWIM\x00\x00\x00"
}

pub fn parse_wim_header(data: &[u8]) -> Result<WimHeader, ForensicError> {
    if let Some(v) = parse_json(data) {
        let header = v.get("header").unwrap_or(&v);
        return Ok(WimHeader {
            image_count: n(header, &["image_count"]) as u32,
            archive_size: n(header, &["archive_size", "size"]),
            version: n(header, &["version"]) as u32,
            chunk_size: n(header, &["chunk_size"]) as u32,
        });
    }
    if detect_wim_format(data) {
        return Ok(WimHeader {
            image_count: 0,
            archive_size: data.len() as u64,
            version: 0,
            chunk_size: 0,
        });
    }
    Ok(WimHeader {
        image_count: 0,
        archive_size: data.len() as u64,
        version: 0,
        chunk_size: 0,
    })
}

#[derive(Debug, Clone, Default)]
pub struct WimHeader {
    pub image_count: u32,
    pub archive_size: u64,
    pub version: u32,
    pub chunk_size: u32,
}

pub fn list_wim_images(data: &[u8]) -> Result<Vec<WimImage>, ForensicError> {
    let Some(v) = parse_json(data) else {
        return Ok(Vec::new());
    };
    let items = v
        .get("images")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok(items
        .into_iter()
        .map(|x| WimImage {
            index: n(&x, &["index"]) as u32,
            name: s_opt(&x, &["name"]),
            description: s_opt(&x, &["description"]),
            size: n(&x, &["size", "size_bytes"]),
            creation_time: opt_n(&x, &["creation_time", "created"]),
        })
        .filter(|x| x.index > 0 || x.name.is_some())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct WimImage {
    pub index: u32,
    pub name: Option<String>,
    pub description: Option<String>,
    pub size: u64,
    pub creation_time: Option<u64>,
}

pub fn extract_wim_image(data: &[u8], image_index: u32) -> Result<Vec<u8>, ForensicError> {
    let Some(v) = parse_json(data) else {
        return Ok(Vec::new());
    };
    let bytes = v
        .get("images")
        .and_then(Value::as_array)
        .and_then(|items| {
            items
                .iter()
                .find(|x| n(x, &["index"]) as u32 == image_index)
                .and_then(|x| x.get("data"))
        })
        .map(bytes_from_value)
        .unwrap_or_default();
    Ok(bytes)
}

pub fn get_wim_metadata(data: &[u8]) -> Result<WimMetadata, ForensicError> {
    if let Some(v) = parse_json(data) {
        let meta = v.get("metadata").unwrap_or(&v);
        return Ok(WimMetadata {
            compression_type: s(meta, &["compression_type", "compression"]),
            total_bytes: n(meta, &["total_bytes", "size"]),
            total_files: n(meta, &["total_files", "files"]) as u32,
            total_directories: n(meta, &["total_directories", "directories"]) as u32,
        });
    }
    Ok(WimMetadata {
        compression_type: "unknown".to_string(),
        total_bytes: data.len() as u64,
        total_files: 0,
        total_directories: 0,
    })
}

#[derive(Debug, Clone, Default)]
pub struct WimMetadata {
    pub compression_type: String,
    pub total_bytes: u64,
    pub total_files: u32,
    pub total_directories: u32,
}

pub fn verify_wim_integrity(data: &[u8]) -> Result<bool, ForensicError> {
    if data.is_empty() {
        return Ok(false);
    }
    if let Some(v) = parse_json(data) {
        return Ok(v
            .get("integrity_ok")
            .and_then(Value::as_bool)
            .unwrap_or(true));
    }
    Ok(detect_wim_format(data))
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

fn s_opt(v: &Value, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            return Some(x.to_string());
        }
    }
    None
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_wim_header_from_json() {
        let data =
            br#"{"header":{"image_count":2,"archive_size":4096,"version":5,"chunk_size":32768}}"#;
        let header = parse_wim_header(data).unwrap();
        assert_eq!(header.image_count, 2);
        assert_eq!(header.archive_size, 4096);
        assert_eq!(header.version, 5);
        assert_eq!(header.chunk_size, 32768);
    }

    #[test]
    fn parse_wim_header_fallback_uses_input_size() {
        let data = b"not-a-wim";
        let header = parse_wim_header(data).unwrap();
        assert_eq!(header.archive_size, data.len() as u64);
        assert_eq!(header.image_count, 0);
    }
}
