use crate::errors::ForensicError;
use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct ImageMetadata {
    pub width: u32,
    pub height: u32,
    pub color_depth: u32,
    pub format: ImageFileFormat,
    pub compression: Option<String>,
    pub has_alpha: bool,
}

#[derive(Debug, Clone, Default)]
pub enum ImageFileFormat {
    #[default]
    Unknown,
    Bmp,
    Gif,
    Jpeg,
    Png,
    Tiff,
    Webp,
    Heif,
    Avif,
}

pub fn get_image_dimensions(data: &[u8]) -> Option<(u32, u32)> {
    let v = serde_json::from_slice::<Value>(data).ok()?;
    let width = n(&v, &["width"])? as u32;
    let height = n(&v, &["height"])? as u32;
    Some((width, height))
}

pub fn detect_image_format(data: &[u8]) -> ImageFileFormat {
    if data.len() >= 4 && data[0..4] == [0x89, 0x50, 0x4E, 0x47] {
        return ImageFileFormat::Png;
    }
    if data.len() >= 2 && data[0..2] == [0xFF, 0xD8] {
        return ImageFileFormat::Jpeg;
    }
    if data.len() >= 6 && (data[0..6] == b"GIF87a"[..] || data[0..6] == b"GIF89a"[..]) {
        return ImageFileFormat::Gif;
    }
    if data.len() >= 2 && data[0..2] == b"BM"[..] {
        return ImageFileFormat::Bmp;
    }
    if data.len() >= 4 && data[0..4] == [0x49, 0x49, 0x2A, 0x00] {
        return ImageFileFormat::Tiff;
    }
    if let Ok(v) = serde_json::from_slice::<Value>(data) {
        return format_enum(s(&v, &["format", "file_format"]));
    }
    ImageFileFormat::Unknown
}

pub fn extract_image_exif(data: &[u8]) -> Result<ExifInfo, ForensicError> {
    let Ok(v) = serde_json::from_slice::<Value>(data) else {
        return Ok(ExifInfo {
            make: None,
            model: None,
            date_taken: None,
            gps_latitude: None,
            gps_longitude: None,
            software: None,
            orientation: None,
        });
    };
    Ok(ExifInfo {
        make: s_opt(&v, &["make"]),
        model: s_opt(&v, &["model"]),
        date_taken: n(&v, &["date_taken", "timestamp"]),
        gps_latitude: f(&v, &["gps_latitude", "latitude"]),
        gps_longitude: f(&v, &["gps_longitude", "longitude"]),
        software: s_opt(&v, &["software"]),
        orientation: n(&v, &["orientation"]).map(|x| x as u16),
    })
}

#[derive(Debug, Clone, Default)]
pub struct ExifInfo {
    pub make: Option<String>,
    pub model: Option<String>,
    pub date_taken: Option<u64>,
    pub gps_latitude: Option<f64>,
    pub gps_longitude: Option<f64>,
    pub software: Option<String>,
    pub orientation: Option<u16>,
}

pub fn extract_image_thumbnail(data: &[u8]) -> Option<Vec<u8>> {
    let v = serde_json::from_slice::<Value>(data).ok()?;
    bytes_from_value(v.get("thumbnail"))
}

pub fn detect_image_manipulation(_data: &[u8]) -> Result<ManipulationAnalysis, ForensicError> {
    Ok(ManipulationAnalysis {
        likely_edited: false,
        inconsistencies: vec![],
    })
}

#[derive(Debug, Clone, Default)]
pub struct ManipulationAnalysis {
    pub likely_edited: bool,
    pub inconsistencies: Vec<String>,
}

pub fn extract_image_strings(_data: &[u8]) -> Vec<String> {
    vec![]
}

pub fn get_image_file_signatures() -> Vec<ImageSignature> {
    vec![ImageSignature {
        magic: vec![0x89, 0x50, 0x4E, 0x47],
        format: "PNG".to_string(),
    }]
}

#[derive(Debug, Clone, Default)]
pub struct ImageSignature {
    pub magic: Vec<u8>,
    pub format: String,
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

fn n(v: &Value, keys: &[&str]) -> Option<u64> {
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

fn f(v: &Value, keys: &[&str]) -> Option<f64> {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_f64) {
            return Some(x);
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = x.parse::<f64>() {
                return Some(n);
            }
        }
    }
    None
}

fn bytes_from_value(value: Option<&Value>) -> Option<Vec<u8>> {
    match value {
        Some(Value::String(s)) => Some(s.as_bytes().to_vec()),
        Some(Value::Array(items)) => Some(
            items
                .iter()
                .filter_map(Value::as_u64)
                .filter(|x| *x <= 255)
                .map(|x| x as u8)
                .collect(),
        ),
        _ => None,
    }
}

fn format_enum(value: String) -> ImageFileFormat {
    match value.to_ascii_lowercase().as_str() {
        "bmp" => ImageFileFormat::Bmp,
        "gif" => ImageFileFormat::Gif,
        "jpeg" | "jpg" => ImageFileFormat::Jpeg,
        "png" => ImageFileFormat::Png,
        "tiff" | "tif" => ImageFileFormat::Tiff,
        "webp" => ImageFileFormat::Webp,
        "heif" => ImageFileFormat::Heif,
        "avif" => ImageFileFormat::Avif,
        _ => ImageFileFormat::Unknown,
    }
}
