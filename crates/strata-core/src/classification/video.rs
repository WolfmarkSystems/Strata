use crate::errors::ForensicError;
use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct VideoMetadata {
    pub format: VideoFormat,
    pub duration_seconds: f64,
    pub width: u32,
    pub height: u32,
    pub frame_rate: Option<f64>,
    pub video_codec: Option<String>,
    pub audio_codec: Option<String>,
    pub bit_rate: Option<u32>,
    pub file_size: u64,
}

#[derive(Debug, Clone, Default)]
pub enum VideoFormat {
    #[default]
    Unknown,
    Mp4,
    Avi,
    Mkv,
    Mov,
    Wmv,
    Flv,
    WebM,
}

pub fn detect_video_format(data: &[u8]) -> VideoFormat {
    if data.len() >= 12 && data[4..8] == b"ftyp"[..] {
        return VideoFormat::Mp4;
    }
    if data.len() >= 12 && (data[8..12] == b"WEBM"[..] || data[8..12] == b"webm"[..]) {
        return VideoFormat::WebM;
    }
    if data.len() >= 4 && data[0..4] == b"RIFF"[..] {
        return VideoFormat::Avi;
    }
    if data.len() >= 4 && data[0..4] == [0x1A, 0x45, 0xDF, 0xA3] {
        return VideoFormat::Mkv;
    }
    if let Ok(v) = serde_json::from_slice::<Value>(data) {
        return format_enum(s(&v, &["format", "container"]));
    }
    VideoFormat::Unknown
}

pub fn extract_video_metadata(data: &[u8]) -> Result<VideoMetadata, ForensicError> {
    let Ok(v) = serde_json::from_slice::<Value>(data) else {
        return Ok(VideoMetadata {
            format: detect_video_format(data),
            ..VideoMetadata::default()
        });
    };
    Ok(VideoMetadata {
        format: format_enum(s(&v, &["format", "container"])),
        duration_seconds: f(&v, &["duration_seconds", "duration"]),
        width: opt_n(&v, &["width"]).unwrap_or(0) as u32,
        height: opt_n(&v, &["height"]).unwrap_or(0) as u32,
        frame_rate: f_opt(&v, &["frame_rate", "fps"]),
        video_codec: s_opt(&v, &["video_codec", "codec"]),
        audio_codec: s_opt(&v, &["audio_codec"]),
        bit_rate: opt_n(&v, &["bit_rate"]).map(|x| x as u32),
        file_size: opt_n(&v, &["file_size", "size"]).unwrap_or(0),
    })
}

pub fn extract_video_streams(data: &[u8]) -> Result<Vec<VideoStream>, ForensicError> {
    let Ok(v) = serde_json::from_slice::<Value>(data) else {
        return Ok(Vec::new());
    };
    let items = v
        .get("streams")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok(items
        .into_iter()
        .map(|x| VideoStream {
            stream_type: s(&x, &["stream_type", "type"]),
            codec: s_opt(&x, &["codec"]),
            width: opt_n(&x, &["width"]).map(|v| v as u32),
            height: opt_n(&x, &["height"]).map(|v| v as u32),
            bit_rate: opt_n(&x, &["bit_rate"]).map(|v| v as u32),
        })
        .filter(|x| !x.stream_type.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct VideoStream {
    pub stream_type: String,
    pub codec: Option<String>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub bit_rate: Option<u32>,
}

pub fn get_video_thumbnail(data: &[u8]) -> Option<Vec<u8>> {
    let v = serde_json::from_slice::<Value>(data).ok()?;
    bytes_from_value(v.get("thumbnail"))
}

pub fn extract_video_creation_software(data: &[u8]) -> Option<String> {
    let v = serde_json::from_slice::<Value>(data).ok()?;
    s_opt(&v, &["creation_software", "encoder", "software"])
}

pub fn check_video_integrity(data: &[u8]) -> Result<bool, ForensicError> {
    if data.is_empty() {
        return Ok(false);
    }
    if let Ok(v) = serde_json::from_slice::<Value>(data) {
        return Ok(v
            .get("integrity_ok")
            .and_then(Value::as_bool)
            .unwrap_or(true));
    }
    Ok(true)
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

fn f(v: &Value, keys: &[&str]) -> f64 {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_f64) {
            return x;
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = x.parse::<f64>() {
                return n;
            }
        }
    }
    0.0
}

fn f_opt(v: &Value, keys: &[&str]) -> Option<f64> {
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

fn format_enum(value: String) -> VideoFormat {
    match value.to_ascii_lowercase().as_str() {
        "mp4" => VideoFormat::Mp4,
        "avi" => VideoFormat::Avi,
        "mkv" | "matroska" => VideoFormat::Mkv,
        "mov" => VideoFormat::Mov,
        "wmv" => VideoFormat::Wmv,
        "flv" => VideoFormat::Flv,
        "webm" => VideoFormat::WebM,
        _ => VideoFormat::Unknown,
    }
}
