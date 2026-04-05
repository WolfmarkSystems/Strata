use crate::errors::ForensicError;
use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct AudioMetadata {
    pub format: AudioFormat,
    pub duration_seconds: f64,
    pub sample_rate: Option<u32>,
    pub channels: Option<u8>,
    pub bit_rate: Option<u32>,
    pub bit_depth: Option<u8>,
    pub codec: Option<String>,
    pub file_size: u64,
}

#[derive(Debug, Clone, Default)]
pub enum AudioFormat {
    #[default]
    Unknown,
    Mp3,
    Wav,
    Flac,
    Aac,
    Ogg,
    Wma,
    M4a,
}

pub fn detect_audio_format(data: &[u8]) -> AudioFormat {
    if data.len() >= 3 && &data[0..3] == b"ID3" {
        return AudioFormat::Mp3;
    }
    if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WAVE" {
        return AudioFormat::Wav;
    }
    if data.len() >= 4 && &data[0..4] == b"fLaC" {
        return AudioFormat::Flac;
    }
    if let Ok(v) = serde_json::from_slice::<Value>(data) {
        return format_enum(s(&v, &["format", "container"]));
    }
    AudioFormat::Unknown
}

pub fn extract_audio_metadata(data: &[u8]) -> Result<AudioMetadata, ForensicError> {
    let Ok(v) = serde_json::from_slice::<Value>(data) else {
        return Ok(AudioMetadata {
            format: detect_audio_format(data),
            file_size: data.len() as u64,
            ..AudioMetadata::default()
        });
    };
    Ok(AudioMetadata {
        format: format_enum(s(&v, &["format", "container"])),
        duration_seconds: f(&v, &["duration_seconds", "duration"]),
        sample_rate: opt_n(&v, &["sample_rate"]).map(|x| x as u32),
        channels: opt_n(&v, &["channels"]).map(|x| x as u8),
        bit_rate: opt_n(&v, &["bit_rate"]).map(|x| x as u32),
        bit_depth: opt_n(&v, &["bit_depth"]).map(|x| x as u8),
        codec: s_opt(&v, &["codec"]),
        file_size: opt_n(&v, &["file_size", "size"]).unwrap_or(data.len() as u64),
    })
}

pub fn extract_audio_id3_tags(_data: &[u8]) -> Result<Id3Tags, ForensicError> {
    Ok(Id3Tags {
        title: None,
        artist: None,
        album: None,
        year: None,
        comment: None,
        genre: None,
    })
}

#[derive(Debug, Clone, Default)]
pub struct Id3Tags {
    pub title: Option<String>,
    pub artist: Option<String>,
    pub album: Option<String>,
    pub year: Option<String>,
    pub comment: Option<String>,
    pub genre: Option<String>,
}

pub fn extract_audio_lyrics(data: &[u8]) -> Option<String> {
    let v = serde_json::from_slice::<Value>(data).ok()?;
    s_opt(&v, &["lyrics"])
}

pub fn get_audio_waveform_data(data: &[u8]) -> Option<Vec<f32>> {
    let v = serde_json::from_slice::<Value>(data).ok()?;
    let items = v.get("waveform")?.as_array()?;
    Some(
        items
            .iter()
            .filter_map(|x| x.as_f64().map(|y| y as f32))
            .collect(),
    )
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

fn format_enum(value: String) -> AudioFormat {
    match value.to_ascii_lowercase().as_str() {
        "mp3" => AudioFormat::Mp3,
        "wav" => AudioFormat::Wav,
        "flac" => AudioFormat::Flac,
        "aac" => AudioFormat::Aac,
        "ogg" => AudioFormat::Ogg,
        "wma" => AudioFormat::Wma,
        "m4a" => AudioFormat::M4a,
        _ => AudioFormat::Unknown,
    }
}
