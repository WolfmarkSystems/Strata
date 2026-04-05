use crate::errors::ForensicError;
use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct FontInfo {
    pub font_name: String,
    pub font_family: String,
    pub font_type: FontType,
    pub version: Option<String>,
    pub copyright: Option<String>,
    pub glyph_count: u32,
}

#[derive(Debug, Clone, Default)]
pub enum FontType {
    #[default]
    Unknown,
    TrueType,
    OpenType,
    Type1,
    Woff,
    Woff2,
}

pub fn detect_font_format(data: &[u8]) -> FontType {
    if data.len() >= 4 && &data[0..4] == b"wOFF" {
        return FontType::Woff;
    }
    if data.len() >= 4 && &data[0..4] == b"wOF2" {
        return FontType::Woff2;
    }
    if data.len() >= 4 && (&data[0..4] == b"OTTO" || &data[0..4] == b"true") {
        return FontType::OpenType;
    }
    FontType::Unknown
}

pub fn parse_font_table_directory(data: &[u8]) -> Result<Vec<FontTable>, ForensicError> {
    let Some(v) = parse_json(data) else {
        return Ok(Vec::new());
    };
    let items = v
        .get("tables")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok(items
        .into_iter()
        .map(|x| FontTable {
            tag: s(&x, &["tag"]),
            offset: n(&x, &["offset"]) as u32,
            length: n(&x, &["length"]) as u32,
        })
        .filter(|x| !x.tag.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct FontTable {
    pub tag: String,
    pub offset: u32,
    pub length: u32,
}

pub fn extract_font_names(data: &[u8]) -> Result<FontInfo, ForensicError> {
    if let Some(v) = parse_json(data) {
        let meta = v.get("font").unwrap_or(&v);
        return Ok(FontInfo {
            font_name: s(meta, &["font_name", "name"]),
            font_family: s(meta, &["font_family", "family"]),
            font_type: font_type_enum(s(meta, &["font_type", "type"])),
            version: opt_s(meta, &["version"]),
            copyright: opt_s(meta, &["copyright"]),
            glyph_count: n(meta, &["glyph_count", "glyphs"]) as u32,
        });
    }
    Ok(FontInfo {
        font_name: String::new(),
        font_family: String::new(),
        font_type: detect_font_format(data),
        version: None,
        copyright: None,
        glyph_count: 0,
    })
}

pub fn extract_font_glyph_outlines(data: &[u8], glyph_id: u16) -> Result<Vec<u8>, ForensicError> {
    let Some(v) = parse_json(data) else {
        return Ok(Vec::new());
    };
    let bytes = v
        .get("glyphs")
        .and_then(Value::as_array)
        .and_then(|items| {
            items
                .iter()
                .find(|x| n(x, &["glyph_id", "id"]) as u16 == glyph_id)
                .and_then(|x| x.get("outline"))
        })
        .map(bytes_from_value)
        .unwrap_or_default();
    Ok(bytes)
}

pub fn analyze_font_hinting(_data: &[u8]) -> Result<FontHinting, ForensicError> {
    Ok(FontHinting {
        is_hinted: false,
        hinting_algorithm: None,
    })
}

#[derive(Debug, Clone, Default)]
pub struct FontHinting {
    pub is_hinted: bool,
    pub hinting_algorithm: Option<String>,
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
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_u64) {
            return x;
        }
        if let Some(x) = v.get(*k).and_then(Value::as_i64) {
            if x >= 0 {
                return x as u64;
            }
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = x.parse::<u64>() {
                return n;
            }
        }
    }
    0
}

fn opt_s(v: &Value, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            return Some(x.to_string());
        }
    }
    None
}

fn font_type_enum(value: String) -> FontType {
    match value.to_ascii_lowercase().as_str() {
        "truetype" | "ttf" => FontType::TrueType,
        "opentype" | "otf" => FontType::OpenType,
        "type1" | "type_1" => FontType::Type1,
        "woff" => FontType::Woff,
        "woff2" => FontType::Woff2,
        _ => FontType::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_font_names_reads_json() {
        let data = br#"{
            "font": {
                "font_name": "Inter",
                "font_family": "Sans",
                "font_type": "woff2",
                "version": "1.0",
                "glyph_count": 128
            }
        }"#;
        let info = extract_font_names(data).unwrap();
        assert_eq!(info.font_name, "Inter");
        assert_eq!(info.font_family, "Sans");
        assert!(matches!(info.font_type, FontType::Woff2));
        assert_eq!(info.glyph_count, 128);
    }

    #[test]
    fn extract_font_names_falls_back_without_json() {
        let info = extract_font_names(b"wOF2....").unwrap();
        assert!(matches!(info.font_type, FontType::Woff2));
        assert_eq!(info.glyph_count, 0);
    }
}
