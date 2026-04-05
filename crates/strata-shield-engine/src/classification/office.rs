use crate::errors::ForensicError;
use serde_json::Value;
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct OfficeDocument {
    pub format: OfficeFormat,
    pub application: Option<String>,
    pub title: Option<String>,
    pub author: Option<String>,
    pub subject: Option<String>,
    pub keywords: Option<String>,
    pub created: Option<u64>,
    pub modified: Option<u64>,
    pub last_saved_by: Option<String>,
    pub revision: u32,
    pub page_count: Option<u32>,
    pub word_count: Option<u32>,
}

#[derive(Debug, Clone, Default)]
pub enum OfficeFormat {
    #[default]
    Unknown,
    Doc,
    Docx,
    Xls,
    Xlsx,
    Ppt,
    Pptx,
    Odt,
    Ods,
    Odp,
}

pub fn detect_office_format(_data: &[u8]) -> OfficeFormat {
    OfficeFormat::Unknown
}

pub fn parse_office_properties(data: &[u8]) -> Result<OfficeDocument, ForensicError> {
    let Some(v) = parse_json(data) else {
        return Ok(OfficeDocument {
            format: OfficeFormat::Unknown,
            application: None,
            title: None,
            author: None,
            subject: None,
            keywords: None,
            created: None,
            modified: None,
            last_saved_by: None,
            revision: 0,
            page_count: None,
            word_count: None,
        });
    };
    Ok(OfficeDocument {
        format: format_enum(s(&v, &["format", "file_format"])),
        application: s_opt(&v, &["application", "app"]),
        title: s_opt(&v, &["title"]),
        author: s_opt(&v, &["author"]),
        subject: s_opt(&v, &["subject"]),
        keywords: s_opt(&v, &["keywords"]),
        created: n_opt(&v, &["created", "created_time"]),
        modified: n_opt(&v, &["modified", "modified_time"]),
        last_saved_by: s_opt(&v, &["last_saved_by"]),
        revision: n(&v, &["revision"]) as u32,
        page_count: n_opt(&v, &["page_count"]).map(|x| x as u32),
        word_count: n_opt(&v, &["word_count"]).map(|x| x as u32),
    })
}

pub fn extract_office_metadata(file_path: &str) -> Result<OfficeDocument, ForensicError> {
    let Ok(data) = super::scalpel::read_prefix(
        Path::new(file_path),
        super::scalpel::DEFAULT_BINARY_MAX_BYTES,
    ) else {
        return Ok(OfficeDocument {
            format: OfficeFormat::Unknown,
            application: None,
            title: None,
            author: None,
            subject: None,
            keywords: None,
            created: None,
            modified: None,
            last_saved_by: None,
            revision: 0,
            page_count: None,
            word_count: None,
        });
    };
    parse_office_properties(&data)
}

pub fn extract_office_custom_properties(data: &[u8]) -> Result<Vec<CustomProperty>, ForensicError> {
    let Some(v) = parse_json(data) else {
        return Ok(Vec::new());
    };
    let items = v
        .get("custom_properties")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok(items
        .into_iter()
        .map(|x| CustomProperty {
            name: s(&x, &["name"]),
            value_type: s(&x, &["value_type", "type"]),
            value: s(&x, &["value"]),
        })
        .filter(|x| !x.name.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct CustomProperty {
    pub name: String,
    pub value_type: String,
    pub value: String,
}

pub fn get_office_version_history(file_path: &str) -> Result<Vec<VersionEntry>, ForensicError> {
    let Ok(data) = super::scalpel::read_prefix(
        Path::new(file_path),
        super::scalpel::DEFAULT_BINARY_MAX_BYTES,
    ) else {
        return Ok(Vec::new());
    };
    let Some(v) = parse_json(&data) else {
        return Ok(Vec::new());
    };
    let items = v
        .get("version_history")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok(items
        .into_iter()
        .map(|x| VersionEntry {
            version: n(&x, &["version"]) as u32,
            timestamp: n(&x, &["timestamp", "time"]),
            author: s(&x, &["author"]),
            comment: s_opt(&x, &["comment"]),
        })
        .filter(|x| x.version > 0 || x.timestamp > 0 || !x.author.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct VersionEntry {
    pub version: u32,
    pub timestamp: u64,
    pub author: String,
    pub comment: Option<String>,
}

pub fn extract_office_embedded_objects(
    data: &[u8],
) -> Result<Vec<OfficeEmbeddedObject>, ForensicError> {
    let Some(v) = parse_json(data) else {
        return Ok(Vec::new());
    };
    let items = v
        .get("embedded_objects")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok(items
        .into_iter()
        .map(|x| OfficeEmbeddedObject {
            name: s(&x, &["name"]),
            object_type: s(&x, &["object_type", "type"]),
            size: n(&x, &["size", "size_bytes"]),
        })
        .filter(|x| !x.name.is_empty() || x.size > 0)
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct OfficeEmbeddedObject {
    pub name: String,
    pub object_type: String,
    pub size: u64,
}

fn parse_json(data: &[u8]) -> Option<Value> {
    serde_json::from_slice::<Value>(data).ok()
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

fn n_opt(v: &Value, keys: &[&str]) -> Option<u64> {
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

fn format_enum(value: String) -> OfficeFormat {
    match value.to_ascii_lowercase().as_str() {
        "doc" => OfficeFormat::Doc,
        "docx" => OfficeFormat::Docx,
        "xls" => OfficeFormat::Xls,
        "xlsx" => OfficeFormat::Xlsx,
        "ppt" => OfficeFormat::Ppt,
        "pptx" => OfficeFormat::Pptx,
        "odt" => OfficeFormat::Odt,
        "ods" => OfficeFormat::Ods,
        "odp" => OfficeFormat::Odp,
        _ => OfficeFormat::Unknown,
    }
}
