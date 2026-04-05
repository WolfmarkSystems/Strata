use crate::errors::ForensicError;
use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct PdfDocument {
    pub version: String,
    pub title: Option<String>,
    pub author: Option<String>,
    pub subject: Option<String>,
    pub creator: Option<String>,
    pub producer: Option<String>,
    pub creation_date: Option<u64>,
    pub modification_date: Option<u64>,
    pub page_count: u32,
    pub encrypted: bool,
    pub permissions: PdfPermissions,
}

#[derive(Debug, Clone, Default)]
pub struct PdfPermissions {
    pub print: bool,
    pub modify: bool,
    pub copy: bool,
    pub annotate: bool,
}

pub fn parse_pdf_header(data: &[u8]) -> Result<PdfDocument, ForensicError> {
    if let Some(v) = parse_json(data) {
        let meta = v.get("metadata").unwrap_or(&v);
        let perms = v.get("permissions").or_else(|| meta.get("permissions"));
        return Ok(PdfDocument {
            version: s(meta, &["version"]),
            title: s_opt(meta, &["title"]),
            author: s_opt(meta, &["author"]),
            subject: s_opt(meta, &["subject"]),
            creator: s_opt(meta, &["creator"]),
            producer: s_opt(meta, &["producer"]),
            creation_date: opt_n(meta, &["creation_date", "created"]),
            modification_date: opt_n(meta, &["modification_date", "modified"]),
            page_count: n(meta, &["page_count", "pages"]) as u32,
            encrypted: v
                .get("encrypted")
                .and_then(Value::as_bool)
                .unwrap_or_else(|| detect_pdf_encryption(data)),
            permissions: PdfPermissions {
                print: perms
                    .and_then(|x| x.get("print"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                modify: perms
                    .and_then(|x| x.get("modify"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                copy: perms
                    .and_then(|x| x.get("copy"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                annotate: perms
                    .and_then(|x| x.get("annotate"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            },
        });
    }
    Ok(PdfDocument {
        version: String::new(),
        encrypted: detect_pdf_encryption(data),
        ..PdfDocument::default()
    })
}

pub fn extract_pdf_metadata(data: &[u8]) -> Result<PdfMetadata, ForensicError> {
    let Some(v) = parse_json(data) else {
        return Ok(PdfMetadata {
            title: None,
            author: None,
            subject: None,
            keywords: None,
            creator: None,
            producer: None,
            creation_date: None,
            modification_date: None,
        });
    };
    let meta = v.get("metadata").unwrap_or(&v);
    Ok(PdfMetadata {
        title: s_opt(meta, &["title"]),
        author: s_opt(meta, &["author"]),
        subject: s_opt(meta, &["subject"]),
        keywords: s_opt(meta, &["keywords"]),
        creator: s_opt(meta, &["creator"]),
        producer: s_opt(meta, &["producer"]),
        creation_date: opt_n(meta, &["creation_date", "created"]),
        modification_date: opt_n(meta, &["modification_date", "modified"]),
    })
}

#[derive(Debug, Clone, Default)]
pub struct PdfMetadata {
    pub title: Option<String>,
    pub author: Option<String>,
    pub subject: Option<String>,
    pub keywords: Option<String>,
    pub creator: Option<String>,
    pub producer: Option<String>,
    pub creation_date: Option<u64>,
    pub modification_date: Option<u64>,
}

pub fn extract_pdf_objects(data: &[u8]) -> Result<Vec<PdfObject>, ForensicError> {
    let Some(v) = parse_json(data) else {
        return Ok(Vec::new());
    };
    let items = v
        .get("objects")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok(items
        .into_iter()
        .map(|x| PdfObject {
            id: n(&x, &["id"]) as u32,
            generation: n(&x, &["generation", "gen"]) as u32,
            object_type: s(&x, &["object_type", "type"]),
            data: bytes_from_value(x.get("data")),
        })
        .filter(|x| x.id > 0 || !x.object_type.is_empty() || !x.data.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct PdfObject {
    pub id: u32,
    pub generation: u32,
    pub object_type: String,
    pub data: Vec<u8>,
}

pub fn detect_pdf_encryption(data: &[u8]) -> bool {
    data.len() > 4 && String::from_utf8_lossy(&data[0..5]).contains("Encrypt")
}

pub fn extract_pdf_outlines(data: &[u8]) -> Result<Vec<PdfOutline>, ForensicError> {
    let Some(v) = parse_json(data) else {
        return Ok(Vec::new());
    };
    let items = v
        .get("outlines")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok(items
        .into_iter()
        .map(|x| PdfOutline {
            title: s(&x, &["title"]),
            page: n(&x, &["page"]) as u32,
            level: n(&x, &["level"]) as u32,
        })
        .filter(|x| !x.title.is_empty() || x.page > 0)
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct PdfOutline {
    pub title: String,
    pub page: u32,
    pub level: u32,
}

pub fn extract_pdf_embedded_files(data: &[u8]) -> Result<Vec<EmbeddedFile>, ForensicError> {
    let Some(v) = parse_json(data) else {
        return Ok(Vec::new());
    };
    let items = v
        .get("embedded_files")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok(items
        .into_iter()
        .map(|x| EmbeddedFile {
            name: s(&x, &["name"]),
            size: n(&x, &["size", "size_bytes"]),
            creation_date: opt_n(&x, &["creation_date", "created"]),
            modification_date: opt_n(&x, &["modification_date", "modified"]),
        })
        .filter(|x| !x.name.is_empty() || x.size > 0)
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct EmbeddedFile {
    pub name: String,
    pub size: u64,
    pub creation_date: Option<u64>,
    pub modification_date: Option<u64>,
}

fn parse_json(data: &[u8]) -> Option<Value> {
    serde_json::from_slice::<Value>(data).ok()
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
    fn extract_pdf_metadata_reads_json() {
        let data = br#"{
            "metadata": {
                "title": "Report",
                "author": "Analyst",
                "creation_date": 1700000000
            }
        }"#;
        let meta = extract_pdf_metadata(data).unwrap();
        assert_eq!(meta.title.as_deref(), Some("Report"));
        assert_eq!(meta.author.as_deref(), Some("Analyst"));
        assert_eq!(meta.creation_date, Some(1700000000));
    }

    #[test]
    fn extract_pdf_metadata_invalid_json_returns_empty_metadata() {
        let meta = extract_pdf_metadata(b"%PDF-1.7").unwrap();
        assert!(meta.title.is_none());
        assert!(meta.author.is_none());
        assert!(meta.creation_date.is_none());
    }
}
