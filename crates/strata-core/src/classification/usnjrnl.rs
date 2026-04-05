use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsnJrnlRecord {
    pub usn: Option<u64>,
    pub file_reference: Option<u64>,
    pub parent_reference: Option<u64>,
    pub file_name: Option<String>,
    pub file_path: Option<String>,
    pub reason_raw: Option<String>,
    pub reason_flags: Vec<String>,
    pub timestamp_utc: Option<String>,
    pub timestamp_unix: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsnInputShape {
    Missing,
    Empty,
    JsonArray,
    JsonObject,
    CsvDelimited,
    LineText,
    Binary,
    Unknown,
}

impl UsnInputShape {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Empty => "empty",
            Self::JsonArray => "json-array",
            Self::JsonObject => "json-object",
            Self::CsvDelimited => "csv-delimited",
            Self::LineText => "line-text",
            Self::Binary => "binary",
            Self::Unknown => "unknown",
        }
    }
}

pub fn detect_usnjrnl_input_shape(path: &Path) -> UsnInputShape {
    if !path.exists() {
        return UsnInputShape::Missing;
    }
    let Ok(bytes) = strata_fs::read(path) else {
        return UsnInputShape::Unknown;
    };
    if bytes.is_empty() {
        return UsnInputShape::Empty;
    }
    let text = String::from_utf8_lossy(&bytes);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return UsnInputShape::Empty;
    }
    if trimmed.starts_with('[') {
        return UsnInputShape::JsonArray;
    }
    if trimmed.starts_with('{') {
        return UsnInputShape::JsonObject;
    }
    let first_line = trimmed
        .lines()
        .next()
        .unwrap_or(trimmed)
        .to_ascii_lowercase();
    if first_line.contains("usn")
        || first_line.contains("timestamp")
        || first_line.contains("file_reference")
    {
        if first_line.contains(',') || first_line.contains('|') {
            return UsnInputShape::CsvDelimited;
        }
        return UsnInputShape::LineText;
    }
    if bytes
        .iter()
        .take(256)
        .any(|b| !b.is_ascii_graphic() && !b.is_ascii_whitespace())
    {
        return UsnInputShape::Binary;
    }
    if first_line.contains(',') || first_line.contains('|') {
        return UsnInputShape::CsvDelimited;
    }
    UsnInputShape::LineText
}

pub fn parse_usnjrnl_records(data: &[u8]) -> Vec<UsnJrnlRecord> {
    if data.is_empty() {
        return Vec::new();
    }

    if let Ok(value) = serde_json::from_slice::<Value>(data) {
        let mut rows = parse_json_records(&value);
        sort_records_newest_first(&mut rows);
        return rows;
    }

    let text = String::from_utf8_lossy(data);
    let mut rows = parse_csv_records(text.as_ref());
    sort_records_newest_first(&mut rows);
    rows
}

pub fn parse_usnjrnl_records_from_path(path: &Path) -> Vec<UsnJrnlRecord> {
    let Ok(bytes) = strata_fs::read(path) else {
        return Vec::new();
    };
    let mut rows = parse_usnjrnl_records(&bytes);
    if rows.is_empty() {
        rows = parse_usnjrnl_text_fallback(path);
        sort_records_newest_first(&mut rows);
    }
    rows
}

pub fn parse_usnjrnl_text_fallback(path: &Path) -> Vec<UsnJrnlRecord> {
    let Ok(content) = strata_fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let trimmed_lc = trimmed.to_ascii_lowercase();
        if trimmed.starts_with('#')
            || trimmed_lc.starts_with("usn")
            || (trimmed_lc.contains("timestamp")
                && trimmed_lc.contains("usn")
                && !trimmed_lc.chars().any(|c| c.is_ascii_digit()))
        {
            continue;
        }
        let fields = if trimmed.contains('|') {
            trimmed
                .split('|')
                .map(|v| v.trim().to_string())
                .collect::<Vec<_>>()
        } else if trimmed.contains(',') {
            split_csv_line(trimmed)
                .into_iter()
                .map(|v| v.trim().to_string())
                .collect::<Vec<_>>()
        } else {
            vec![trimmed.to_string()]
        };
        let usn = fields
            .first()
            .and_then(|v| parse_u64_text(v))
            .or_else(|| fields.get(1).and_then(|v| parse_u64_text(v)));
        let file_path = fields
            .iter()
            .find(|v| is_likely_path_token(v))
            .map(|v| normalize_path(v));
        let file_name = derive_file_name(file_path.as_deref());
        let reason_raw = fields.iter().enumerate().find_map(|(idx, v)| {
            let token = v.trim();
            if token.is_empty() {
                return None;
            }
            let token_lc = token.to_ascii_lowercase();
            if token_lc.contains("reason") {
                return Some(token.to_string());
            }
            if token.starts_with("0x") || token.starts_with("0X") {
                return Some(token.to_string());
            }
            if idx >= 2 && parse_u64_text(token).is_some() {
                return Some(token.to_string());
            }
            let normalized = normalize_reason_token(token);
            if reason_map().iter().any(|(_, label)| *label == normalized) {
                return Some(token.to_string());
            }
            None
        });
        let reason_flags = expand_reason(reason_raw.as_deref());
        let (timestamp_utc, timestamp_unix) = fields
            .iter()
            .find_map(|v| {
                let parsed = parse_timestamp_str(Some(v));
                if parsed.1.is_some() {
                    Some(parsed)
                } else {
                    None
                }
            })
            .unwrap_or((None, None));
        out.push(UsnJrnlRecord {
            usn,
            file_reference: None,
            parent_reference: None,
            file_name,
            file_path,
            reason_raw,
            reason_flags,
            timestamp_utc,
            timestamp_unix,
        });
    }
    out
}

fn parse_json_records(value: &Value) -> Vec<UsnJrnlRecord> {
    if let Some(rows) = value.as_array() {
        return rows.iter().filter_map(parse_json_row).collect();
    }

    if let Some(obj) = value.as_object() {
        for key in ["records", "entries", "events", "items", "rows"] {
            if let Some(rows) = obj.get(key).and_then(Value::as_array) {
                return rows.iter().filter_map(parse_json_row).collect();
            }
        }
        if let Some(data_obj) = obj.get("data").and_then(Value::as_object) {
            for key in ["records", "entries", "events", "items", "rows"] {
                if let Some(rows) = data_obj.get(key).and_then(Value::as_array) {
                    return rows.iter().filter_map(parse_json_row).collect();
                }
            }
        }
        if let Some(row) = parse_json_row(value) {
            return vec![row];
        }
    }

    Vec::new()
}

fn parse_json_row(row: &Value) -> Option<UsnJrnlRecord> {
    let obj = row.as_object()?;
    let usn = get_u64(obj, &["usn", "USN", "Usn"]);
    let file_reference = get_u64(
        obj,
        &["file_reference", "file_ref", "frn", "FileReferenceNumber"],
    );
    let parent_reference = get_u64(
        obj,
        &[
            "parent_reference",
            "parent_ref",
            "parent_frn",
            "ParentFileReferenceNumber",
        ],
    );
    let mut file_name = get_string(obj, &["file_name", "FileName", "name"]);
    let mut file_path = get_string(
        obj,
        &[
            "file_path",
            "full_path",
            "fullPath",
            "fullpath",
            "path",
            "target_path",
            "TargetPath",
        ],
    );
    if let Some(path) = file_path.take() {
        file_path = Some(normalize_path(&path));
    }
    if file_name.is_none() {
        file_name = derive_file_name(file_path.as_deref());
    }
    let reason_raw = get_reason_string(
        obj,
        &[
            "reason",
            "Reason",
            "reason_flags",
            "ReasonCode",
            "reason_mask",
            "ReasonMask",
            "reasonmask",
            "usn_reason",
        ],
    );
    let reason_flags = expand_reason(reason_raw.as_deref());
    let (timestamp_utc, timestamp_unix) = parse_timestamp_value(
        obj.get("timestamp_utc")
            .or_else(|| obj.get("timestamp"))
            .or_else(|| obj.get("TimeStamp"))
            .or_else(|| obj.get("timestamp_unix"))
            .or_else(|| obj.get("time_unix"))
            .or_else(|| obj.get("occurred_utc"))
            .or_else(|| obj.get("event_time"))
            .or_else(|| obj.get("EventTime"))
            .or_else(|| obj.get("time_created"))
            .or_else(|| obj.get("time")),
    );

    Some(UsnJrnlRecord {
        usn,
        file_reference,
        parent_reference,
        file_name,
        file_path,
        reason_raw,
        reason_flags,
        timestamp_utc,
        timestamp_unix,
    })
}

fn parse_csv_records(text: &str) -> Vec<UsnJrnlRecord> {
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if lines.is_empty() {
        return Vec::new();
    }

    let header = lines.remove(0);
    let header_parts = split_csv_line(header);
    let normalized_header: Vec<String> = header_parts
        .iter()
        .map(|v| v.trim().to_ascii_lowercase())
        .collect();

    let timestamp_index = header_index(
        &normalized_header,
        &[
            "timestamp_utc",
            "timestamp",
            "time",
            "timestamp_unix",
            "time_unix",
            "event_time",
            "timecreated",
            "time_created",
        ],
    );
    let usn_index = header_index(&normalized_header, &["usn", "journal_id"]);
    let file_ref_index = header_index(
        &normalized_header,
        &[
            "file_reference",
            "filereferencenumber",
            "file_reference_number",
            "frn",
        ],
    );
    let parent_ref_index = header_index(
        &normalized_header,
        &[
            "parent_reference",
            "parentfilereferencenumber",
            "parent_frn",
        ],
    );
    let file_name_index = header_index(
        &normalized_header,
        &["file_name", "filename", "name", "file"],
    );
    let file_path_index = header_index(
        &normalized_header,
        &["file_path", "path", "full_path", "fullpath", "target_path"],
    );
    let reason_index = header_index(
        &normalized_header,
        &[
            "reason",
            "reason_flags",
            "reason_mask",
            "reasoncode",
            "usn_reason",
        ],
    );

    let mut out = Vec::new();
    for line in lines {
        let cols = split_csv_line(line);
        let reason_raw = get_col(&cols, reason_index).map(ToString::to_string);
        let reason_flags = expand_reason(reason_raw.as_deref());
        let (timestamp_utc, timestamp_unix) = parse_timestamp_str(get_col(&cols, timestamp_index));
        let mut file_name = get_col(&cols, file_name_index).map(ToString::to_string);
        let file_path = get_col(&cols, file_path_index).map(normalize_path);
        if file_name.is_none() {
            file_name = derive_file_name(file_path.as_deref());
        }
        out.push(UsnJrnlRecord {
            usn: get_col(&cols, usn_index).and_then(parse_u64_text),
            file_reference: get_col(&cols, file_ref_index).and_then(parse_u64_text),
            parent_reference: get_col(&cols, parent_ref_index).and_then(parse_u64_text),
            file_name,
            file_path,
            reason_raw,
            reason_flags,
            timestamp_utc,
            timestamp_unix,
        });
    }
    out
}

fn split_csv_line(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cell = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                if in_quotes && chars.peek() == Some(&'"') {
                    cell.push('"');
                    let _ = chars.next();
                } else {
                    in_quotes = !in_quotes;
                }
            }
            ',' if !in_quotes => {
                out.push(cell.trim().to_string());
                cell.clear();
            }
            _ => cell.push(ch),
        }
    }
    out.push(cell.trim().to_string());
    out
}

fn header_index(headers: &[String], names: &[&str]) -> Option<usize> {
    headers.iter().position(|h| names.iter().any(|n| h == n))
}

fn get_col(cols: &[String], index: Option<usize>) -> Option<&str> {
    cols.get(index?).map(|v| v.trim()).filter(|v| !v.is_empty())
}

fn get_u64(map: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .find_map(|k| map.get(*k))
        .and_then(parse_numeric_value_u64)
}

fn get_string(map: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|k| map.get(*k))
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn get_reason_string(map: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<String> {
    for key in keys {
        let Some(value) = map.get(*key) else {
            continue;
        };
        match value {
            Value::String(s) if !s.trim().is_empty() => return Some(s.trim().to_string()),
            Value::Number(n) => return Some(n.to_string()),
            _ => {}
        }
    }
    None
}

fn parse_numeric_value_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Number(n) => n.as_u64().or_else(|| n.as_i64().map(|v| v.max(0) as u64)),
        Value::String(s) => parse_u64_text(s),
        _ => None,
    }
}

fn parse_u64_text(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).ok();
    }
    trimmed.parse::<u64>().ok()
}

fn parse_timestamp_value(value: Option<&Value>) -> (Option<String>, Option<i64>) {
    match value {
        Some(Value::Number(n)) => {
            if let Some(v) = n.as_i64() {
                timestamp_from_numeric(v)
            } else if let Some(v) = n.as_u64() {
                timestamp_from_numeric(v as i64)
            } else {
                (None, None)
            }
        }
        Some(Value::String(s)) => parse_timestamp_str(Some(s)),
        _ => (None, None),
    }
}

fn parse_timestamp_str(value: Option<&str>) -> (Option<String>, Option<i64>) {
    let Some(raw) = value else {
        return (None, None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return (None, None);
    }

    if let Ok(v) = trimmed.parse::<i64>() {
        return timestamp_from_numeric(v);
    }

    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        let utc = dt.with_timezone(&Utc).to_rfc3339();
        return (Some(utc), Some(dt.timestamp()));
    }

    for format in [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y/%m/%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    ] {
        if let Ok(dt) = NaiveDateTime::parse_from_str(trimmed, format) {
            let dt = dt.and_utc();
            return (Some(dt.to_rfc3339()), Some(dt.timestamp()));
        }
    }

    (None, None)
}

fn timestamp_from_numeric(raw: i64) -> (Option<String>, Option<i64>) {
    let unix = if (116_444_736_000_000_000..400_000_000_000_000_000).contains(&raw) {
        // Windows FILETIME (100ns intervals since 1601-01-01).
        (raw / 10_000_000) - 11_644_473_600
    } else if raw > 1_000_000_000_000_000_000 {
        // Nanosecond unix timestamps.
        raw / 1_000_000_000
    } else if raw > 1_000_000_000_000_000 {
        // Microsecond unix timestamps.
        raw / 1_000_000
    } else if raw > 4_000_000_000 {
        // Millisecond unix timestamps.
        raw / 1000
    } else {
        raw
    };

    if let Some(dt) = DateTime::<Utc>::from_timestamp(unix, 0) {
        (Some(dt.to_rfc3339()), Some(unix))
    } else {
        (None, None)
    }
}

fn expand_reason(raw: Option<&str>) -> Vec<String> {
    let Some(raw_text) = raw else {
        return Vec::new();
    };
    let trimmed = raw_text.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut labels = BTreeSet::new();
    if let Some(mask) = parse_u64_text(trimmed) {
        for (bit, label) in reason_map() {
            if (mask as u32 & bit) != 0 {
                labels.insert(label.to_string());
            }
        }
    } else {
        let mut token_set = BTreeSet::new();
        for part in trimmed.split(['|', ',', ';']) {
            let token = normalize_reason_token(part);
            if !token.is_empty() {
                token_set.insert(token);
            }
        }
        for token in token_set {
            if let Some((_, label)) = reason_map()
                .iter()
                .find(|(_, label)| *label == token || format!("USN_REASON_{}", label) == token)
            {
                labels.insert((*label).to_string());
            } else {
                labels.insert(token);
            }
        }
    }

    labels.into_iter().collect()
}

fn normalize_reason_token(token: &str) -> String {
    token
        .trim()
        .trim_matches('"')
        .replace(['-', ' '], "_")
        .to_ascii_uppercase()
        .trim_start_matches("USN_REASON_")
        .to_string()
}

fn derive_file_name(path: Option<&str>) -> Option<String> {
    let path = path?;
    path.rsplit('\\')
        .find(|segment| !segment.trim().is_empty())
        .map(ToString::to_string)
}

fn is_likely_path_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed.contains('\\') || trimmed.contains('/') {
        return true;
    }
    let bytes = trimmed.as_bytes();
    bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic()
}

fn normalize_path(path: &str) -> String {
    path.trim().replace('/', "\\")
}

fn reason_map() -> &'static [(u32, &'static str)] {
    &[
        (0x00000001, "DATA_OVERWRITE"),
        (0x00000002, "DATA_EXTEND"),
        (0x00000004, "DATA_TRUNCATION"),
        (0x00000010, "NAMED_DATA_OVERWRITE"),
        (0x00000020, "NAMED_DATA_EXTEND"),
        (0x00000040, "NAMED_DATA_TRUNCATION"),
        (0x00000100, "FILE_CREATE"),
        (0x00000200, "FILE_DELETE"),
        (0x00000400, "EA_CHANGE"),
        (0x00000800, "SECURITY_CHANGE"),
        (0x00001000, "RENAME_OLD_NAME"),
        (0x00002000, "RENAME_NEW_NAME"),
        (0x00004000, "INDEXABLE_CHANGE"),
        (0x00008000, "BASIC_INFO_CHANGE"),
        (0x00010000, "HARD_LINK_CHANGE"),
        (0x00020000, "COMPRESSION_CHANGE"),
        (0x00040000, "ENCRYPTION_CHANGE"),
        (0x00080000, "OBJECT_ID_CHANGE"),
        (0x00100000, "REPARSE_POINT_CHANGE"),
        (0x00200000, "STREAM_CHANGE"),
        (0x00400000, "TRANSACTED_CHANGE"),
        (0x00800000, "INTEGRITY_CHANGE"),
        (0x80000000, "CLOSE"),
    ]
}

fn sort_records_newest_first(rows: &mut [UsnJrnlRecord]) {
    rows.sort_by(|a, b| {
        b.timestamp_unix
            .unwrap_or_default()
            .cmp(&a.timestamp_unix.unwrap_or_default())
            .then_with(|| b.usn.unwrap_or_default().cmp(&a.usn.unwrap_or_default()))
            .then_with(|| a.file_name.cmp(&b.file_name))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_usnjrnl_json_records_sorted_newest_first() {
        let raw = br#"[
            {
                "usn": 1,
                "timestamp": "2026-03-10T10:00:00Z",
                "reason": "0x00000101",
                "file_name": "a.txt",
                "file_path": "C:\\a.txt"
            },
            {
                "usn": 2,
                "timestamp_unix": 1773146400,
                "reason": "FILE_DELETE|CLOSE",
                "file_name": "b.txt",
                "file_path": "C:\\b.txt"
            }
        ]"#;
        let rows = parse_usnjrnl_records(raw);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].usn, Some(2));
        assert!(rows[0].reason_flags.iter().any(|v| v == "FILE_DELETE"));
        assert!(rows[0].reason_flags.iter().any(|v| v == "CLOSE"));
        assert_eq!(rows[1].usn, Some(1));
        assert!(rows[1].reason_flags.iter().any(|v| v == "FILE_CREATE"));
        assert!(rows[1].reason_flags.iter().any(|v| v == "DATA_OVERWRITE"));
    }

    #[test]
    fn parse_usnjrnl_csv_with_reason_mask() {
        let raw = "\
timestamp,usn,reason,file_name,file_path\n\
2026-03-10T09:00:00Z,42,0x00000003,test.txt,C:\\test.txt\n";
        let rows = parse_usnjrnl_records(raw.as_bytes());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].usn, Some(42));
        assert_eq!(rows[0].file_name.as_deref(), Some("test.txt"));
        assert!(rows[0].reason_flags.iter().any(|v| v == "DATA_OVERWRITE"));
        assert!(rows[0].reason_flags.iter().any(|v| v == "DATA_EXTEND"));
    }

    #[test]
    fn parse_usnjrnl_converts_filetime_timestamp() {
        let raw = br#"{
            "records": [
                {
                    "usn": 5,
                    "timestamp": "133860816000000000",
                    "reason": "0x00000200"
                }
            ]
        }"#;
        let rows = parse_usnjrnl_records(raw);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].timestamp_unix, Some(1741608000));
        assert!(rows[0].timestamp_utc.is_some());
        assert!(rows[0].reason_flags.iter().any(|v| v == "FILE_DELETE"));
    }

    #[test]
    fn parse_usnjrnl_json_numeric_reason_mask_expands_flags() {
        let raw = br#"{
            "records": [
                {
                    "usn": 6,
                    "timestamp_unix": 1773146401,
                    "reason_mask": 513,
                    "file_path": "C:/Temp/report.txt"
                }
            ]
        }"#;
        let rows = parse_usnjrnl_records(raw);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].file_name.as_deref(), Some("report.txt"));
        assert!(rows[0].reason_flags.iter().any(|v| v == "DATA_OVERWRITE"));
        assert!(rows[0].reason_flags.iter().any(|v| v == "FILE_DELETE"));
    }

    #[test]
    fn parse_usnjrnl_csv_supports_quoted_commas() {
        let raw = "\
timestamp,usn,reason,file_path\n\
2026-03-10T09:00:00Z,43,0x00000003,\"C:\\Users\\Analyst\\My, Folder\\test.txt\"\n";
        let rows = parse_usnjrnl_records(raw.as_bytes());
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].file_path.as_deref(),
            Some("C:\\Users\\Analyst\\My, Folder\\test.txt")
        );
        assert_eq!(rows[0].file_name.as_deref(), Some("test.txt"));
    }

    #[test]
    fn parse_usnjrnl_text_fallback_extracts_reason_mask_without_reason_label() {
        let temp = std::env::temp_dir().join(format!(
            "usn_reason_mask_{}_{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        let txt = temp.join("sample.txt");
        std::fs::write(
            &txt,
            "42|C:/Windows/System32/notepad.exe|0x00000200|2026-03-11T10:00:00Z\n",
        )
        .unwrap();
        let rows = parse_usnjrnl_records_from_path(&txt);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].reason_flags.iter().any(|v| v == "FILE_DELETE"));
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn parse_usnjrnl_timestamp_legacy_datetime_format() {
        let raw = "timestamp,usn,reason,file_name\n2026-03-10 09:00:00,90,FILE_DELETE,a.txt\n";
        let rows = parse_usnjrnl_records(raw.as_bytes());
        assert_eq!(rows.len(), 1);
        assert!(rows[0].timestamp_unix.is_some());
        assert!(rows[0].reason_flags.iter().any(|v| v == "FILE_DELETE"));
    }

    #[test]
    fn parse_usnjrnl_handles_invalid_input() {
        let rows = parse_usnjrnl_records(b"not-usn-data");
        assert!(rows.is_empty());
    }

    #[test]
    fn detect_usnjrnl_input_shape_supports_json_csv() {
        let temp = std::env::temp_dir().join(format!(
            "usn_shape_{}_{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        let json = temp.join("sample.json");
        let csv = temp.join("sample.csv");
        std::fs::write(&json, r#"[{"usn":1,"timestamp_unix":1700000000}]"#).unwrap();
        std::fs::write(
            &csv,
            "timestamp,usn,file_name\n2026-03-10T00:00:00Z,1,a.txt\n",
        )
        .unwrap();
        assert_eq!(detect_usnjrnl_input_shape(&json), UsnInputShape::JsonArray);
        assert_eq!(
            detect_usnjrnl_input_shape(&csv),
            UsnInputShape::CsvDelimited
        );
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn parse_usnjrnl_records_from_path_uses_fallback_for_line_text() {
        let temp = std::env::temp_dir().join(format!(
            "usn_fallback_{}_{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        let txt = temp.join("sample.txt");
        std::fs::write(
            &txt,
            "42|C:/Windows/System32/notepad.exe|0x00000200|2026-03-11T10:00:00Z\n",
        )
        .unwrap();
        let rows = parse_usnjrnl_records_from_path(&txt);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].usn, Some(42));
        assert_eq!(
            rows[0].file_path.as_deref(),
            Some("C:\\Windows\\System32\\notepad.exe")
        );
        assert!(rows[0].timestamp_unix.is_some());
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn parse_usnjrnl_json_supports_nested_data_rows_and_aliases() {
        let raw = br#"{
            "data": {
                "rows": [
                    {
                        "USN": "0x2A",
                        "target_path": "C:/Windows/System32/notepad.exe",
                        "ReasonMask": "0x00000200",
                        "event_time": "2026-03-10T09:00:00Z"
                    }
                ]
            }
        }"#;
        let rows = parse_usnjrnl_records(raw);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].usn, Some(42));
        assert_eq!(
            rows[0].file_path.as_deref(),
            Some("C:\\Windows\\System32\\notepad.exe")
        );
        assert!(rows[0].reason_flags.iter().any(|v| v == "FILE_DELETE"));
        assert!(rows[0].timestamp_unix.is_some());
    }

    #[test]
    fn parse_usnjrnl_normalizes_microsecond_and_nanosecond_timestamps() {
        let raw = br#"[
            {"usn": 1, "timestamp_unix": 1773146400000000, "reason": "FILE_CREATE"},
            {"usn": 2, "timestamp_unix": 1773146400000000000, "reason": "FILE_DELETE"}
        ]"#;
        let rows = parse_usnjrnl_records(raw);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].timestamp_unix, Some(1_773_146_400));
        assert_eq!(rows[1].timestamp_unix, Some(1_773_146_400));
    }

    #[test]
    fn parse_usnjrnl_text_fallback_handles_quoted_csv_path_with_comma() {
        let temp = std::env::temp_dir().join(format!(
            "usn_fallback_csv_quote_{}_{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        let txt = temp.join("sample.txt");
        std::fs::write(
            &txt,
            "timestamp,usn,reason,file_path\n2026-03-10T09:00:00Z,91,0x00000200,\"C:/Users/Analyst/My, Folder/a.txt\"\n",
        )
        .unwrap();
        let rows = parse_usnjrnl_text_fallback(&txt);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].usn, Some(91));
        assert_eq!(
            rows[0].file_path.as_deref(),
            Some("C:\\Users\\Analyst\\My, Folder\\a.txt")
        );
        let _ = std::fs::remove_dir_all(&temp);
    }
}
