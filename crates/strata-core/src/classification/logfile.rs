use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NtfsLogFileSignal {
    pub offset: u64,
    pub signal: String,
    pub context: String,
    pub timestamp_unix: Option<i64>,
    pub timestamp_utc: Option<String>,
    pub sid: Option<String>,
    pub user: Option<String>,
    pub device: Option<String>,
    pub process_path: Option<String>,
    pub source_module: Option<String>,
    pub dedupe_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtfsLogFileInputShape {
    Missing,
    Empty,
    BinaryRaw,
    JsonArray,
    JsonObject,
    LineText,
    Unknown,
}

impl NtfsLogFileInputShape {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Empty => "empty",
            Self::BinaryRaw => "binary-raw",
            Self::JsonArray => "json-array",
            Self::JsonObject => "json-object",
            Self::LineText => "line-text",
            Self::Unknown => "unknown",
        }
    }
}

pub fn detect_ntfs_logfile_input_shape(path: &Path) -> NtfsLogFileInputShape {
    if !path.exists() {
        return NtfsLogFileInputShape::Missing;
    }
    let Ok(bytes) = strata_fs::read(path) else {
        return NtfsLogFileInputShape::Unknown;
    };
    if bytes.is_empty() {
        return NtfsLogFileInputShape::Empty;
    }
    let text = String::from_utf8_lossy(&bytes);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return NtfsLogFileInputShape::Empty;
    }
    if trimmed.starts_with('[') {
        return NtfsLogFileInputShape::JsonArray;
    }
    if trimmed.starts_with('{') {
        return NtfsLogFileInputShape::JsonObject;
    }
    if trimmed
        .lines()
        .next()
        .unwrap_or(trimmed)
        .to_ascii_lowercase()
        .contains("signal")
    {
        return NtfsLogFileInputShape::LineText;
    }
    if bytes
        .iter()
        .take(512)
        .any(|b| !b.is_ascii_graphic() && !b.is_ascii_whitespace())
    {
        return NtfsLogFileInputShape::BinaryRaw;
    }
    NtfsLogFileInputShape::LineText
}

pub fn parse_ntfs_logfile_signals(data: &[u8], max_signals: usize) -> Vec<NtfsLogFileSignal> {
    if data.is_empty() || max_signals == 0 {
        return Vec::new();
    }

    if let Ok(value) = serde_json::from_slice::<Value>(data) {
        let mut rows = parse_json_signals(&value);
        rows.sort_by(|a, b| {
            a.offset
                .cmp(&b.offset)
                .then_with(|| a.signal.cmp(&b.signal))
        });
        rows.truncate(max_signals);
        return rows;
    }

    let mut seen = BTreeSet::<(String, String)>::new();
    let mut out = Vec::new();

    for (offset, text) in extract_candidate_strings(data) {
        let lower = text.to_ascii_lowercase();
        for (needle, signal) in keyword_map() {
            if lower.contains(needle) {
                let key = ((*signal).to_string(), text.clone());
                if seen.insert(key) {
                    out.push(NtfsLogFileSignal {
                        offset,
                        signal: (*signal).to_string(),
                        context: text.clone(),
                        timestamp_unix: None,
                        timestamp_utc: None,
                        sid: None,
                        user: None,
                        device: None,
                        process_path: None,
                        source_module: Some("logfile-keyword-scan".to_string()),
                        dedupe_reason: None,
                    });
                }
            }
        }
    }

    out.sort_by(|a, b| {
        a.offset
            .cmp(&b.offset)
            .then_with(|| a.signal.cmp(&b.signal))
    });
    out.truncate(max_signals);
    out
}

pub fn parse_ntfs_logfile_signals_from_path(
    path: &Path,
    max_signals: usize,
) -> Vec<NtfsLogFileSignal> {
    if !path.exists() || max_signals == 0 {
        return Vec::new();
    }

    let Ok(raw) = strata_fs::read(path) else {
        return Vec::new();
    };
    let mut rows = parse_ntfs_logfile_signals(&raw, max_signals);
    if rows.is_empty() {
        rows = parse_ntfs_logfile_text_fallback(path, max_signals);
    }
    rows
}

pub fn parse_ntfs_logfile_text_fallback(path: &Path, max_signals: usize) -> Vec<NtfsLogFileSignal> {
    if !path.exists() || max_signals == 0 {
        return Vec::new();
    }
    let Ok(content) = strata_fs::read_to_string(path) else {
        return Vec::new();
    };

    let mut out: Vec<NtfsLogFileSignal> = Vec::new();
    let mut seen = BTreeSet::<String>::new();
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let parts = split_line(trimmed);
        let signal = parts
            .get(1)
            .map(|v| (*v).to_string())
            .unwrap_or_else(|| infer_signal_from_text(trimmed));
        if signal.is_empty() {
            continue;
        }

        let timestamp_utc = parts
            .first()
            .and_then(|v| normalize_timestamp_text(v).map(|x| x.1));
        let timestamp_unix = parts
            .first()
            .and_then(|v| normalize_timestamp_text(v).map(|x| x.0));
        let context = parts.get(2).copied().unwrap_or(trimmed).to_string();
        let process_path = parts
            .iter()
            .find_map(|p| executable_path_from_text(p).map(|v| v.replace('/', "\\")));
        let sid = parts
            .iter()
            .find_map(|p| sid_from_text(p).map(ToString::to_string));
        let sid = sid.or_else(|| {
            parts
                .iter()
                .find_map(|p| value_from_keyed_fragment(p, &["sid", "user_sid", "userid"]))
        });
        let user = parts.iter().find_map(|p| {
            value_from_keyed_fragment(
                p,
                &[
                    "user",
                    "username",
                    "account",
                    "subjectuser",
                    "subject_user_name",
                    "targetuser",
                    "target_user_name",
                ],
            )
        });
        let device = parts.iter().find_map(|p| {
            value_from_keyed_fragment(
                p,
                &[
                    "device",
                    "computer",
                    "host",
                    "workstation",
                    "workstationname",
                ],
            )
        });
        let process_path = process_path.or_else(|| {
            parts
                .iter()
                .find_map(|p| {
                    value_from_keyed_fragment(
                        p,
                        &[
                            "process",
                            "processname",
                            "image",
                            "imagepath",
                            "path",
                            "targetfilename",
                        ],
                    )
                })
                .map(|v| v.replace('/', "\\"))
        });
        let key = format!(
            "{}|{}|{}|{}|{}",
            idx,
            signal,
            context,
            timestamp_unix
                .map(|v| v.to_string())
                .unwrap_or_else(|| "null".to_string()),
            process_path.clone().unwrap_or_default()
        );
        if !seen.insert(key) {
            continue;
        }

        out.push(NtfsLogFileSignal {
            offset: idx as u64,
            signal,
            context,
            timestamp_unix,
            timestamp_utc,
            sid,
            user,
            device,
            process_path,
            source_module: Some("logfile-text-fallback".to_string()),
            dedupe_reason: Some("line-index+signal+context+timestamp+process".to_string()),
        });
    }

    out.sort_by(|a, b| {
        b.timestamp_unix
            .is_some()
            .cmp(&a.timestamp_unix.is_some())
            .then_with(|| {
                b.timestamp_unix
                    .unwrap_or_default()
                    .cmp(&a.timestamp_unix.unwrap_or_default())
            })
            .then_with(|| a.offset.cmp(&b.offset))
            .then_with(|| a.signal.cmp(&b.signal))
    });
    out.truncate(max_signals);
    out
}

fn parse_json_signals(value: &Value) -> Vec<NtfsLogFileSignal> {
    if let Some(arr) = value.as_array() {
        return parse_json_signal_rows(arr);
    }
    if let Some(obj) = value.as_object() {
        if let Some(rows) = obj
            .get("signals")
            .or_else(|| obj.get("events"))
            .and_then(Value::as_array)
        {
            return parse_json_signal_rows(rows);
        }
    }
    Vec::new()
}

fn parse_json_signal_rows(rows: &[Value]) -> Vec<NtfsLogFileSignal> {
    rows.iter()
        .filter_map(|row| {
            let signal = row
                .get("signal")
                .or_else(|| row.get("event_type"))
                .and_then(Value::as_str)?;
            let context = row
                .get("context")
                .or_else(|| row.get("summary"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let offset = row
                .get("offset")
                .and_then(Value::as_u64)
                .or_else(|| {
                    row.get("offset")
                        .and_then(Value::as_i64)
                        .map(|v| v.max(0) as u64)
                })
                .unwrap_or(0);
            let timestamp_unix = row
                .get("timestamp_unix")
                .and_then(Value::as_i64)
                .or_else(|| {
                    row.get("timestamp_unix")
                        .and_then(Value::as_str)
                        .and_then(|v| normalize_timestamp_text(v).map(|x| x.0))
                })
                .or_else(|| row.get("timestamp").and_then(Value::as_i64))
                .or_else(|| {
                    row.get("timestamp")
                        .and_then(Value::as_str)
                        .and_then(|v| normalize_timestamp_text(v).map(|x| x.0))
                })
                .or_else(|| {
                    row.get("timestamp_utc")
                        .or_else(|| row.get("timestamp"))
                        .and_then(Value::as_str)
                        .and_then(|v| normalize_timestamp_text(v).map(|x| x.0))
                });
            let timestamp_utc = timestamp_unix.map(unix_to_rfc3339).or_else(|| {
                row.get("timestamp_utc")
                    .or_else(|| row.get("timestamp"))
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
            });
            Some(NtfsLogFileSignal {
                offset,
                signal: signal.to_string(),
                context,
                timestamp_unix,
                timestamp_utc,
                sid: row
                    .get("sid")
                    .or_else(|| row.get("user_sid"))
                    .and_then(Value::as_str)
                    .map(ToString::to_string),
                user: row
                    .get("user")
                    .or_else(|| row.get("actor"))
                    .or_else(|| row.get("username"))
                    .or_else(|| row.get("subject_user_name"))
                    .or_else(|| row.get("target_user_name"))
                    .and_then(Value::as_str)
                    .map(ToString::to_string),
                device: row
                    .get("device")
                    .or_else(|| row.get("computer"))
                    .or_else(|| row.get("host"))
                    .or_else(|| row.get("workstation"))
                    .and_then(Value::as_str)
                    .map(ToString::to_string),
                process_path: row
                    .get("process_path")
                    .or_else(|| row.get("image"))
                    .or_else(|| row.get("image_path"))
                    .or_else(|| row.get("process"))
                    .or_else(|| row.get("path"))
                    .and_then(Value::as_str)
                    .map(|v| v.replace('/', "\\")),
                source_module: row
                    .get("source_module")
                    .and_then(Value::as_str)
                    .map(ToString::to_string),
                dedupe_reason: None,
            })
        })
        .collect()
}

fn split_line(value: &str) -> Vec<&str> {
    if value.contains('|') {
        value.split('|').map(|v| v.trim()).collect()
    } else if value.contains('\t') {
        value.split('\t').map(|v| v.trim()).collect()
    } else if value.contains(',') {
        value.split(',').map(|v| v.trim()).collect()
    } else {
        vec![value.trim()]
    }
}

fn infer_signal_from_text(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    for (needle, signal) in keyword_map() {
        if lower.contains(needle) {
            return (*signal).to_string();
        }
    }
    String::new()
}

fn unix_to_rfc3339(ts: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| ts.to_string())
}

fn normalize_timestamp_text(value: &str) -> Option<(i64, String)> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(ts) = trimmed.parse::<i64>() {
        if trimmed.len() >= 16 && ts >= 116_444_736_000_000_000 {
            let unix = ts / 10_000_000 - 11_644_473_600;
            return Some((unix, unix_to_rfc3339(unix)));
        }
        if trimmed.len() == 13 && ts > 1_000_000_000_000 {
            let unix = ts / 1000;
            return Some((unix, unix_to_rfc3339(unix)));
        }
        return Some((ts, unix_to_rfc3339(ts)));
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(trimmed) {
        let ts = dt.timestamp();
        return Some((ts, unix_to_rfc3339(ts)));
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S") {
        let dt = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(naive, chrono::Utc);
        let ts = dt.timestamp();
        return Some((ts, unix_to_rfc3339(ts)));
    }
    None
}

fn sid_from_text(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.starts_with("S-1-") {
        Some(trimmed)
    } else {
        None
    }
}

fn value_from_keyed_fragment(fragment: &str, keys: &[&str]) -> Option<String> {
    let trimmed = fragment.trim().trim_matches('"');
    let split_at = trimmed.find('=').or_else(|| trimmed.find(':'))?;
    let key = trimmed[..split_at]
        .trim()
        .trim_matches('"')
        .replace([' ', '-'], "_")
        .to_ascii_lowercase();
    if !keys
        .iter()
        .any(|candidate| key == candidate.to_ascii_lowercase())
    {
        return None;
    }
    let value = trimmed[split_at + 1..].trim().trim_matches('"').to_string();
    (!value.is_empty()).then_some(value)
}

fn executable_path_from_text(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    let candidate = if let Some(eq) = trimmed.find('=') {
        trimmed.get(eq + 1..).map(str::trim).unwrap_or(trimmed)
    } else if let Some(colon) = trimmed.find(':') {
        if colon == 1 {
            trimmed
        } else {
            trimmed.get(colon + 1..).map(str::trim).unwrap_or(trimmed)
        }
    } else {
        trimmed
    };
    let lower = candidate.to_ascii_lowercase();
    if (lower.ends_with(".exe")
        || lower.ends_with(".dll")
        || lower.ends_with(".sys")
        || lower.ends_with(".bat")
        || lower.ends_with(".cmd"))
        && (candidate.contains('\\') || candidate.contains('/'))
    {
        Some(candidate)
    } else {
        None
    }
}

fn extract_candidate_strings(data: &[u8]) -> Vec<(u64, String)> {
    let mut out = Vec::new();
    out.extend(extract_ascii_strings(data, 8));
    out.extend(extract_utf16le_strings(data, 8));
    out
}

fn extract_ascii_strings(data: &[u8], min_len: usize) -> Vec<(u64, String)> {
    let mut out = Vec::new();
    let mut start = None::<usize>;
    for (index, byte) in data.iter().enumerate() {
        if byte.is_ascii_graphic() || *byte == b' ' {
            if start.is_none() {
                start = Some(index);
            }
        } else if let Some(begin) = start.take() {
            if index.saturating_sub(begin) >= min_len {
                out.push((
                    begin as u64,
                    String::from_utf8_lossy(&data[begin..index]).to_string(),
                ));
            }
        }
    }
    if let Some(begin) = start {
        if data.len().saturating_sub(begin) >= min_len {
            out.push((
                begin as u64,
                String::from_utf8_lossy(&data[begin..]).to_string(),
            ));
        }
    }
    out
}

fn extract_utf16le_strings(data: &[u8], min_len: usize) -> Vec<(u64, String)> {
    let mut out = Vec::new();
    let mut index = 0usize;
    while index + 2 <= data.len() {
        let mut chars = Vec::new();
        let start = index;
        while index + 2 <= data.len() {
            let unit = u16::from_le_bytes([data[index], data[index + 1]]);
            if unit == 0 {
                index += 2;
                break;
            }
            if !(0x20..=0x7E).contains(&unit) {
                chars.clear();
                index += 2;
                break;
            }
            chars.push(unit);
            index += 2;
        }
        if chars.len() >= min_len {
            if let Ok(text) = String::from_utf16(&chars) {
                out.push((start as u64, text));
            }
        }
        if index == start {
            index += 2;
        }
    }
    out
}

fn keyword_map() -> &'static [(&'static str, &'static str)] {
    &[
        ("$mft", "mft_reference"),
        ("$usnjrnl", "usn_reference"),
        ("file_create", "file_create"),
        ("createfile", "file_create"),
        ("file_delete", "file_delete"),
        ("delete", "file_delete"),
        ("rename", "rename"),
        ("setsize", "set_size"),
        ("truncate", "set_size"),
        ("$extend", "metadata_extend"),
        ("$secure", "metadata_security"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ntfs_logfile_signals_extracts_ascii_markers() {
        let raw = b"txn CreateFile C:\\temp\\a.txt ... $MFT ... Rename";
        let rows = parse_ntfs_logfile_signals(raw, 32);
        assert!(rows.iter().any(|v| v.signal == "file_create"));
        assert!(rows.iter().any(|v| v.signal == "mft_reference"));
        assert!(rows.iter().any(|v| v.signal == "rename"));
    }

    #[test]
    fn parse_ntfs_logfile_signals_extracts_utf16_markers() {
        let mut raw = Vec::new();
        for unit in "$UsnJrnl FILE_DELETE".encode_utf16() {
            raw.extend_from_slice(&unit.to_le_bytes());
        }
        raw.extend_from_slice(&[0, 0]);
        let rows = parse_ntfs_logfile_signals(&raw, 32);
        assert!(rows.iter().any(|v| v.signal == "usn_reference"));
        assert!(rows.iter().any(|v| v.signal == "file_delete"));
    }

    #[test]
    fn parse_ntfs_logfile_signals_accepts_json_input() {
        let raw = br#"{
            "signals": [
                {"offset": 12, "signal": "file_create", "context": "CreateFile x"},
                {"offset": 20, "event_type": "rename", "summary": "Rename y"}
            ]
        }"#;
        let rows = parse_ntfs_logfile_signals(raw, 32);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].offset, 12);
        assert_eq!(rows[1].signal, "rename");
    }

    #[test]
    fn parse_ntfs_logfile_signals_from_path_uses_json_rows() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("sample.json");
        std::fs::write(
            &path,
            r#"{"signals":[{"offset":8,"signal":"file_delete","context":"Delete","timestamp_unix":1700000000,"process_path":"C:/Windows/System32/cmd.exe"}]}"#,
        )
        .unwrap();
        let rows = parse_ntfs_logfile_signals_from_path(&path, 50);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].signal, "file_delete");
        assert_eq!(rows[0].timestamp_unix, Some(1_700_000_000));
        assert_eq!(
            rows[0].process_path.as_deref(),
            Some(r"C:\Windows\System32\cmd.exe")
        );
    }

    #[test]
    fn parse_ntfs_logfile_text_fallback_handles_partial_rows() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("sample.txt");
        std::fs::write(
            &path,
            "2024-01-01T00:00:00Z|file_delete|C:\\Temp\\gone.exe|S-1-5-21-1000\nfile_create C:\\Temp\\new.exe\n",
        )
        .unwrap();
        let rows = parse_ntfs_logfile_text_fallback(&path, 20);
        assert!(rows.iter().any(|v| v.signal == "file_delete"));
        assert!(rows.iter().any(|v| v.signal == "file_create"));
    }

    #[test]
    fn parse_ntfs_logfile_text_fallback_extracts_user_device_and_sid_from_keyed_fields() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("sample_keyed.txt");
        std::fs::write(
            &path,
            "2024-01-01T00:00:00Z|file_delete|User=analyst|Host=WS-01|SID=S-1-5-21-1001|Process=C:/Windows/System32/cmd.exe\n",
        )
        .unwrap();

        let rows = parse_ntfs_logfile_text_fallback(&path, 20);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].user.as_deref(), Some("analyst"));
        assert_eq!(rows[0].device.as_deref(), Some("WS-01"));
        assert_eq!(rows[0].sid.as_deref(), Some("S-1-5-21-1001"));
        assert_eq!(
            rows[0].process_path.as_deref(),
            Some(r"C:\Windows\System32\cmd.exe")
        );
    }

    #[test]
    fn parse_ntfs_logfile_json_supports_alt_timestamp_and_identity_fields() {
        let raw = br#"{
            "signals": [
                {
                    "offset": 3,
                    "signal": "file_create",
                    "context": "CreateFile",
                    "timestamp_unix": "1700000000000",
                    "user_sid": "S-1-5-21-1002",
                    "username": "investigator",
                    "host": "LAB-WS",
                    "image_path": "C:/Windows/System32/notepad.exe"
                }
            ]
        }"#;
        let rows = parse_ntfs_logfile_signals(raw, 32);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].timestamp_unix, Some(1_700_000_000));
        assert_eq!(rows[0].sid.as_deref(), Some("S-1-5-21-1002"));
        assert_eq!(rows[0].user.as_deref(), Some("investigator"));
        assert_eq!(rows[0].device.as_deref(), Some("LAB-WS"));
        assert_eq!(
            rows[0].process_path.as_deref(),
            Some(r"C:\Windows\System32\notepad.exe")
        );
    }

    #[test]
    fn normalize_timestamp_text_supports_filetime_and_millis_epoch() {
        let filetime = "133444736000000000";
        let (file_unix, _) =
            normalize_timestamp_text(filetime).expect("FILETIME timestamp should parse");
        assert_eq!(file_unix, 1_700_000_000);

        let millis = "1700000000000";
        let (ms_unix, _) =
            normalize_timestamp_text(millis).expect("unix-millis timestamp should parse");
        assert_eq!(ms_unix, 1_700_000_000);
    }

    #[test]
    fn parse_ntfs_logfile_signals_handles_invalid_data() {
        let rows = parse_ntfs_logfile_signals(b"\x01\x02\x03\x04", 10);
        assert!(rows.is_empty());
    }

    #[test]
    fn detect_ntfs_logfile_input_shape_supports_json_and_binary() {
        let temp = std::env::temp_dir().join(format!(
            "logfile_shape_{}_{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        let json = temp.join("sample.json");
        let bin = temp.join("sample.bin");
        std::fs::write(
            &json,
            r#"{"signals":[{"offset":1,"signal":"file_create","context":"CreateFile"}]}"#,
        )
        .unwrap();
        std::fs::write(&bin, b"\x01\x02txn CreateFile ... $MFT").unwrap();
        assert_eq!(
            detect_ntfs_logfile_input_shape(&json),
            NtfsLogFileInputShape::JsonObject
        );
        assert_eq!(
            detect_ntfs_logfile_input_shape(&bin),
            NtfsLogFileInputShape::BinaryRaw
        );
        let _ = std::fs::remove_dir_all(&temp);
    }
}
