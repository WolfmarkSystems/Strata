use crate::errors::ForensicError;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use super::lnk::parse_lnk;
use super::scalpel::{read_prefix, DEFAULT_BINARY_MAX_BYTES};

const FILETIME_UNIX_EPOCH_OFFSET: u64 = 11_644_473_600;

#[derive(Debug, Clone)]
pub struct JumpListEntry {
    pub entry_type: JumpListEntryType,
    pub target_path: Option<String>,
    pub arguments: Option<String>,
    pub timestamp: Option<i64>,
    pub app_id: String,
    pub source_record_id: Option<u64>,
    pub mru_rank: Option<u32>,
}

#[derive(Debug, Clone)]
pub enum JumpListEntryType {
    Recent,
    Frequent,
    Tasks,
    Custom,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct JumpListHistory {
    pub entries: Vec<JumpListEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JumpListInputShape {
    Missing,
    Empty,
    Directory,
    AutomaticDestinations,
    CustomDestinations,
    LnkFile,
    JsonArray,
    JsonObject,
    CsvText,
    LineText,
    Unknown,
}

impl JumpListInputShape {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Empty => "empty",
            Self::Directory => "directory",
            Self::AutomaticDestinations => "automatic-destinations",
            Self::CustomDestinations => "custom-destinations",
            Self::LnkFile => "lnk-file",
            Self::JsonArray => "json-array",
            Self::JsonObject => "json-object",
            Self::CsvText => "csv-text",
            Self::LineText => "line-text",
            Self::Unknown => "unknown",
        }
    }
}

pub fn detect_jumplist_input_shape(path: &Path) -> JumpListInputShape {
    if !path.exists() {
        return JumpListInputShape::Missing;
    }
    if path.is_dir() {
        return JumpListInputShape::Directory;
    }

    if let Some(ext) = path.extension().and_then(|v| v.to_str()) {
        if ext.eq_ignore_ascii_case("automaticdestinations-ms") {
            return JumpListInputShape::AutomaticDestinations;
        }
        if ext.eq_ignore_ascii_case("customdestinations-ms") {
            return JumpListInputShape::CustomDestinations;
        }
        if ext.eq_ignore_ascii_case("lnk") {
            return JumpListInputShape::LnkFile;
        }
    }

    let Ok(bytes) = strata_fs::read(path) else {
        return JumpListInputShape::Unknown;
    };
    if bytes.is_empty() {
        return JumpListInputShape::Empty;
    }
    if bytes.windows(8).any(|w| w == b"DestList") {
        return JumpListInputShape::AutomaticDestinations;
    }
    let text = String::from_utf8_lossy(&bytes);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return JumpListInputShape::Empty;
    }
    if trimmed.starts_with('[') {
        return JumpListInputShape::JsonArray;
    }
    if trimmed.starts_with('{') {
        return JumpListInputShape::JsonObject;
    }
    let first = trimmed
        .lines()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if first.contains("target_path")
        || first.contains("app_id")
        || first.contains("timestamp")
        || first.contains("entry_type")
    {
        return JumpListInputShape::CsvText;
    }
    JumpListInputShape::LineText
}

pub fn parse_jumplist_entries_from_path(path: &Path, limit: usize) -> Vec<JumpListEntry> {
    if !path.exists() || limit == 0 {
        return Vec::new();
    }

    let mut rows = if path.is_dir() {
        parse_jump_list(path).map(|v| v.entries).unwrap_or_default()
    } else if path
        .extension()
        .and_then(|v| v.to_str())
        .map(|v| v.eq_ignore_ascii_case("automaticdestinations-ms"))
        .unwrap_or(false)
    {
        parseautomaticdestinations(path)
            .map(|v| v.entries)
            .unwrap_or_default()
    } else if path
        .extension()
        .and_then(|v| v.to_str())
        .map(|v| v.eq_ignore_ascii_case("customdestinations-ms"))
        .unwrap_or(false)
    {
        parsecustomdestinations(path)
            .map(|v| v.entries)
            .unwrap_or_default()
    } else if path
        .extension()
        .and_then(|v| v.to_str())
        .map(|v| v.eq_ignore_ascii_case("lnk"))
        .unwrap_or(false)
    {
        parse_lnk(path)
            .ok()
            .map(|lnk| JumpListEntry {
                entry_type: JumpListEntryType::Recent,
                target_path: lnk.target_path,
                arguments: lnk.arguments,
                timestamp: lnk.write_time,
                app_id: "lnk".to_string(),
                source_record_id: None,
                mru_rank: None,
            })
            .into_iter()
            .collect::<Vec<_>>()
    } else if let Ok(bytes) = strata_fs::read(path) {
        if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
            parse_jumplist_rows_json_value(&value)
        } else {
            parse_jumplist_csv_or_lines(String::from_utf8_lossy(&bytes).as_ref())
        }
    } else {
        Vec::new()
    };

    if rows.is_empty() && path.is_file() {
        rows = parse_jumplist_text_fallback(path);
    }

    let mut dedupe = BTreeSet::<String>::new();
    rows.retain(|row| {
        let key = format!(
            "{}|{}|{}|{}|{}",
            jump_list_entry_type_as_str(&row.entry_type),
            row.target_path.as_deref().unwrap_or(""),
            row.timestamp.map(|v| v.to_string()).unwrap_or_default(),
            row.app_id,
            row.arguments.as_deref().unwrap_or("")
        );
        dedupe.insert(key)
    });

    rows.sort_by(|a, b| {
        b.timestamp
            .unwrap_or_default()
            .cmp(&a.timestamp.unwrap_or_default())
            .then_with(|| {
                a.mru_rank
                    .unwrap_or(u32::MAX)
                    .cmp(&b.mru_rank.unwrap_or(u32::MAX))
            })
            .then_with(|| a.target_path.cmp(&b.target_path))
    });
    rows.truncate(limit);
    rows
}

pub fn parse_jumplist_text_fallback(path: &Path) -> Vec<JumpListEntry> {
    if !path.exists() {
        return Vec::new();
    }
    let Ok(content) = strata_fs::read_to_string(path) else {
        return Vec::new();
    };
    parse_jumplist_csv_or_lines(&content)
}

pub fn jump_list_entry_type_as_str(value: &JumpListEntryType) -> &'static str {
    match value {
        JumpListEntryType::Recent => "recent",
        JumpListEntryType::Frequent => "frequent",
        JumpListEntryType::Tasks => "tasks",
        JumpListEntryType::Custom => "custom",
        JumpListEntryType::Unknown => "unknown",
    }
}

pub fn parse_jump_list(path: &Path) -> Result<JumpListHistory, ForensicError> {
    let mut entries = Vec::new();

    if !path.exists() {
        return Ok(JumpListHistory { entries });
    }

    if let Ok(shell_items) = strata_fs::read_dir(path) {
        for item in shell_items.flatten() {
            let item_path = item.path();
            if item_path.is_dir() {
                let app_name = item_path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();

                let custom_path = item_path.join("CustomDestinationHandler");
                if let Ok(custom) = strata_fs::read_dir(&custom_path) {
                    for entry in custom.flatten() {
                        if let Ok(jumplist_entry) =
                            parse_shell_item_folder(&entry.path(), &app_name)
                        {
                            entries.push(jumplist_entry);
                        }
                    }
                }

                let recent_path = item_path.join("Recent");
                if let Ok(recent) = strata_fs::read_dir(&recent_path) {
                    for entry in recent.flatten() {
                        let mut jumplist_entry = parse_recent_entry(&entry.path(), &app_name);
                        jumplist_entry.entry_type = JumpListEntryType::Recent;
                        entries.push(jumplist_entry);
                    }
                }
            } else if item_path
                .extension()
                .map(|e| e.eq_ignore_ascii_case("automaticdestinations-ms"))
                .unwrap_or(false)
            {
                if let Ok(parsed) = parseautomaticdestinations(&item_path) {
                    entries.extend(parsed.entries);
                }
            } else if item_path
                .extension()
                .map(|e| e.eq_ignore_ascii_case("customdestinations-ms"))
                .unwrap_or(false)
            {
                if let Ok(parsed) = parsecustomdestinations(&item_path) {
                    entries.extend(parsed.entries);
                }
            }
        }
    }

    Ok(JumpListHistory { entries })
}

fn parse_jumplist_rows_json_value(value: &Value) -> Vec<JumpListEntry> {
    if let Some(arr) = value.as_array() {
        return parse_jumplist_rows_json(arr);
    }
    if let Some(obj) = value.as_object() {
        if let Some(arr) = obj
            .get("entries")
            .or_else(|| obj.get("records"))
            .or_else(|| obj.get("jumplist"))
            .or_else(|| obj.get("items"))
            .or_else(|| obj.get("rows"))
            .or_else(|| obj.get("results"))
            .and_then(Value::as_array)
        {
            return parse_jumplist_rows_json(arr);
        }
        if let Some(data_obj) = obj.get("data").and_then(Value::as_object) {
            if let Some(arr) = data_obj
                .get("entries")
                .or_else(|| data_obj.get("records"))
                .or_else(|| data_obj.get("items"))
                .or_else(|| data_obj.get("rows"))
                .or_else(|| data_obj.get("results"))
                .and_then(Value::as_array)
            {
                return parse_jumplist_rows_json(arr);
            }
        }
    }
    Vec::new()
}

fn parse_jumplist_rows_json(rows: &[Value]) -> Vec<JumpListEntry> {
    let mut out = Vec::new();
    for row in rows {
        let Some(obj) = row.as_object() else {
            continue;
        };
        let target_path = obj
            .get("target_path")
            .or_else(|| obj.get("target"))
            .or_else(|| obj.get("path"))
            .or_else(|| obj.get("targetPath"))
            .or_else(|| obj.get("full_path"))
            .or_else(|| obj.get("destination"))
            .or_else(|| obj.get("destination_path"))
            .and_then(Value::as_str)
            .map(|v| v.trim().replace('/', "\\"))
            .filter(|v| !v.is_empty());
        let arguments = obj
            .get("arguments")
            .or_else(|| obj.get("args"))
            .or_else(|| obj.get("command_line"))
            .or_else(|| obj.get("cmdline"))
            .and_then(Value::as_str)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        let timestamp = obj
            .get("timestamp")
            .and_then(value_to_i64)
            .or_else(|| obj.get("timestamp_unix").and_then(value_to_i64))
            .or_else(|| obj.get("last_access_unix").and_then(value_to_i64))
            .or_else(|| obj.get("last_accessed_unix").and_then(value_to_i64))
            .or_else(|| obj.get("last_run_unix").and_then(value_to_i64))
            .or_else(|| obj.get("last_access").and_then(value_to_i64))
            .or_else(|| obj.get("last_run").and_then(value_to_i64))
            .or_else(|| {
                obj.get("timestamp_utc")
                    .and_then(Value::as_str)
                    .and_then(parse_utc_to_unix)
            })
            .or_else(|| {
                obj.get("occurred_utc")
                    .and_then(Value::as_str)
                    .and_then(parse_utc_to_unix)
            });
        let app_id = obj
            .get("app_id")
            .or_else(|| obj.get("app"))
            .or_else(|| obj.get("appId"))
            .or_else(|| obj.get("application"))
            .or_else(|| obj.get("app_name"))
            .or_else(|| obj.get("source"))
            .and_then(Value::as_str)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "jumplist".to_string());
        let entry_type = obj
            .get("entry_type")
            .or_else(|| obj.get("type"))
            .or_else(|| obj.get("list_type"))
            .and_then(Value::as_str)
            .and_then(parse_entry_type)
            .unwrap_or(JumpListEntryType::Unknown);
        let source_record_id = obj
            .get("source_record_id")
            .and_then(value_to_u64)
            .or_else(|| obj.get("record_id").and_then(value_to_u64));
        let mru_rank = obj
            .get("mru_rank")
            .and_then(value_to_u32)
            .or_else(|| obj.get("rank").and_then(value_to_u32))
            .or_else(|| obj.get("mru").and_then(value_to_u32));
        out.push(JumpListEntry {
            entry_type,
            target_path,
            arguments,
            timestamp,
            app_id,
            source_record_id,
            mru_rank,
        });
    }
    out
}

fn parse_jumplist_csv_or_lines(content: &str) -> Vec<JumpListEntry> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut lines = trimmed.lines();
    let first = lines.next().unwrap_or_default().trim().to_string();
    let first_lower = first.to_ascii_lowercase();
    let first_delimiter = if first.contains('|') && !first.contains(',') {
        '|'
    } else {
        ','
    };
    let first_tokens = split_delimited_line(&first_lower, first_delimiter);
    let has_header = first_tokens.iter().any(|token| {
        matches!(
            token.trim(),
            "entry_type"
                | "type"
                | "list_type"
                | "target_path"
                | "target"
                | "path"
                | "targetpath"
                | "full_path"
                | "destination"
                | "arguments"
                | "args"
                | "command_line"
                | "cmdline"
                | "timestamp"
                | "timestamp_unix"
                | "timestamp_utc"
                | "occurred_utc"
                | "last_accessed"
                | "last_run"
                | "app_id"
                | "appid"
                | "app_name"
                | "application"
                | "source"
                | "mru"
                | "mru_rank"
                | "rank"
                | "record_id"
                | "source_record_id"
        )
    });

    let mut rows = Vec::new();
    let mut normalized_header = Vec::<String>::new();
    let delimiter = if first.contains('|') && !first.contains(',') {
        '|'
    } else {
        ','
    };
    if has_header {
        normalized_header = split_delimited_line(&first, delimiter)
            .into_iter()
            .map(|v| v.trim().to_ascii_lowercase())
            .collect();
        rows.extend(lines.map(|v| v.to_string()));
    } else {
        rows.push(first);
        rows.extend(lines.map(|v| v.to_string()));
    }

    for line in rows {
        let clean = line.trim();
        if clean.is_empty() {
            continue;
        }
        let parts = split_delimited_line(clean, delimiter);
        if parts.is_empty() {
            continue;
        }

        let mut entry = JumpListEntry {
            entry_type: JumpListEntryType::Unknown,
            target_path: None,
            arguments: None,
            timestamp: None,
            app_id: "jumplist".to_string(),
            source_record_id: None,
            mru_rank: None,
        };

        if has_header {
            let entry_type_index =
                header_index(&normalized_header, &["entry_type", "type", "list_type"]);
            let target_index = header_index(
                &normalized_header,
                &[
                    "target_path",
                    "target",
                    "path",
                    "targetpath",
                    "full_path",
                    "destination",
                ],
            );
            let args_index = header_index(
                &normalized_header,
                &[
                    "arguments",
                    "args",
                    "command_line",
                    "cmdline",
                    "commandline",
                ],
            );
            let timestamp_index = header_index(
                &normalized_header,
                &[
                    "timestamp",
                    "timestamp_unix",
                    "last_access_unix",
                    "last_run_unix",
                    "timestamp_utc",
                    "occurred_utc",
                    "last_accessed",
                    "last_run",
                ],
            );
            let app_id_index = header_index(
                &normalized_header,
                &[
                    "app_id",
                    "app",
                    "appid",
                    "application",
                    "app_name",
                    "source",
                ],
            );
            let mru_index = header_index(&normalized_header, &["mru_rank", "rank", "mru"]);
            let record_id_index =
                header_index(&normalized_header, &["source_record_id", "record_id"]);

            if let Some(v) = get_col(&parts, entry_type_index) {
                if let Some(ty) = parse_entry_type(v) {
                    entry.entry_type = ty;
                }
            }
            if let Some(v) = get_col(&parts, target_index) {
                let normalized = v.replace('/', "\\");
                if !normalized.is_empty() {
                    entry.target_path = Some(normalized);
                }
            }
            if let Some(v) = get_col(&parts, args_index) {
                if !v.is_empty() {
                    entry.arguments = Some(v.to_string());
                }
            }
            if let Some(v) = get_col(&parts, timestamp_index) {
                entry.timestamp = parse_utc_to_unix(v);
            }
            if let Some(v) = get_col(&parts, app_id_index) {
                if !v.is_empty() {
                    entry.app_id = v.to_string();
                }
            }
            if let Some(v) = get_col(&parts, mru_index) {
                entry.mru_rank = parse_u32_text(v);
            }
            if let Some(v) = get_col(&parts, record_id_index) {
                entry.source_record_id = parse_u64_text(v);
            }
        } else {
            entry.timestamp = parts.first().and_then(|v| parse_utc_to_unix(v.as_str()));
            entry.target_path = parts
                .get(1)
                .map(|v| v.replace('/', "\\"))
                .filter(|v| !v.is_empty());
            if let Some(v) = parts.get(2) {
                if !v.is_empty() {
                    entry.app_id = v.to_string();
                }
            }
            if let Some(v) = parts.get(3).and_then(|v| parse_entry_type(v)) {
                entry.entry_type = v;
            }
            if let Some(v) = parts.get(4) {
                if !v.is_empty() {
                    entry.arguments = Some(v.to_string());
                }
            }
            entry.mru_rank = parts.get(5).and_then(|v| v.parse::<u32>().ok());
        }
        out.push(entry);
    }
    out
}

fn parse_entry_type(value: &str) -> Option<JumpListEntryType> {
    match value.trim().to_ascii_lowercase().as_str() {
        "recent" => Some(JumpListEntryType::Recent),
        "frequent" => Some(JumpListEntryType::Frequent),
        "tasks" => Some(JumpListEntryType::Tasks),
        "custom" => Some(JumpListEntryType::Custom),
        "unknown" => Some(JumpListEntryType::Unknown),
        _ => None,
    }
}

fn value_to_i64(value: &Value) -> Option<i64> {
    let parsed = value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|v| i64::try_from(v).ok()))
        .or_else(|| value.as_str().and_then(|v| v.parse::<i64>().ok()));
    parsed.and_then(normalize_unix_timestamp)
}

fn value_to_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_i64().and_then(|v| u64::try_from(v).ok()))
        .or_else(|| {
            value.as_str().and_then(parse_u64_text).or_else(|| {
                value.as_str().and_then(|v| {
                    u64::from_str_radix(v.trim_start_matches("0x").trim_start_matches("0X"), 16)
                        .ok()
                })
            })
        })
}

fn value_to_u32(value: &Value) -> Option<u32> {
    value_to_u64(value).and_then(|v| u32::try_from(v).ok())
}

fn parse_utc_to_unix(value: &str) -> Option<i64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    chrono::DateTime::parse_from_rfc3339(trimmed)
        .map(|v| v.timestamp())
        .ok()
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S")
                .ok()
                .map(|dt| dt.and_utc().timestamp())
        })
        .or_else(|| trimmed.parse::<i64>().ok())
        .and_then(normalize_unix_timestamp)
}

fn parse_u32_text(value: &str) -> Option<u32> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u32::from_str_radix(hex, 16).ok();
    }
    trimmed.parse::<u32>().ok()
}

fn parse_u64_text(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).ok();
    }
    trimmed.parse::<u64>().ok()
}

fn split_delimited_line(line: &str, delimiter: char) -> Vec<String> {
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
            _ if ch == delimiter && !in_quotes => {
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

fn normalize_unix_timestamp(value: i64) -> Option<i64> {
    let abs = value.unsigned_abs();
    // Windows FILETIME range for contemporary timestamps.
    if (116_444_736_000_000_000..400_000_000_000_000_000).contains(&abs) {
        let seconds = (abs / 10_000_000) as i64 - 11_644_473_600;
        return Some(if value.is_negative() {
            -seconds
        } else {
            seconds
        });
    }
    // Nanoseconds / microseconds / milliseconds since Unix epoch.
    if abs >= 1_000_000_000_000_000_000 {
        return Some(value / 1_000_000_000);
    }
    if abs >= 1_000_000_000_000_000 {
        return Some(value / 1_000_000);
    }
    if abs >= 10_000_000_000 {
        return Some(value / 1_000);
    }
    Some(value)
}

pub fn parseautomaticdestinations(path: &Path) -> Result<JumpListHistory, ForensicError> {
    let mut entries = Vec::new();

    if !path.exists() {
        return Ok(JumpListHistory { entries });
    }

    if path.is_file() {
        if let Ok(data) = read_prefix(path, DEFAULT_BINARY_MAX_BYTES) {
            let app_id_hint = app_id_from_path(path);
            entries.extend(parse_jumplist_binary_with_app_id(
                &data,
                app_id_hint.as_deref(),
            ));
        }
        return Ok(JumpListHistory { entries });
    }

    if let Ok(entries_iter) = strata_fs::read_dir(path) {
        for entry in entries_iter.flatten() {
            let entry_path = entry.path();
            if entry_path
                .extension()
                .map(|e| e.eq_ignore_ascii_case("automaticdestinations-ms"))
                .unwrap_or(false)
            {
                if let Ok(data) = read_prefix(&entry_path, DEFAULT_BINARY_MAX_BYTES) {
                    let app_id_hint = app_id_from_path(&entry_path);
                    entries.extend(parse_jumplist_binary_with_app_id(
                        &data,
                        app_id_hint.as_deref(),
                    ));
                }
            }
        }
    }

    Ok(JumpListHistory { entries })
}

pub fn parsecustomdestinations(path: &Path) -> Result<JumpListHistory, ForensicError> {
    let mut entries = Vec::new();

    if !path.exists() {
        return Ok(JumpListHistory { entries });
    }

    if path.is_file() {
        if let Ok(data) = read_prefix(path, DEFAULT_BINARY_MAX_BYTES) {
            let app_id_hint = app_id_from_path(path);
            let mut parsed = parse_jumplist_binary_with_app_id(&data, app_id_hint.as_deref());
            for entry in &mut parsed {
                entry.entry_type = JumpListEntryType::Custom;
            }
            entries.extend(parsed);
        }
        return Ok(JumpListHistory { entries });
    }

    if let Ok(entries_iter) = strata_fs::read_dir(path) {
        for entry in entries_iter.flatten() {
            let entry_path = entry.path();
            if entry_path
                .extension()
                .map(|e| e.eq_ignore_ascii_case("customdestinations-ms"))
                .unwrap_or(false)
            {
                if let Ok(data) = read_prefix(&entry_path, DEFAULT_BINARY_MAX_BYTES) {
                    let app_id_hint = app_id_from_path(&entry_path);
                    let mut parsed =
                        parse_jumplist_binary_with_app_id(&data, app_id_hint.as_deref());
                    for row in &mut parsed {
                        row.entry_type = JumpListEntryType::Custom;
                    }
                    entries.extend(parsed);
                }
            }
        }
    }

    Ok(JumpListHistory { entries })
}

fn parse_shell_item_folder(path: &Path, app_id: &str) -> Result<JumpListEntry, ForensicError> {
    let target_path = path.file_name().map(|n| n.to_string_lossy().to_string());
    let timestamp = strata_fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .map(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64
        });

    Ok(JumpListEntry {
        entry_type: JumpListEntryType::Custom,
        target_path,
        arguments: None,
        timestamp,
        app_id: app_id.to_string(),
        source_record_id: None,
        mru_rank: None,
    })
}

fn parse_recent_entry(path: &Path, app_id: &str) -> JumpListEntry {
    let mut target_path = path.file_name().map(|n| n.to_string_lossy().to_string());
    let mut arguments = None;
    let mut timestamp = strata_fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .map(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64
        });

    if path
        .extension()
        .map(|e| e.eq_ignore_ascii_case("lnk"))
        .unwrap_or(false)
    {
        if let Ok(lnk) = parse_lnk(path) {
            if lnk.target_path.is_some() {
                target_path = lnk.target_path;
            }
            if lnk.arguments.is_some() {
                arguments = lnk.arguments;
            }
            if lnk.write_time.is_some() {
                timestamp = lnk.write_time;
            }
        }
    }

    JumpListEntry {
        entry_type: JumpListEntryType::Unknown,
        target_path,
        arguments,
        timestamp,
        app_id: app_id.to_string(),
        source_record_id: None,
        mru_rank: None,
    }
}

fn parse_jumplist_binary_with_app_id(data: &[u8], app_id_hint: Option<&str>) -> Vec<JumpListEntry> {
    let mut entries = Vec::new();

    let mut timestamps = extract_possible_filetimes(data);
    timestamps.sort_by(|a, b| b.cmp(a));
    timestamps.dedup();

    let app_id = app_id_hint
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            if data.windows(8).any(|w| w == b"DestList") {
                "automaticdestinations".to_string()
            } else {
                "jumplist".to_string()
            }
        });

    if data.windows(8).any(|w| w == b"DestList") {
        let mut destlist_entries = extract_destlist_entries(data, &app_id);
        if !destlist_entries.is_empty() {
            entries.append(&mut destlist_entries);
            return dedupe_and_sort_entries(entries);
        }
    }

    let mut paths = extract_utf16_path_like_strings(data);
    paths.extend(extract_ascii_path_like_strings(data));
    paths.sort();
    paths.dedup();

    for (idx, path) in paths.into_iter().enumerate().take(1000) {
        let ts = timestamps.get(idx).copied();
        entries.push(JumpListEntry {
            entry_type: JumpListEntryType::Frequent,
            target_path: Some(path),
            arguments: None,
            timestamp: ts.map(|v| v as i64),
            app_id: app_id.clone(),
            source_record_id: None,
            mru_rank: Some(idx as u32),
        });
    }

    if entries.is_empty() && data.windows(8).any(|w| w == b"DestList") {
        entries.push(JumpListEntry {
            entry_type: JumpListEntryType::Frequent,
            target_path: Some("DestList header present".to_string()),
            arguments: None,
            timestamp: None,
            app_id,
            source_record_id: None,
            mru_rank: None,
        });
    }

    dedupe_and_sort_entries(entries)
}

fn app_id_from_path(path: &Path) -> Option<String> {
    path.file_stem()
        .map(|s| s.to_string_lossy().trim().to_string())
        .filter(|s| !s.is_empty())
}

#[derive(Debug, Clone)]
struct PathCandidate {
    path: String,
    offset: usize,
}

fn extract_destlist_entries(data: &[u8], app_id: &str) -> Vec<JumpListEntry> {
    let mut structured = extract_destlist_entries_structured(data, app_id);
    if !structured.is_empty() {
        return structured;
    }

    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::<String>::new();
    let mut candidates = extract_utf16_path_candidates(data);
    candidates.sort_by(|a, b| a.offset.cmp(&b.offset));

    for (idx, candidate) in candidates.into_iter().enumerate().take(1000) {
        if !seen.insert(candidate.path.clone()) {
            continue;
        }
        let source_record_id = read_candidate_record_id_near(data, candidate.offset);
        let mru_rank = read_u32_near(data, candidate.offset, 16, 48)
            .filter(|v| *v <= 1_000_000)
            .or(Some(idx as u32));
        let timestamp = find_nearest_filetime(data, candidate.offset, 96).map(|v| v as i64);

        out.push(JumpListEntry {
            entry_type: JumpListEntryType::Frequent,
            target_path: Some(candidate.path),
            arguments: None,
            timestamp,
            app_id: app_id.to_string(),
            source_record_id,
            mru_rank,
        });
    }
    structured.append(&mut out);
    structured
}

fn extract_destlist_entries_structured(data: &[u8], app_id: &str) -> Vec<JumpListEntry> {
    let mut out = Vec::new();
    let Some(destlist_start) = find_subslice(data, b"DestList", 0) else {
        return out;
    };

    // DestList starts with a fixed-size header; common variants are 32 bytes.
    let mut pos = destlist_start.saturating_add(32);
    while pos + 114 <= data.len() && out.len() < 1000 {
        let Some(name_len_chars) = le_u16_at(data, pos + 112).map(|v| v as usize) else {
            break;
        };
        if name_len_chars == 0 || name_len_chars > 4096 {
            pos += 1;
            continue;
        }

        let path_start = pos + 114;
        let Some(path_end) = path_start.checked_add(name_len_chars.saturating_mul(2)) else {
            pos += 1;
            continue;
        };
        if path_end > data.len() {
            pos += 1;
            continue;
        }

        let Some(path) = decode_utf16_path(&data[path_start..path_end]) else {
            pos += 1;
            continue;
        };
        if !looks_like_path(&path) {
            pos += 1;
            continue;
        }

        let source_record_id = le_u64_at(data, pos + 88)
            .filter(|v| *v > 0)
            .or_else(|| le_u64_at(data, pos + 72).filter(|v| *v > 0));
        let mru_rank = extract_structured_mru_rank(data, pos).or(Some(out.len() as u32));
        let timestamp = extract_structured_destlist_time(data, pos).map(|v| v as i64);

        out.push(JumpListEntry {
            entry_type: JumpListEntryType::Frequent,
            target_path: Some(path),
            arguments: None,
            timestamp,
            app_id: app_id.to_string(),
            source_record_id,
            mru_rank,
        });

        pos = path_end;
    }

    out
}

fn dedupe_and_sort_entries(entries: Vec<JumpListEntry>) -> Vec<JumpListEntry> {
    let mut best_by_path = std::collections::BTreeMap::<String, JumpListEntry>::new();
    let mut passthrough = Vec::<JumpListEntry>::new();

    for entry in entries {
        let Some(path) = entry.target_path.as_deref() else {
            passthrough.push(entry);
            continue;
        };

        let key = path.trim().to_ascii_lowercase();
        if key.is_empty() {
            passthrough.push(entry);
            continue;
        }

        match best_by_path.get(&key) {
            Some(existing) => {
                if should_replace_entry(existing, &entry) {
                    best_by_path.insert(key, entry);
                }
            }
            None => {
                best_by_path.insert(key, entry);
            }
        }
    }

    let mut out: Vec<JumpListEntry> = best_by_path.into_values().collect();
    out.extend(passthrough);
    out.sort_by(|a, b| {
        let a_rank = a.mru_rank.unwrap_or(u32::MAX);
        let b_rank = b.mru_rank.unwrap_or(u32::MAX);
        a_rank
            .cmp(&b_rank)
            .then_with(|| {
                b.timestamp
                    .unwrap_or_default()
                    .cmp(&a.timestamp.unwrap_or_default())
            })
            .then_with(|| a.target_path.cmp(&b.target_path))
    });
    out
}

fn should_replace_entry(existing: &JumpListEntry, candidate: &JumpListEntry) -> bool {
    let existing_rank = existing.mru_rank.unwrap_or(u32::MAX);
    let candidate_rank = candidate.mru_rank.unwrap_or(u32::MAX);
    if candidate_rank != existing_rank {
        return candidate_rank < existing_rank;
    }

    let existing_has_record = existing.source_record_id.is_some();
    let candidate_has_record = candidate.source_record_id.is_some();
    if candidate_has_record != existing_has_record {
        return candidate_has_record;
    }

    candidate.timestamp.unwrap_or_default() > existing.timestamp.unwrap_or_default()
}

fn extract_utf16_path_like_strings(data: &[u8]) -> Vec<String> {
    extract_utf16_path_candidates(data)
        .into_iter()
        .map(|c| c.path)
        .collect()
}

fn extract_utf16_path_candidates(data: &[u8]) -> Vec<PathCandidate> {
    let mut out = Vec::new();
    let mut current = Vec::<u16>::new();
    let mut current_start = 0usize;
    let mut i = 0usize;
    while i + 1 < data.len() {
        let u = u16::from_le_bytes([data[i], data[i + 1]]);
        if u == 0 {
            if current.len() >= 6 {
                let s = String::from_utf16_lossy(&current);
                if looks_like_path(&s) {
                    out.push(PathCandidate {
                        path: s.trim().to_string(),
                        offset: current_start,
                    });
                }
            }
            current.clear();
            current_start = i + 2;
        } else if (0x20..=0x7e).contains(&u) || u == 0x5c {
            if current.is_empty() {
                current_start = i;
            }
            current.push(u);
        } else {
            current.clear();
            current_start = i + 2;
        }
        i += 2;
    }
    out
}

fn decode_utf16_path(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut units = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks(2) {
        if chunk.len() != 2 {
            break;
        }
        let u = u16::from_le_bytes([chunk[0], chunk[1]]);
        if u == 0 {
            break;
        }
        units.push(u);
    }
    let decoded = String::from_utf16(&units).ok()?;
    let trimmed = decoded.trim().to_string();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed)
}

fn extract_ascii_path_like_strings(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0usize;
    while start < data.len() {
        while start < data.len() && !is_ascii_path_char(data[start]) {
            start += 1;
        }
        if start >= data.len() {
            break;
        }
        let mut end = start;
        while end < data.len() && is_ascii_path_char(data[end]) {
            end += 1;
        }
        if end - start >= 8 {
            let s = String::from_utf8_lossy(&data[start..end]).to_string();
            if looks_like_path(&s) {
                out.push(s);
            }
        }
        start = end + 1;
    }
    out
}

fn extract_possible_filetimes(data: &[u8]) -> Vec<u64> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 8 <= data.len() {
        let ft = u64::from_le_bytes([
            data[i],
            data[i + 1],
            data[i + 2],
            data[i + 3],
            data[i + 4],
            data[i + 5],
            data[i + 6],
            data[i + 7],
        ]);
        if let Some(ts) = filetime_to_unix(ft) {
            if is_plausible_unix_time(ts) {
                out.push(ts);
            }
        }
        i += 8;
    }
    out
}

fn looks_like_path(s: &str) -> bool {
    if s.len() < 4 {
        return false;
    }
    let sl = s.trim();
    if sl.starts_with(r"\\") {
        return true;
    }
    sl.len() >= 3 && sl.as_bytes()[1] == b':' && sl.contains('\\')
}

fn is_ascii_path_char(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'\\' | b':' | b'.' | b'_' | b'-' | b' ' | b'(' | b')' | b'[' | b']'
        )
}

fn filetime_to_unix(filetime: u64) -> Option<u64> {
    if filetime == 0 {
        return None;
    }
    let seconds = filetime / 10_000_000;
    if seconds < FILETIME_UNIX_EPOCH_OFFSET {
        return None;
    }
    Some(seconds - FILETIME_UNIX_EPOCH_OFFSET)
}

fn is_plausible_unix_time(ts: u64) -> bool {
    (946_684_800..=4_102_444_800).contains(&ts)
}

fn is_plausible_filetime(v: u64) -> bool {
    filetime_to_unix(v)
        .map(is_plausible_unix_time)
        .unwrap_or(false)
}

fn extract_structured_mru_rank(data: &[u8], record_start: usize) -> Option<u32> {
    for off in [84usize, 92, 96, 104, 108] {
        let Some(v) = le_u32_at(data, record_start + off) else {
            continue;
        };
        if (1..=1_000_000).contains(&v) {
            return Some(v);
        }
    }
    None
}

fn extract_structured_destlist_time(data: &[u8], record_start: usize) -> Option<u64> {
    for off in [100usize, 96, 104, 64] {
        let Some(raw) = le_u64_at(data, record_start + off) else {
            continue;
        };
        let Some(ts) = filetime_to_unix(raw) else {
            continue;
        };
        if is_plausible_unix_time(ts) {
            return Some(ts);
        }
    }
    None
}

fn read_u32_near(data: &[u8], offset: usize, back: usize, window: usize) -> Option<u32> {
    let start = offset.saturating_sub(window);
    let preferred = offset.saturating_sub(back);
    if let Some(v) = le_u32_at(data, preferred) {
        return Some(v);
    }
    let mut pos = start;
    while pos + 4 <= offset {
        if let Some(v) = le_u32_at(data, pos) {
            if v > 0 {
                return Some(v);
            }
        }
        pos += 4;
    }
    None
}

fn read_candidate_record_id_near(data: &[u8], offset: usize) -> Option<u64> {
    // Most useful guess: record-id often sits a few qwords before path text, unlike FILETIME.
    for back in [24usize, 16, 32, 40, 8, 48, 56] {
        let off = offset.saturating_sub(back);
        let Some(v) = le_u64_at(data, off) else {
            continue;
        };
        if v == 0 {
            continue;
        }
        if is_plausible_filetime(v) {
            continue;
        }
        return Some(v);
    }

    // Fallback broad scan in a short window for non-FILETIME non-zero qwords.
    let start = offset.saturating_sub(80);
    let mut pos = start;
    while pos + 8 <= offset {
        if let Some(v) = le_u64_at(data, pos) {
            if v != 0 && !is_plausible_filetime(v) {
                return Some(v);
            }
        }
        pos += 8;
    }
    None
}

fn find_nearest_filetime(data: &[u8], offset: usize, window: usize) -> Option<u64> {
    let start = offset.saturating_sub(window);
    let mut best: Option<(usize, u64)> = None;
    let mut pos = start;
    while pos + 8 <= offset {
        if let Some(raw) = le_u64_at(data, pos) {
            if let Some(ts) = filetime_to_unix(raw) {
                if is_plausible_unix_time(ts) {
                    let dist = offset.saturating_sub(pos);
                    match best {
                        None => best = Some((dist, ts)),
                        Some((best_dist, _)) if dist < best_dist => best = Some((dist, ts)),
                        _ => {}
                    }
                }
            }
        }
        pos += 1;
    }
    best.map(|(_, ts)| ts)
}

fn le_u32_at(data: &[u8], off: usize) -> Option<u32> {
    if off + 4 > data.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
    ]))
}

fn le_u64_at(data: &[u8], off: usize) -> Option<u64> {
    if off + 8 > data.len() {
        return None;
    }
    Some(u64::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
        data[off + 4],
        data[off + 5],
        data[off + 6],
        data[off + 7],
    ]))
}

fn le_u16_at(data: &[u8], off: usize) -> Option<u16> {
    if off + 2 > data.len() {
        return None;
    }
    Some(u16::from_le_bytes([data[off], data[off + 1]]))
}

fn find_subslice(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= haystack.len() || needle.len() > haystack.len() {
        return None;
    }
    let max = haystack.len() - needle.len();
    let mut i = from;
    while i <= max {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_jumplist_binary_extracts_utf16_paths_and_timestamps() {
        let mut bytes = b"DestList".to_vec();
        bytes.resize(64, 0);
        let ft = (FILETIME_UNIX_EPOCH_OFFSET + 1_700_000_000u64) * 10_000_000u64;
        bytes.extend_from_slice(&ft.to_le_bytes());
        let path = r"C:\Users\lab\Desktop\report.docx";
        for u in path.encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        bytes.extend_from_slice(&[0, 0]);

        let entries = parse_jumplist_binary_with_app_id(&bytes, None);
        assert!(!entries.is_empty());
        assert!(entries
            .iter()
            .any(|e| e.target_path.as_deref() == Some(path)));
        assert!(entries.iter().any(|e| e.timestamp == Some(1_700_000_000)));
        assert!(entries.iter().any(|e| e.mru_rank.is_some()));
    }

    #[test]
    fn parseautomaticdestinations_accepts_single_file_input() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("sample.automaticdestinations-ms");
        let data = b"DestList".to_vec();
        std::fs::write(&file, data).unwrap();

        let parsed = parseautomaticdestinations(&file).unwrap();
        assert!(!parsed.entries.is_empty());
        assert!(parsed.entries.iter().all(|e| e.app_id == "sample"));
    }

    #[test]
    fn parse_jumplist_binary_extracts_ascii_paths() {
        let mut bytes = b"DestList".to_vec();
        bytes.push(0);
        bytes.extend_from_slice(b"C:\\Temp\\evidence\\report.txt\0");

        let entries = parse_jumplist_binary_with_app_id(&bytes, None);
        assert!(entries
            .iter()
            .any(|e| e.target_path.as_deref() == Some("C:\\Temp\\evidence\\report.txt")));
    }

    #[test]
    fn parse_jumplist_binary_fallback_when_destlist_without_paths() {
        let entries = parse_jumplist_binary_with_app_id(b"DestList", None);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].target_path.as_deref(),
            Some("DestList header present")
        );
    }

    #[test]
    fn parseautomaticdestinations_uses_per_file_app_id_hint() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("9b9cdc69c1c24e2b.automaticdestinations-ms");
        std::fs::write(&file, b"DestList\0C:\\test\\a.txt\0").unwrap();

        let parsed = parseautomaticdestinations(&file).unwrap();
        assert!(!parsed.entries.is_empty());
        assert!(parsed
            .entries
            .iter()
            .all(|e| e.app_id == "9b9cdc69c1c24e2b"));
    }

    #[test]
    fn parsecustomdestinations_accepts_single_file_input() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("sample.customdestinations-ms");
        std::fs::write(&file, b"DestList\0C:\\test\\custom.txt\0").unwrap();

        let parsed = parsecustomdestinations(&file).unwrap();
        assert!(!parsed.entries.is_empty());
        assert!(parsed.entries.iter().all(|e| e.app_id == "sample"));
        assert!(parsed
            .entries
            .iter()
            .all(|e| matches!(e.entry_type, JumpListEntryType::Custom)));
    }

    #[test]
    fn parse_destlist_entries_surfaces_record_metadata() {
        let mut bytes = b"DestList".to_vec();
        bytes.resize(32, 0);
        let record_id = 0x1122_3344_5566_7788u64;
        let ft = (FILETIME_UNIX_EPOCH_OFFSET + 1_700_100_000u64) * 10_000_000u64;
        let mru = 7u32;
        let path = r"C:\Users\lab\Desktop\destlist.bin";

        // Structured DestList entry layout: 114-byte header + UTF16 path.
        bytes.resize(32 + 114, 0);
        let rec = 32usize;
        bytes[rec + 88..rec + 96].copy_from_slice(&record_id.to_le_bytes());
        bytes[rec + 84..rec + 88].copy_from_slice(&mru.to_le_bytes());
        bytes[rec + 100..rec + 108].copy_from_slice(&ft.to_le_bytes());
        bytes[rec + 112..rec + 114]
            .copy_from_slice(&(path.encode_utf16().count() as u16).to_le_bytes());
        for u in path.encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        bytes.extend_from_slice(&[0, 0]);

        let entries = parse_jumplist_binary_with_app_id(&bytes, Some("testapp"));
        let item = entries
            .iter()
            .find(|e| e.target_path.as_deref() == Some(path))
            .expect("destlist path entry missing");
        assert_eq!(item.app_id, "testapp");
        assert_eq!(item.source_record_id, Some(record_id));
        assert_eq!(item.mru_rank, Some(mru));
        assert_eq!(item.timestamp, Some(1_700_100_000));
    }

    #[test]
    fn parse_destlist_structured_parses_multiple_entries() {
        let mut bytes = b"DestList".to_vec();
        bytes.resize(32, 0);

        let p1 = r"C:\Windows\System32\cmd.exe";
        let p2 = r"C:\Users\lab\Desktop\notes.txt";
        let ft1 = (FILETIME_UNIX_EPOCH_OFFSET + 1_700_010_000u64) * 10_000_000u64;
        let ft2 = (FILETIME_UNIX_EPOCH_OFFSET + 1_700_020_000u64) * 10_000_000u64;

        for (idx, (path, ft)) in [(p1, ft1), (p2, ft2)].into_iter().enumerate() {
            let rec_start = bytes.len();
            bytes.resize(rec_start + 114, 0);
            bytes[rec_start + 84..rec_start + 88]
                .copy_from_slice(&((idx + 1) as u32).to_le_bytes());
            bytes[rec_start + 88..rec_start + 96]
                .copy_from_slice(&(0xAA00u64 + idx as u64).to_le_bytes());
            bytes[rec_start + 100..rec_start + 108].copy_from_slice(&ft.to_le_bytes());
            bytes[rec_start + 112..rec_start + 114]
                .copy_from_slice(&(path.encode_utf16().count() as u16).to_le_bytes());
            for u in path.encode_utf16() {
                bytes.extend_from_slice(&u.to_le_bytes());
            }
        }

        let entries = parse_jumplist_binary_with_app_id(&bytes, Some("destapp"));
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.target_path.as_deref() == Some(p1)));
        assert!(entries.iter().any(|e| e.target_path.as_deref() == Some(p2)));
        assert!(entries.iter().all(|e| e.app_id == "destapp"));
    }

    #[test]
    fn parse_destlist_structured_ignores_truncated_tail_record() {
        let mut bytes = b"DestList".to_vec();
        bytes.resize(32, 0);

        let path = r"C:\Users\lab\Desktop\stable.txt";
        let rec_start = bytes.len();
        bytes.resize(rec_start + 114, 0);
        bytes[rec_start + 84..rec_start + 88].copy_from_slice(&1u32.to_le_bytes());
        bytes[rec_start + 88..rec_start + 96].copy_from_slice(&0xAA11u64.to_le_bytes());
        bytes[rec_start + 112..rec_start + 114]
            .copy_from_slice(&(path.encode_utf16().count() as u16).to_le_bytes());
        for u in path.encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }

        // Append truncated tail record that advertises a path but lacks bytes.
        let bad_start = bytes.len();
        bytes.resize(bad_start + 114, 0);
        bytes[bad_start + 112..bad_start + 114].copy_from_slice(&200u16.to_le_bytes());
        bytes.truncate(bytes.len().saturating_sub(40));

        let entries = parse_jumplist_binary_with_app_id(&bytes, Some("destapp"));
        assert!(entries
            .iter()
            .any(|e| e.target_path.as_deref() == Some(path)));
    }

    #[test]
    fn dedupe_and_sort_entries_prefers_lower_rank_and_record_id() {
        let in_entries = vec![
            JumpListEntry {
                entry_type: JumpListEntryType::Frequent,
                target_path: Some(r"C:\Temp\A.txt".to_string()),
                arguments: None,
                timestamp: Some(1_700_000_000),
                app_id: "app".to_string(),
                source_record_id: None,
                mru_rank: Some(8),
            },
            JumpListEntry {
                entry_type: JumpListEntryType::Frequent,
                target_path: Some(r"c:\temp\a.txt".to_string()),
                arguments: None,
                timestamp: Some(1_700_000_100),
                app_id: "app".to_string(),
                source_record_id: Some(77),
                mru_rank: Some(2),
            },
        ];

        let out = dedupe_and_sort_entries(in_entries);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].mru_rank, Some(2));
        assert_eq!(out[0].source_record_id, Some(77));
    }

    #[test]
    fn dedupe_and_sort_entries_orders_by_rank_then_timestamp() {
        let in_entries = vec![
            JumpListEntry {
                entry_type: JumpListEntryType::Frequent,
                target_path: Some(r"C:\Temp\B.txt".to_string()),
                arguments: None,
                timestamp: Some(1_700_000_300),
                app_id: "app".to_string(),
                source_record_id: None,
                mru_rank: Some(4),
            },
            JumpListEntry {
                entry_type: JumpListEntryType::Frequent,
                target_path: Some(r"C:\Temp\C.txt".to_string()),
                arguments: None,
                timestamp: Some(1_700_000_100),
                app_id: "app".to_string(),
                source_record_id: None,
                mru_rank: Some(1),
            },
            JumpListEntry {
                entry_type: JumpListEntryType::Frequent,
                target_path: Some(r"C:\Temp\A.txt".to_string()),
                arguments: None,
                timestamp: Some(1_700_000_500),
                app_id: "app".to_string(),
                source_record_id: None,
                mru_rank: Some(4),
            },
        ];

        let out = dedupe_and_sort_entries(in_entries);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].target_path.as_deref(), Some(r"C:\Temp\C.txt"));
        assert_eq!(out[1].target_path.as_deref(), Some(r"C:\Temp\A.txt"));
        assert_eq!(out[2].target_path.as_deref(), Some(r"C:\Temp\B.txt"));
    }

    #[test]
    fn detect_jumplist_input_shape_supports_directory_json_csv() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("jumplist");
        let auto = temp.path().join("sample.automaticdestinations-ms");
        let custom = temp.path().join("sample.customdestinations-ms");
        let lnk = temp.path().join("sample.lnk");
        let json = temp.path().join("jumplist.json");
        let csv = temp.path().join("jumplist.csv");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&auto, b"DestList").unwrap();
        std::fs::write(&custom, b"DestList").unwrap();
        std::fs::write(&lnk, b"L").unwrap();
        std::fs::write(
            &json,
            r#"{"entries":[{"entry_type":"recent","target_path":"C:/Windows/System32/cmd.exe"}]}"#,
        )
        .unwrap();
        std::fs::write(
            &csv,
            "entry_type,target_path,arguments,timestamp,app_id,mru_rank\nrecent,C:\\Windows\\System32\\cmd.exe,,1700001000,app,1\n",
        )
        .unwrap();

        assert_eq!(
            detect_jumplist_input_shape(&dir),
            JumpListInputShape::Directory
        );
        assert_eq!(
            detect_jumplist_input_shape(&auto),
            JumpListInputShape::AutomaticDestinations
        );
        assert_eq!(
            detect_jumplist_input_shape(&custom),
            JumpListInputShape::CustomDestinations
        );
        assert_eq!(
            detect_jumplist_input_shape(&lnk),
            JumpListInputShape::LnkFile
        );
        assert_eq!(
            detect_jumplist_input_shape(&json),
            JumpListInputShape::JsonObject
        );
        assert_eq!(
            detect_jumplist_input_shape(&csv),
            JumpListInputShape::CsvText
        );
    }

    #[test]
    fn parse_jumplist_entries_from_path_parses_json_rows() {
        let temp = tempfile::tempdir().unwrap();
        let json = temp.path().join("jumplist.json");
        std::fs::write(
            &json,
            r#"{"entries":[{"entry_type":"recent","target_path":"C:/Windows/System32/cmd.exe","timestamp_unix":1700005000,"app_id":"shell","mru_rank":2}]}"#,
        )
        .unwrap();

        let rows = parse_jumplist_entries_from_path(&json, 20);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].target_path.as_deref(),
            Some(r"C:\Windows\System32\cmd.exe")
        );
        assert_eq!(rows[0].timestamp, Some(1_700_005_000));
        assert_eq!(rows[0].app_id, "shell");
        assert_eq!(rows[0].mru_rank, Some(2));
    }

    #[test]
    fn parse_jumplist_entries_from_path_supports_nested_alias_fields_and_ms_timestamps() {
        let temp = tempfile::tempdir().unwrap();
        let json = temp.path().join("jumplist_aliases.json");
        std::fs::write(
            &json,
            r#"{"data":{"items":[{"type":"recent","destination":"C:/Program Files/Tool/tool.exe","command_line":"--scan --fast","last_accessed_unix":"1700005000123","appId":"tool-shell","rank":"3","record_id":"0x10"}]}}"#,
        )
        .unwrap();

        let rows = parse_jumplist_entries_from_path(&json, 20);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].target_path.as_deref(),
            Some(r"C:\Program Files\Tool\tool.exe")
        );
        assert_eq!(rows[0].timestamp, Some(1_700_005_000));
        assert_eq!(rows[0].app_id, "tool-shell");
        assert_eq!(rows[0].mru_rank, Some(3));
        assert_eq!(rows[0].source_record_id, Some(16));
        assert_eq!(rows[0].arguments.as_deref(), Some("--scan --fast"));
    }

    #[test]
    fn parse_jumplist_entries_from_path_normalizes_filetime_timestamps() {
        let temp = tempfile::tempdir().unwrap();
        let json = temp.path().join("jumplist_filetime.json");
        std::fs::write(
            &json,
            r#"{"rows":[{"entry_type":"recent","target_path":"C:/Windows/System32/notepad.exe","timestamp":"133860816000000000","app_id":"shell"}]}"#,
        )
        .unwrap();

        let rows = parse_jumplist_entries_from_path(&json, 20);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].timestamp, Some(1_741_608_000));
    }

    #[test]
    fn parse_jumplist_entries_from_path_csv_header_maps_fields_and_handles_quoted_path() {
        let temp = tempfile::tempdir().unwrap();
        let csv = temp.path().join("jumplist_aliases.csv");
        std::fs::write(
            &csv,
            "type,path,command_line,last_accessed,app_name,rank,record_id\nrecent,\"C:/Users/Analyst/My, Folder/report.docx\",\"/safe /preview\",2026-03-10 09:00:00,shell,5,22\n",
        )
        .unwrap();

        let rows = parse_jumplist_entries_from_path(&csv, 20);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].target_path.as_deref(),
            Some(r"C:\Users\Analyst\My, Folder\report.docx")
        );
        assert_eq!(rows[0].app_id, "shell");
        assert_eq!(rows[0].mru_rank, Some(5));
        assert_eq!(rows[0].source_record_id, Some(22));
        assert_eq!(rows[0].arguments.as_deref(), Some("/safe /preview"));
        assert!(rows[0].timestamp.is_some());
    }

    #[test]
    fn parse_jumplist_entries_from_path_pipe_header_maps_fields() {
        let temp = tempfile::tempdir().unwrap();
        let txt = temp.path().join("jumplist_pipe.txt");
        std::fs::write(
            &txt,
            "entry_type|target|args|occurred_utc|application|mru\nfrequent|C:/Windows/System32/calc.exe|/n|2026-03-10T09:00:00Z|shell|7\n",
        )
        .unwrap();

        let rows = parse_jumplist_text_fallback(&txt);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].target_path.as_deref(),
            Some(r"C:\Windows\System32\calc.exe")
        );
        assert_eq!(rows[0].app_id, "shell");
        assert_eq!(rows[0].mru_rank, Some(7));
        assert_eq!(rows[0].arguments.as_deref(), Some("/n"));
        assert!(matches!(rows[0].entry_type, JumpListEntryType::Frequent));
    }

    #[test]
    fn parse_jumplist_text_fallback_handles_partial_rows() {
        let temp = tempfile::tempdir().unwrap();
        let txt = temp.path().join("jumplist.txt");
        std::fs::write(
            &txt,
            "1700001000|C:/Windows/System32/cmd.exe|shell|recent|/c whoami\n1700000000|C:/Windows/System32/notepad.exe|shell|frequent|\n",
        )
        .unwrap();

        let rows = parse_jumplist_text_fallback(&txt);
        assert_eq!(rows.len(), 2);
        assert!(rows
            .iter()
            .any(|v| v.target_path.as_deref() == Some(r"C:\Windows\System32\cmd.exe")));
        assert!(rows
            .iter()
            .any(|v| matches!(v.entry_type, JumpListEntryType::Frequent)));
    }
}
