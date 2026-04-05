use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct TimelineCorrelationQaRecord {
    pub source: String,
    pub event_type: String,
    pub event_category: Option<String>,
    pub summary: Option<String>,
    pub severity: String,
    pub timestamp_unix: Option<i64>,
    pub timestamp_utc: Option<String>,
    pub timestamp_precision: String,
    pub executable_name: Option<String>,
    pub command: Option<String>,
    pub path: Option<String>,
    pub source_module: Option<String>,
    pub source_record_id: Option<String>,
    pub case_id: Option<String>,
    pub evidence_id: Option<String>,
    pub actor: Option<String>,
    pub data_json: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimelineCorrelationInputShape {
    Missing,
    Empty,
    Directory,
    JsonArray,
    JsonObject,
    CsvText,
    LineText,
    Unknown,
}

impl TimelineCorrelationInputShape {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Empty => "empty",
            Self::Directory => "directory",
            Self::JsonArray => "json-array",
            Self::JsonObject => "json-object",
            Self::CsvText => "csv-text",
            Self::LineText => "line-text",
            Self::Unknown => "unknown",
        }
    }
}

pub fn detect_timeline_correlation_input_shape(path: &Path) -> TimelineCorrelationInputShape {
    if !path.exists() {
        return TimelineCorrelationInputShape::Missing;
    }
    if path.is_dir() {
        return TimelineCorrelationInputShape::Directory;
    }
    let Ok(bytes) = strata_fs::read(path) else {
        return TimelineCorrelationInputShape::Unknown;
    };
    if bytes.is_empty() {
        return TimelineCorrelationInputShape::Empty;
    }
    let text = String::from_utf8_lossy(&bytes);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return TimelineCorrelationInputShape::Empty;
    }
    if trimmed.starts_with('[') {
        return TimelineCorrelationInputShape::JsonArray;
    }
    if trimmed.starts_with('{') {
        return TimelineCorrelationInputShape::JsonObject;
    }
    let first = trimmed
        .lines()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if first.contains("timestamp")
        || first.contains("source")
        || first.contains("event_type")
        || first.contains("severity")
    {
        return TimelineCorrelationInputShape::CsvText;
    }
    TimelineCorrelationInputShape::LineText
}

pub fn parse_timeline_correlation_qa_records_from_path(
    path: &Path,
    limit: usize,
) -> Vec<TimelineCorrelationQaRecord> {
    if !path.exists() || limit == 0 {
        return Vec::new();
    }

    let mut rows = if path.is_dir() {
        parse_dir(path, limit)
    } else {
        parse_file(path)
    };
    if rows.is_empty() {
        rows = parse_timeline_correlation_qa_text_fallback(path);
    }

    let mut seen = BTreeSet::<String>::new();
    rows.retain(|row| {
        let key = format!(
            "{}|{}|{}|{}|{}|{}",
            row.source,
            row.event_type,
            row.timestamp_unix
                .map(|v| v.to_string())
                .unwrap_or_default(),
            row.executable_name.clone().unwrap_or_default(),
            row.source_record_id.clone().unwrap_or_default(),
            row.summary.clone().unwrap_or_default()
        );
        seen.insert(key)
    });

    rows.sort_by(|a, b| {
        b.timestamp_unix
            .is_some()
            .cmp(&a.timestamp_unix.is_some())
            .then_with(|| {
                b.timestamp_unix
                    .unwrap_or_default()
                    .cmp(&a.timestamp_unix.unwrap_or_default())
            })
            .then_with(|| a.source.cmp(&b.source))
            .then_with(|| a.event_type.cmp(&b.event_type))
            .then_with(|| {
                a.executable_name
                    .as_deref()
                    .unwrap_or_default()
                    .cmp(b.executable_name.as_deref().unwrap_or_default())
            })
    });
    rows.truncate(limit);
    rows
}

pub fn parse_timeline_correlation_qa_text_fallback(
    path: &Path,
) -> Vec<TimelineCorrelationQaRecord> {
    if !path.exists() {
        return Vec::new();
    }
    let Ok(content) = strata_fs::read_to_string(path) else {
        return Vec::new();
    };
    parse_csv_or_lines(&content)
}

fn parse_dir(path: &Path, limit: usize) -> Vec<TimelineCorrelationQaRecord> {
    let mut out = Vec::new();
    let Ok(entries) = strata_fs::read_dir(path) else {
        return out;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            let mut nested = parse_dir(&p, limit.saturating_sub(out.len()));
            out.append(&mut nested);
        } else {
            let mut rows = parse_file(&p);
            out.append(&mut rows);
        }
        if out.len() >= limit {
            break;
        }
    }
    out
}

fn parse_file(path: &Path) -> Vec<TimelineCorrelationQaRecord> {
    let Ok(bytes) = strata_fs::read(path) else {
        return Vec::new();
    };
    if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
        return parse_json_value(&value);
    }
    parse_csv_or_lines(String::from_utf8_lossy(&bytes).as_ref())
}

fn parse_json_value(value: &Value) -> Vec<TimelineCorrelationQaRecord> {
    let rows = if let Some(arr) = value.as_array() {
        arr.clone()
    } else if let Some(obj) = value.as_object() {
        obj.get("records")
            .and_then(Value::as_array)
            .or_else(|| obj.get("events").and_then(Value::as_array))
            .or_else(|| obj.get("entries").and_then(Value::as_array))
            .or_else(|| obj.get("items").and_then(Value::as_array))
            .or_else(|| obj.get("results").and_then(Value::as_array))
            .or_else(|| obj.get("correlations").and_then(Value::as_array))
            .or_else(|| obj.get("data").and_then(Value::as_array))
            .cloned()
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let mut out = Vec::new();
    for row in rows {
        let Some(obj) = row.as_object() else {
            continue;
        };
        let ts = parse_ts(
            obj.get("timestamp_unix")
                .or_else(|| obj.get("timestamp"))
                .or_else(|| obj.get("timestamp_utc"))
                .or_else(|| obj.get("occurred_utc"))
                .or_else(|| obj.get("last_seen_unix"))
                .or_else(|| obj.get("last_seen_utc"))
                .or_else(|| obj.get("first_seen_unix"))
                .or_else(|| obj.get("first_seen_utc")),
        );
        let source = obj
            .get("source")
            .and_then(Value::as_str)
            .or_else(|| obj.get("source_module").and_then(Value::as_str))
            .map(normalize_token)
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "timeline-correlation-qa".to_string());
        let event_type = obj
            .get("event_type")
            .and_then(Value::as_str)
            .or_else(|| obj.get("type").and_then(Value::as_str))
            .map(normalize_token)
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "timeline-event".to_string());
        let command = obj
            .get("command")
            .and_then(Value::as_str)
            .map(normalize_path_like);
        let path = obj
            .get("path")
            .and_then(Value::as_str)
            .or_else(|| obj.get("target_path").and_then(Value::as_str))
            .map(normalize_path_like);
        let executable_name = obj
            .get("executable_name")
            .and_then(Value::as_str)
            .map(|v| v.trim().to_ascii_lowercase())
            .filter(|v| !v.is_empty())
            .or_else(|| {
                command
                    .as_deref()
                    .and_then(executable_name_from_command_text)
            })
            .or_else(|| path.as_deref().and_then(executable_name_from_hint));
        let severity = obj
            .get("severity")
            .and_then(Value::as_str)
            .map(normalize_severity)
            .unwrap_or_else(|| "info".to_string());

        out.push(TimelineCorrelationQaRecord {
            source,
            event_type,
            event_category: obj
                .get("event_category")
                .and_then(Value::as_str)
                .or_else(|| obj.get("category").and_then(Value::as_str))
                .or_else(|| obj.get("kind").and_then(Value::as_str))
                .map(normalize_token),
            summary: obj
                .get("summary")
                .and_then(Value::as_str)
                .or_else(|| obj.get("message").and_then(Value::as_str))
                .or_else(|| obj.get("description").and_then(Value::as_str))
                .or_else(|| obj.get("title").and_then(Value::as_str))
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            severity,
            timestamp_unix: ts.0,
            timestamp_utc: ts.1,
            timestamp_precision: ts.2,
            executable_name,
            command,
            path,
            source_module: obj
                .get("source_module")
                .and_then(Value::as_str)
                .map(normalize_token)
                .filter(|v| !v.is_empty()),
            source_record_id: obj
                .get("source_record_id")
                .and_then(Value::as_str)
                .or_else(|| obj.get("record_id").and_then(Value::as_str))
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            case_id: obj
                .get("case_id")
                .and_then(Value::as_str)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            evidence_id: obj
                .get("evidence_id")
                .and_then(Value::as_str)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            actor: obj
                .get("actor")
                .and_then(Value::as_str)
                .or_else(|| obj.get("user").and_then(Value::as_str))
                .or_else(|| obj.get("username").and_then(Value::as_str))
                .map(normalize_actor),
            data_json: obj
                .get("data_json")
                .and_then(Value::as_str)
                .map(|v| v.to_string())
                .or_else(|| obj.get("data").map(|v| v.to_string())),
        });
    }
    out
}

fn parse_csv_or_lines(content: &str) -> Vec<TimelineCorrelationQaRecord> {
    let mut out = Vec::new();
    let mut lines = content.lines().map(str::trim).filter(|v| !v.is_empty());
    let Some(first) = lines.next() else {
        return out;
    };
    let delimiter = if first.contains(',') {
        Some(',')
    } else if first.contains('|') {
        Some('|')
    } else {
        None
    };
    if let Some(delim) = delimiter {
        let headers = split_delimited_line(first, delim)
            .into_iter()
            .map(|v| normalize_token(&v))
            .collect::<Vec<_>>();
        for line in lines {
            let cells = split_delimited_line(line, delim);
            let cols = cells.iter().map(|v| v.as_str()).collect::<Vec<_>>();
            if cols.iter().all(|v| v.is_empty()) {
                continue;
            }
            let get = |name: &str| -> Option<&str> {
                headers
                    .iter()
                    .position(|h| h == name)
                    .and_then(|idx| cols.get(idx).copied())
            };
            let source = get("source")
                .or_else(|| get("source-module"))
                .map(normalize_token)
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "timeline-correlation-qa".to_string());
            let event_type = get("event-type")
                .or_else(|| get("type"))
                .map(normalize_token)
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "timeline-event".to_string());
            let ts = parse_ts_str(
                get("timestamp-unix")
                    .or_else(|| get("timestamp"))
                    .or_else(|| get("timestamp-utc"))
                    .or_else(|| get("occurred-utc"))
                    .or_else(|| get("last-seen-unix"))
                    .or_else(|| get("last-seen-utc"))
                    .or_else(|| get("first-seen-unix"))
                    .or_else(|| get("first-seen-utc"))
                    .unwrap_or_default(),
            );
            let command = get("command").map(normalize_path_like);
            let path = get("path")
                .or_else(|| get("target-path"))
                .map(normalize_path_like);
            let executable_name = get("executable-name")
                .map(|v| v.trim().to_ascii_lowercase())
                .filter(|v| !v.is_empty())
                .or_else(|| {
                    command
                        .as_deref()
                        .and_then(executable_name_from_command_text)
                })
                .or_else(|| path.as_deref().and_then(executable_name_from_hint));
            let severity = get("severity")
                .map(normalize_severity)
                .unwrap_or_else(|| "info".to_string());

            out.push(TimelineCorrelationQaRecord {
                source,
                event_type,
                event_category: get("event-category")
                    .or_else(|| get("category"))
                    .or_else(|| get("kind"))
                    .map(normalize_token),
                summary: get("summary")
                    .or_else(|| get("message"))
                    .or_else(|| get("description"))
                    .or_else(|| get("title"))
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty()),
                severity,
                timestamp_unix: ts.0,
                timestamp_utc: ts.1,
                timestamp_precision: ts.2,
                executable_name,
                command,
                path,
                source_module: get("source-module")
                    .map(normalize_token)
                    .filter(|v| !v.is_empty()),
                source_record_id: get("source-record-id")
                    .or_else(|| get("record-id"))
                    .map(|v| v.to_string())
                    .filter(|v| !v.is_empty()),
                case_id: get("case-id")
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty()),
                evidence_id: get("evidence-id")
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty()),
                actor: get("actor")
                    .or_else(|| get("user"))
                    .or_else(|| get("username"))
                    .map(normalize_actor),
                data_json: get("data-json")
                    .or_else(|| get("data"))
                    .map(|v| v.to_string())
                    .filter(|v| !v.is_empty()),
            });
        }
        return out;
    }

    for line in std::iter::once(first).chain(lines) {
        let ts = parse_ts_str(line);
        let severity = if line.to_ascii_lowercase().contains("error") {
            "error".to_string()
        } else if line.to_ascii_lowercase().contains("warn") {
            "warn".to_string()
        } else {
            "info".to_string()
        };
        out.push(TimelineCorrelationQaRecord {
            source: "timeline-correlation-qa".to_string(),
            event_type: "timeline-line".to_string(),
            event_category: Some("line-fallback".to_string()),
            summary: Some(line.to_string()),
            severity,
            timestamp_unix: ts.0,
            timestamp_utc: ts.1,
            timestamp_precision: ts.2,
            executable_name: executable_name_from_command_text(line),
            command: Some(line.to_string()),
            path: None,
            source_module: Some("timeline-correlation-qa".to_string()),
            source_record_id: None,
            case_id: None,
            evidence_id: None,
            actor: None,
            data_json: None,
        });
    }
    out
}

fn parse_ts(value: Option<&Value>) -> (Option<i64>, Option<String>, String) {
    let Some(v) = value else {
        return (None, None, "none".to_string());
    };
    if let Some(n) = value_to_i64(v) {
        return normalize_epochish_ts(n);
    }
    if let Some(s) = v.as_str() {
        return parse_ts_str(s);
    }
    (None, None, "none".to_string())
}

fn parse_ts_str(value: &str) -> (Option<i64>, Option<String>, String) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return (None, None, "none".to_string());
    }
    if let Ok(v) = trimmed.parse::<i64>() {
        return normalize_epochish_ts(v);
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        let ts = dt.timestamp();
        return (Some(ts), Some(ts_to_utc(ts)), "seconds".to_string());
    }
    for format in [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y/%m/%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    ] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(trimmed, format) {
            let ts = DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc).timestamp();
            return (Some(ts), Some(ts_to_utc(ts)), "seconds".to_string());
        }
    }
    (None, None, "none".to_string())
}

fn normalize_epochish_ts(value: i64) -> (Option<i64>, Option<String>, String) {
    if value <= 0 {
        return (None, None, "none".to_string());
    }
    let (ts, precision) = if value > 11_644_473_600_000_000 {
        (
            (value / 10_000_000) - 11_644_473_600,
            "filetime".to_string(),
        )
    } else if value > 10_000_000_000 {
        (value / 1_000, "milliseconds".to_string())
    } else {
        (value, "seconds".to_string())
    };
    (Some(ts), Some(ts_to_utc(ts)), precision)
}

fn ts_to_utc(ts: i64) -> String {
    DateTime::<Utc>::from_timestamp(ts, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| ts.to_string())
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

fn value_to_i64(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|v| i64::try_from(v).ok()))
        .or_else(|| value.as_str().and_then(|v| v.trim().parse::<i64>().ok()))
}

fn normalize_token(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace(['_', ' '], "-")
}

fn normalize_path_like(value: &str) -> String {
    value.trim().trim_matches('"').replace('/', "\\")
}

fn normalize_actor(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn normalize_severity(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "error" | "critical" | "high" => "error".to_string(),
        "warn" | "warning" | "medium" => "warn".to_string(),
        _ => "info".to_string(),
    }
}

fn executable_name_from_hint(value: &str) -> Option<String> {
    let normalized = value.trim().trim_matches('"').replace('/', "\\");
    if normalized.is_empty() {
        return None;
    }
    let basename = normalized.rsplit('\\').next().unwrap_or_default().trim();
    let lower = basename.to_ascii_lowercase();
    if lower.ends_with(".exe")
        || lower.ends_with(".com")
        || lower.ends_with(".bat")
        || lower.ends_with(".cmd")
        || lower.ends_with(".ps1")
    {
        Some(lower)
    } else {
        None
    }
}

fn executable_name_from_command_text(value: &str) -> Option<String> {
    if value.trim().is_empty() {
        return None;
    }
    for token in value.split_whitespace() {
        let candidate = token.trim_matches(|c: char| {
            c == '"'
                || c == '\''
                || c == ','
                || c == ';'
                || c == '('
                || c == ')'
                || c == '['
                || c == ']'
        });
        if let Some(exe) = executable_name_from_hint(candidate) {
            return Some(exe);
        }
    }
    executable_name_from_hint(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn detect_timeline_correlation_input_shape_json_csv_directory() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("qa");
        let json = dir.path().join("timeline.json");
        let csv = dir.path().join("timeline.csv");
        strata_fs::create_dir_all(&root).unwrap();
        strata_fs::write(&json, r#"[{"timestamp_unix":1700000000}]"#).unwrap();
        strata_fs::write(
            &csv,
            "timestamp_unix,source,event_type\n1700000000,prefetch,exec\n",
        )
        .unwrap();

        assert_eq!(
            detect_timeline_correlation_input_shape(&root),
            TimelineCorrelationInputShape::Directory
        );
        assert_eq!(
            detect_timeline_correlation_input_shape(&json),
            TimelineCorrelationInputShape::JsonArray
        );
        assert_eq!(
            detect_timeline_correlation_input_shape(&csv),
            TimelineCorrelationInputShape::CsvText
        );
    }

    #[test]
    fn parse_timeline_correlation_qa_records_from_path_parses_json_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("timeline.json");
        strata_fs::write(
            &path,
            r#"[{"source":"execution","event_type":"prefetch-run","timestamp_unix":1700000200,"executable_name":"cmd.exe","severity":"warn"}]"#,
        )
        .unwrap();

        let rows = parse_timeline_correlation_qa_records_from_path(&path, 10);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].source, "execution");
        assert_eq!(rows[0].event_type, "prefetch-run");
        assert_eq!(rows[0].timestamp_unix, Some(1_700_000_200));
        assert_eq!(rows[0].severity, "warn");
    }

    #[test]
    fn parse_timeline_correlation_qa_text_fallback_handles_partial_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("timeline.txt");
        strata_fs::write(&path, "powershell.exe -enc TEST").unwrap();

        let rows = parse_timeline_correlation_qa_text_fallback(&path);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_type, "timeline-line");
        assert_eq!(rows[0].executable_name.as_deref(), Some("powershell.exe"));
    }

    #[test]
    fn parse_timeline_correlation_csv_supports_quoted_commas() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("timeline.csv");
        strata_fs::write(
            &path,
            "timestamp_unix,source,event_type,path,summary\n1700000200,execution,prefetch-run,\"C:\\Users\\lab\\My, Folder\\cmd.exe\",\"opened, with args\"\n",
        )
        .unwrap();

        let rows = parse_timeline_correlation_qa_records_from_path(&path, 10);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].path.as_deref(),
            Some("C:\\Users\\lab\\My, Folder\\cmd.exe")
        );
        assert_eq!(rows[0].executable_name.as_deref(), Some("cmd.exe"));
        assert_eq!(rows[0].summary.as_deref(), Some("opened, with args"));
    }

    #[test]
    fn parse_timeline_correlation_pipe_delimited_header_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("timeline_pipe.txt");
        strata_fs::write(
            &path,
            "timestamp|source|event_type|severity|command\n1700000300|execution|command-run|warning|\"C:\\Windows\\System32\\cmd.exe\" /c whoami\n",
        )
        .unwrap();

        let rows = parse_timeline_correlation_qa_records_from_path(&path, 10);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].source, "execution");
        assert_eq!(rows[0].event_type, "command-run");
        assert_eq!(rows[0].severity, "warn");
        assert_eq!(rows[0].executable_name.as_deref(), Some("cmd.exe"));
    }

    #[test]
    fn parse_timeline_correlation_filetime_timestamps() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("timeline_filetime.json");
        strata_fs::write(
            &path,
            r#"[{"source":"execution","event_type":"usn-change","timestamp_unix":133860816000000000}]"#,
        )
        .unwrap();

        let rows = parse_timeline_correlation_qa_records_from_path(&path, 10);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].timestamp_unix, Some(1_741_608_000));
        assert_eq!(rows[0].timestamp_precision, "filetime");
        assert!(rows[0].timestamp_utc.is_some());
    }

    #[test]
    fn parse_timeline_correlation_legacy_datetime_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("timeline_legacy.csv");
        strata_fs::write(
            &path,
            "timestamp,source,event_type\n2026-03-10 09:00:00,execution,prefetch-run\n",
        )
        .unwrap();

        let rows = parse_timeline_correlation_qa_records_from_path(&path, 10);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].timestamp_unix.is_some());
        assert_eq!(rows[0].timestamp_precision, "seconds");
    }
}
