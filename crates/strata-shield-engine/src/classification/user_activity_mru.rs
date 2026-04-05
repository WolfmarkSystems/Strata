use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct UserActivityMruRecord {
    pub source: String,
    pub event_type: String,
    pub timestamp_unix: Option<i64>,
    pub timestamp_utc: Option<String>,
    pub timestamp_precision: String,
    pub command: Option<String>,
    pub path: Option<String>,
    pub program_name: Option<String>,
    pub executable_name: Option<String>,
    pub mru_index: Option<u32>,
    pub run_count: Option<u32>,
    pub user_sid: Option<String>,
    pub username: Option<String>,
    pub source_path: Option<String>,
    pub source_record_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserActivityMruInputShape {
    Missing,
    Empty,
    Directory,
    JsonArray,
    JsonObject,
    CsvText,
    RegExportText,
    LineText,
    Unknown,
}

impl UserActivityMruInputShape {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Empty => "empty",
            Self::Directory => "directory",
            Self::JsonArray => "json-array",
            Self::JsonObject => "json-object",
            Self::CsvText => "csv-text",
            Self::RegExportText => "reg-export",
            Self::LineText => "line-text",
            Self::Unknown => "unknown",
        }
    }
}

pub fn detect_user_activity_mru_input_shape(path: &Path) -> UserActivityMruInputShape {
    if !path.exists() {
        return UserActivityMruInputShape::Missing;
    }
    if path.is_dir() {
        return UserActivityMruInputShape::Directory;
    }
    let Ok(bytes) = strata_fs::read(path) else {
        return UserActivityMruInputShape::Unknown;
    };
    if bytes.is_empty() {
        return UserActivityMruInputShape::Empty;
    }
    let text = String::from_utf8_lossy(&bytes);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return UserActivityMruInputShape::Empty;
    }
    if trimmed.starts_with("Windows Registry Editor") {
        return UserActivityMruInputShape::RegExportText;
    }
    if trimmed.starts_with('{') {
        return UserActivityMruInputShape::JsonObject;
    }
    if trimmed.starts_with('[') {
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("[hkey_") || lower.starts_with("[hkeylocalmachine") {
            return UserActivityMruInputShape::RegExportText;
        }
        return UserActivityMruInputShape::JsonArray;
    }
    let first = trimmed
        .lines()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if first.contains("source")
        || first.contains("runmru")
        || first.contains("opensave")
        || first.contains("userassist")
        || first.contains("recentdocs")
    {
        return UserActivityMruInputShape::CsvText;
    }
    UserActivityMruInputShape::LineText
}

pub fn parse_user_activity_mru_records_from_path(
    path: &Path,
    limit: usize,
) -> Vec<UserActivityMruRecord> {
    if !path.exists() || limit == 0 {
        return Vec::new();
    }

    let mut rows = if path.is_dir() {
        parse_dir(path, limit)
    } else {
        parse_file(path)
    };
    if rows.is_empty() {
        rows = parse_user_activity_mru_text_fallback(path);
    }

    let mut seen = BTreeSet::<String>::new();
    rows.retain(|row| {
        let key = format!(
            "{}|{}|{}|{}|{}|{}|{}",
            row.source,
            row.command.clone().unwrap_or_default(),
            row.path.clone().unwrap_or_default(),
            row.program_name.clone().unwrap_or_default(),
            row.timestamp_unix
                .map(|v| v.to_string())
                .unwrap_or_default(),
            row.user_sid.clone().unwrap_or_default(),
            row.source_record_id.clone().unwrap_or_default()
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
            .then_with(|| {
                a.command
                    .as_deref()
                    .unwrap_or_default()
                    .cmp(b.command.as_deref().unwrap_or_default())
            })
            .then_with(|| {
                a.path
                    .as_deref()
                    .unwrap_or_default()
                    .cmp(b.path.as_deref().unwrap_or_default())
            })
    });
    rows.truncate(limit);
    rows
}

pub fn parse_user_activity_mru_text_fallback(path: &Path) -> Vec<UserActivityMruRecord> {
    if !path.exists() {
        return Vec::new();
    }
    let Ok(content) = strata_fs::read_to_string(path) else {
        return Vec::new();
    };
    parse_csv_or_lines(&content)
}

fn parse_dir(path: &Path, limit: usize) -> Vec<UserActivityMruRecord> {
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

fn parse_file(path: &Path) -> Vec<UserActivityMruRecord> {
    let Ok(bytes) = strata_fs::read(path) else {
        return Vec::new();
    };
    if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
        return parse_json_value(&value);
    }
    parse_csv_or_lines(String::from_utf8_lossy(&bytes).as_ref())
}

fn parse_json_value(value: &Value) -> Vec<UserActivityMruRecord> {
    let rows = if let Some(arr) = value.as_array() {
        arr.clone()
    } else if let Some(obj) = value.as_object() {
        obj.get("records")
            .and_then(Value::as_array)
            .or_else(|| obj.get("entries").and_then(Value::as_array))
            .or_else(|| obj.get("items").and_then(Value::as_array))
            .or_else(|| obj.get("results").and_then(Value::as_array))
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
        let source = obj
            .get("source")
            .and_then(Value::as_str)
            .map(normalize_token)
            .unwrap_or_else(|| infer_source(obj).to_string());
        let event_type = obj
            .get("event_type")
            .and_then(Value::as_str)
            .map(normalize_token)
            .unwrap_or_else(|| infer_event_type(&source));
        let ts = parse_ts(
            obj.get("timestamp_unix")
                .or_else(|| obj.get("timestamp"))
                .or_else(|| obj.get("occurred_utc"))
                .or_else(|| obj.get("last_run"))
                .or_else(|| obj.get("last_run_utc")),
        );
        let command = obj
            .get("command")
            .and_then(Value::as_str)
            .or_else(|| obj.get("value").and_then(Value::as_str))
            .map(normalize_path_like);
        let path = obj
            .get("path")
            .and_then(Value::as_str)
            .or_else(|| obj.get("target").and_then(Value::as_str))
            .or_else(|| obj.get("name").and_then(Value::as_str))
            .map(normalize_path_like);
        let program_name = obj
            .get("program_name")
            .and_then(Value::as_str)
            .or_else(|| obj.get("program").and_then(Value::as_str))
            .map(normalize_path_like);
        let exe = obj
            .get("executable_name")
            .and_then(Value::as_str)
            .map(|v| v.trim().to_ascii_lowercase())
            .filter(|v| !v.is_empty())
            .or_else(|| command.as_deref().and_then(executable_name_from_hint))
            .or_else(|| path.as_deref().and_then(executable_name_from_hint))
            .or_else(|| program_name.as_deref().and_then(executable_name_from_hint));

        out.push(UserActivityMruRecord {
            source,
            event_type,
            timestamp_unix: ts.0,
            timestamp_utc: ts.1,
            timestamp_precision: ts.2,
            command,
            path,
            program_name,
            executable_name: exe,
            mru_index: obj
                .get("index")
                .and_then(value_to_i64)
                .and_then(|v| u32::try_from(v).ok())
                .or_else(|| {
                    obj.get("mru_index")
                        .and_then(value_to_i64)
                        .and_then(|v| u32::try_from(v).ok())
                }),
            run_count: obj
                .get("run_count")
                .and_then(value_to_i64)
                .and_then(|v| u32::try_from(v).ok()),
            user_sid: obj
                .get("user_sid")
                .and_then(Value::as_str)
                .or_else(|| obj.get("sid").and_then(Value::as_str))
                .map(normalize_sid),
            username: obj
                .get("username")
                .and_then(Value::as_str)
                .or_else(|| obj.get("user").and_then(Value::as_str))
                .map(normalize_username),
            source_path: obj
                .get("source_path")
                .and_then(Value::as_str)
                .map(normalize_path_like),
            source_record_id: obj
                .get("source_record_id")
                .and_then(Value::as_str)
                .or_else(|| obj.get("record_id").and_then(Value::as_str))
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
        });
    }
    out
}

fn parse_csv_or_lines(content: &str) -> Vec<UserActivityMruRecord> {
    let mut out = Vec::new();
    let mut lines = content.lines().map(str::trim).filter(|v| !v.is_empty());
    let Some(first) = lines.next() else {
        return out;
    };
    if first.contains(',') {
        let headers = first.split(',').map(normalize_token).collect::<Vec<_>>();
        for line in lines {
            let cols = line.split(',').map(|v| v.trim()).collect::<Vec<_>>();
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
                .map(normalize_token)
                .unwrap_or_else(|| "runmru".to_string());
            let event_type = get("event_type")
                .map(normalize_token)
                .unwrap_or_else(|| infer_event_type(&source));
            let ts = parse_ts_str(
                get("timestamp_unix")
                    .or_else(|| get("timestamp"))
                    .or_else(|| get("occurred_utc"))
                    .or_else(|| get("last_run"))
                    .unwrap_or_default(),
            );
            let command = get("command")
                .or_else(|| get("value"))
                .map(normalize_path_like);
            let path = get("path")
                .or_else(|| get("target"))
                .map(normalize_path_like);
            let program_name = get("program_name")
                .or_else(|| get("program"))
                .map(normalize_path_like);
            let executable_name = get("executable_name")
                .map(|v| v.trim().to_ascii_lowercase())
                .filter(|v| !v.is_empty())
                .or_else(|| command.as_deref().and_then(executable_name_from_hint))
                .or_else(|| path.as_deref().and_then(executable_name_from_hint))
                .or_else(|| program_name.as_deref().and_then(executable_name_from_hint));
            out.push(UserActivityMruRecord {
                source,
                event_type,
                timestamp_unix: ts.0,
                timestamp_utc: ts.1,
                timestamp_precision: ts.2,
                command,
                path,
                program_name,
                executable_name,
                mru_index: get("mru_index")
                    .or_else(|| get("index"))
                    .and_then(|v| v.parse::<u32>().ok()),
                run_count: get("run_count").and_then(|v| v.parse::<u32>().ok()),
                user_sid: get("user_sid").or_else(|| get("sid")).map(normalize_sid),
                username: get("username")
                    .or_else(|| get("user"))
                    .map(normalize_username),
                source_path: get("source_path").map(normalize_path_like),
                source_record_id: get("source_record_id")
                    .or_else(|| get("record_id"))
                    .map(|v| v.to_string())
                    .filter(|v| !v.is_empty()),
            });
        }
        return out;
    }

    for line in std::iter::once(first).chain(lines) {
        let ts = parse_ts_str(line);
        out.push(UserActivityMruRecord {
            source: "runmru".to_string(),
            event_type: "user-activity-line".to_string(),
            timestamp_unix: ts.0,
            timestamp_utc: ts.1,
            timestamp_precision: ts.2,
            command: Some(line.to_string()),
            path: None,
            program_name: None,
            executable_name: executable_name_from_command_text(line)
                .or_else(|| executable_name_from_hint(line)),
            mru_index: None,
            run_count: None,
            user_sid: None,
            username: None,
            source_path: None,
            source_record_id: None,
        });
    }
    out
}

fn infer_source(obj: &serde_json::Map<String, Value>) -> &'static str {
    if obj.get("run_count").is_some() || obj.get("program_name").is_some() {
        "userassist"
    } else if obj.get("command").is_some() || obj.get("value").is_some() {
        "runmru"
    } else if obj.get("path").is_some() {
        "opensave"
    } else {
        "recentdocs"
    }
}

fn infer_event_type(source: &str) -> String {
    match source {
        "userassist" => "userassist-program".to_string(),
        "opensave" => "opensave-path".to_string(),
        "recentdocs" => "recent-doc".to_string(),
        _ => "runmru-command".to_string(),
    }
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
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(trimmed) {
        let ts = dt.timestamp();
        return (Some(ts), Some(ts_to_utc(ts)), "seconds".to_string());
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S") {
        let ts = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(naive, chrono::Utc)
            .timestamp();
        return (Some(ts), Some(ts_to_utc(ts)), "seconds".to_string());
    }
    (None, None, "none".to_string())
}

fn normalize_epochish_ts(value: i64) -> (Option<i64>, Option<String>, String) {
    if value <= 0 {
        return (None, None, "none".to_string());
    }
    let (ts, precision) = if value > 10_000_000_000 {
        (value / 1_000, "milliseconds".to_string())
    } else {
        (value, "seconds".to_string())
    };
    (Some(ts), Some(ts_to_utc(ts)), precision)
}

fn ts_to_utc(ts: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| ts.to_string())
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

fn normalize_sid(value: &str) -> String {
    value.trim().to_ascii_uppercase()
}

fn normalize_username(value: &str) -> String {
    value.trim().to_ascii_lowercase()
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
    fn detect_user_activity_mru_input_shape_supports_directory_json_csv() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("activity");
        let json = dir.path().join("activity.json");
        let csv = dir.path().join("activity.csv");
        strata_fs::create_dir_all(&root).unwrap();
        strata_fs::write(&json, r#"[{"source":"runmru","command":"cmd.exe"}]"#).unwrap();
        strata_fs::write(&csv, "source,command\nrunmru,cmd.exe\n").unwrap();

        assert_eq!(
            detect_user_activity_mru_input_shape(&root),
            UserActivityMruInputShape::Directory
        );
        assert_eq!(
            detect_user_activity_mru_input_shape(&json),
            UserActivityMruInputShape::JsonArray
        );
        assert_eq!(
            detect_user_activity_mru_input_shape(&csv),
            UserActivityMruInputShape::CsvText
        );
    }

    #[test]
    fn parse_user_activity_mru_records_from_path_parses_json_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("activity.json");
        strata_fs::write(
            &path,
            r#"[{"source":"userassist","program_name":"C:\\Windows\\explorer.exe","run_count":4,"last_run":1700000200}]"#,
        )
        .unwrap();

        let rows = parse_user_activity_mru_records_from_path(&path, 10);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].source, "userassist");
        assert_eq!(rows[0].run_count, Some(4));
        assert_eq!(rows[0].timestamp_unix, Some(1_700_000_200));
    }

    #[test]
    fn parse_user_activity_mru_text_fallback_handles_partial_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("activity.txt");
        strata_fs::write(&path, "powershell.exe -nop").unwrap();

        let rows = parse_user_activity_mru_text_fallback(&path);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].source, "runmru");
        assert_eq!(rows[0].executable_name.as_deref(), Some("powershell.exe"));
    }
}
