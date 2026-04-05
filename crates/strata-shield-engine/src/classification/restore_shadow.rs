use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct RestoreShadowRecord {
    pub source: String,
    pub event_type: String,
    pub restore_point_id: Option<u32>,
    pub snapshot_id: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub restore_point_type: Option<String>,
    pub file_path: Option<String>,
    pub change_type: Option<String>,
    pub status: Option<String>,
    pub integrity_ok: Option<bool>,
    pub timestamp_unix: Option<i64>,
    pub timestamp_utc: Option<String>,
    pub timestamp_precision: String,
    pub user_sid: Option<String>,
    pub username: Option<String>,
    pub source_path: Option<String>,
    pub source_record_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreShadowInputShape {
    Missing,
    Empty,
    Directory,
    JsonArray,
    JsonObject,
    CsvText,
    LineText,
    Unknown,
}

impl RestoreShadowInputShape {
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

pub fn detect_restore_shadow_input_shape(path: &Path) -> RestoreShadowInputShape {
    if !path.exists() {
        return RestoreShadowInputShape::Missing;
    }
    if path.is_dir() {
        return RestoreShadowInputShape::Directory;
    }
    let Ok(bytes) = strata_fs::read(path) else {
        return RestoreShadowInputShape::Unknown;
    };
    if bytes.is_empty() {
        return RestoreShadowInputShape::Empty;
    }
    let text = String::from_utf8_lossy(&bytes);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return RestoreShadowInputShape::Empty;
    }
    if trimmed.starts_with('[') {
        return RestoreShadowInputShape::JsonArray;
    }
    if trimmed.starts_with('{') {
        return RestoreShadowInputShape::JsonObject;
    }
    let first = trimmed
        .lines()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if first.contains("restore")
        || first.contains("shadow")
        || first.contains("snapshot")
        || first.contains("creation")
    {
        return RestoreShadowInputShape::CsvText;
    }
    RestoreShadowInputShape::LineText
}

pub fn parse_restore_shadow_records_from_path(
    path: &Path,
    limit: usize,
) -> Vec<RestoreShadowRecord> {
    if !path.exists() || limit == 0 {
        return Vec::new();
    }

    let mut rows = if path.is_dir() {
        parse_dir(path, limit)
    } else {
        parse_file(path)
    };
    if rows.is_empty() {
        rows = parse_restore_shadow_text_fallback(path);
    }

    let mut seen = BTreeSet::<String>::new();
    rows.retain(|row| {
        let key = format!(
            "{}|{}|{}|{}|{}|{}",
            row.source,
            row.restore_point_id
                .map(|v| v.to_string())
                .unwrap_or_default(),
            row.snapshot_id.clone().unwrap_or_default(),
            row.timestamp_unix
                .map(|v| v.to_string())
                .unwrap_or_default(),
            row.file_path.clone().unwrap_or_default(),
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
                a.restore_point_id
                    .unwrap_or_default()
                    .cmp(&b.restore_point_id.unwrap_or_default())
            })
            .then_with(|| {
                a.snapshot_id
                    .as_deref()
                    .unwrap_or_default()
                    .cmp(b.snapshot_id.as_deref().unwrap_or_default())
            })
    });
    rows.truncate(limit);
    rows
}

pub fn parse_restore_shadow_text_fallback(path: &Path) -> Vec<RestoreShadowRecord> {
    if !path.exists() {
        return Vec::new();
    }
    let Ok(content) = strata_fs::read_to_string(path) else {
        return Vec::new();
    };
    parse_csv_or_lines(&content)
}

fn parse_dir(path: &Path, limit: usize) -> Vec<RestoreShadowRecord> {
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

fn parse_file(path: &Path) -> Vec<RestoreShadowRecord> {
    let Ok(bytes) = strata_fs::read(path) else {
        return Vec::new();
    };
    if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
        return parse_json_value(&value);
    }
    parse_csv_or_lines(String::from_utf8_lossy(&bytes).as_ref())
}

fn parse_json_value(value: &Value) -> Vec<RestoreShadowRecord> {
    let rows = if let Some(arr) = value.as_array() {
        arr.clone()
    } else if let Some(obj) = value.as_object() {
        obj.get("records")
            .and_then(Value::as_array)
            .or_else(|| obj.get("restore_points").and_then(Value::as_array))
            .or_else(|| obj.get("shadow_copies").and_then(Value::as_array))
            .or_else(|| obj.get("entries").and_then(Value::as_array))
            .or_else(|| obj.get("items").and_then(Value::as_array))
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
                .or_else(|| obj.get("snapshot_time"))
                .or_else(|| obj.get("creation_time"))
                .or_else(|| obj.get("created"))
                .or_else(|| obj.get("occurred_utc"))
                .or_else(|| obj.get("timestamp_utc")),
        );
        let source = obj
            .get("source")
            .and_then(Value::as_str)
            .map(normalize_token)
            .unwrap_or_else(|| infer_source(obj).to_string());
        let event_type = obj
            .get("event_type")
            .and_then(Value::as_str)
            .map(normalize_token)
            .unwrap_or_else(|| infer_event_type(&source, obj));
        out.push(RestoreShadowRecord {
            source,
            event_type,
            restore_point_id: obj
                .get("restore_point_id")
                .and_then(value_to_i64)
                .and_then(|v| u32::try_from(v).ok())
                .or_else(|| {
                    obj.get("id")
                        .and_then(value_to_i64)
                        .and_then(|v| u32::try_from(v).ok())
                }),
            snapshot_id: obj
                .get("snapshot_id")
                .and_then(Value::as_str)
                .or_else(|| obj.get("shadow_copy_id").and_then(Value::as_str))
                .or_else(|| obj.get("vss_id").and_then(Value::as_str))
                .map(normalize_path_like),
            name: obj
                .get("name")
                .and_then(Value::as_str)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            description: obj
                .get("description")
                .and_then(Value::as_str)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            restore_point_type: obj
                .get("restore_point_type")
                .and_then(Value::as_str)
                .or_else(|| obj.get("type").and_then(Value::as_str))
                .map(normalize_token),
            file_path: obj
                .get("file_path")
                .and_then(Value::as_str)
                .or_else(|| obj.get("path").and_then(Value::as_str))
                .map(normalize_path_like),
            change_type: obj
                .get("change_type")
                .and_then(Value::as_str)
                .map(normalize_token),
            status: obj
                .get("status")
                .and_then(Value::as_str)
                .map(normalize_token),
            integrity_ok: obj.get("integrity_ok").and_then(Value::as_bool),
            timestamp_unix: ts.0,
            timestamp_utc: ts.1,
            timestamp_precision: ts.2,
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

fn parse_csv_or_lines(content: &str) -> Vec<RestoreShadowRecord> {
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
            let ts = parse_ts_str(
                get("timestamp_unix")
                    .or_else(|| get("timestamp"))
                    .or_else(|| get("snapshot_time"))
                    .or_else(|| get("creation_time"))
                    .or_else(|| get("occurred_utc"))
                    .unwrap_or_default(),
            );
            let source = get("source")
                .map(normalize_token)
                .unwrap_or_else(|| "restore-point".to_string());
            let event_type = get("event_type")
                .map(normalize_token)
                .unwrap_or_else(|| infer_event_type(&source, &serde_json::Map::new()));
            out.push(RestoreShadowRecord {
                source,
                event_type,
                restore_point_id: get("restore_point_id")
                    .or_else(|| get("id"))
                    .and_then(|v| v.parse::<u32>().ok()),
                snapshot_id: get("snapshot_id")
                    .or_else(|| get("shadow_copy_id"))
                    .map(normalize_path_like),
                name: get("name").map(|v| v.to_string()).filter(|v| !v.is_empty()),
                description: get("description")
                    .map(|v| v.to_string())
                    .filter(|v| !v.is_empty()),
                restore_point_type: get("restore_point_type").map(normalize_token),
                file_path: get("file_path")
                    .or_else(|| get("path"))
                    .map(normalize_path_like),
                change_type: get("change_type").map(normalize_token),
                status: get("status").map(normalize_token),
                integrity_ok: get("integrity_ok").and_then(|v| {
                    match v.to_ascii_lowercase().as_str() {
                        "true" | "1" | "yes" => Some(true),
                        "false" | "0" | "no" => Some(false),
                        _ => None,
                    }
                }),
                timestamp_unix: ts.0,
                timestamp_utc: ts.1,
                timestamp_precision: ts.2,
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
        let mut parts = line.splitn(2, '|');
        let left = parts.next().unwrap_or_default().trim();
        let right = parts.next().unwrap_or_default().trim();
        let ts = parse_ts_str(left);
        out.push(RestoreShadowRecord {
            source: if right.to_ascii_lowercase().contains("shadow") {
                "shadow-copy".to_string()
            } else {
                "restore-point".to_string()
            },
            event_type: "restore-shadow-line".to_string(),
            restore_point_id: None,
            snapshot_id: None,
            name: None,
            description: if right.is_empty() {
                None
            } else {
                Some(right.to_string())
            },
            restore_point_type: None,
            file_path: None,
            change_type: None,
            status: None,
            integrity_ok: None,
            timestamp_unix: ts.0,
            timestamp_utc: ts.1,
            timestamp_precision: ts.2,
            user_sid: None,
            username: None,
            source_path: None,
            source_record_id: None,
        });
    }
    out
}

fn infer_source(obj: &serde_json::Map<String, Value>) -> &'static str {
    if obj.get("snapshot_id").is_some()
        || obj.get("shadow_copy_id").is_some()
        || obj.get("vss_id").is_some()
    {
        "shadow-copy"
    } else {
        "restore-point"
    }
}

fn infer_event_type(source: &str, obj: &serde_json::Map<String, Value>) -> String {
    if source == "shadow-copy" {
        if obj.get("mount_path").is_some() {
            "shadow-copy-mount".to_string()
        } else {
            "shadow-copy-event".to_string()
        }
    } else {
        "restore-point-event".to_string()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn detect_restore_shadow_input_shape_supports_directory_json_csv() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("restore");
        let json = dir.path().join("restore.json");
        let csv = dir.path().join("restore.csv");
        strata_fs::create_dir_all(&root).unwrap();
        strata_fs::write(&json, r#"[{"id":1,"snapshot_time":1700000000}]"#).unwrap();
        strata_fs::write(&csv, "restore_point_id,snapshot_time\n1,1700000001\n").unwrap();

        assert_eq!(
            detect_restore_shadow_input_shape(&root),
            RestoreShadowInputShape::Directory
        );
        assert_eq!(
            detect_restore_shadow_input_shape(&json),
            RestoreShadowInputShape::JsonArray
        );
        assert_eq!(
            detect_restore_shadow_input_shape(&csv),
            RestoreShadowInputShape::CsvText
        );
    }

    #[test]
    fn parse_restore_shadow_records_from_path_parses_json_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("restore.json");
        strata_fs::write(
            &path,
            r#"[{"id":7,"source":"restore_point","event_type":"checkpoint","snapshot_time":1700000100,"name":"before update"}]"#,
        )
        .unwrap();

        let rows = parse_restore_shadow_records_from_path(&path, 10);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].restore_point_id, Some(7));
        assert_eq!(rows[0].timestamp_unix, Some(1_700_000_100));
        assert_eq!(rows[0].source, "restore-point");
    }

    #[test]
    fn parse_restore_shadow_text_fallback_handles_partial_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("restore.txt");
        strata_fs::write(&path, "2024-01-01T00:00:00Z | shadow created").unwrap();

        let rows = parse_restore_shadow_text_fallback(&path);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].source, "shadow-copy");
        assert!(rows[0].timestamp_unix.is_some());
    }
}
