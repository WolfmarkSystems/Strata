use super::scalpel::{read_prefix, DEFAULT_BINARY_MAX_BYTES};
use crate::errors::ForensicError;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct RecycleBinEntry {
    pub original_path: Option<String>,
    pub deleted_time: Option<i64>,
    pub file_size: u64,
    pub file_name: String,
    pub drive_letter: char,
    pub owner_sid: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RecycleBinInfo {
    pub drive_letter: char,
    pub entries: Vec<RecycleBinEntry>,
    pub total_files: usize,
    pub total_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecycleBinInputShape {
    Missing,
    Empty,
    Directory,
    JsonArray,
    JsonObject,
    CsvText,
    LineText,
    Unknown,
}

impl RecycleBinInputShape {
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

pub fn detect_recycle_input_shape(path: &Path) -> RecycleBinInputShape {
    if !path.exists() {
        return RecycleBinInputShape::Missing;
    }
    if path.is_dir() {
        return RecycleBinInputShape::Directory;
    }
    let Ok(bytes) = strata_fs::read(path) else {
        return RecycleBinInputShape::Unknown;
    };
    if bytes.is_empty() {
        return RecycleBinInputShape::Empty;
    }
    let text = String::from_utf8_lossy(&bytes);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return RecycleBinInputShape::Empty;
    }
    if trimmed.starts_with('[') {
        return RecycleBinInputShape::JsonArray;
    }
    if trimmed.starts_with('{') {
        return RecycleBinInputShape::JsonObject;
    }
    let first_line = trimmed
        .lines()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if first_line.contains("original_path")
        || first_line.contains("file_name")
        || first_line.contains("deleted_time")
        || first_line.contains("owner_sid")
    {
        return RecycleBinInputShape::CsvText;
    }
    RecycleBinInputShape::LineText
}

pub fn parse_recycle_entries_from_path(path: &Path, limit: usize) -> Vec<RecycleBinEntry> {
    if !path.exists() || limit == 0 {
        return Vec::new();
    }

    let mut rows = Vec::new();
    if path.is_dir() {
        if let Ok(entries) = strata_fs::read_dir(path) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    continue;
                }
                let mut parsed =
                    parse_recycle_entries_from_path(&p, limit.saturating_sub(rows.len()));
                rows.append(&mut parsed);
                if rows.len() >= limit {
                    break;
                }
            }
        }
    } else if let Ok(bytes) = strata_fs::read(path) {
        if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
            rows = parse_recycle_json_value(&value);
        }
        if rows.is_empty() {
            rows = parse_recycle_csv_or_lines(String::from_utf8_lossy(&bytes).as_ref());
        }
    }

    if rows.is_empty() {
        rows = parse_recycle_text_fallback(path);
    }

    let mut seen = BTreeSet::<String>::new();
    rows.retain(|row| {
        let key = format!(
            "{}|{}|{}|{}|{}",
            row.original_path.clone().unwrap_or_default(),
            row.deleted_time.map(|v| v.to_string()).unwrap_or_default(),
            row.file_size,
            row.file_name,
            row.owner_sid.clone().unwrap_or_default()
        );
        seen.insert(key)
    });

    rows.sort_by(|a, b| {
        b.deleted_time
            .unwrap_or_default()
            .cmp(&a.deleted_time.unwrap_or_default())
            .then_with(|| a.file_name.cmp(&b.file_name))
            .then_with(|| a.drive_letter.cmp(&b.drive_letter))
    });
    rows.truncate(limit);
    rows
}

pub fn parse_recycle_text_fallback(path: &Path) -> Vec<RecycleBinEntry> {
    if !path.exists() {
        return Vec::new();
    }
    let Ok(content) = strata_fs::read_to_string(path) else {
        return Vec::new();
    };
    parse_recycle_csv_or_lines(&content)
}

pub fn scan_recycle_bin(drive_letter: char) -> Result<RecycleBinInfo, ForensicError> {
    let mut entries = Vec::new();
    let mut total_size: u64 = 0;

    let recycle_path = get_recycle_path(drive_letter);

    if !recycle_path.exists() {
        return Ok(RecycleBinInfo {
            drive_letter,
            entries: Vec::new(),
            total_files: 0,
            total_size: 0,
        });
    }

    let info2_path = recycle_path.join("INFO2");
    let owner_sid = extract_sid_from_path(&recycle_path);

    if info2_path.exists() {
        if let Ok(parsed) = parse_info2(&info2_path, drive_letter, owner_sid.clone()) {
            entries = parsed.0;
            total_size = parsed.1;
        }
    }

    let dollar_path = recycle_path.join("$I");
    if dollar_path.exists() {
        if let Ok(parsed) = parse_dollar_files(&dollar_path, drive_letter, owner_sid.clone()) {
            for entry in parsed {
                total_size += entry.file_size;
                entries.push(entry);
            }
        }
    }

    Ok(RecycleBinInfo {
        drive_letter,
        total_files: entries.len(),
        total_size,
        entries,
    })
}

fn get_recycle_path(drive_letter: char) -> PathBuf {
    #[cfg(windows)]
    {
        let user_id = std::env::var("USERNAME").unwrap_or_else(|_| "S-1-5-21".to_string());
        PathBuf::from(format!("{}:\\$Recycle.Bin\\{}", drive_letter, user_id))
    }
    #[cfg(not(windows))]
    {
        PathBuf::from(format!("/home/.local/share/Trash/files"))
    }
}

fn parse_info2(
    path: &Path,
    drive_letter: char,
    owner_sid: Option<String>,
) -> Result<(Vec<RecycleBinEntry>, u64), ForensicError> {
    let mut entries = Vec::new();
    let mut total_size: u64 = 0;

    let data = read_prefix(path, DEFAULT_BINARY_MAX_BYTES * 4)?;

    let mut offset = 0;

    while offset + 260 < data.len() {
        let file_size = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as u64;

        let deleted_time = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);

        let deleted_timestamp = if deleted_time > 0 {
            Some((deleted_time as i64 - 11644473600) * 86400 + 134774)
        } else {
            None
        };

        let name_offset = 12;
        let name_end = data[offset + name_offset..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(260 - name_offset);

        let file_name =
            String::from_utf8_lossy(&data[offset + name_offset..offset + name_offset + name_end])
                .to_string();

        let path_offset = name_offset + 260;
        let original_path = if data.len() > path_offset + 260 {
            let path_end = data[path_offset..]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(260);
            Some(String::from_utf8_lossy(&data[path_offset..path_offset + path_end]).to_string())
        } else {
            None
        };

        total_size += file_size;

        entries.push(RecycleBinEntry {
            original_path,
            deleted_time: deleted_timestamp,
            file_size,
            file_name,
            drive_letter,
            owner_sid: owner_sid.clone(),
        });

        offset += 532;
    }

    Ok((entries, total_size))
}

fn parse_dollar_files(
    path: &Path,
    drive_letter: char,
    owner_sid: Option<String>,
) -> Result<Vec<RecycleBinEntry>, ForensicError> {
    let mut entries = Vec::new();

    if let Ok(files) = strata_fs::read_dir(path) {
        for file in files.flatten() {
            let file_name = file.file_name().to_string_lossy().to_string();

            if file_name.starts_with("$I") && file_name.len() > 2 {
                let original_file_name = format!("{}$R{}", &file_name[2..], &file_name[2..]);
                let original_path = path.parent().map(|p| p.join(&original_file_name));

                let deleted_time = strata_fs::metadata(file.path())
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .map(|t| {
                        t.duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs() as i64
                    });

                let file_size = if let Some(ref orig) = original_path {
                    strata_fs::metadata(orig).map(|m| m.len()).unwrap_or(0)
                } else {
                    0
                };

                let deleted_file_name = if file_name.len() > 2 {
                    file_name[2..].to_string()
                } else {
                    file_name.clone()
                };

                entries.push(RecycleBinEntry {
                    original_path: original_path.map(|p| p.display().to_string()),
                    deleted_time,
                    file_size,
                    file_name: deleted_file_name,
                    drive_letter,
                    owner_sid: owner_sid.clone(),
                });
            }
        }
    }

    Ok(entries)
}

fn parse_recycle_json_value(value: &Value) -> Vec<RecycleBinEntry> {
    if let Some(arr) = value.as_array() {
        return parse_recycle_json_rows(arr);
    }
    if let Some(obj) = value.as_object() {
        if let Some(rows) = obj
            .get("entries")
            .or_else(|| obj.get("files"))
            .or_else(|| obj.get("deletions"))
            .and_then(Value::as_array)
        {
            return parse_recycle_json_rows(rows);
        }
    }
    Vec::new()
}

fn parse_recycle_json_rows(rows: &[Value]) -> Vec<RecycleBinEntry> {
    rows.iter()
        .filter_map(|row| {
            let file_name = row
                .get("file_name")
                .or_else(|| row.get("name"))
                .and_then(Value::as_str)
                .map(ToString::to_string)
                .or_else(|| {
                    row.get("original_path")
                        .or_else(|| row.get("path"))
                        .and_then(Value::as_str)
                        .and_then(|p| Path::new(p).file_name())
                        .map(|v| v.to_string_lossy().to_string())
                })?;
            let original_path = row
                .get("original_path")
                .or_else(|| row.get("path"))
                .or_else(|| row.get("original"))
                .and_then(Value::as_str)
                .map(|v| v.replace('/', "\\"));
            let deleted_time = row
                .get("deleted_time")
                .or_else(|| row.get("deleted_unix"))
                .or_else(|| row.get("timestamp_unix"))
                .and_then(Value::as_i64)
                .or_else(|| {
                    row.get("deleted_utc")
                        .or_else(|| row.get("timestamp_utc"))
                        .and_then(Value::as_str)
                        .and_then(parse_timestamp_text_to_unix)
                });
            let file_size = row
                .get("file_size")
                .or_else(|| row.get("size"))
                .and_then(Value::as_u64)
                .or_else(|| {
                    row.get("file_size")
                        .or_else(|| row.get("size"))
                        .and_then(Value::as_i64)
                        .map(|v| v.max(0) as u64)
                })
                .unwrap_or(0);
            let owner_sid = row
                .get("owner_sid")
                .or_else(|| row.get("sid"))
                .and_then(Value::as_str)
                .map(ToString::to_string);
            let drive_letter = row
                .get("drive_letter")
                .and_then(Value::as_str)
                .and_then(|v| v.chars().next())
                .or_else(|| {
                    original_path
                        .as_ref()
                        .and_then(|v| v.chars().next())
                        .filter(|c| c.is_ascii_alphabetic())
                })
                .unwrap_or('?')
                .to_ascii_uppercase();

            Some(RecycleBinEntry {
                original_path,
                deleted_time,
                file_size,
                file_name,
                drive_letter,
                owner_sid,
            })
        })
        .collect()
}

fn parse_recycle_csv_or_lines(content: &str) -> Vec<RecycleBinEntry> {
    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.to_ascii_lowercase().contains("file_name")
            && trimmed.to_ascii_lowercase().contains("deleted")
        {
            continue;
        }
        let parts = split_fields(trimmed);
        if parts.is_empty() {
            continue;
        }

        let deleted_time = parts
            .first()
            .and_then(|v| parse_timestamp_text_to_unix(v))
            .or_else(|| parts.get(1).and_then(|v| parse_timestamp_text_to_unix(v)));
        let original_path = parts
            .iter()
            .find(|p| p.contains('\\') || p.contains('/'))
            .map(|v| v.replace('/', "\\"));
        let file_name = parts
            .iter()
            .rev()
            .find(|p| {
                let t = p.trim();
                !t.is_empty()
                    && !t.contains(':')
                    && !t.contains('\\')
                    && !t.contains('/')
                    && !looks_like_sid(t)
                    && t.parse::<u64>().is_err()
            })
            .map(ToString::to_string)
            .or_else(|| {
                original_path
                    .as_ref()
                    .and_then(|p| Path::new(p).file_name())
                    .map(|v| v.to_string_lossy().to_string())
            });
        let Some(file_name) = file_name else {
            continue;
        };
        let file_size = parts
            .iter()
            .find_map(|p| p.parse::<u64>().ok())
            .unwrap_or(0);
        let owner_sid = parts
            .iter()
            .find(|p| looks_like_sid(p))
            .map(ToString::to_string);
        let drive_letter = original_path
            .as_ref()
            .and_then(|v| v.chars().next())
            .filter(|c| c.is_ascii_alphabetic())
            .unwrap_or('?')
            .to_ascii_uppercase();

        out.push(RecycleBinEntry {
            original_path,
            deleted_time,
            file_size,
            file_name,
            drive_letter,
            owner_sid,
        });
    }
    out
}

fn split_fields(value: &str) -> Vec<String> {
    if value.contains('|') {
        value.split('|').map(|v| v.trim().to_string()).collect()
    } else if value.contains('\t') {
        value.split('\t').map(|v| v.trim().to_string()).collect()
    } else if value.contains(',') {
        value.split(',').map(|v| v.trim().to_string()).collect()
    } else {
        vec![value.trim().to_string()]
    }
}

fn parse_timestamp_text_to_unix(value: &str) -> Option<i64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(ts) = trimmed.parse::<i64>() {
        return Some(ts);
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(trimmed) {
        return Some(dt.timestamp());
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S") {
        let dt = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(naive, chrono::Utc);
        return Some(dt.timestamp());
    }
    None
}

pub fn scan_all_drives() -> Result<Vec<RecycleBinInfo>, ForensicError> {
    let mut results = Vec::new();
    let drives = ['C', 'D', 'E', 'F', 'G', 'H'];

    for drive in drives {
        if let Ok(info) = scan_recycle_bin(drive) {
            if !info.entries.is_empty() {
                results.push(info);
            }
        }
    }

    Ok(results)
}

fn extract_sid_from_path(path: &Path) -> Option<String> {
    path.components()
        .filter_map(|component| component.as_os_str().to_str())
        .find(|segment| looks_like_sid(segment))
        .map(ToString::to_string)
}

fn looks_like_sid(value: &str) -> bool {
    let trimmed = value.trim();
    if !trimmed.starts_with("S-") {
        return false;
    }
    let mut parts = trimmed.split('-');
    if parts.next() != Some("S") {
        return false;
    }
    let revision = parts.next();
    let authority = parts.next();
    if revision.is_none() || authority.is_none() {
        return false;
    }
    let mut saw_sub_authority = false;
    for part in parts {
        if part.is_empty() || !part.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        saw_sub_authority = true;
    }
    saw_sub_authority
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_sid_from_path_detects_sid_component() {
        let path = Path::new(r"C:\$Recycle.Bin\S-1-5-21-1000-2000-3000-1001");
        assert_eq!(
            extract_sid_from_path(path).as_deref(),
            Some("S-1-5-21-1000-2000-3000-1001")
        );
    }

    #[test]
    fn extract_sid_from_path_returns_none_for_non_sid() {
        let path = Path::new(r"C:\$Recycle.Bin\korby");
        assert!(extract_sid_from_path(path).is_none());
    }

    #[test]
    fn detect_recycle_input_shape_supports_json_csv_and_dir() {
        let temp = tempfile::tempdir().unwrap();
        let json = temp.path().join("recycle.json");
        let csv = temp.path().join("recycle.csv");
        let sub = temp.path().join("dir");
        std::fs::write(
            &json,
            r#"[{"file_name":"bad.exe","deleted_time":1700000000,"original_path":"C:/Temp/bad.exe"}]"#,
        )
        .unwrap();
        std::fs::write(
            &csv,
            "deleted_time,file_name,original_path\n1700000000,bad.exe,C:\\Temp\\bad.exe\n",
        )
        .unwrap();
        std::fs::create_dir_all(&sub).unwrap();

        assert_eq!(
            detect_recycle_input_shape(&json),
            RecycleBinInputShape::JsonArray
        );
        assert_eq!(
            detect_recycle_input_shape(&csv),
            RecycleBinInputShape::CsvText
        );
        assert_eq!(
            detect_recycle_input_shape(&sub),
            RecycleBinInputShape::Directory
        );
    }

    #[test]
    fn parse_recycle_entries_from_path_parses_json_rows() {
        let temp = tempfile::tempdir().unwrap();
        let json = temp.path().join("recycle.json");
        std::fs::write(
            &json,
            r#"{"entries":[{"file_name":"gone.exe","deleted_time":1700000010,"file_size":42,"original_path":"C:/Users/lab/gone.exe","owner_sid":"S-1-5-21-1000"}]}"#,
        )
        .unwrap();

        let rows = parse_recycle_entries_from_path(&json, 20);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].file_name, "gone.exe");
        assert_eq!(rows[0].deleted_time, Some(1_700_000_010));
        assert_eq!(rows[0].owner_sid.as_deref(), Some("S-1-5-21-1000"));
    }

    #[test]
    fn parse_recycle_text_fallback_handles_partial_rows() {
        let temp = tempfile::tempdir().unwrap();
        let txt = temp.path().join("recycle.txt");
        std::fs::write(
            &txt,
            "2024-01-01T00:00:00Z|C:\\Temp\\gone.exe|128|gone.exe|S-1-5-21-1000\n1700000200,bad.dll,C:\\Temp\\bad.dll\n",
        )
        .unwrap();

        let rows = parse_recycle_text_fallback(&txt);
        assert!(rows.len() >= 2);
        assert!(rows.iter().any(|r| r.file_name == "gone.exe"));
    }
}
