use crate::errors::ForensicError;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use super::prefetchdata;
use super::scalpel::{read_prefix, DEFAULT_BINARY_MAX_BYTES};

#[derive(Debug, Clone)]
pub struct PrefetchInfo {
    pub version: u32,
    pub program_name: String,
    pub last_run_time: Option<i64>,
    pub run_times: Vec<i64>,
    pub run_count: u32,
    pub volumes_referenced: Vec<String>,
    pub files_referenced: Vec<String>,
    pub directories_referenced: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefetchInputShape {
    Missing,
    Empty,
    Directory,
    BinaryPf,
    JsonArray,
    JsonObject,
    CsvText,
    LineText,
    Unknown,
}

impl PrefetchInputShape {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Empty => "empty",
            Self::Directory => "directory",
            Self::BinaryPf => "binary-pf",
            Self::JsonArray => "json-array",
            Self::JsonObject => "json-object",
            Self::CsvText => "csv-text",
            Self::LineText => "line-text",
            Self::Unknown => "unknown",
        }
    }
}

pub fn detect_prefetch_input_shape(path: &Path) -> PrefetchInputShape {
    if !path.exists() {
        return PrefetchInputShape::Missing;
    }
    if path.is_dir() {
        return PrefetchInputShape::Directory;
    }
    let Ok(bytes) = strata_fs::read(path) else {
        return PrefetchInputShape::Unknown;
    };
    if bytes.is_empty() {
        return PrefetchInputShape::Empty;
    }
    if bytes.len() >= 4 && &bytes[0..4] == b"SCCA" {
        return PrefetchInputShape::BinaryPf;
    }
    let text = String::from_utf8_lossy(&bytes);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return PrefetchInputShape::Empty;
    }
    if trimmed.starts_with('[') {
        return PrefetchInputShape::JsonArray;
    }
    if trimmed.starts_with('{') {
        return PrefetchInputShape::JsonObject;
    }
    let first_line = trimmed
        .lines()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if first_line.contains("program_name")
        || first_line.contains("last_run")
        || first_line.contains("run_count")
    {
        return PrefetchInputShape::CsvText;
    }
    PrefetchInputShape::LineText
}

pub fn parse_prefetch_records_from_path(path: &Path, limit: usize) -> Vec<PrefetchInfo> {
    if !path.exists() || limit == 0 {
        return Vec::new();
    }

    let mut rows = if path.is_dir() {
        scan_prefetch_directory(path).unwrap_or_default()
    } else if path
        .extension()
        .map(|v| v.eq_ignore_ascii_case("pf"))
        .unwrap_or(false)
    {
        parse_prefetch(path).ok().into_iter().collect::<Vec<_>>()
    } else if let Ok(bytes) = strata_fs::read(path) {
        if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
            parse_prefetch_rows_json_value(&value)
        } else {
            parse_prefetch_csv_or_lines(String::from_utf8_lossy(&bytes).as_ref())
        }
    } else {
        Vec::new()
    };

    if rows.is_empty() {
        rows = parse_prefetch_text_fallback(path);
    }

    let mut seen = BTreeSet::<String>::new();
    rows.retain(|row| {
        let key = format!(
            "{}|{}|{}",
            row.program_name,
            row.last_run_time.map(|v| v.to_string()).unwrap_or_default(),
            row.run_count
        );
        seen.insert(key)
    });

    rows.sort_by(|a, b| {
        b.last_run_time
            .unwrap_or_default()
            .cmp(&a.last_run_time.unwrap_or_default())
            .then_with(|| a.program_name.cmp(&b.program_name))
    });
    rows.truncate(limit);
    rows
}

pub fn parse_prefetch_text_fallback(path: &Path) -> Vec<PrefetchInfo> {
    if !path.exists() {
        return Vec::new();
    }
    let Ok(content) = strata_fs::read_to_string(path) else {
        return Vec::new();
    };
    parse_prefetch_csv_or_lines(&content)
}

pub fn parse_prefetch(path: &Path) -> Result<PrefetchInfo, ForensicError> {
    let mut info = PrefetchInfo {
        version: 0,
        program_name: String::new(),
        last_run_time: None,
        run_times: Vec::new(),
        run_count: 0,
        volumes_referenced: Vec::new(),
        files_referenced: Vec::new(),
        directories_referenced: Vec::new(),
    };

    if !path.exists() {
        return Ok(info);
    }

    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    info.program_name = normalize_prefetch_program_from_filename(&file_name);

    let data = read_prefix(path, DEFAULT_BINARY_MAX_BYTES)?;
    if data.len() < 44 {
        return Ok(info);
    }

    if &data[0..4] != b"SCCA" {
        return Ok(info);
    }

    // First, use the richer parser to extract name, run times, and file references.
    if let Ok(rich) = prefetchdata::parse_prefetch_info(&data) {
        info.version = rich.version;
        if !rich.application_name.trim().is_empty() {
            info.program_name = rich.application_name;
        }
        if rich.last_run > 0 {
            info.last_run_time = Some(rich.last_run as i64);
        }
        info.run_times = rich
            .run_times
            .into_iter()
            .filter(|t| *t <= i64::MAX as u64)
            .map(|t| t as i64)
            .collect();
        info.run_count = rich.run_count;
        info.files_referenced = rich.files;
        info.directories_referenced = rich.directories;
        info.volumes_referenced = derive_volumes(&info.directories_referenced);
    }

    // Keep backward-compatible header fallback when richer data is sparse.
    if info.run_count == 0 {
        let run_count_offset = 0x78usize;
        if data.len() >= run_count_offset + 4 {
            info.run_count = u32::from_le_bytes([
                data[run_count_offset],
                data[run_count_offset + 1],
                data[run_count_offset + 2],
                data[run_count_offset + 3],
            ]);
        }
    }
    if info.last_run_time.is_none() {
        let last_run_offset = 0x80usize;
        if data.len() >= last_run_offset + 8 {
            let timestamp = u64::from_le_bytes([
                data[last_run_offset],
                data[last_run_offset + 1],
                data[last_run_offset + 2],
                data[last_run_offset + 3],
                data[last_run_offset + 4],
                data[last_run_offset + 5],
                data[last_run_offset + 6],
                data[last_run_offset + 7],
            ]);
            if timestamp > 0 {
                let seconds = timestamp / 10_000_000;
                if seconds >= 11_644_473_600 {
                    info.last_run_time = Some((seconds - 11_644_473_600) as i64);
                }
            }
        }
    }

    info.files_referenced.sort();
    info.files_referenced.dedup();
    info.directories_referenced.sort();
    info.directories_referenced.dedup();
    info.volumes_referenced.sort();
    info.volumes_referenced.dedup();
    info.run_times.sort_by(|a, b| b.cmp(a));
    info.run_times.dedup();
    if info.last_run_time.is_none() {
        info.last_run_time = info.run_times.first().copied();
    }

    Ok(info)
}

pub fn scan_prefetch_directory(path: &Path) -> Result<Vec<PrefetchInfo>, ForensicError> {
    let mut prefetches = Vec::new();

    if !path.exists() {
        return Ok(prefetches);
    }

    if let Ok(entries) = strata_fs::read_dir(path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            if entry_path
                .extension()
                .map(|e| e.eq_ignore_ascii_case("pf"))
                .unwrap_or(false)
            {
                if let Ok(info) = parse_prefetch(&entry_path) {
                    prefetches.push(info);
                }
            }
        }
    }

    prefetches.sort_by(|a, b| {
        b.last_run_time
            .unwrap_or_default()
            .cmp(&a.last_run_time.unwrap_or_default())
            .then_with(|| a.program_name.cmp(&b.program_name))
    });

    Ok(prefetches)
}

pub fn get_prefetch_metadata(
    path: &Path,
) -> Result<std::collections::HashMap<String, String>, ForensicError> {
    let mut metadata = std::collections::HashMap::new();

    if !path.exists() {
        return Ok(metadata);
    }

    if let Ok(meta) = strata_fs::metadata(path) {
        if let Ok(modified) = meta.modified() {
            let timestamp = modified
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            metadata.insert("modified".to_string(), timestamp.to_string());
        }

        if let Ok(created) = meta.created() {
            let timestamp = created
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            metadata.insert("created".to_string(), timestamp.to_string());
        }

        metadata.insert("size".to_string(), meta.len().to_string());
    }

    Ok(metadata)
}

fn derive_volumes(directories: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for dir in directories {
        if dir.len() >= 2 && dir.as_bytes()[1] == b':' {
            out.push(dir[0..2].to_string());
        } else if dir.starts_with(r"\\") {
            out.push(r"\\network".to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}

fn normalize_prefetch_program_from_filename(file_name: &str) -> String {
    let base = file_name.trim_end_matches(".pf").trim();
    if let Some((left, right)) = base.rsplit_once('-') {
        let looks_hash = right.len() >= 6 && right.chars().all(|c| c.is_ascii_hexdigit());
        if looks_hash {
            return left.to_string();
        }
    }
    base.to_string()
}

fn parse_prefetch_rows_json_value(value: &Value) -> Vec<PrefetchInfo> {
    if let Some(arr) = value.as_array() {
        return parse_prefetch_rows_json(arr);
    }
    if let Some(obj) = value.as_object() {
        if let Some(arr) = obj
            .get("records")
            .or_else(|| obj.get("entries"))
            .or_else(|| obj.get("prefetch"))
            .and_then(Value::as_array)
        {
            return parse_prefetch_rows_json(arr);
        }
    }
    Vec::new()
}

fn parse_prefetch_rows_json(rows: &[Value]) -> Vec<PrefetchInfo> {
    rows.iter()
        .filter_map(|row| {
            let program_name = row
                .get("program_name")
                .or_else(|| row.get("application_name"))
                .or_else(|| row.get("exe_name"))
                .or_else(|| row.get("executable"))
                .or_else(|| row.get("image"))
                .or_else(|| row.get("process_name"))
                .or_else(|| row.get("name"))
                .and_then(Value::as_str)
                .map(ToString::to_string)?;

            let mut run_times = row
                .get("run_times")
                .and_then(Value::as_array)
                .map(|vals| {
                    vals.iter()
                        .filter_map(value_to_prefetch_unix)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            run_times.sort_by(|a, b| b.cmp(a));
            run_times.dedup();

            let last_run_time = row
                .get("last_run_time")
                .or_else(|| row.get("last_run_unix"))
                .or_else(|| row.get("last_run"))
                .or_else(|| row.get("last_execution_time"))
                .or_else(|| row.get("last_run_timestamp"))
                .or_else(|| row.get("last_run_time_utc"))
                .and_then(value_to_prefetch_unix)
                .or_else(|| run_times.first().copied());
            let run_count = row
                .get("run_count")
                .or_else(|| row.get("execution_count"))
                .or_else(|| row.get("launch_count"))
                .and_then(value_to_u32)
                .unwrap_or_else(|| run_times.len() as u32);

            let volumes_referenced = row
                .get("volumes_referenced")
                .or_else(|| row.get("volumes"))
                .and_then(Value::as_array)
                .map(|vals| {
                    vals.iter()
                        .filter_map(Value::as_str)
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            let files_referenced = row
                .get("files_referenced")
                .or_else(|| row.get("referenced_files"))
                .or_else(|| row.get("files"))
                .and_then(Value::as_array)
                .map(|vals| {
                    vals.iter()
                        .filter_map(Value::as_str)
                        .map(|v| v.replace('/', "\\"))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            let directories_referenced = row
                .get("directories_referenced")
                .or_else(|| row.get("referenced_directories"))
                .or_else(|| row.get("directories"))
                .and_then(Value::as_array)
                .map(|vals| {
                    vals.iter()
                        .filter_map(Value::as_str)
                        .map(|v| v.replace('/', "\\"))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            let mut info = PrefetchInfo {
                version: row.get("version").and_then(value_to_u32).unwrap_or(0),
                program_name,
                last_run_time,
                run_times,
                run_count,
                volumes_referenced,
                files_referenced,
                directories_referenced,
            };
            if info.volumes_referenced.is_empty() {
                info.volumes_referenced = derive_volumes(&info.directories_referenced);
            }
            if info.last_run_time.is_none() && !info.run_times.is_empty() {
                info.last_run_time = info.run_times.first().copied();
            } else if let Some(ts) = info.last_run_time {
                if !info.run_times.contains(&ts) {
                    info.run_times.push(ts);
                    info.run_times.sort_by(|a, b| b.cmp(a));
                    info.run_times.dedup();
                }
            }
            Some(info)
        })
        .collect()
}

fn value_to_u32(value: &Value) -> Option<u32> {
    value
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .or_else(|| value.as_i64().and_then(|v| u32::try_from(v).ok()))
        .or_else(|| value.as_str().and_then(|v| v.trim().parse::<u32>().ok()))
}

fn value_to_prefetch_unix(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .and_then(normalize_prefetch_timestamp)
        .or_else(|| {
            value
                .as_u64()
                .and_then(|v| normalize_prefetch_timestamp(v as i64))
        })
        .or_else(|| value.as_str().and_then(parse_timestamp_text_to_unix))
}

fn parse_prefetch_csv_or_lines(content: &str) -> Vec<PrefetchInfo> {
    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.to_ascii_lowercase().contains("program_name")
            && trimmed.to_ascii_lowercase().contains("last_run")
        {
            continue;
        }
        let parts = split_fields(trimmed);
        if parts.is_empty() {
            continue;
        }
        let program_name = parts
            .iter()
            .find(|v| v.to_ascii_lowercase().ends_with(".exe"))
            .map(ToString::to_string)
            .or_else(|| parts.first().cloned());
        let Some(program_name) = program_name else {
            continue;
        };
        let last_run_time = parts.iter().find_map(|v| parse_timestamp_text_to_unix(v));
        let run_count = parts
            .iter()
            .find_map(|v| v.parse::<u32>().ok())
            .unwrap_or_else(|| u32::from(last_run_time.is_some()));
        let files_referenced = parts
            .iter()
            .filter(|v| v.contains('\\') || v.contains('/'))
            .map(|v| v.replace('/', "\\"))
            .collect::<Vec<_>>();
        let directories_referenced = files_referenced
            .iter()
            .filter_map(|v| Path::new(v).parent())
            .map(|v| v.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        let volumes_referenced = derive_volumes(&directories_referenced);

        out.push(PrefetchInfo {
            version: 0,
            program_name,
            last_run_time,
            run_times: last_run_time.into_iter().collect::<Vec<_>>(),
            run_count,
            volumes_referenced,
            files_referenced,
            directories_referenced,
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
        return normalize_prefetch_timestamp(ts);
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(trimmed) {
        return normalize_prefetch_timestamp(dt.timestamp());
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S") {
        let dt = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(naive, chrono::Utc);
        return normalize_prefetch_timestamp(dt.timestamp());
    }
    None
}

fn normalize_prefetch_timestamp(raw: i64) -> Option<i64> {
    if raw <= 0 {
        return None;
    }
    let value = raw as i128;

    // Windows FILETIME (100ns intervals since 1601-01-01).
    if value >= 116_444_736_000_000_000 {
        let secs = (value / 10_000_000) - 11_644_473_600;
        return i64::try_from(secs).ok();
    }
    // Nanoseconds since Unix epoch.
    if value >= 10_000_000_000_000_000 {
        return i64::try_from(value / 1_000_000_000).ok();
    }
    // Microseconds since Unix epoch.
    if value >= 10_000_000_000_000 {
        return i64::try_from(value / 1_000_000).ok();
    }
    // Milliseconds since Unix epoch.
    if value >= 10_000_000_000 {
        return i64::try_from(value / 1_000).ok();
    }
    Some(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_utf16le(bytes: &mut [u8], offset: usize, text: &str) {
        let mut pos = offset;
        for u in text.encode_utf16() {
            if pos + 2 > bytes.len() {
                break;
            }
            let le = u.to_le_bytes();
            bytes[pos] = le[0];
            bytes[pos + 1] = le[1];
            pos += 2;
        }
        if pos + 2 <= bytes.len() {
            bytes[pos] = 0;
            bytes[pos + 1] = 0;
        }
    }

    #[test]
    fn parse_prefetch_surfaces_references_and_run_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("NOTEPAD.EXE-12345678.pf");

        let mut data = vec![0u8; 2048];
        data[0..4].copy_from_slice(b"SCCA");
        data[4..8].copy_from_slice(&0x1Eu32.to_le_bytes());
        data[0x78..0x7c].copy_from_slice(&7u32.to_le_bytes());
        let ft = (11_644_473_600u64 + 1_700_000_000u64) * 10_000_000u64;
        data[0x80..0x88].copy_from_slice(&ft.to_le_bytes());
        let ft2 = (11_644_473_600u64 + 1_699_990_000u64) * 10_000_000u64;
        data[0x88..0x90].copy_from_slice(&ft2.to_le_bytes());
        write_utf16le(&mut data, 0x10, "NOTEPAD.EXE");
        write_utf16le(&mut data, 0x200, r"C:\Windows\System32\notepad.exe");
        write_utf16le(&mut data, 0x260, r"C:\Users\lab\Desktop\notes.txt");

        std::fs::write(&path, data).unwrap();

        let info = parse_prefetch(&path).unwrap();
        assert_eq!(info.version, 0x1E);
        assert_eq!(info.program_name, "NOTEPAD.EXE");
        assert_eq!(info.run_count, 7);
        assert_eq!(info.last_run_time, Some(1_700_000_000));
        assert!(info.run_times.contains(&1_700_000_000));
        assert!(info.run_times.contains(&1_699_990_000));
        assert!(info
            .files_referenced
            .iter()
            .any(|f| f.ends_with(r"notepad.exe")));
        assert!(info
            .directories_referenced
            .iter()
            .any(|d| d.ends_with(r"System32")));
        assert!(info.volumes_referenced.iter().any(|v| v == "C:"));
    }

    #[test]
    fn derive_volumes_handles_drive_and_network_paths() {
        let volumes = derive_volumes(&[
            r"C:\Windows\System32".to_string(),
            r"\\server\share\folder".to_string(),
            r"D:\Evidence".to_string(),
        ]);
        assert_eq!(
            volumes,
            vec![
                "C:".to_string(),
                "D:".to_string(),
                "\\\\network".to_string()
            ]
        );
    }

    #[test]
    fn scan_prefetch_directory_only_reads_pf_files() {
        let dir = tempfile::tempdir().unwrap();
        let pf = dir.path().join("CMD.EXE-11111111.pf");
        let txt = dir.path().join("ignore.txt");

        let mut data = vec![0u8; 256];
        data[0..4].copy_from_slice(b"SCCA");
        std::fs::write(&pf, data).unwrap();
        std::fs::write(&txt, b"not-prefetch").unwrap();

        let entries = scan_prefetch_directory(dir.path()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].program_name, "CMD.EXE");
    }

    #[test]
    fn scan_prefetch_directory_sorts_by_last_run_time_desc() {
        let dir = tempfile::tempdir().unwrap();
        let newer = dir.path().join("NEWER.EXE-11111111.pf");
        let older = dir.path().join("OLDER.EXE-22222222.pf");

        let mut newer_data = vec![0u8; 512];
        newer_data[0..4].copy_from_slice(b"SCCA");
        newer_data[4..8].copy_from_slice(&0x1Eu32.to_le_bytes());
        let newer_ft = (11_644_473_600u64 + 1_700_000_123u64) * 10_000_000u64;
        newer_data[0x80..0x88].copy_from_slice(&newer_ft.to_le_bytes());

        let mut older_data = vec![0u8; 512];
        older_data[0..4].copy_from_slice(b"SCCA");
        older_data[4..8].copy_from_slice(&0x1Eu32.to_le_bytes());
        let older_ft = (11_644_473_600u64 + 1_699_000_000u64) * 10_000_000u64;
        older_data[0x80..0x88].copy_from_slice(&older_ft.to_le_bytes());

        std::fs::write(&newer, newer_data).unwrap();
        std::fs::write(&older, older_data).unwrap();

        let entries = scan_prefetch_directory(dir.path()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].program_name, "NEWER.EXE");
        assert_eq!(entries[1].program_name, "OLDER.EXE");
    }

    #[test]
    fn normalize_prefetch_program_from_filename_keeps_non_hash_suffix() {
        assert_eq!(
            normalize_prefetch_program_from_filename("SOME-TOOL.pf"),
            "SOME-TOOL"
        );
        assert_eq!(
            normalize_prefetch_program_from_filename("EXPLORER.EXE-1A2B3C4D.pf"),
            "EXPLORER.EXE"
        );
    }

    #[test]
    fn detect_prefetch_input_shape_supports_directory_pf_json_csv() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("prefetch");
        let pf = temp.path().join("ONE.PF");
        let json = temp.path().join("prefetch.json");
        let csv = temp.path().join("prefetch.csv");
        std::fs::create_dir_all(&dir).unwrap();

        let mut pf_data = vec![0u8; 64];
        pf_data[0..4].copy_from_slice(b"SCCA");
        std::fs::write(&pf, pf_data).unwrap();
        std::fs::write(
            &json,
            r#"[{"program_name":"CMD.EXE","last_run_time":1700000000}]"#,
        )
        .unwrap();
        std::fs::write(
            &csv,
            "program_name,last_run_time,run_count\nCMD.EXE,1700000000,5\n",
        )
        .unwrap();

        assert_eq!(
            detect_prefetch_input_shape(&dir),
            PrefetchInputShape::Directory
        );
        assert_eq!(
            detect_prefetch_input_shape(&pf),
            PrefetchInputShape::BinaryPf
        );
        assert_eq!(
            detect_prefetch_input_shape(&json),
            PrefetchInputShape::JsonArray
        );
        assert_eq!(
            detect_prefetch_input_shape(&csv),
            PrefetchInputShape::CsvText
        );
    }

    #[test]
    fn parse_prefetch_records_from_path_parses_json_rows() {
        let temp = tempfile::tempdir().unwrap();
        let json = temp.path().join("prefetch.json");
        std::fs::write(
            &json,
            r#"{"records":[{"program_name":"POWERSHELL.EXE","last_run_time":1700000123,"run_count":4,"files_referenced":["C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"]}]}"#,
        )
        .unwrap();

        let rows = parse_prefetch_records_from_path(&json, 20);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].program_name, "POWERSHELL.EXE");
        assert_eq!(rows[0].last_run_time, Some(1_700_000_123));
        assert_eq!(rows[0].run_count, 4);
    }

    #[test]
    fn parse_prefetch_records_from_path_accepts_variant_json_keys() {
        let temp = tempfile::tempdir().unwrap();
        let json = temp.path().join("prefetch_variants.json");
        std::fs::write(
            &json,
            r#"{"records":[{"exe_name":"RUNDLL32.EXE","last_execution_time":"2024-01-01T00:00:00Z","execution_count":"9","files":["C:/Windows/System32/rundll32.exe"],"directories":["C:/Windows/System32"]}]}"#,
        )
        .unwrap();

        let rows = parse_prefetch_records_from_path(&json, 20);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].program_name, "RUNDLL32.EXE");
        assert_eq!(rows[0].last_run_time, Some(1_704_067_200));
        assert_eq!(rows[0].run_count, 9);
        assert!(rows[0].volumes_referenced.iter().any(|v| v == "C:"));
    }

    #[test]
    fn parse_prefetch_records_from_path_normalizes_ms_and_filetime_timestamps() {
        let temp = tempfile::tempdir().unwrap();
        let json = temp.path().join("prefetch_ts_variants.json");
        let filetime = (11_644_473_600u64 + 1_700_000_000u64) * 10_000_000u64;
        std::fs::write(
            &json,
            format!(
                r#"{{"records":[{{"program_name":"CMD.EXE","last_run_timestamp":1700000000123,"run_count":1}},{{"program_name":"POWERSHELL.EXE","last_run_time":{},"run_count":2}}]}}"#,
                filetime
            ),
        )
        .unwrap();

        let rows = parse_prefetch_records_from_path(&json, 20);
        assert_eq!(rows.len(), 2);
        assert!(rows
            .iter()
            .any(|r| r.program_name == "CMD.EXE" && r.last_run_time == Some(1_700_000_000)));
        assert!(rows
            .iter()
            .any(|r| r.program_name == "POWERSHELL.EXE" && r.last_run_time == Some(1_700_000_000)));
    }

    #[test]
    fn parse_prefetch_text_fallback_handles_partial_rows() {
        let temp = tempfile::tempdir().unwrap();
        let txt = temp.path().join("prefetch.txt");
        std::fs::write(
            &txt,
            "2024-01-01T00:00:00Z|CMD.EXE|3|C:\\Windows\\System32\\cmd.exe\nNOTEPAD.EXE,C:\\Windows\\System32\\notepad.exe,1700000000,1\n",
        )
        .unwrap();

        let rows = parse_prefetch_text_fallback(&txt);
        assert!(rows.iter().any(|r| r.program_name == "CMD.EXE"));
        assert!(rows.iter().any(|r| r.program_name == "NOTEPAD.EXE"));
    }

    #[test]
    fn parse_prefetch_text_fallback_normalizes_millisecond_timestamps() {
        let temp = tempfile::tempdir().unwrap();
        let txt = temp.path().join("prefetch_ms.txt");
        std::fs::write(
            &txt,
            "CMD.EXE,1700000000123,5,C:\\Windows\\System32\\cmd.exe\n",
        )
        .unwrap();
        let rows = parse_prefetch_text_fallback(&txt);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].last_run_time, Some(1_700_000_000));
    }
}
