use super::scalpel::{read_text_prefix, DEFAULT_TEXT_MAX_BYTES};
use chrono::{DateTime, Utc};
use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct RegKeyRecord {
    pub path: String,
    pub values: BTreeMap<String, String>,
}

pub fn default_reg_path(file_name: &str) -> PathBuf {
    if let Ok(dir) = env::var("FORENSIC_REG_EXPORT_DIR") {
        return PathBuf::from(dir).join(file_name);
    }
    PathBuf::from("artifacts").join("registry").join(file_name)
}

pub fn load_reg_records(path: &Path) -> Vec<RegKeyRecord> {
    let content = match read_text_prefix(path, DEFAULT_TEXT_MAX_BYTES * 8) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut records = Vec::new();
    let mut current_path: Option<String> = None;
    let mut current_values: BTreeMap<String, String> = BTreeMap::new();

    for line in normalize_logical_lines(&content) {
        if line.is_empty() || line.starts_with(';') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            if let Some(path_value) = current_path.take() {
                records.push(RegKeyRecord {
                    path: path_value,
                    values: current_values,
                });
                current_values = BTreeMap::new();
            }
            current_path = Some(line[1..line.len() - 1].trim().to_string());
            continue;
        }

        if let Some((name, value)) = split_value_line(&line) {
            current_values.insert(name, value);
        }
    }

    if let Some(path_value) = current_path {
        records.push(RegKeyRecord {
            path: path_value,
            values: current_values,
        });
    }

    records
}

fn normalize_logical_lines(content: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();

    for raw_line in content.lines() {
        let trimmed = raw_line.trim();
        current.push_str(trimmed);

        if current.ends_with('\\') {
            current.pop();
            continue;
        }

        lines.push(current.trim().to_string());
        current.clear();
    }

    if !current.trim().is_empty() {
        lines.push(current.trim().to_string());
    }

    lines
}

fn split_value_line(line: &str) -> Option<(String, String)> {
    if let Some(stripped) = line.strip_prefix("@=") {
        return Some(("@".to_string(), stripped.trim().to_string()));
    }

    if !line.starts_with('"') {
        return None;
    }

    let after_open = &line[1..];
    let close = after_open.find('"')?;
    let name = &after_open[..close];
    let rest = &after_open[close + 1..];
    let raw = rest.strip_prefix('=')?.trim();

    let normalized_name = name.replace("\\\\", "\\").replace("\\\"", "\"");
    Some((normalized_name, raw.to_string()))
}

pub fn decode_reg_string(raw: &str) -> Option<String> {
    let value = raw.trim();

    if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        let inner = &value[1..value.len() - 1];
        return Some(inner.replace("\\\\", "\\").replace("\\\"", "\""));
    }

    if let Some(hex_payload) = value.strip_prefix("hex(2):") {
        let bytes = parse_hex_csv(hex_payload)?;
        let mut units = Vec::new();
        let mut i = 0usize;
        while i + 1 < bytes.len() {
            let u = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
            if u == 0 {
                break;
            }
            units.push(u);
            i += 2;
        }
        return String::from_utf16(&units).ok();
    }

    if let Some(hex_payload) = value.strip_prefix("hex:") {
        let bytes = parse_hex_csv(hex_payload)?;
        if bytes.is_empty() {
            return None;
        }
        let maybe_text = bytes
            .iter()
            .copied()
            .take_while(|b| *b != 0u8)
            .collect::<Vec<u8>>();
        if maybe_text.is_empty() {
            return None;
        }
        return String::from_utf8(maybe_text).ok();
    }

    None
}

pub fn parse_reg_u32(raw: &str) -> Option<u32> {
    let value = raw.trim();
    if let Some(hex) = value.strip_prefix("dword:") {
        return u32::from_str_radix(hex, 16).ok();
    }
    if let Some(hex) = value.strip_prefix("qword:") {
        let v = u64::from_str_radix(hex, 16).ok()?;
        return u32::try_from(v).ok();
    }
    value.parse::<u32>().ok()
}

pub fn parse_reg_u64(raw: &str) -> Option<u64> {
    let value = raw.trim();
    if let Some(hex) = value.strip_prefix("qword:") {
        return u64::from_str_radix(hex, 16).ok();
    }
    if let Some(hex) = value.strip_prefix("dword:") {
        return u64::from_str_radix(hex, 16).ok();
    }
    value.parse::<u64>().ok()
}

pub fn parse_hex_bytes(raw: &str) -> Option<Vec<u8>> {
    let value = raw.trim();
    if let Some(hex_payload) = value.strip_prefix("hex:") {
        return parse_hex_csv(hex_payload);
    }
    if let Some(hex_payload) = value.strip_prefix("hex(b):") {
        return parse_hex_csv(hex_payload);
    }
    if let Some(hex_payload) = value.strip_prefix("hex(7):") {
        return parse_hex_csv(hex_payload);
    }
    None
}

fn parse_hex_csv(payload: &str) -> Option<Vec<u8>> {
    let compact = payload.replace("\\", "").replace(' ', "");
    if compact.is_empty() {
        return Some(Vec::new());
    }
    let mut bytes = Vec::new();
    for part in compact.split(',') {
        if part.is_empty() {
            continue;
        }
        let b = u8::from_str_radix(part, 16).ok()?;
        bytes.push(b);
    }
    Some(bytes)
}

pub fn filetime_to_unix(filetime: u64) -> Option<u64> {
    if filetime == 0 {
        return None;
    }
    let seconds = filetime / 10_000_000;
    if seconds < 11_644_473_600 {
        return None;
    }
    Some(seconds - 11_644_473_600)
}

pub fn filetime_bytes_to_unix(bytes: &[u8]) -> Option<u64> {
    if bytes.len() < 8 {
        return None;
    }
    let ft = u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    filetime_to_unix(ft)
}

pub fn unix_to_utc_rfc3339(unix: u64) -> Option<String> {
    DateTime::<Utc>::from_timestamp(unix as i64, 0).map(|dt| dt.to_rfc3339())
}

pub fn parse_yyyymmdd_to_unix(text: &str) -> Option<u64> {
    let trimmed = text.trim();
    if trimmed.len() != 8 || !trimmed.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }

    let year = trimmed.get(0..4)?.parse::<i32>().ok()?;
    let month = trimmed.get(4..6)?.parse::<u32>().ok()?;
    let day = trimmed.get(6..8)?.parse::<u32>().ok()?;

    ymd_to_unix_utc(year, month, day)
}

fn ymd_to_unix_utc(year: i32, month: u32, day: u32) -> Option<u64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || year < 1970 {
        return None;
    }

    let y = year - i32::from(month <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = (era * 146097 + doe as i32 - 719468) as i64;
    if days < 0 {
        return None;
    }
    Some((days as u64) * 86_400)
}

pub fn key_leaf(path: &str) -> String {
    path.rsplit('\\').next().unwrap_or_default().to_string()
}

pub fn find_first_string_value(record: &RegKeyRecord, names: &[&str]) -> Option<String> {
    for name in names {
        if let Some(raw) = record.values.get(*name) {
            if let Some(decoded) = decode_reg_string(raw) {
                return Some(decoded);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_basic_reg_records() {
        let content = r#"
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Example]
"Name"="Value"
"Build"=dword:0000000a
"Path"=hex(2):43,00,3a,00,5c,00,54,00,65,00,73,00,74,00,00,00
"#;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.reg");
        strata_fs::write(&file, content).unwrap();

        let records = load_reg_records(&file);
        assert_eq!(records.len(), 1);
        let rec = &records[0];
        assert_eq!(rec.path, "HKEY_CURRENT_USER\\Software\\Example");
        assert_eq!(
            decode_reg_string(rec.values.get("Name").unwrap()).unwrap(),
            "Value"
        );
        assert_eq!(parse_reg_u32(rec.values.get("Build").unwrap()), Some(10));
        assert_eq!(
            decode_reg_string(rec.values.get("Path").unwrap()).unwrap(),
            "C:\\Test"
        );
    }

    #[test]
    fn convert_filetime() {
        assert_eq!(filetime_to_unix(0), None);
        assert_eq!(filetime_to_unix(11644473600 * 10_000_000), Some(0));
    }

    #[test]
    fn parse_yyyymmdd_to_unix_value() {
        assert_eq!(parse_yyyymmdd_to_unix("20240305"), Some(1_709_596_800));
        assert_eq!(parse_yyyymmdd_to_unix("2024-03-05"), None);
    }
}
