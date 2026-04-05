use crate::errors::ForensicError;
use std::path::Path;

use super::reg_export::{
    decode_reg_string, default_reg_path, filetime_to_unix, load_reg_records, parse_reg_u64,
    parse_yyyymmdd_to_unix, unix_to_utc_rfc3339,
};

#[derive(Debug, Clone, Default)]
pub struct AmCacheEntry {
    pub file_path: String,
    pub sha1: Option<String>,
    pub program_id: Option<String>,
    pub last_modified: u64,
    pub last_modified_utc: Option<String>,
    pub created: u64,
    pub created_utc: Option<String>,
}

pub fn parse_amcache(data: &[u8]) -> Result<Vec<AmCacheEntry>, ForensicError> {
    // Best-effort parser for textual AmCache exports embedded in bytes.
    let mut out = Vec::new();
    let text = String::from_utf8_lossy(data);
    let mut current = AmCacheEntry::default();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if !current.file_path.is_empty() {
                out.push(current.clone());
                current = AmCacheEntry::default();
            }
            continue;
        }

        if let Some((k, v)) = split_kv(trimmed) {
            let key = k.to_ascii_lowercase();
            if key.contains("path") && current.file_path.is_empty() {
                current.file_path = normalize_path(v);
            } else if key.contains("sha1") {
                current.sha1 = normalize_sha1(v);
            } else if key.contains("program") && current.program_id.is_none() {
                current.program_id = Some(v.trim().to_string());
            } else if key.contains("modified") {
                let ts = parse_timestamp_text(v);
                current.last_modified = ts.unwrap_or(0);
                current.last_modified_utc = ts.and_then(unix_to_utc_rfc3339);
            } else if key.contains("created") {
                let ts = parse_timestamp_text(v);
                current.created = ts.unwrap_or(0);
                current.created_utc = ts.and_then(unix_to_utc_rfc3339);
            }
        }
    }

    if !current.file_path.is_empty() {
        out.push(current);
    }

    Ok(out)
}

pub fn get_amcache_file_entries() -> Result<Vec<AmCacheEntry>, ForensicError> {
    get_amcache_file_entries_from_reg(&default_reg_path("amcache.reg"))
}

pub fn get_amcache_file_entries_from_reg(path: &Path) -> Result<Vec<AmCacheEntry>, ForensicError> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records
        .iter()
        .filter(|r| r.path.to_ascii_lowercase().contains("amcache"))
    {
        let file_path = record
            .values
            .get("LowerCaseLongPath")
            .and_then(|v| decode_reg_string(v))
            .or_else(|| {
                record
                    .values
                    .get("FilePath")
                    .and_then(|v| decode_reg_string(v))
            })
            .map(|v| normalize_path(&v))
            .unwrap_or_default();

        let sha1 = record
            .values
            .get("Sha1")
            .and_then(|v| decode_reg_string(v))
            .or_else(|| {
                record
                    .values
                    .get("FileId")
                    .and_then(|v| decode_reg_string(v))
            })
            .and_then(|v| normalize_sha1(&v));

        let program_id = record
            .values
            .get("ProgramId")
            .and_then(|v| decode_reg_string(v))
            .map(|v| v.trim().to_string());

        let last_modified = record
            .values
            .get("LastWriteTime")
            .and_then(|v| parse_amcache_timestamp(v));
        let created = record
            .values
            .get("Created")
            .and_then(|v| parse_amcache_timestamp(v));

        if !file_path.is_empty() || sha1.is_some() {
            out.push(AmCacheEntry {
                file_path,
                sha1,
                program_id,
                last_modified: last_modified.unwrap_or(0),
                last_modified_utc: last_modified.and_then(unix_to_utc_rfc3339),
                created: created.unwrap_or(0),
                created_utc: created.and_then(unix_to_utc_rfc3339),
            });
        }
    }

    Ok(out)
}

fn split_kv(line: &str) -> Option<(&str, &str)> {
    let (k, v) = line.split_once(':')?;
    Some((k.trim(), v.trim()))
}

fn normalize_path(path: &str) -> String {
    path.trim().trim_matches('"').replace('/', "\\")
}

fn normalize_sha1(value: &str) -> Option<String> {
    let compact = value
        .trim()
        .trim_matches('"')
        .trim_start_matches("sha1:")
        .trim_start_matches("SHA1:")
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>();

    if compact.len() >= 40 {
        let tail = &compact[compact.len() - 40..];
        return Some(tail.to_ascii_uppercase());
    }

    None
}

fn parse_timestamp_text(value: &str) -> Option<u64> {
    let trimmed = value.trim().trim_matches('"');
    parse_yyyymmdd_to_unix(trimmed)
        .or_else(|| parse_timestamp_numeric(trimmed.parse::<u64>().ok()?))
}

fn parse_timestamp_numeric(value: u64) -> Option<u64> {
    if (946_684_800..4_102_444_800).contains(&value) {
        return Some(value);
    }

    // FILETIME in 100ns ticks.
    if value > 116_444_736_000_000_000 {
        return filetime_to_unix(value);
    }

    parse_yyyymmdd_to_unix(&value.to_string())
}

fn parse_amcache_timestamp(raw: &str) -> Option<u64> {
    if let Some(decoded) = decode_reg_string(raw) {
        if let Some(ts) = parse_timestamp_text(&decoded) {
            return Some(ts);
        }
    }
    parse_reg_u64(raw).and_then(parse_timestamp_numeric)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_amcache_text_normalizes_values() {
        let data = br#"
FilePath: "C:/Windows/System32/cmd.exe"
Sha1: sha1:00112233445566778899aabbccddeeff00112233
ProgramId: test-program
LastModified: 20240305
Created: 1700000000

FilePath: C:\Temp\bad.exe
Sha1: not-a-hash
LastModified: bad
"#;

        let rows = parse_amcache(data).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].file_path, r"C:\Windows\System32\cmd.exe");
        assert_eq!(
            rows[0].sha1.as_deref(),
            Some("00112233445566778899AABBCCDDEEFF00112233")
        );
        assert_eq!(rows[0].last_modified, 1_709_596_800);
        assert!(rows[0].last_modified_utc.is_some());
        assert_eq!(rows[1].sha1, None);
    }

    #[test]
    fn parse_amcache_reg_handles_filetime_and_yyyymmdd() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("amcache.reg");

        let expected_unix = 1_700_000_000u64;
        let filetime = (expected_unix + 11_644_473_600) * 10_000_000;
        strata_fs::write(
            &file,
            format!(
                r#"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateChange\PackageList\Amcache\Files\0001]
"LowerCaseLongPath"="c:\temp\calc.exe"
"FileId"="0000000000000000000000000000000000000000aa11bb22cc33dd44ee55ff6677889900"
"ProgramId"="Program-1"
"LastWriteTime"=qword:{filetime:016x}
"Created"="20240305"
"#
            ),
        )
        .unwrap();

        let rows = get_amcache_file_entries_from_reg(&file).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].file_path, r"c:\temp\calc.exe");
        let sha1 = rows[0].sha1.as_deref().unwrap();
        assert_eq!(sha1.len(), 40);
        assert!(sha1.ends_with("AA11BB22CC33DD44EE55FF6677889900"));
        assert_eq!(rows[0].last_modified, expected_unix);
        assert_eq!(rows[0].created, 1_709_596_800);
        assert!(rows[0].created_utc.is_some());
    }
}
