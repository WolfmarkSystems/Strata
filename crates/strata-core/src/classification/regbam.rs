use std::collections::BTreeMap;
use std::path::Path;

use super::reg_export::{
    decode_reg_string, default_reg_path, filetime_bytes_to_unix, filetime_to_unix,
    load_reg_records, parse_hex_bytes, parse_reg_u64, unix_to_utc_rfc3339,
};

pub fn get_bam_state() -> Vec<BamEntry> {
    get_bam_state_from_reg(&default_reg_path("bam.reg"))
}

pub fn get_bam_state_from_reg(path: &Path) -> Vec<BamEntry> {
    let records = load_reg_records(path);
    let mut by_path: BTreeMap<String, BamEntry> = BTreeMap::new();

    for record in records.iter().filter(|r| {
        let path_lc = r.path.to_ascii_lowercase();
        path_lc.contains("\\services\\bam\\state\\usersettings\\")
            || path_lc.contains("\\services\\dam\\state\\usersettings\\")
    }) {
        let source = if record
            .path
            .to_ascii_lowercase()
            .contains("\\services\\dam\\")
        {
            "dam"
        } else {
            "bam"
        };
        let actor_sid = record
            .path
            .rsplit('\\')
            .next()
            .unwrap_or_default()
            .to_string();
        for (name, raw) in &record.values {
            if name.eq_ignore_ascii_case("@") {
                continue;
            }
            let program_path = normalize_windows_path(name);
            let last_execution = parse_bam_timestamp(raw);
            let candidate = BamEntry {
                program_path: program_path.clone(),
                last_execution_utc: last_execution.and_then(unix_to_utc_rfc3339),
                actor_sid: (!actor_sid.is_empty()).then_some(actor_sid.clone()),
                source: source.to_string(),
                last_execution,
            };

            match by_path.get(&program_path) {
                Some(existing)
                    if existing.last_execution.unwrap_or(0)
                        >= candidate.last_execution.unwrap_or(0) => {}
                _ => {
                    by_path.insert(program_path, candidate);
                }
            }
        }
    }

    let mut out = by_path.into_values().collect::<Vec<_>>();
    out.sort_by(|a, b| {
        b.last_execution
            .unwrap_or(0)
            .cmp(&a.last_execution.unwrap_or(0))
            .then_with(|| a.program_path.cmp(&b.program_path))
    });
    out
}

fn parse_bam_timestamp(raw: &str) -> Option<u64> {
    if let Some(bytes) = parse_hex_bytes(raw) {
        if let Some(ts) = parse_filetime_candidate(&bytes) {
            return Some(ts);
        }
    }

    if let Some(decoded) = decode_reg_string(raw) {
        if let Ok(value) = decoded.trim().parse::<u64>() {
            if let Some(ts) = parse_timestamp_numeric(value) {
                return Some(ts);
            }
        }
    }

    parse_reg_u64(raw).and_then(parse_timestamp_numeric)
}

fn parse_timestamp_numeric(value: u64) -> Option<u64> {
    if (946_684_800..4_102_444_800).contains(&value) {
        return Some(value);
    }
    if value > 116_444_736_000_000_000 {
        return filetime_to_unix(value);
    }
    None
}

fn parse_filetime_candidate(bytes: &[u8]) -> Option<u64> {
    if bytes.len() < 8 {
        return None;
    }

    if let Some(first) = filetime_bytes_to_unix(&bytes[..8]) {
        if (946_684_800..=4_102_444_800).contains(&first) {
            return Some(first);
        }
    }

    for window in bytes.windows(8) {
        if let Some(ts) = filetime_bytes_to_unix(window) {
            if (946_684_800..=4_102_444_800).contains(&ts) {
                return Some(ts);
            }
        }
    }

    None
}

fn normalize_windows_path(value: &str) -> String {
    value.trim().trim_matches('"').replace('/', "\\")
}

#[derive(Debug, Clone, Default)]
pub struct BamEntry {
    pub program_path: String,
    pub last_execution: Option<u64>,
    pub last_execution_utc: Option<String>,
    pub actor_sid: Option<String>,
    pub source: String,
}

pub fn get_shim_cache() -> Vec<ShimCacheEntry> {
    get_shim_cache_from_reg(&default_reg_path("appcompat.reg"))
}

pub fn get_shim_cache_from_reg(path: &Path) -> Vec<ShimCacheEntry> {
    let records = load_reg_records(path);
    let mut by_path: BTreeMap<String, ShimCacheEntry> = BTreeMap::new();

    for record in records.iter().filter(|r| {
        let p = r.path.to_ascii_lowercase();
        p.contains("appcompatcache") || p.contains("shimcache")
    }) {
        for (name, raw) in &record.values {
            if name.eq_ignore_ascii_case("@") {
                continue;
            }

            let last_modified = parse_shim_timestamp(raw);
            let candidates = extract_shim_paths(name, raw);
            if candidates.is_empty() {
                let fallback = normalize_windows_path(name);
                if !fallback.is_empty() {
                    upsert_shim(&mut by_path, fallback, last_modified, record.path.clone());
                }
                continue;
            }

            for candidate in candidates {
                upsert_shim(&mut by_path, candidate, last_modified, record.path.clone());
            }
        }
    }

    let mut out = by_path.into_values().collect::<Vec<_>>();
    out.sort_by(|a, b| {
        b.last_modified
            .unwrap_or(0)
            .cmp(&a.last_modified.unwrap_or(0))
            .then_with(|| a.path.cmp(&b.path))
    });
    out
}

fn upsert_shim(
    by_path: &mut BTreeMap<String, ShimCacheEntry>,
    path: String,
    last_modified: Option<u64>,
    source_key: String,
) {
    let entry = ShimCacheEntry {
        path: path.clone(),
        last_modified_utc: last_modified.and_then(unix_to_utc_rfc3339),
        source_key,
        last_modified,
    };

    match by_path.get(&path) {
        Some(existing)
            if existing.last_modified.unwrap_or(0) >= entry.last_modified.unwrap_or(0) => {}
        _ => {
            by_path.insert(path, entry);
        }
    }
}

fn parse_shim_timestamp(raw: &str) -> Option<u64> {
    if let Some(bytes) = parse_hex_bytes(raw) {
        return parse_filetime_candidate(&bytes);
    }
    decode_reg_string(raw)
        .and_then(|s| s.parse::<u64>().ok())
        .and_then(parse_timestamp_numeric)
        .or_else(|| parse_reg_u64(raw).and_then(parse_timestamp_numeric))
}

fn extract_shim_paths(name: &str, raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    if name.contains('\\') && (name.contains(":\\") || name.starts_with("\\\\")) {
        out.push(normalize_windows_path(name));
    }

    if let Some(decoded) = decode_reg_string(raw) {
        for token in decoded.split('\0') {
            let t = normalize_windows_path(token);
            if t.contains(":\\") || t.starts_with("\\\\") {
                out.push(t);
            }
        }
    }

    if out.is_empty() {
        if let Some(bytes) = parse_hex_bytes(raw) {
            let text = String::from_utf8_lossy(&bytes);
            for token in text.split('\0') {
                let t = normalize_windows_path(token);
                if t.contains(":\\") || t.starts_with("\\\\") {
                    out.push(t);
                }
            }
        }
    }

    out.sort();
    out.dedup();
    out
}

#[derive(Debug, Clone, Default)]
pub struct ShimCacheEntry {
    pub path: String,
    pub last_modified: Option<u64>,
    pub last_modified_utc: Option<String>,
    pub source_key: String,
}

pub fn get_appcompat_cache() -> Vec<AppCompatEntry> {
    get_appcompat_cache_from_reg(&default_reg_path("appcompat.reg"))
}

pub fn get_appcompat_cache_from_reg(path: &Path) -> Vec<AppCompatEntry> {
    get_shim_cache_from_reg(path)
        .into_iter()
        .map(|entry| AppCompatEntry {
            program: entry.path,
            flags: "shimcache".to_string(),
        })
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct AppCompatEntry {
    pub program: String,
    pub flags: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_bam_state_entries() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("bam.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21]
"C:\\Windows\\System32\\cmd.exe"=hex:b0,6c,4f,be,78,cd,d9,01
"#,
        )
        .unwrap();
        let rows = get_bam_state_from_reg(&file);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].program_path, "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(rows[0].actor_sid.as_deref(), Some("S-1-5-21"));
        assert_eq!(rows[0].source, "bam");
    }

    #[test]
    fn bam_prefers_newest_duplicate_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("bam.reg");
        let old_ft = (1_700_000_000u64 + 11_644_473_600) * 10_000_000;
        let new_ft = (1_700_000_500u64 + 11_644_473_600) * 10_000_000;
        strata_fs::write(
            &file,
            format!(
                r#"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21]
"C:\\Windows\\System32\\cmd.exe"=qword:{old_ft:016x}
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-22]
"C:\\Windows\\System32\\cmd.exe"=qword:{new_ft:016x}
"#
            ),
        )
        .unwrap();
        let rows = get_bam_state_from_reg(&file);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].last_execution, Some(1_700_000_500));
        assert_eq!(rows[0].actor_sid.as_deref(), Some("S-1-5-22"));
    }

    #[test]
    fn parse_dam_state_entries() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("bam.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\S-1-5-18]
"C:\\Windows\\System32\\svchost.exe"=hex:b0,6c,4f,be,78,cd,d9,01
"#,
        )
        .unwrap();
        let rows = get_bam_state_from_reg(&file);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].program_path, "C:\\Windows\\System32\\svchost.exe");
        assert_eq!(rows[0].actor_sid.as_deref(), Some("S-1-5-18"));
        assert_eq!(rows[0].source, "dam");
    }

    #[test]
    fn extract_shim_paths_from_value_data() {
        let rows = extract_shim_paths(
            "AppCompatCache",
            "\"C:\\\\Windows\\\\System32\\\\notepad.exe\\0C:\\\\Windows\\\\System32\\\\cmd.exe\"",
        );
        assert!(!rows.is_empty());
        assert!(rows.iter().any(|v| v.contains("notepad.exe")));
    }

    #[test]
    fn shim_cache_dedup_and_timestamp_prefers_newest() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("appcompat.reg");
        let old_ft = (1_700_000_000u64 + 11_644_473_600) * 10_000_000;
        let new_ft = (1_700_000_050u64 + 11_644_473_600) * 10_000_000;
        strata_fs::write(
            &file,
            format!(
                r#"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache]
"Entry1"=qword:{old_ft:016x}
"Entry2"=qword:{new_ft:016x}
"#,
            ),
        )
        .unwrap();
        let rows = get_shim_cache_from_reg(&file);
        assert!(!rows.is_empty());
        let newest = rows
            .iter()
            .max_by_key(|r| r.last_modified.unwrap_or(0))
            .unwrap();
        assert_eq!(newest.last_modified, Some(1_700_000_050));
        assert!(newest.last_modified_utc.is_some());
    }

    #[test]
    fn shim_cache_sorted_newest_first_then_path() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("appcompat.reg");
        let same_ft = (1_700_000_010u64 + 11_644_473_600) * 10_000_000;
        let new_ft = (1_700_000_100u64 + 11_644_473_600) * 10_000_000;
        strata_fs::write(
            &file,
            format!(
                r#"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache]
"C:\\B.exe"=qword:{same_ft:016x}
"C:\\A.exe"=qword:{same_ft:016x}
"C:\\Newest.exe"=qword:{new_ft:016x}
"#,
            ),
        )
        .unwrap();
        let rows = get_shim_cache_from_reg(&file);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].path, r"C:\Newest.exe");
        assert_eq!(rows[1].path, r"C:\A.exe");
        assert_eq!(rows[2].path, r"C:\B.exe");
    }
}
