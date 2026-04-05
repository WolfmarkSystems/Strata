use crate::errors::ForensicError;

#[derive(Debug, Clone, Default)]
pub struct PrefetchInfo {
    pub version: u32,
    pub application_name: String,
    pub last_run: u64,
    pub run_times: Vec<u64>,
    pub run_count: u32,
    pub directories: Vec<String>,
    pub files: Vec<String>,
}

pub fn parse_prefetch_info(data: &[u8]) -> Result<PrefetchInfo, ForensicError> {
    if data.len() < 8 {
        return Ok(PrefetchInfo {
            version: 0,
            application_name: String::new(),
            last_run: 0,
            run_times: Vec::new(),
            run_count: 0,
            directories: Vec::new(),
            files: Vec::new(),
        });
    }

    if data[0..4] != b"SCCA"[..] {
        return Ok(PrefetchInfo {
            version: 0,
            application_name: String::new(),
            last_run: 0,
            run_times: Vec::new(),
            run_count: 0,
            directories: Vec::new(),
            files: Vec::new(),
        });
    }

    let mut info = PrefetchInfo {
        version: extract_prefetch_version(data),
        ..PrefetchInfo::default()
    };

    let filename = extract_prefetch_name(data);
    info.application_name = filename;

    info.run_count = extract_run_count(data, info.version);

    info.run_times = get_prefetch_times(data, info.version);
    info.last_run = info.run_times.first().copied().unwrap_or(0);

    let strings = extract_prefetch_strings(data);
    for s in strings {
        if let Some((dir, _)) = s.rsplit_once('\\') {
            info.files.push(s.clone());
            info.directories.push(dir.to_string());
        }
    }

    info.directories = dedupe_sorted_paths(info.directories);
    info.files = dedupe_sorted_paths(info.files);

    Ok(info)
}

pub fn get_prefetch_times(data: &[u8], version: u32) -> Vec<u64> {
    let mut out = Vec::new();
    let mut bases = time_offsets_for_version(version);
    bases.sort();
    bases.dedup();

    let slots = 8usize;
    for base in bases {
        for i in 0..slots {
            let off = base + i * 8;
            if data.len() < off + 8 {
                break;
            }
            let ft = u64::from_le_bytes([
                data[off],
                data[off + 1],
                data[off + 2],
                data[off + 3],
                data[off + 4],
                data[off + 5],
                data[off + 6],
                data[off + 7],
            ]);
            if let Some(unix) = filetime_to_unix(ft) {
                out.push(unix);
            }
        }
    }
    out.sort_by(|a, b| b.cmp(a));
    out.dedup();
    out
}

pub fn extract_prefetch_strings(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = Vec::<u16>::new();
    let mut i = 0usize;
    while i + 1 < data.len() {
        let ch = u16::from_le_bytes([data[i], data[i + 1]]);
        if ch == 0 {
            if current.len() >= 4 {
                if let Ok(s) = String::from_utf16(&current) {
                    let cleaned = s.trim().to_string();
                    if !cleaned.is_empty() {
                        out.push(cleaned);
                    }
                }
            }
            current.clear();
        } else if ch <= 0x7f {
            current.push(ch);
        } else {
            current.clear();
        }
        i += 2;
    }

    out.sort();
    out.dedup();
    out
}

fn extract_prefetch_name(data: &[u8]) -> String {
    let start = 0x10usize;
    let end = (start + 60).min(data.len());
    if start >= end {
        return String::new();
    }
    let mut units = Vec::new();
    let mut i = start;
    while i + 1 < end {
        let u = u16::from_le_bytes([data[i], data[i + 1]]);
        if u == 0 {
            break;
        }
        units.push(u);
        i += 2;
    }
    String::from_utf16(&units).unwrap_or_default()
}

fn extract_prefetch_version(data: &[u8]) -> u32 {
    if data.len() < 8 {
        return 0;
    }
    u32::from_le_bytes([data[4], data[5], data[6], data[7]])
}

fn extract_run_count(data: &[u8], version: u32) -> u32 {
    let mut candidates = run_count_offsets_for_version(version);
    candidates.sort();
    candidates.dedup();

    for off in candidates {
        if data.len() < off + 4 {
            continue;
        }
        let count = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        if count > 0 && count <= 10_000_000 {
            return count;
        }
    }
    0
}

fn run_count_offsets_for_version(version: u32) -> Vec<usize> {
    match version {
        17 => vec![0x90usize, 0x98usize, 0x78usize],
        23 => vec![0x98usize, 0x90usize, 0x78usize],
        26 | 30 => vec![0xD0usize, 0x98usize, 0x90usize, 0x78usize],
        _ => vec![0x78usize, 0x90usize, 0x98usize, 0xD0usize],
    }
}

fn time_offsets_for_version(version: u32) -> Vec<usize> {
    match version {
        17 => vec![0x78usize, 0x80usize, 0x90usize],
        23 => vec![0x80usize, 0x88usize, 0x90usize],
        26 | 30 => vec![0x80usize, 0x88usize, 0x90usize, 0x98usize],
        _ => vec![0x80usize, 0x90usize, 0x98usize],
    }
}

fn normalize_prefetch_reference_path(value: &str) -> String {
    let mut normalized = value.trim().replace('/', "\\");
    while normalized.ends_with('\\') {
        normalized.pop();
    }
    normalized
}

fn dedupe_sorted_paths(values: Vec<String>) -> Vec<String> {
    let mut keys = std::collections::BTreeMap::<String, String>::new();
    for value in values {
        let normalized = normalize_prefetch_reference_path(&value);
        if normalized.is_empty() {
            continue;
        }
        let key = normalized.to_ascii_lowercase();
        keys.entry(key).or_insert(normalized);
    }
    keys.into_values().collect()
}

fn filetime_to_unix(ft: u64) -> Option<u64> {
    if ft == 0 {
        return None;
    }
    let seconds = ft / 10_000_000;
    if seconds < 11_644_473_600 {
        return None;
    }
    let unix = seconds - 11_644_473_600;
    // Plausible analyst timeline range.
    if !(631_152_000..=4_102_444_800).contains(&unix) {
        return None;
    }
    Some(unix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_prefetch_header_fields() {
        let mut data = vec![0u8; 256];
        data[0..4].copy_from_slice(b"SCCA");
        data[4..8].copy_from_slice(&30u32.to_le_bytes());
        // run count at 0x78
        data[0x78..0x7c].copy_from_slice(&5u32.to_le_bytes());
        // first run time at 0x80
        let ft = (11_644_473_600u64 + 1_700_000_000u64) * 10_000_000u64;
        data[0x80..0x88].copy_from_slice(&ft.to_le_bytes());
        let info = parse_prefetch_info(&data).unwrap();
        assert_eq!(info.version, 30);
        assert_eq!(info.run_count, 5);
        assert_eq!(info.last_run, 1_700_000_000u64);
        assert!(info.run_times.contains(&1_700_000_000u64));
    }

    #[test]
    fn parse_prefetch_legacy_run_count_offset() {
        let mut data = vec![0u8; 320];
        data[0..4].copy_from_slice(b"SCCA");
        data[4..8].copy_from_slice(&17u32.to_le_bytes());
        data[0x90..0x94].copy_from_slice(&11u32.to_le_bytes());
        let ft = (11_644_473_600u64 + 1_701_000_000u64) * 10_000_000u64;
        data[0x80..0x88].copy_from_slice(&ft.to_le_bytes());

        let info = parse_prefetch_info(&data).unwrap();
        assert_eq!(info.version, 17);
        assert_eq!(info.run_count, 11);
        assert_eq!(info.last_run, 1_701_000_000u64);
    }

    #[test]
    fn parse_prefetch_v23_uses_expected_offsets() {
        let mut data = vec![0u8; 320];
        data[0..4].copy_from_slice(b"SCCA");
        data[4..8].copy_from_slice(&23u32.to_le_bytes());
        data[0x98..0x9c].copy_from_slice(&9u32.to_le_bytes());
        let ft = (11_644_473_600u64 + 1_702_000_000u64) * 10_000_000u64;
        data[0x88..0x90].copy_from_slice(&ft.to_le_bytes());

        let info = parse_prefetch_info(&data).unwrap();
        assert_eq!(info.version, 23);
        assert_eq!(info.run_count, 9);
        assert_eq!(info.last_run, 1_702_000_000u64);
    }

    #[test]
    fn parse_prefetch_v26_uses_expected_offsets() {
        let mut data = vec![0u8; 384];
        data[0..4].copy_from_slice(b"SCCA");
        data[4..8].copy_from_slice(&26u32.to_le_bytes());
        data[0xD0..0xD4].copy_from_slice(&4u32.to_le_bytes());
        let ft = (11_644_473_600u64 + 1_703_000_000u64) * 10_000_000u64;
        data[0x98..0xA0].copy_from_slice(&ft.to_le_bytes());

        let info = parse_prefetch_info(&data).unwrap();
        assert_eq!(info.version, 26);
        assert_eq!(info.run_count, 4);
        assert_eq!(info.last_run, 1_703_000_000u64);
    }

    #[test]
    fn parse_prefetch_truncated_record_returns_safe_defaults() {
        let mut data = vec![0u8; 72];
        data[0..4].copy_from_slice(b"SCCA");
        data[4..8].copy_from_slice(&30u32.to_le_bytes());
        let info = parse_prefetch_info(&data).unwrap();
        assert_eq!(info.version, 30);
        assert_eq!(info.run_count, 0);
        assert!(info.run_times.is_empty());
        assert!(info.files.is_empty());
    }

    #[test]
    fn dedupe_sorted_paths_is_case_insensitive_and_normalized() {
        let values = vec![
            r"C:\Windows\System32\NOTEPAD.EXE".to_string(),
            r"c:/windows/system32/notepad.exe".to_string(),
            r"C:\Windows\System32\calc.exe\".to_string(),
        ];
        let deduped = dedupe_sorted_paths(values);
        assert_eq!(deduped.len(), 2);
        assert!(deduped
            .iter()
            .any(|v| v.eq_ignore_ascii_case(r"C:\Windows\System32\NOTEPAD.EXE")));
        assert!(deduped
            .iter()
            .any(|v| v.eq_ignore_ascii_case(r"C:\Windows\System32\calc.exe")));
    }
}
