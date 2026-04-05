use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Default)]
pub struct PrefetchEntry {
    pub executable_name: String,
    pub prefetch_hash: u32,
    pub run_count: u32,
    pub last_run_times: Vec<DateTime<Utc>>,
    pub volume_paths: Vec<String>,
    pub file_references: Vec<String>,
    pub version: u32,
    pub compressed: bool,
}

pub fn parse_prefetch(data: &[u8]) -> Result<PrefetchEntry, String> {
    if data.len() < 8 {
        return Err("prefetch data too small".to_string());
    }

    let (parsed, compressed) = maybe_decompress_mam(data)?;
    let data = parsed.as_slice();

    let signature = &data[4..8];
    if signature != b"SCCA" {
        return Err("not a prefetch file".to_string());
    }

    let version = read_u32_le(data, 0).unwrap_or(0);
    let executable_name = read_utf16z(data, 16, 60).unwrap_or_else(|| "<unknown>".to_string());
    let prefetch_hash = read_u32_le(data, 0x4C).unwrap_or(0);

    let run_count_offset = match version {
        17 => 0x90,
        23 => 0x98,
        26 | 30 => 0xD0,
        _ => 0xD0,
    };
    let run_count = read_u32_le(data, run_count_offset).unwrap_or(0);

    let mut last_run_times = Vec::new();
    let base_run_offset = match version {
        17 => 0x78,
        23 => 0x80,
        26 | 30 => 0x80,
        _ => 0x80,
    };
    let max_runs = if matches!(version, 26 | 30) { 8 } else { 1 };
    for i in 0..max_runs {
        let off = base_run_offset + (i * 8);
        if let Some(ft) = read_u64_le(data, off) {
            if let Some(dt) = filetime_to_utc(ft) {
                last_run_times.push(dt);
            }
        }
    }
    let (volume_paths, file_references) = extract_prefetch_paths(data);

    Ok(PrefetchEntry {
        executable_name,
        prefetch_hash,
        run_count,
        last_run_times,
        volume_paths,
        file_references,
        version,
        compressed,
    })
}

fn maybe_decompress_mam(data: &[u8]) -> Result<(Vec<u8>, bool), String> {
    if !data.starts_with(&[0x4D, 0x41, 0x4D, 0x04]) {
        return Ok((data.to_vec(), false));
    }
    if data.len() < 12 {
        return Err("MAM prefetch header too small".to_string());
    }

    let signature = read_u32_le(data, 0).ok_or_else(|| "invalid MAM header".to_string())?;
    let decompressed_size =
        read_u32_le(data, 4).ok_or_else(|| "invalid MAM decompressed size".to_string())?;
    let compression = (signature & 0x0F00_0000) >> 24;
    let magic = signature & 0x00FF_FFFF;
    let expected_magic = u32::from_le_bytes([b'M', b'A', b'M', 0x00]);
    if magic != expected_magic {
        return Err("invalid MAM prefetch signature".to_string());
    }

    let compressed = &data[8..];
    let mut out = Vec::with_capacity(decompressed_size as usize);
    frnsc_prefetch::decompress::decompress(
        compressed,
        &mut out,
        frnsc_prefetch::decompress::CompressionAlgorithm::from(compression),
    )
    .map_err(|e| format!("MAM decompression failed: {}", e))?;

    if out.len() < 8 || &out[4..8] != b"SCCA" {
        return Err("decompressed prefetch payload is invalid".to_string());
    }

    Ok((out, true))
}

fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
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

fn read_u64_le(data: &[u8], off: usize) -> Option<u64> {
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

fn read_utf16z(data: &[u8], off: usize, chars: usize) -> Option<String> {
    if off >= data.len() {
        return None;
    }
    let max_bytes = chars.saturating_mul(2);
    let end = (off + max_bytes).min(data.len());
    let mut u16s = Vec::new();
    let mut i = off;
    while i + 1 < end {
        let v = u16::from_le_bytes([data[i], data[i + 1]]);
        if v == 0 {
            break;
        }
        u16s.push(v);
        i += 2;
    }
    String::from_utf16(&u16s).ok()
}

fn filetime_to_utc(filetime: u64) -> Option<DateTime<Utc>> {
    if filetime == 0 {
        return None;
    }
    let secs_since_1601 = filetime / 10_000_000;
    if secs_since_1601 < 11_644_473_600 {
        return None;
    }
    let unix_secs = secs_since_1601 - 11_644_473_600;
    DateTime::<Utc>::from_timestamp(unix_secs as i64, 0)
}

fn extract_prefetch_paths(data: &[u8]) -> (Vec<String>, Vec<String>) {
    let mut all_strings = extract_utf16_strings(data, 4);
    all_strings.sort_unstable();
    all_strings.dedup();

    let mut volume_paths = Vec::new();
    let mut file_references = Vec::new();

    for s in &all_strings {
        let lc = s.to_lowercase();
        if (lc.starts_with("\\device\\")
            || (lc.len() >= 3
                && lc.as_bytes().get(1) == Some(&b':')
                && lc.as_bytes().get(2) == Some(&b'\\')))
            && !volume_paths.contains(s)
        {
            volume_paths.push(s.clone());
        }
        if lc.contains('\\')
            && (lc.contains('.') || lc.contains(":\\") || lc.contains("\\\\"))
            && !file_references.contains(s)
        {
            file_references.push(s.clone());
        }
    }

    if file_references.len() > 200 {
        file_references.truncate(200);
    }
    if volume_paths.len() > 32 {
        volume_paths.truncate(32);
    }

    (volume_paths, file_references)
}

fn extract_utf16_strings(data: &[u8], min_chars: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 1 < data.len() {
        let mut u16s = Vec::new();
        let start = i;
        while i + 1 < data.len() {
            let v = u16::from_le_bytes([data[i], data[i + 1]]);
            if v == 0 {
                i += 2;
                break;
            }
            if (0x20..=0x7E).contains(&(v as u8)) || v == 0x5C {
                u16s.push(v);
                i += 2;
                continue;
            }
            u16s.clear();
            i = start.saturating_add(2);
            break;
        }

        if u16s.len() >= min_chars {
            if let Ok(s) = String::from_utf16(&u16s) {
                let trimmed = s.trim_matches(char::from(0)).trim().to_string();
                if !trimmed.is_empty() {
                    out.push(trimmed);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_prefetch_rejects_small_input() {
        let err = parse_prefetch(&[0u8; 4]).err().unwrap_or_default();
        assert!(err.contains("too small"));
    }

    #[test]
    fn parse_prefetch_rejects_invalid_signature() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&30u32.to_le_bytes());
        data[4..8].copy_from_slice(b"BAD!");
        let err = parse_prefetch(&data).err().unwrap_or_default();
        assert!(err.contains("not a prefetch"));
    }

    #[test]
    fn parse_prefetch_parses_basic_v30_layout() {
        let mut data = vec![0u8; 0xE0];
        data[0..4].copy_from_slice(&30u32.to_le_bytes());
        data[4..8].copy_from_slice(b"SCCA");

        let name = "CMD.EXE";
        let mut at = 16usize;
        for c in name.encode_utf16() {
            data[at..at + 2].copy_from_slice(&c.to_le_bytes());
            at += 2;
        }

        data[0x4C..0x50].copy_from_slice(&0xABCD1234u32.to_le_bytes());
        data[0xD0..0xD4].copy_from_slice(&3u32.to_le_bytes());
        data[0x80..0x88].copy_from_slice(&133_515_874_611_440_142u64.to_le_bytes());

        let parsed = parse_prefetch(&data).ok().unwrap_or_default();
        assert_eq!(parsed.version, 30);
        assert_eq!(parsed.run_count, 3);
        assert_eq!(parsed.prefetch_hash, 0xABCD1234);
        assert!(parsed.executable_name.contains("CMD.EXE"));
        assert!(!parsed.last_run_times.is_empty());
    }

    #[test]
    fn parse_prefetch_parses_basic_v17_layout() {
        let mut data = vec![0u8; 0xA0];
        data[0..4].copy_from_slice(&17u32.to_le_bytes());
        data[4..8].copy_from_slice(b"SCCA");

        let name = "CALC.EXE";
        let mut at = 16usize;
        for c in name.encode_utf16() {
            data[at..at + 2].copy_from_slice(&c.to_le_bytes());
            at += 2;
        }

        data[0x4C..0x50].copy_from_slice(&0x11223344u32.to_le_bytes());
        data[0x90..0x94].copy_from_slice(&7u32.to_le_bytes());
        data[0x78..0x80].copy_from_slice(&133_515_874_611_440_142u64.to_le_bytes());

        let parsed = parse_prefetch(&data).ok().unwrap_or_default();
        assert_eq!(parsed.version, 17);
        assert_eq!(parsed.run_count, 7);
        assert_eq!(parsed.prefetch_hash, 0x11223344);
        assert!(parsed.executable_name.contains("CALC.EXE"));
        assert_eq!(parsed.last_run_times.len(), 1);
    }

    #[test]
    fn parse_prefetch_flags_invalid_mam_payload() {
        let data = vec![0x4D, 0x41, 0x4D, 0x04, 0, 0, 0, 0, 0, 0, 0, 0];
        let err = parse_prefetch(&data).err().unwrap_or_default();
        assert!(!err.is_empty());
    }
}
