use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Default)]
pub struct LnkEntry {
    pub target_path: Option<String>,
    pub target_size: Option<u64>,
    pub target_modified: Option<DateTime<Utc>>,
    pub target_created: Option<DateTime<Utc>>,
    pub target_accessed: Option<DateTime<Utc>>,
    pub working_directory: Option<String>,
    pub arguments: Option<String>,
    pub machine_id: Option<String>,
    pub volume_label: Option<String>,
    pub drive_type: Option<String>,
    pub lnk_created: Option<DateTime<Utc>>,
    pub lnk_modified: Option<DateTime<Utc>>,
}

pub fn parse_lnk(data: &[u8]) -> Result<LnkEntry, String> {
    if data.len() < 0x4c {
        return Err("lnk data too small".to_string());
    }
    if !data.starts_with(&[0x4c, 0x00, 0x00, 0x00]) {
        return Err("invalid lnk header".to_string());
    }
    if !data.starts_with(&[0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00]) {
        return Err("invalid lnk magic".to_string());
    }

    let utf16 = extract_utf16_strings(data);
    let target_path = utf16
        .iter()
        .find(|s| {
            let sl = s.to_lowercase();
            sl.contains(":\\") || sl.starts_with("\\\\")
        })
        .cloned();
    let working_directory = utf16
        .iter()
        .find(|s| {
            let sl = s.to_lowercase();
            (sl.contains(":\\") || sl.starts_with("\\\\"))
                && target_path
                    .as_ref()
                    .map(|t| !t.eq_ignore_ascii_case(s))
                    .unwrap_or(true)
        })
        .cloned();
    let arguments = utf16
        .iter()
        .find(|s| s.starts_with('-') || s.starts_with('/') || s.contains(" -"))
        .cloned();
    let volume_label = utf16
        .iter()
        .find(|s| s.to_lowercase().contains("volume"))
        .cloned();

    let machine_id = utf16
        .iter()
        .find(|s| {
            s.len() >= 3
                && s.len() <= 32
                && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
        .cloned();

    let lnk_created = read_filetime(data, 0x1c);
    let lnk_accessed = read_filetime(data, 0x24);
    let lnk_modified = read_filetime(data, 0x2c);
    let target_size = read_u32_le(data, 0x34).map(|v| v as u64);

    let drive_type = target_path.as_deref().map(infer_drive_type);

    Ok(LnkEntry {
        target_path,
        target_size,
        target_modified: lnk_modified,
        target_created: lnk_created,
        target_accessed: lnk_accessed,
        working_directory,
        arguments,
        machine_id,
        volume_label,
        drive_type,
        lnk_created,
        lnk_modified,
    })
}

fn infer_drive_type(target: &str) -> String {
    let t = target.to_lowercase();
    if t.starts_with("\\\\") {
        "Network".to_string()
    } else if t.starts_with("\\\\?\\usb") || t.starts_with("a:\\") || t.starts_with("b:\\") {
        "Removable".to_string()
    } else if t.len() >= 3 && t.as_bytes()[1] == b':' && t.as_bytes()[2] == b'\\' {
        "Local Fixed Disk".to_string()
    } else {
        "Unknown".to_string()
    }
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

fn read_filetime(data: &[u8], off: usize) -> Option<DateTime<Utc>> {
    let ft = read_u64_le(data, off)?;
    if ft == 0 {
        return None;
    }
    let secs_since_1601 = ft / 10_000_000;
    if secs_since_1601 < 11_644_473_600 {
        return None;
    }
    let unix_secs = secs_since_1601 - 11_644_473_600;
    DateTime::<Utc>::from_timestamp(unix_secs as i64, 0)
}

fn extract_utf16_strings(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = Vec::<u16>::new();
    let mut i = 0usize;
    while i + 1 < data.len() {
        let v = u16::from_le_bytes([data[i], data[i + 1]]);
        if v == 0 {
            if cur.len() >= 4 {
                if let Ok(s) = String::from_utf16(&cur) {
                    let trimmed = s.trim().to_string();
                    if !trimmed.is_empty() {
                        out.push(trimmed);
                    }
                }
            }
            cur.clear();
        } else if (0x20..=0x7E).contains(&v) {
            cur.push(v);
        } else {
            if cur.len() >= 4 {
                if let Ok(s) = String::from_utf16(&cur) {
                    let trimmed = s.trim().to_string();
                    if !trimmed.is_empty() {
                        out.push(trimmed);
                    }
                }
            }
            cur.clear();
        }
        i += 2;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_lnk_rejects_small_data() {
        let err = parse_lnk(&[0u8; 12]).err().unwrap_or_default();
        assert!(err.contains("too small"));
    }

    #[test]
    fn parse_lnk_rejects_bad_magic() {
        let mut data = vec![0u8; 0x60];
        data[0..4].copy_from_slice(&[0x4c, 0x00, 0x00, 0x00]);
        data[4..8].copy_from_slice(&[0, 0, 0, 0]);
        let err = parse_lnk(&data).err().unwrap_or_default();
        assert!(err.contains("invalid lnk magic"));
    }

    #[test]
    fn parse_lnk_detects_local_fixed_drive_target() {
        let mut data = vec![0u8; 0x140];
        data[0..8].copy_from_slice(&[0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00]);
        data[0x1c..0x24].copy_from_slice(&133_515_874_611_440_142u64.to_le_bytes());
        data[0x34..0x38].copy_from_slice(&4096u32.to_le_bytes());
        put_utf16(&mut data, 0x80, "C:\\Windows\\System32\\cmd.exe");

        let parsed = parse_lnk(&data).ok().unwrap_or_default();
        assert_eq!(parsed.target_size, Some(4096));
        assert_eq!(parsed.drive_type.as_deref(), Some("Local Fixed Disk"));
        assert!(parsed
            .target_path
            .unwrap_or_default()
            .to_lowercase()
            .contains("cmd.exe"));
    }

    #[test]
    fn parse_lnk_detects_network_target() {
        let mut data = vec![0u8; 0x140];
        data[0..8].copy_from_slice(&[0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00]);
        put_utf16(&mut data, 0x80, "\\\\server\\share\\payload.exe");

        let parsed = parse_lnk(&data).ok().unwrap_or_default();
        assert_eq!(parsed.drive_type.as_deref(), Some("Network"));
    }

    fn put_utf16(data: &mut [u8], mut off: usize, text: &str) {
        for c in text.encode_utf16() {
            if off + 1 >= data.len() {
                return;
            }
            data[off..off + 2].copy_from_slice(&c.to_le_bytes());
            off += 2;
        }
    }
}
