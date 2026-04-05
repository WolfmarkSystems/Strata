use std::path::Path;

use super::reg_export::{
    decode_reg_string, default_reg_path, filetime_bytes_to_unix, load_reg_records, parse_hex_bytes,
    parse_reg_u32, unix_to_utc_rfc3339,
};

pub fn get_user_assist() -> Vec<UserAssistEntry> {
    get_user_assist_from_reg(&default_reg_path("userassist.reg"))
}

pub fn get_user_assist_from_reg(path: &Path) -> Vec<UserAssistEntry> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records.iter().filter(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("\\explorer\\userassist\\")
    }) {
        for (name, raw) in &record.values {
            if name.eq_ignore_ascii_case("@") {
                continue;
            }

            let decoded_name = normalize_userassist_name(name);
            let mut run_count = parse_reg_u32(raw).unwrap_or(0);
            let mut last_run = None;

            if let Some(bytes) = parse_hex_bytes(raw) {
                if let Some((binary_count, binary_last_run)) = parse_userassist_binary(&bytes) {
                    run_count = binary_count;
                    last_run = binary_last_run;
                }
            } else if let Some(text) = decode_reg_string(raw) {
                if let Ok(parsed) = text.parse::<u32>() {
                    run_count = parsed;
                }
            }

            out.push(UserAssistEntry {
                program_name: decoded_name,
                run_count,
                last_run_utc: last_run.and_then(unix_to_utc_rfc3339),
                last_run,
            });
        }
    }

    out
}

#[derive(Debug, Clone, Default)]
pub struct UserAssistEntry {
    pub program_name: String,
    pub run_count: u32,
    pub last_run_utc: Option<String>,
    pub last_run: Option<u64>,
}

pub fn get_userassist_v2() -> Vec<UserAssistV2> {
    get_userassist_v2_from_reg(&default_reg_path("userassist.reg"))
}

pub fn get_userassist_v2_from_reg(path: &Path) -> Vec<UserAssistV2> {
    get_user_assist_from_reg(path)
        .into_iter()
        .enumerate()
        .map(|(idx, entry)| UserAssistV2 {
            entry_id: idx as u32 + 1,
            run_count: entry.run_count,
            last_run_time: entry.last_run,
        })
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct UserAssistV2 {
    pub entry_id: u32,
    pub run_count: u32,
    pub last_run_time: Option<u64>,
}

fn rot13(input: &str) -> String {
    input
        .chars()
        .map(|ch| match ch {
            'a'..='m' | 'A'..='M' => ((ch as u8) + 13) as char,
            'n'..='z' | 'N'..='Z' => ((ch as u8) - 13) as char,
            _ => ch,
        })
        .collect()
}

fn normalize_userassist_name(input: &str) -> String {
    rot13(input)
        .replace('/', "\\")
        .trim_matches('\0')
        .to_string()
}

fn parse_userassist_binary(bytes: &[u8]) -> Option<(u32, Option<u64>)> {
    if bytes.len() < 8 {
        return None;
    }

    let count_v5 = read_u32_le(bytes, 4).unwrap_or(0);
    let count_v3 = read_u32_le(bytes, 8).unwrap_or(0);
    let run_count = if count_v5 != 0 { count_v5 } else { count_v3 };

    // Windows 7+ usually stores FILETIME around offset 60. Keep legacy fallbacks.
    let last_run = [60usize, 8usize, 0usize]
        .iter()
        .filter_map(|offset| {
            bytes
                .get(*offset..offset.saturating_add(8))
                .and_then(|slice| {
                    filetime_bytes_to_unix(slice).and_then(|unix| {
                        if (946_684_800..=4_102_444_800).contains(&unix) {
                            Some(unix)
                        } else {
                            None
                        }
                    })
                })
        })
        .next();

    Some((run_count, last_run))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn decode_userassist_name() {
        assert_eq!(
            rot13("P:\\Jvaqbjf\\Rkcybere.rkr"),
            "C:\\Windows\\Explorer.exe"
        );
    }

    #[test]
    fn parse_userassist_count() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("userassist.reg");
        strata_fs::write(
            &file,
            r#"
Windows Registry Editor Version 5.00
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\Count]
"P:\\Jvaqbjf\\Rkcybere.rkr"=dword:00000004
"#,
        )
        .unwrap();
        let rows = get_user_assist_from_reg(&file);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].program_name, "C:\\Windows\\Explorer.exe");
        assert_eq!(rows[0].run_count, 4);
    }

    #[test]
    fn parse_userassist_binary_count_and_last_run() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("userassist.reg");

        let expected_unix = 1_700_000_000u64;
        let filetime = (expected_unix + 11_644_473_600) * 10_000_000;
        let mut bytes = [0u8; 68];
        bytes[4..8].copy_from_slice(&7u32.to_le_bytes());
        bytes[60..68].copy_from_slice(&filetime.to_le_bytes());
        let payload = bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(",");

        strata_fs::write(
            &file,
            format!(
                r#"
Windows Registry Editor Version 5.00
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\Count]
"P:\\Jvaqbjf\\abgrcnq.rkr"=hex:{payload}
"#
            ),
        )
        .unwrap();

        let rows = get_user_assist_from_reg(&file);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].program_name, "C:\\Windows\\notepad.exe");
        assert_eq!(rows[0].run_count, 7);
        assert_eq!(rows[0].last_run, Some(expected_unix));
    }
}
