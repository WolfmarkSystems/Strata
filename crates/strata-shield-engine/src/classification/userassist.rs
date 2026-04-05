use std::collections::BTreeMap;
use std::path::Path;

use super::reg_export::{
    default_reg_path, filetime_bytes_to_unix, load_reg_records, parse_hex_bytes, unix_to_utc_rfc3339,
};
use super::reguserassist;

pub fn get_user_assist_data() -> Vec<UserAssistEntry> {
    get_user_assist_data_from_reg(&default_reg_path("userassist.reg"))
}

pub fn get_user_assist_data_from_reg(path: &Path) -> Vec<UserAssistEntry> {
    let base_rows = reguserassist::get_user_assist_from_reg(path);
    let detail_map = parse_userassist_focus_and_last_run(path);

    base_rows
        .into_iter()
        .map(|entry| {
            let key = entry.program_name.to_ascii_lowercase();
            let details = detail_map.get(&key);
            let last_run = details
                .and_then(|d| d.last_run)
                .or(entry.last_run)
                .unwrap_or(0);

            UserAssistEntry {
                name: entry.program_name.clone(),
                run_count: entry.run_count,
                last_run,
                focus_time_seconds: details.and_then(|d| d.focus_time_seconds),
                last_run_utc: if last_run > 0 {
                    unix_to_utc_rfc3339(last_run)
                } else {
                    None
                },
                suspicious: is_suspicious_userassist_entry(&entry.program_name, entry.run_count),
            }
        })
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct UserAssistEntry {
    pub name: String,
    pub run_count: u32,
    pub last_run: u64,
    pub focus_time_seconds: Option<u32>,
    pub last_run_utc: Option<String>,
    pub suspicious: bool,
}

#[derive(Debug, Clone, Default)]
struct UserAssistBinaryDetails {
    focus_time_seconds: Option<u32>,
    last_run: Option<u64>,
}

fn parse_userassist_focus_and_last_run(path: &Path) -> BTreeMap<String, UserAssistBinaryDetails> {
    let records = load_reg_records(path);
    let mut out = BTreeMap::new();

    for record in records.iter().filter(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("\\explorer\\userassist\\")
    }) {
        for (value_name, raw) in &record.values {
            if value_name.eq_ignore_ascii_case("@") {
                continue;
            }

            let Some(bytes) = parse_hex_bytes(raw) else {
                continue;
            };
            if bytes.len() < 16 {
                continue;
            }

            let decoded_name = normalize_userassist_name(value_name);
            let (_, focus_time_seconds, last_run) = parse_userassist_binary(&bytes);

            out.insert(
                decoded_name.to_ascii_lowercase(),
                UserAssistBinaryDetails {
                    focus_time_seconds,
                    last_run,
                },
            );
        }
    }

    out
}

fn parse_userassist_binary(bytes: &[u8]) -> (Option<u32>, Option<u32>, Option<u64>) {
    let run_count = read_u32_le(bytes, 4).or_else(|| read_u32_le(bytes, 8));

    // UserAssist focus time is typically stored as a millisecond counter at offset 12.
    // Convert to seconds for stable reporting.
    let focus_time_seconds = read_u32_le(bytes, 12).map(|ms| ms / 1000);

    let last_run = [60usize, 8usize, 0usize]
        .iter()
        .find_map(|offset| {
            bytes
                .get(*offset..offset.saturating_add(8))
                .and_then(filetime_bytes_to_unix)
                .and_then(|unix| {
                    if (946_684_800..=4_102_444_800).contains(&unix) {
                        Some(unix)
                    } else {
                        None
                    }
                })
        });

    (run_count, focus_time_seconds, last_run)
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn normalize_userassist_name(input: &str) -> String {
    rot13(input)
        .replace('/', "\\")
        .trim_matches('\0')
        .to_string()
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

fn is_suspicious_userassist_entry(program_name: &str, run_count: u32) -> bool {
    let lower = program_name.to_ascii_lowercase();
    run_count >= 5_000
        || lower.contains("\\temp\\")
        || lower.contains("\\appdata\\local\\temp\\")
        || lower.contains("\\users\\public\\")
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::reg_export::parse_reg_u32;
    use std::fs;

    #[test]
    fn parse_userassist_binary_focus_time_and_last_run() {
        let expected_unix = 1_700_000_000u64;
        let filetime = (expected_unix + 11_644_473_600) * 10_000_000;

        let mut bytes = [0u8; 72];
        bytes[4..8].copy_from_slice(&11u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&(45_000u32).to_le_bytes());
        bytes[60..68].copy_from_slice(&filetime.to_le_bytes());

        let (run_count, focus_time_seconds, last_run) = parse_userassist_binary(&bytes);
        assert_eq!(run_count, Some(11));
        assert_eq!(focus_time_seconds, Some(45));
        assert_eq!(last_run, Some(expected_unix));
    }

    #[test]
    fn get_user_assist_data_from_reg_decodes_and_enriches() {
        let dir = tempfile::tempdir().expect("temp dir");
        let file = dir.path().join("userassist.reg");

        let expected_unix = 1_710_000_000u64;
        let filetime = (expected_unix + 11_644_473_600) * 10_000_000;

        let mut bytes = [0u8; 72];
        bytes[4..8].copy_from_slice(&7u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&(12_000u32).to_le_bytes());
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
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{{GUID}}\Count]
"P:\\Jvaqbjf\\abgrcnq.rkr"=hex:{payload}
"#
            ),
        )
        .expect("write test reg");

        let rows = get_user_assist_data_from_reg(&file);
        assert_eq!(rows.len(), 1);
        let first = &rows[0];
        assert_eq!(first.name, "C:\\Windows\\notepad.exe");
        assert_eq!(first.run_count, 7);
        assert_eq!(first.focus_time_seconds, Some(12));
        assert_eq!(first.last_run, expected_unix);
        assert!(first.last_run_utc.is_some());
    }

    #[test]
    fn flags_suspicious_userassist_entries() {
        assert!(is_suspicious_userassist_entry(
            "C:\\Users\\Public\\Tools\\evil.exe",
            2
        ));
        assert!(is_suspicious_userassist_entry(
            "C:\\Windows\\System32\\cmd.exe",
            9000
        ));
        assert!(!is_suspicious_userassist_entry(
            "C:\\Windows\\explorer.exe",
            3
        ));
    }

    #[test]
    fn supports_dword_only_entries() {
        let dir = tempfile::tempdir().expect("temp dir");
        let file = dir.path().join("userassist.reg");

        strata_fs::write(
            &file,
            r#"
Windows Registry Editor Version 5.00
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\Count]
"P:\\Jvaqbjf\\Rkcybere.rkr"=dword:00000005
"#,
        )
        .expect("write test reg");

        let rows = get_user_assist_data_from_reg(&file);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "C:\\Windows\\Explorer.exe");
        assert_eq!(rows[0].run_count, 5);
        assert_eq!(rows[0].last_run, 0);
    }

    #[test]
    fn parse_reg_u32_is_available_for_future_reg_fallbacks() {
        assert_eq!(parse_reg_u32("dword:00000010"), Some(16));
    }
}

