use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Windows UserAssist ROT13 Decoder and Parser
///
/// Registry: HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count
///
/// UserAssist tracks program execution with run counts, focus time, and
/// last execution timestamps. Program names are ROT13 encoded in the
/// registry. GUIDs identify the tracking category:
///   - {CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}: Executable file execution
///   - {F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}: Shortcut file execution
///
/// Forensic value: Proves program execution with timestamps and frequency.
/// Critical for malware analysis and user activity reconstruction.
pub struct UserAssistParser;

impl Default for UserAssistParser {
    fn default() -> Self {
        Self::new()
    }
}

impl UserAssistParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserAssistEntry {
    pub program_name: String,
    pub program_name_encoded: String,
    pub run_count: u32,
    pub focus_count: Option<u32>,
    pub focus_time_ms: Option<u32>,
    pub last_execution: Option<i64>,
    pub guid_category: String,
    pub forensic_flags: Vec<String>,
}

/// Decode ROT13 encoded string (UserAssist encoding)
fn rot13_decode(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            'A'..='M' | 'a'..='m' => (c as u8 + 13) as char,
            'N'..='Z' | 'n'..='z' => (c as u8 - 13) as char,
            _ => c,
        })
        .collect()
}

impl ArtifactParser for UserAssistParser {
    fn name(&self) -> &str {
        "Windows UserAssist ROT13 Parser"
    }

    fn artifact_type(&self) -> &str {
        "execution"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["NTUSER.DAT", "ntuser.dat", "UsrClass.dat"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();

        // Scan binary data for UserAssist value entries
        // UserAssist value names are ROT13-encoded paths
        // Value data is a fixed-size struct (16 or 72 bytes depending on version)

        // Look for ROT13-encoded path patterns in the binary data
        let _text = String::from_utf8_lossy(data);

        // Extract potential UserAssist entries from registry binary data
        let mut offset = 0;
        while offset + 72 < data.len() {
            // Look for value data structures (version 5 = 72 bytes)
            // Offset 4: run count (u32)
            // Offset 8: focus count (u32)
            // Offset 12: focus time (u32, milliseconds)
            // Offset 60: last execution FILETIME (u64)

            // Try to find registry value name strings (UTF-16LE)
            if data[offset] != 0 && data[offset + 1] == 0 {
                // Possible UTF-16LE string start
                let mut end = offset;
                while end + 1 < data.len() && !(data[end] == 0 && data[end + 1] == 0) {
                    end += 2;
                }

                let str_len = end - offset;
                if (10..=1024).contains(&str_len) {
                    let utf16_bytes: Vec<u16> = data[offset..end]
                        .chunks_exact(2)
                        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                        .collect();

                    if let Ok(encoded_name) = String::from_utf16(&utf16_bytes) {
                        let decoded = rot13_decode(&encoded_name);

                        // Check if this looks like a UserAssist entry (contains path separators)
                        if (decoded.contains('\\') || decoded.contains("UEME"))
                            && !decoded.contains('\0')
                        {
                            let mut forensic_flags = Vec::new();

                            // Check for suspicious executables
                            let decoded_lower = decoded.to_lowercase();
                            if decoded_lower.contains("powershell")
                                || decoded_lower.contains("cmd.exe")
                                || decoded_lower.contains("mshta")
                                || decoded_lower.contains("wscript")
                                || decoded_lower.contains("cscript")
                                || decoded_lower.contains("rundll32")
                                || decoded_lower.contains("regsvr32")
                            {
                                forensic_flags
                                    .push("LOLBIN — Living off the Land binary".to_string());
                            }

                            if decoded_lower.contains("\\temp\\")
                                || decoded_lower.contains("\\tmp\\")
                                || decoded_lower.contains("\\appdata\\")
                            {
                                forensic_flags.push(
                                    "SUSPICIOUS_PATH — Execution from temp/user directory"
                                        .to_string(),
                                );
                            }

                            // Try to read the value data after the name
                            let value_data_offset = end + 2;
                            let (run_count, focus_count, focus_time, last_exec) =
                                if value_data_offset + 72 <= data.len() {
                                    parse_userassist_value_v5(&data[value_data_offset..])
                                } else if value_data_offset + 16 <= data.len() {
                                    parse_userassist_value_v3(&data[value_data_offset..])
                                } else {
                                    (0, None, None, None)
                                };

                            if run_count > 0 || last_exec.is_some() {
                                let entry = UserAssistEntry {
                                    program_name: decoded.clone(),
                                    program_name_encoded: encoded_name,
                                    run_count,
                                    focus_count,
                                    focus_time_ms: focus_time,
                                    last_execution: last_exec,
                                    guid_category: "Executable".to_string(),
                                    forensic_flags: forensic_flags.clone(),
                                };

                                let mut desc =
                                    format!("UserAssist: {} (run {} times)", decoded, run_count,);
                                if let Some(ft) = focus_time {
                                    if ft > 0 {
                                        desc.push_str(&format!(" [focus: {}ms]", ft));
                                    }
                                }
                                for flag in &forensic_flags {
                                    desc.push_str(&format!(" [{}]", flag));
                                }

                                artifacts.push(ParsedArtifact {
                                    timestamp: last_exec,
                                    artifact_type: "userassist_execution".to_string(),
                                    description: desc,
                                    source_path: source.clone(),
                                    json_data: serde_json::to_value(&entry).unwrap_or_default(),
                                });
                            }
                        }
                    }
                }
            }

            offset += 2;
        }

        if artifacts.is_empty() {
            // Fallback: at least identify the file
            let path_str = path.to_string_lossy().to_lowercase();
            if path_str.contains("ntuser") || path_str.contains("usrclass") {
                artifacts.push(ParsedArtifact {
                    timestamp: None,
                    artifact_type: "registry_hive".to_string(),
                    description: format!(
                        "Registry hive: {} ({} bytes)",
                        path.file_name().unwrap_or_default().to_string_lossy(),
                        data.len(),
                    ),
                    source_path: source,
                    json_data: serde_json::json!({
                        "note": "Registry hive detected. UserAssist entries require full registry parsing.",
                    }),
                });
            }
        }

        Ok(artifacts)
    }
}

/// Parse UserAssist value data version 5 (Windows 7+, 72 bytes)
fn parse_userassist_value_v5(data: &[u8]) -> (u32, Option<u32>, Option<u32>, Option<i64>) {
    if data.len() < 72 {
        return (0, None, None, None);
    }

    let run_count = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let focus_count = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let focus_time = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);

    let filetime = u64::from_le_bytes([
        data[60], data[61], data[62], data[63], data[64], data[65], data[66], data[67],
    ]);

    let last_exec = if filetime > 0 {
        let unix_epoch_filetime: u64 = 116_444_736_000_000_000;
        if filetime > unix_epoch_filetime {
            Some(((filetime - unix_epoch_filetime) / 10_000_000) as i64)
        } else {
            None
        }
    } else {
        None
    };

    (run_count, Some(focus_count), Some(focus_time), last_exec)
}

/// Parse UserAssist value data version 3 (Windows XP, 16 bytes)
fn parse_userassist_value_v3(data: &[u8]) -> (u32, Option<u32>, Option<u32>, Option<i64>) {
    if data.len() < 16 {
        return (0, None, None, None);
    }

    let _session_id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let run_count = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    // Subtract 5 for the offset used in XP
    let adjusted_count = run_count.saturating_sub(5);

    let filetime = u64::from_le_bytes([
        data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
    ]);

    let last_exec = if filetime > 0 {
        let unix_epoch_filetime: u64 = 116_444_736_000_000_000;
        if filetime > unix_epoch_filetime {
            Some(((filetime - unix_epoch_filetime) / 10_000_000) as i64)
        } else {
            None
        }
    } else {
        None
    };

    (adjusted_count, None, None, last_exec)
}
