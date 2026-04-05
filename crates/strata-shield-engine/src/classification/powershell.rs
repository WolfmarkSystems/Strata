use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use super::scalpel::{read_text_prefix, DEFAULT_TEXT_MAX_BYTES};
use crate::errors::ForensicError;

#[derive(Debug, Clone, Default)]
pub struct PowerShellHistory {
    pub command: String,
    pub execution_time: u64,
    pub execution_count: u32,
    pub last_used: u64,
}

pub fn get_powershell_history() -> Result<Vec<PowerShellHistory>, ForensicError> {
    Ok(parse_powershell_history_file(&powershell_history_path()))
}

pub fn parse_powershell_history_file(path: &Path) -> Vec<PowerShellHistory> {
    let content = match read_text_prefix(path, DEFAULT_TEXT_MAX_BYTES) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut seen: BTreeMap<String, (u32, u64)> = BTreeMap::new();
    for (idx, line) in content.lines().enumerate() {
        let cmd = line.trim();
        if cmd.is_empty() || cmd.starts_with('#') {
            continue;
        }
        let entry = seen.entry(cmd.to_string()).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = idx as u64;
    }

    seen.into_iter()
        .map(|(command, (count, last))| PowerShellHistory {
            command,
            execution_time: last,
            execution_count: count,
            last_used: last,
        })
        .collect()
}

pub fn get_powershell_profile_paths() -> Vec<String> {
    let mut out = vec![r"C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1".to_string()];
    if let Ok(user_profile) = env::var("USERPROFILE") {
        out.push(
            PathBuf::from(user_profile)
                .join("Documents")
                .join("WindowsPowerShell")
                .join("profile.ps1")
                .to_string_lossy()
                .to_string(),
        );
    } else {
        out.push(r"C:\Users\Default\Documents\WindowsPowerShell\profile.ps1".to_string());
    }
    out
}

pub fn get_powershell_modules() -> Result<Vec<PowerShellModule>, ForensicError> {
    let mut out = Vec::new();

    // Optional flat inventory file used by forensic exports.
    out.extend(parse_powershell_modules_inventory(&modules_inventory_path()));

    // Best-effort discovery from PSModulePath folders.
    if let Ok(module_paths) = env::var("PSModulePath") {
        for root in module_paths.split(';') {
            let root_path = Path::new(root.trim());
            if !root_path.exists() {
                continue;
            }
            if let Ok(entries) = strata_fs::read_dir(root_path) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if !p.is_dir() {
                        continue;
                    }
                    let name = p
                        .file_name()
                        .map(|v| v.to_string_lossy().to_string())
                        .unwrap_or_default();
                    if name.is_empty() {
                        continue;
                    }
                    out.push(PowerShellModule {
                        name,
                        version: "".to_string(),
                        path: p.to_string_lossy().to_string(),
                        description: "".to_string(),
                    });
                }
            }
        }
    }

    Ok(out)
}

#[derive(Debug, Clone, Default)]
pub struct PowerShellModule {
    pub name: String,
    pub version: String,
    pub path: String,
    pub description: String,
}

pub fn get_powershell_transcripts() -> Result<Vec<TranscriptFile>, ForensicError> {
    Ok(parse_powershell_transcripts_dir(&transcript_dir()))
}

#[derive(Debug, Clone, Default)]
pub struct TranscriptFile {
    pub path: String,
    pub start_time: u64,
    pub end_time: Option<u64>,
    pub command_count: u32,
}

pub fn get_powershell_script_log() -> Result<Vec<ScriptLogEntry>, ForensicError> {
    Ok(parse_powershell_script_log_file(&script_log_path()))
}

#[derive(Debug, Clone, Default)]
pub struct ScriptLogEntry {
    pub timestamp: u64,
    pub script_path: String,
    pub parameters: String,
    pub result: String,
}

pub fn parse_powershell_modules_inventory(path: &Path) -> Vec<PowerShellModule> {
    let content = match read_text_prefix(path, DEFAULT_TEXT_MAX_BYTES * 2) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let delimiter = if trimmed.contains('|') && !trimmed.contains(',') {
            '|'
        } else {
            ','
        };
        let parts = split_delimited_line(trimmed, delimiter);
        if parts.is_empty() {
            continue;
        }
        out.push(PowerShellModule {
            name: parts[0].trim().to_string(),
            version: parts.get(1).map(|v| v.trim()).unwrap_or("").to_string(),
            path: parts.get(2).map(|v| v.trim()).unwrap_or("").to_string(),
            description: parts.get(3).map(|v| v.trim()).unwrap_or("").to_string(),
        });
    }
    out
}

pub fn parse_powershell_transcripts_dir(path: &Path) -> Vec<TranscriptFile> {
    let mut out = Vec::new();
    if let Ok(entries) = strata_fs::read_dir(path) {
        let mut files = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|p| p.is_file())
            .collect::<Vec<_>>();
        files.sort();

        for p in files {
            let Ok(content) = read_text_prefix(&p, DEFAULT_TEXT_MAX_BYTES * 4) else {
                continue;
            };
            let command_count = content
                .lines()
                .filter(|line| {
                    let t = line.trim_start();
                    t.starts_with("PS ") || t.starts_with("PS>")
                })
                .count() as u32;
            let ts = strata_fs::metadata(&p)
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|st| st.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            out.push(TranscriptFile {
                path: p.to_string_lossy().to_string(),
                start_time: ts,
                end_time: Some(ts),
                command_count,
            });
        }
    }
    out
}

pub fn parse_powershell_script_log_file(path: &Path) -> Vec<ScriptLogEntry> {
    let content = match read_text_prefix(path, DEFAULT_TEXT_MAX_BYTES * 2) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let delimiter = if trimmed.contains('|') && !trimmed.contains(',') {
            '|'
        } else {
            ','
        };
        let parts = split_delimited_line(trimmed, delimiter);
        let timestamp =
            parse_timestamp_token(parts.first().map(|s| s.as_str()).unwrap_or_default());
        let (script_path, parameters, result) = match parts.len() {
            0 => continue,
            1 => (parts[0].trim().to_string(), String::new(), String::new()),
            2 => (parts[1].trim().to_string(), String::new(), String::new()),
            _ => (
                parts[1].trim().to_string(),
                parts[2].trim().to_string(),
                parts.get(3).map(|v| v.trim()).unwrap_or("").to_string(),
            ),
        };
        if script_path.is_empty() && parameters.is_empty() && result.is_empty() {
            continue;
        }
        out.push(ScriptLogEntry {
            timestamp,
            script_path,
            parameters,
            result,
        });
    }

    out
}

fn parse_timestamp_token(token: &str) -> u64 {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return 0;
    }
    if let Ok(ts) = trimmed.parse::<u64>() {
        if (116_444_736_000_000_000..400_000_000_000_000_000).contains(&ts) {
            return (ts / 10_000_000).saturating_sub(11_644_473_600);
        }
        if ts > 1_000_000_000_000_000_000 {
            return ts / 1_000_000_000;
        }
        if ts > 1_000_000_000_000_000 {
            return ts / 1_000_000;
        }
        if ts > 4_000_000_000 {
            return ts / 1_000;
        }
        return ts;
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(trimmed) {
        let unix = dt.timestamp();
        if unix > 0 {
            return unix as u64;
        }
    }
    for fmt in [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y/%m/%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    ] {
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(trimmed, fmt) {
            let unix = naive.and_utc().timestamp();
            if unix > 0 {
                return unix as u64;
            }
        }
    }
    0
}

fn split_delimited_line(line: &str, delimiter: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut cell = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                if in_quotes && chars.peek() == Some(&'"') {
                    cell.push('"');
                    let _ = chars.next();
                } else {
                    in_quotes = !in_quotes;
                }
            }
            _ if ch == delimiter && !in_quotes => {
                out.push(cell.trim().to_string());
                cell.clear();
            }
            _ => cell.push(ch),
        }
    }
    out.push(cell.trim().to_string());
    out
}

fn powershell_history_path() -> PathBuf {
    if let Ok(path) = env::var("FORENSIC_POWERSHELL_HISTORY") {
        return PathBuf::from(path);
    }
    if let Ok(user_profile) = env::var("USERPROFILE") {
        return PathBuf::from(user_profile)
            .join("AppData")
            .join("Roaming")
            .join("Microsoft")
            .join("Windows")
            .join("PowerShell")
            .join("PSReadLine")
            .join("ConsoleHost_history.txt");
    }
    PathBuf::from("artifacts")
        .join("powershell")
        .join("ConsoleHost_history.txt")
}

fn modules_inventory_path() -> PathBuf {
    if let Ok(path) = env::var("FORENSIC_POWERSHELL_MODULES") {
        return PathBuf::from(path);
    }
    PathBuf::from("artifacts")
        .join("powershell")
        .join("modules.txt")
}

fn transcript_dir() -> PathBuf {
    if let Ok(path) = env::var("FORENSIC_POWERSHELL_TRANSCRIPTS") {
        return PathBuf::from(path);
    }
    PathBuf::from("artifacts")
        .join("powershell")
        .join("Transcripts")
}

fn script_log_path() -> PathBuf {
    if let Ok(path) = env::var("FORENSIC_POWERSHELL_SCRIPT_LOG") {
        return PathBuf::from(path);
    }
    PathBuf::from("artifacts")
        .join("powershell")
        .join("script_block.log")
}

#[cfg(test)]
mod tests {
    use super::{
        parse_powershell_history_file, parse_powershell_modules_inventory,
        parse_powershell_script_log_file, parse_powershell_transcripts_dir,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("forensic_suite_{name}_{unique}"))
    }

    #[test]
    fn parse_history_dedupes_commands_and_tracks_count() {
        let root = temp_dir("ps_history");
        strata_fs::create_dir_all(&root).unwrap();
        let path = root.join("ConsoleHost_history.txt");
        strata_fs::write(
            &path,
            "Get-Process\n#comment\nGet-Process\nGet-Service\nGet-Process\n",
        )
        .unwrap();

        let rows = parse_powershell_history_file(&path);
        assert_eq!(rows.len(), 2, "expected two distinct commands");
        let gp = rows
            .iter()
            .find(|r| r.command == "Get-Process")
            .expect("Get-Process row should exist");
        assert_eq!(gp.execution_count, 3, "command count should match");

        let _ = strata_fs::remove_dir_all(root);
    }

    #[test]
    fn parse_modules_inventory_supports_pipe_and_csv() {
        let root = temp_dir("ps_modules");
        strata_fs::create_dir_all(&root).unwrap();
        let path = root.join("modules.txt");
        strata_fs::write(
            &path,
            "Az.Accounts|2.14.1|C:\\Modules\\Az.Accounts|Azure module\nPester,5.5.0,C:\\Modules\\Pester,Test module\n",
        )
        .unwrap();

        let rows = parse_powershell_modules_inventory(&path);
        assert_eq!(rows.len(), 2, "expected two module rows");
        assert_eq!(rows[0].name, "Az.Accounts");
        assert_eq!(rows[1].name, "Pester");

        let _ = strata_fs::remove_dir_all(root);
    }

    #[test]
    fn parse_modules_inventory_supports_quoted_csv_with_commas() {
        let root = temp_dir("ps_modules_quoted");
        strata_fs::create_dir_all(&root).unwrap();
        let path = root.join("modules.txt");
        strata_fs::write(
            &path,
            "\"Az.Accounts\",2.14.1,\"C:\\Modules\\Az, Accounts\",\"Azure, module\"\n",
        )
        .unwrap();

        let rows = parse_powershell_modules_inventory(&path);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "Az.Accounts");
        assert_eq!(rows[0].path, r"C:\Modules\Az, Accounts");
        assert_eq!(rows[0].description, "Azure, module");

        let _ = strata_fs::remove_dir_all(root);
    }

    #[test]
    fn parse_script_log_tolerates_partial_and_rfc3339_rows() {
        let root = temp_dir("ps_script_log");
        strata_fs::create_dir_all(&root).unwrap();
        let path = root.join("script_block.log");
        strata_fs::write(
            &path,
            "1700000000|C:\\Scripts\\a.ps1|-enc AAAA|ok\n2026-03-11T12:00:00Z|C:\\Scripts\\b.ps1|/safe\nC:\\Scripts\\c.ps1\n",
        )
        .unwrap();

        let rows = parse_powershell_script_log_file(&path);
        assert_eq!(rows.len(), 3, "expected all parsable rows");
        assert!(rows[0].timestamp > 0, "unix timestamp should parse");
        assert!(rows[1].timestamp > 0, "rfc3339 timestamp should parse");
        assert_eq!(rows[2].script_path, "C:\\Scripts\\c.ps1");

        let _ = strata_fs::remove_dir_all(root);
    }

    #[test]
    fn parse_script_log_supports_quoted_csv_rows() {
        let root = temp_dir("ps_script_log_csv_quoted");
        strata_fs::create_dir_all(&root).unwrap();
        let path = root.join("script_block.log");
        strata_fs::write(
            &path,
            "2026-03-11 12:00:00,\"C:\\Scripts\\My, Script.ps1\",\"-enc AAAA,BBBB\",ok\n",
        )
        .unwrap();

        let rows = parse_powershell_script_log_file(&path);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].timestamp > 0);
        assert_eq!(rows[0].script_path, r"C:\Scripts\My, Script.ps1");
        assert_eq!(rows[0].parameters, "-enc AAAA,BBBB");

        let _ = strata_fs::remove_dir_all(root);
    }

    #[test]
    fn parse_script_log_normalizes_ms_and_filetime_timestamps() {
        let root = temp_dir("ps_script_log_time_norm");
        strata_fs::create_dir_all(&root).unwrap();
        let path = root.join("script_block.log");
        strata_fs::write(
            &path,
            "1773111600000|C:\\Scripts\\a.ps1\n133860816000000000|C:\\Scripts\\b.ps1\n",
        )
        .unwrap();

        let rows = parse_powershell_script_log_file(&path);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].timestamp, 1_773_111_600);
        assert_eq!(rows[1].timestamp, 1_741_608_000);

        let _ = strata_fs::remove_dir_all(root);
    }

    #[test]
    fn parse_transcripts_counts_ps_prompts() {
        let root = temp_dir("ps_transcripts");
        strata_fs::create_dir_all(&root).unwrap();
        let transcript = root.join("Transcript-1.txt");
        strata_fs::write(
            &transcript,
            "Header\nPS C:\\> Get-Process\nsome line\nPS> Get-Service\n",
        )
        .unwrap();

        let rows = parse_powershell_transcripts_dir(&root);
        assert_eq!(rows.len(), 1, "expected one transcript row");
        assert_eq!(rows[0].command_count, 2, "expected two prompt commands");
        assert!(
            rows[0].path.ends_with("Transcript-1.txt"),
            "transcript path should be preserved"
        );

        let _ = strata_fs::remove_dir_all(root);
    }
}
