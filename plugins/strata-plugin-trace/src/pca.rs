//! Program Compatibility Assistant (PCA) parser (TRACE-2).
//!
//! Parses `C:\Windows\appcompat\pca\PcaAppLaunchDic.txt` and
//! `PcaGeneralDb2.txt`. PCA logs executables that triggered compat
//! shims — new in Windows 11 22H2, distinct from ShimCache / AmCache.
//!
//! PCA timestamps are local time; our parser records them as UTC
//! (labelling the conversion). Downstream consumers that know the
//! host's TZ can recover the original wall time.
//!
//! MITRE: T1059, T1218.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcaEntry {
    pub exe_path: String,
    pub exe_name: String,
    pub last_executed: DateTime<Utc>,
    pub local_time_converted: bool,
    pub source_file: String,
}

const LOLBINS: &[&str] = &[
    "certutil.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "bitsadmin.exe",
    "msbuild.exe",
    "installutil.exe",
];

pub fn parse_launch_dic(body: &str, source_file: &str) -> Vec<PcaEntry> {
    let mut out = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((exe_path, ts_str)) = line.split_once('|') else {
            continue;
        };
        let Some(ts) = parse_pca_timestamp(ts_str.trim()) else {
            continue;
        };
        let exe_name = extract_exe_name(exe_path.trim()).to_string();
        out.push(PcaEntry {
            exe_path: exe_path.trim().to_string(),
            exe_name,
            last_executed: ts,
            local_time_converted: true,
            source_file: source_file.to_string(),
        });
    }
    out
}

pub fn parse_general_db(body: &str, source_file: &str) -> Vec<PcaEntry> {
    // PcaGeneralDb2 is tab-delimited; we treat any whitespace split as
    // field separator and look for the path + timestamp combination.
    let mut out = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut path: Option<&str> = None;
        let mut ts: Option<DateTime<Utc>> = None;
        for field in line.split('\t') {
            let f = field.trim();
            if path.is_none() && f.contains('\\') && f.contains(':') {
                path = Some(f);
            } else if ts.is_none() {
                if let Some(parsed) = parse_pca_timestamp(f) {
                    ts = Some(parsed);
                }
            }
        }
        if let (Some(p), Some(t)) = (path, ts) {
            let exe_name = extract_exe_name(p).to_string();
            out.push(PcaEntry {
                exe_path: p.to_string(),
                exe_name,
                last_executed: t,
                local_time_converted: true,
                source_file: source_file.to_string(),
            });
        }
    }
    out
}

fn parse_pca_timestamp(s: &str) -> Option<DateTime<Utc>> {
    for fmt in ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%d %H:%M:%S"] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(Utc.from_utc_datetime(&ndt));
        }
    }
    None
}

fn extract_exe_name(path: &str) -> &str {
    let b = path.as_bytes();
    let split_at = b.iter().rposition(|c| *c == b'\\' || *c == b'/').map(|i| i + 1).unwrap_or(0);
    &path[split_at..]
}

/// Returns a suspicion reason when the entry should be flagged.
pub fn check_suspicion(entry: &PcaEntry) -> Option<String> {
    let pl = entry.exe_path.to_ascii_lowercase();
    if pl.contains("\\temp\\")
        || pl.contains("\\appdata\\")
        || pl.contains("\\downloads\\")
        || pl.contains("\\users\\public\\")
    {
        return Some(format!("Execution from user-writable path: {}", entry.exe_path));
    }
    let ename = entry.exe_name.to_ascii_lowercase();
    if LOLBINS.contains(&ename.as_str()) {
        return Some(format!("LOLBin execution: {}", entry.exe_name));
    }
    None
}

pub fn is_pca_path(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    name == "pcaapplaunchdic.txt" || name == "pcageneraldb2.txt"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_launch_dic_extracts_pipe_separated_entries() {
        let body = "C:\\Users\\alice\\AppData\\Local\\Temp\\evil.exe|2024-06-01 12:00:00.000\n\
                    C:\\Program Files\\App\\app.exe|2024-06-01 13:00:00\n";
        let entries = parse_launch_dic(body, "PcaAppLaunchDic.txt");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].exe_name, "evil.exe");
        assert_eq!(entries[0].last_executed.timestamp(), 1_717_243_200);
    }

    #[test]
    fn check_suspicion_flags_temp_path() {
        let e = PcaEntry {
            exe_path: "C:\\Users\\alice\\AppData\\Local\\Temp\\evil.exe".into(),
            exe_name: "evil.exe".into(),
            last_executed: Utc.timestamp_opt(1_717_243_200, 0).single().expect("ts"),
            local_time_converted: true,
            source_file: "PcaAppLaunchDic.txt".into(),
        };
        assert!(check_suspicion(&e).is_some());
    }

    #[test]
    fn check_suspicion_flags_lolbin() {
        let e = PcaEntry {
            exe_path: "C:\\Windows\\System32\\mshta.exe".into(),
            exe_name: "mshta.exe".into(),
            last_executed: Utc.timestamp_opt(1_717_243_200, 0).single().expect("ts"),
            local_time_converted: true,
            source_file: "PcaAppLaunchDic.txt".into(),
        };
        let reason = check_suspicion(&e).expect("flagged");
        assert!(reason.contains("LOLBin"));
    }

    #[test]
    fn is_pca_path_recognises_both_files() {
        assert!(is_pca_path(Path::new("/x/PcaAppLaunchDic.txt")));
        assert!(is_pca_path(Path::new("/x/pcageneraldb2.txt")));
        assert!(!is_pca_path(Path::new("/x/other.txt")));
    }

    #[test]
    fn clean_entry_not_flagged() {
        let e = PcaEntry {
            exe_path: "C:\\Windows\\System32\\notepad.exe".into(),
            exe_name: "notepad.exe".into(),
            last_executed: Utc.timestamp_opt(1_717_243_200, 0).single().expect("ts"),
            local_time_converted: true,
            source_file: "PcaAppLaunchDic.txt".into(),
        };
        assert!(check_suspicion(&e).is_none());
    }
}
