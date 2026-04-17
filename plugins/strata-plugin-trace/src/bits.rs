//! BITS Jobs deep parse (W-13).
//!
//! `qmgr0.dat` / `qmgr1.dat` (Windows 7–10) are proprietary binary
//! blobs. We extract the on-disk evidence with pattern-based carving
//! (URLs, paths, GUIDs) — same approach used by forensic tooling when
//! the MSFT internal parser isn't available.
//!
//! MITRE: T1197 (BITS Jobs).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitsJob {
    pub job_id: String,
    pub display_name: Option<String>,
    pub source_url: Option<String>,
    pub destination_path: Option<String>,
    pub state: Option<String>,
    pub created: Option<DateTime<Utc>>,
    pub completed: Option<DateTime<Utc>>,
    pub bytes_transferred: Option<u64>,
    pub notify_url: Option<String>,
}

/// Carve every URL, GUID, and absolute Windows path run from a qmgr
/// blob. Each URL is paired with the nearest following absolute path
/// as the destination.
pub fn parse_qmgr_binary(bytes: &[u8]) -> Vec<BitsJob> {
    let ascii_runs = extract_ascii_runs(bytes, 8);
    let mut urls: Vec<String> = Vec::new();
    let mut paths: Vec<String> = Vec::new();
    let mut guids: Vec<String> = Vec::new();
    for run in ascii_runs {
        if run.starts_with("http://") || run.starts_with("https://") {
            urls.push(run);
        } else if is_windows_path(&run) {
            paths.push(run);
        } else if is_guid(&run) {
            guids.push(run);
        }
    }
    let mut out = Vec::new();
    let max = urls.len().max(1).max(guids.len()).max(paths.len());
    for i in 0..max.min(urls.len().max(guids.len())) {
        let url = urls.get(i).cloned();
        let path = paths.get(i).cloned();
        let id = guids
            .get(i)
            .cloned()
            .unwrap_or_else(|| format!("job-{}", i));
        if url.is_none() && path.is_none() && guids.get(i).is_none() {
            continue;
        }
        out.push(BitsJob {
            job_id: id,
            display_name: None,
            source_url: url,
            destination_path: path,
            state: None,
            created: None,
            completed: None,
            bytes_transferred: None,
            notify_url: None,
        });
    }
    out
}

fn extract_ascii_runs(bytes: &[u8], min: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    for &b in bytes {
        if (0x20..=0x7E).contains(&b) {
            current.push(b);
        } else {
            if current.len() >= min {
                if let Ok(s) = std::str::from_utf8(&current) {
                    out.push(s.to_string());
                }
            }
            current.clear();
        }
    }
    if current.len() >= min {
        if let Ok(s) = std::str::from_utf8(&current) {
            out.push(s.to_string());
        }
    }
    out
}

fn is_windows_path(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\'
}

fn is_guid(s: &str) -> bool {
    // `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` — 38 chars.
    if s.len() != 38 {
        return false;
    }
    let b = s.as_bytes();
    if b[0] != b'{' || b[37] != b'}' {
        return false;
    }
    for (i, c) in b[1..37].iter().enumerate() {
        if [8, 13, 18, 23].contains(&i) {
            if *c != b'-' {
                return false;
            }
        } else if !c.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

const MS_DOMAINS: &[&str] = &[
    "windowsupdate.com",
    "windowsupdate.microsoft.com",
    "download.microsoft.com",
    "download.windowsupdate.com",
    "delivery.mp.microsoft.com",
];

/// Returns a suspicion reason when the job should be flagged, or `None`.
pub fn check_suspicion(job: &BitsJob) -> Option<String> {
    if let Some(url) = &job.source_url {
        let lc = url.to_ascii_lowercase();
        if !MS_DOMAINS.iter().any(|d| lc.contains(d)) {
            return Some(format!("Non-Microsoft source URL: {}", url));
        }
    }
    if job.notify_url.is_some() {
        return Some("NotifyUrl present — unusual for legitimate BITS".into());
    }
    if let Some(dest) = &job.destination_path {
        let lc = dest.to_ascii_lowercase();
        if lc.contains("\\temp\\") || lc.contains("\\appdata\\") {
            return Some(format!("Destination in user-writable path: {}", dest));
        }
    }
    None
}

pub fn is_bits_path(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    name == "qmgr0.dat" || name == "qmgr1.dat" || name == "qmgr.db"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_guid_rejects_malformed() {
        assert!(is_guid("{12345678-1234-1234-1234-123456789012}"));
        assert!(!is_guid("{too-short}"));
        assert!(!is_guid("12345678-1234-1234-1234-123456789012"));
    }

    #[test]
    fn parse_qmgr_binary_carves_url_and_path() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&[0u8; 32]);
        blob.extend_from_slice(b"https://evil.example.com/payload.exe");
        blob.extend_from_slice(&[0u8; 8]);
        blob.extend_from_slice(b"C:\\Users\\alice\\AppData\\Local\\Temp\\x.exe");
        blob.extend_from_slice(&[0u8; 8]);
        blob.extend_from_slice(b"{12345678-1234-1234-1234-123456789012}");
        blob.extend_from_slice(&[0u8; 8]);
        let jobs = parse_qmgr_binary(&blob);
        assert!(!jobs.is_empty());
        assert!(jobs
            .iter()
            .any(|j| j.source_url.as_deref() == Some("https://evil.example.com/payload.exe")));
    }

    #[test]
    fn check_suspicion_flags_non_microsoft_url() {
        let j = BitsJob {
            job_id: "{X}".into(),
            display_name: None,
            source_url: Some("https://evil.example.com/x".into()),
            destination_path: None,
            state: None,
            created: None,
            completed: None,
            bytes_transferred: None,
            notify_url: None,
        };
        assert!(check_suspicion(&j).is_some());
    }

    #[test]
    fn check_suspicion_ignores_microsoft_update_url() {
        let j = BitsJob {
            job_id: "{Y}".into(),
            display_name: None,
            source_url: Some(
                "https://download.windowsupdate.com/something".into(),
            ),
            destination_path: Some("C:\\Windows\\SoftwareDistribution\\x".into()),
            state: None,
            created: None,
            completed: None,
            bytes_transferred: None,
            notify_url: None,
        };
        assert!(check_suspicion(&j).is_none());
    }

    #[test]
    fn is_bits_path_matches_known_filenames() {
        assert!(is_bits_path(Path::new("/x/qmgr0.dat")));
        assert!(is_bits_path(Path::new("/x/qmgr1.dat")));
        assert!(is_bits_path(Path::new("/x/qmgr.db")));
        assert!(!is_bits_path(Path::new("/x/other.db")));
    }
}
