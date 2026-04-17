//! Memory image structure heuristics (MEM-2).
//!
//! Heuristic: FILETIME + printable process-name 16-byte runs as a
//! proxy for EPROCESS locations; valid IPv4 pair + ports + TCP state
//! for network connection table entries.
//!
//! Every artifact carries the mandatory "verify with Volatility"
//! caveat.
//!
//! MITRE: T1057, T1049.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use std::path::Path;
use strata_plugin_sdk::Artifact;

const FILETIME_EPOCH_DELTA_SECS: i64 = 11_644_473_600;
const MIN_FILETIME_UNIX: i64 = 946_684_800; // 2000-01-01
const MAX_FILETIME_UNIX: i64 = 4_102_444_800; // 2100-01-01

pub const CAVEAT: &str =
    "MEMORY FORENSICS: Heuristic detection. Results require verification with dedicated memory analysis tools (Volatility, MemProcFS) before evidentiary use.";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryProcess {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub create_time: Option<DateTime<Utc>>,
    pub offset: u64,
    pub detection_confidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryNetworkConnection {
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: Option<u32>,
    pub offset: u64,
}

fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4).and_then(|s| s.try_into().ok()).map(u32::from_le_bytes)
}

fn read_u64_le(buf: &[u8], off: usize) -> Option<u64> {
    buf.get(off..off + 8).and_then(|s| s.try_into().ok()).map(u64::from_le_bytes)
}

fn decode_filetime(ft: u64) -> Option<DateTime<Utc>> {
    if ft == 0 {
        return None;
    }
    let secs = (ft / 10_000_000) as i64 - FILETIME_EPOCH_DELTA_SECS;
    if !(MIN_FILETIME_UNIX..=MAX_FILETIME_UNIX).contains(&secs) {
        return None;
    }
    DateTime::<Utc>::from_timestamp(secs, 0)
}

fn is_printable_process_name(bytes: &[u8]) -> Option<String> {
    let nul = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    if nul < 3 {
        return None;
    }
    let name_bytes = &bytes[..nul];
    if !name_bytes
        .iter()
        .all(|b| (0x20..=0x7E).contains(b))
    {
        return None;
    }
    let s = std::str::from_utf8(name_bytes).ok()?.to_string();
    let lower = s.to_ascii_lowercase();
    if lower.ends_with(".exe") || looks_like_executable_name(&lower) {
        Some(s)
    } else {
        None
    }
}

fn looks_like_executable_name(s: &str) -> bool {
    matches!(
        s,
        "system"
            | "registry"
            | "smss"
            | "csrss"
            | "wininit"
            | "services"
            | "lsass"
            | "svchost"
            | "explorer"
            | "init"
            | "kthreadd"
    )
}

/// Scan bytes for `(pid, ppid, name[16], filetime)` sequences. This is
/// an intentionally conservative heuristic.
pub fn scan_processes(bytes: &[u8]) -> Vec<MemoryProcess> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 32 <= bytes.len() && out.len() < 10_000 {
        let pid = match read_u32_le(bytes, i) {
            Some(v) if (1..=99_999).contains(&v) => v,
            _ => {
                i += 4;
                continue;
            }
        };
        let ppid = match read_u32_le(bytes, i + 4) {
            Some(v) if v <= 99_999 => v,
            _ => {
                i += 4;
                continue;
            }
        };
        let Some(name) = is_printable_process_name(&bytes[i + 8..i + 24]) else {
            i += 4;
            continue;
        };
        let ft = read_u64_le(bytes, i + 24);
        let create_time = ft.and_then(decode_filetime);
        if create_time.is_none() {
            i += 4;
            continue;
        }
        out.push(MemoryProcess {
            pid,
            ppid,
            name,
            create_time,
            offset: i as u64,
            detection_confidence: "Heuristic".into(),
        });
        i += 32;
    }
    out
}

/// Scan for plausible TCP connection entries. Structure: u32 local_ip,
/// u16 local_port, u32 remote_ip, u16 remote_port, u32 state, u32 pid.
pub fn scan_connections(bytes: &[u8]) -> Vec<MemoryNetworkConnection> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 20 <= bytes.len() && out.len() < 10_000 {
        let local_ip = match read_u32_le(bytes, i) {
            Some(v) if v != 0 && v != u32::MAX => v,
            _ => {
                i += 4;
                continue;
            }
        };
        let local_port = read_u32_le(bytes, i + 4).map(|v| v as u16).unwrap_or(0);
        let remote_ip = read_u32_le(bytes, i + 8).unwrap_or(0);
        let remote_port = read_u32_le(bytes, i + 12).map(|v| v as u16).unwrap_or(0);
        let state = read_u32_le(bytes, i + 16).unwrap_or(0);
        let pid = read_u32_le(bytes, i + 20);
        if local_port == 0
            || remote_port == 0
            || remote_ip == 0
            || state > 12
            || !is_plausible_ipv4(local_ip)
            || !is_plausible_ipv4(remote_ip)
        {
            i += 4;
            continue;
        }
        out.push(MemoryNetworkConnection {
            local_ip: ipv4_to_string(local_ip),
            local_port,
            remote_ip: ipv4_to_string(remote_ip),
            remote_port,
            state: tcp_state_name(state).to_string(),
            pid: pid.filter(|p| (1..=99_999).contains(p)),
            offset: i as u64,
        });
        i += 24;
    }
    out
}

fn is_plausible_ipv4(v: u32) -> bool {
    // Exclude 0.0.0.0 and 255.255.255.255.
    v != 0 && v != u32::MAX
}

fn ipv4_to_string(v: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (v >> 24) & 0xFF,
        (v >> 16) & 0xFF,
        (v >> 8) & 0xFF,
        v & 0xFF
    )
}

fn tcp_state_name(v: u32) -> &'static str {
    match v {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

pub fn scan(path: &Path) -> Vec<Artifact> {
    if !super::memory_carving::is_memory_image_path(path) {
        return Vec::new();
    }
    let Ok(meta) = fs::metadata(path) else {
        return Vec::new();
    };
    if meta.len() < super::memory_carving::SCAN_MIN_FILE_SIZE {
        return Vec::new();
    }
    let Ok(mut f) = fs::File::open(path) else {
        return Vec::new();
    };
    let cap = meta.len().min(256 * 1024 * 1024) as usize;
    let mut buf = vec![0u8; cap];
    if f.read_exact(&mut buf).is_err() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for p in scan_processes(&buf).into_iter().take(512) {
        let mut a = Artifact::new("Memory Process", &path.to_string_lossy());
        a.timestamp = p.create_time.map(|d| d.timestamp() as u64);
        a.add_field(
            "title",
            &format!("Memory process: {} (pid {})", p.name, p.pid),
        );
        a.add_field("detail", CAVEAT);
        a.add_field("file_type", "Memory Process");
        a.add_field("process_name", &p.name);
        a.add_field("pid", &p.pid.to_string());
        a.add_field("ppid", &p.ppid.to_string());
        a.add_field("offset", &format!("0x{:X}", p.offset));
        a.add_field("detection_confidence", &p.detection_confidence);
        a.add_field("mitre", "T1057");
        a.add_field("forensic_value", "Medium");
        out.push(a);
    }
    for c in scan_connections(&buf).into_iter().take(512) {
        let mut a = Artifact::new("Memory Network Connection", &path.to_string_lossy());
        a.add_field(
            "title",
            &format!(
                "TCP {}:{} -> {}:{} {}",
                c.local_ip, c.local_port, c.remote_ip, c.remote_port, c.state
            ),
        );
        a.add_field("detail", CAVEAT);
        a.add_field("file_type", "Memory Network Connection");
        a.add_field("local_ip", &c.local_ip);
        a.add_field("local_port", &c.local_port.to_string());
        a.add_field("remote_ip", &c.remote_ip);
        a.add_field("remote_port", &c.remote_port.to_string());
        a.add_field("state", &c.state);
        if let Some(pid) = c.pid {
            a.add_field("pid", &pid.to_string());
        }
        a.add_field("mitre", "T1049");
        a.add_field("forensic_value", "Medium");
        out.push(a);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_filetime_rejects_out_of_range() {
        assert!(decode_filetime(0).is_none());
        assert!(decode_filetime(1).is_none());
        // Valid FILETIME for 2024-06-01.
        let ft = (1_717_243_200 + FILETIME_EPOCH_DELTA_SECS) as u64 * 10_000_000;
        assert_eq!(
            decode_filetime(ft).map(|d| d.timestamp()),
            Some(1_717_243_200)
        );
    }

    #[test]
    fn is_printable_process_name_accepts_exe_tokens() {
        let mut bytes = [0u8; 16];
        bytes[..11].copy_from_slice(b"notepad.exe");
        assert_eq!(
            is_printable_process_name(&bytes).as_deref(),
            Some("notepad.exe")
        );
        let bad = [0u8; 16];
        assert!(is_printable_process_name(&bad).is_none());
    }

    #[test]
    fn scan_processes_finds_planted_record() {
        let mut buf = vec![0u8; 128];
        let pid: u32 = 1234;
        let ppid: u32 = 4;
        buf[0..4].copy_from_slice(&pid.to_le_bytes());
        buf[4..8].copy_from_slice(&ppid.to_le_bytes());
        let mut name = [0u8; 16];
        name[..11].copy_from_slice(b"notepad.exe");
        buf[8..24].copy_from_slice(&name);
        let ft = (1_717_243_200 + FILETIME_EPOCH_DELTA_SECS) as u64 * 10_000_000;
        buf[24..32].copy_from_slice(&ft.to_le_bytes());
        let processes = scan_processes(&buf);
        assert_eq!(processes.len(), 1);
        assert_eq!(processes[0].name, "notepad.exe");
    }

    #[test]
    fn tcp_state_name_maps_known_values() {
        assert_eq!(tcp_state_name(5), "ESTABLISHED");
        assert_eq!(tcp_state_name(11), "TIME_WAIT");
        assert_eq!(tcp_state_name(42), "UNKNOWN");
    }

    #[test]
    fn ipv4_to_string_big_endian_net_order() {
        assert_eq!(ipv4_to_string(0x0A000005), "10.0.0.5");
    }
}
