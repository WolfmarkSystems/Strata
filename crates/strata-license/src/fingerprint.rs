use crate::error::{LicenseError, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
#[cfg(any(target_os = "windows", target_os = "linux"))]
use std::process::Command;

pub fn generate_machine_id() -> Result<String> {
    let identifiers = collect_identifiers()?;
    if identifiers.is_empty() {
        return Err(LicenseError::HardwareFingerprintFailed);
    }

    Ok(hash_identifiers(&identifiers))
}

pub fn machine_id_matches(stored_id: &str) -> bool {
    if stored_id.trim().is_empty() {
        return false;
    }

    let identifiers = match collect_identifiers() {
        Ok(ids) => ids,
        Err(_) => return false,
    };

    if identifiers.is_empty() {
        return false;
    }

    let current = hash_identifiers(&identifiers);
    if current.eq_ignore_ascii_case(stored_id) {
        return true;
    }

    if identifiers.len() < 3 {
        return false;
    }

    // Tolerant fallback: accept hashes computed from 3/4 identifier subsets.
    for skip_index in 0..identifiers.len() {
        let subset: BTreeMap<String, String> = identifiers
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != skip_index)
            .map(|(_, (key, value))| (key.clone(), value.clone()))
            .collect();

        if subset.len() >= 3 {
            let candidate = hash_identifiers(&subset);
            if candidate.eq_ignore_ascii_case(stored_id) {
                return true;
            }
        }
    }

    false
}

fn hash_identifiers(identifiers: &BTreeMap<String, String>) -> String {
    let mut hasher = Sha256::new();

    for (key, value) in identifiers {
        hasher.update(key.as_bytes());
        hasher.update(b"=");
        hasher.update(value.as_bytes());
        hasher.update(b"\n");
    }

    hex::encode(hasher.finalize())
}

fn collect_identifiers() -> Result<BTreeMap<String, String>> {
    let mut ids = BTreeMap::new();

    #[cfg(target_os = "windows")]
    {
        if let Some(value) = query_registry_value(
            r"HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            "ProcessorNameString",
        ) {
            ids.insert("cpu_brand".to_string(), value);
        }

        if let Some(value) = query_volume_serial_c() {
            ids.insert("volume_serial".to_string(), value);
        }

        if let Some(value) =
            query_registry_value(r"HKLM\SOFTWARE\Microsoft\Cryptography", "MachineGuid")
        {
            ids.insert("machine_guid".to_string(), value);
        }

        if let Some(value) = query_registry_value(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "InstallDate",
        ) {
            ids.insert("install_date".to_string(), value);
        }

        if let Some(hostname) = std::env::var_os("COMPUTERNAME") {
            ids.entry("hostname".to_string())
                .or_insert_with(|| hostname.to_string_lossy().trim().to_string());
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(value) = linux_cpu_brand() {
            ids.insert("cpu_brand".to_string(), value);
        }

        if let Some(value) = linux_root_disk_uuid() {
            ids.insert("disk_uuid".to_string(), value);
        }

        if let Some(value) = std::fs::read_to_string("/etc/machine-id")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
        {
            ids.insert("machine_guid".to_string(), value);
        }

        if let Some(value) = linux_install_time() {
            ids.insert("install_date".to_string(), value);
        }

        if let Some(hostname) = std::env::var_os("HOSTNAME") {
            ids.entry("hostname".to_string())
                .or_insert_with(|| hostname.to_string_lossy().trim().to_string());
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        if let Some(hostname) = std::env::var_os("HOSTNAME") {
            ids.insert(
                "hostname".to_string(),
                hostname.to_string_lossy().trim().to_string(),
            );
        }
    }

    if ids.is_empty() {
        return Err(LicenseError::HardwareFingerprintFailed);
    }

    Ok(ids)
}

#[cfg(target_os = "windows")]
fn query_registry_value(key: &str, value: &str) -> Option<String> {
    let output = run_command("reg", &["query", key, "/v", value])?;

    for line in output.lines() {
        let trimmed = line.trim();
        if !trimmed
            .to_ascii_lowercase()
            .starts_with(&value.to_ascii_lowercase())
        {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 3 {
            let data = parts[2..].join(" ");
            if !data.is_empty() {
                return Some(data);
            }
        }
    }

    None
}

#[cfg(target_os = "windows")]
fn query_volume_serial_c() -> Option<String> {
    let output = run_command("cmd", &["/C", "vol C:"])?;
    for line in output.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(index) = lower.find("serial number is") {
            let start = index + "serial number is".len();
            let value = line[start..].trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }

    None
}

#[cfg(target_os = "linux")]
fn linux_cpu_brand() -> Option<String> {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    for line in cpuinfo.lines() {
        let mut parts = line.splitn(2, ':');
        let key = parts.next()?.trim();
        let value = parts.next()?.trim();
        if key.eq_ignore_ascii_case("model name") && !value.is_empty() {
            return Some(value.to_string());
        }
    }

    None
}

#[cfg(target_os = "linux")]
fn linux_root_disk_uuid() -> Option<String> {
    let output = run_command("findmnt", &["-no", "UUID", "/"])?;
    let value = output.trim();
    if value.is_empty() {
        return None;
    }

    Some(value.to_string())
}

#[cfg(target_os = "linux")]
fn linux_install_time() -> Option<String> {
    let output = run_command("stat", &["-c", "%Y", "/"])?;
    let value = output.trim();
    if value.is_empty() {
        return None;
    }

    Some(value.to_string())
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
fn run_command(command: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(command).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }

    let value = String::from_utf8(output.stdout).ok()?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    Some(trimmed.to_string())
}
