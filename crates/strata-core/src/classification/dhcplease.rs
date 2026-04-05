use super::scalpel::{read_text_prefix, DEFAULT_TEXT_MAX_BYTES};
use std::env;
use std::path::PathBuf;

pub fn get_dhcp_leases() -> Vec<DhcpLease> {
    let path = env::var("FORENSIC_DHCP_LEASES")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("artifacts")
                .join("network")
                .join("dhcp_leases.txt")
        });
    let content = match read_text_prefix(&path, DEFAULT_TEXT_MAX_BYTES) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    parse_dhcp_lease_text(&content)
}

pub fn parse_dhcp_lease_text(content: &str) -> Vec<DhcpLease> {
    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = if trimmed.contains('|') {
            trimmed.split('|').collect()
        } else if trimmed.contains(',') {
            trimmed.split(',').collect()
        } else {
            trimmed.split_whitespace().collect()
        };
        if parts.len() < 2 {
            continue;
        }

        let (ip, mac) = if is_ipv4(parts[0].trim()) {
            (parts[0].trim(), parts[1].trim())
        } else if is_ipv4(parts[1].trim()) {
            (parts[1].trim(), parts[0].trim())
        } else {
            continue;
        };

        if !is_mac(mac) {
            continue;
        }

        out.push(DhcpLease {
            ip: ip.to_string(),
            mac: normalize_mac(mac),
        });
    }
    out
}

fn normalize_mac(raw: &str) -> String {
    raw.replace('-', ":").to_ascii_uppercase()
}

fn is_ipv4(candidate: &str) -> bool {
    let parts: Vec<&str> = candidate.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|part| part.parse::<u8>().is_ok())
}

fn is_mac(candidate: &str) -> bool {
    let normalized = candidate.replace('-', ":");
    let parts: Vec<&str> = normalized.split(':').collect();
    if parts.len() != 6 {
        return false;
    }
    parts
        .iter()
        .all(|part| part.len() == 2 && u8::from_str_radix(part, 16).is_ok())
}

#[derive(Debug, Clone, Default)]
pub struct DhcpLease {
    pub ip: String,
    pub mac: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dhcp_csv() {
        let rows = parse_dhcp_lease_text("192.168.1.20,aa-bb-cc-dd-ee-ff\n");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].ip, "192.168.1.20");
        assert_eq!(rows[0].mac, "AA:BB:CC:DD:EE:FF");
    }
}
