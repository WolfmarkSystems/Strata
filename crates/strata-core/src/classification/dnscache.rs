use super::scalpel::{read_text_prefix, DEFAULT_TEXT_MAX_BYTES};
use std::env;
use std::path::PathBuf;

pub fn get_dns_cache_entries() -> Vec<DnsCache> {
    let path = env::var("FORENSIC_DNS_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("artifacts")
                .join("network")
                .join("dns_cache.txt")
        });
    let content = match read_text_prefix(&path, DEFAULT_TEXT_MAX_BYTES) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    parse_dns_cache_text(&content)
}

pub fn parse_dns_cache_text(content: &str) -> Vec<DnsCache> {
    let mut out = Vec::new();
    let mut current_name: Option<String> = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // ipconfig /displaydns style:
        // Record Name . . . . . : example.com
        if trimmed.to_ascii_lowercase().starts_with("record name") {
            if let Some((_, rhs)) = trimmed.split_once(':') {
                current_name = Some(rhs.trim().to_string());
            }
            continue;
        }
        // A (Host) Record . . . . : 1.2.3.4
        if trimmed.to_ascii_lowercase().starts_with("a (host) record") {
            if let Some((_, rhs)) = trimmed.split_once(':') {
                let ip = rhs.trim().to_string();
                if is_ipv4(&ip) {
                    out.push(DnsCache {
                        name: current_name.clone().unwrap_or_default(),
                        ip,
                    });
                }
            }
            continue;
        }

        // CSV / pipe / whitespace fallback.
        let parts: Vec<&str> = if trimmed.contains('|') {
            trimmed.split('|').collect()
        } else if trimmed.contains(',') {
            trimmed.split(',').collect()
        } else {
            trimmed.split_whitespace().collect()
        };
        if parts.len() >= 2 {
            let left = parts[0].trim();
            let right = parts[1].trim();
            if is_ipv4(right) {
                out.push(DnsCache {
                    name: left.to_string(),
                    ip: right.to_string(),
                });
            } else if is_ipv4(left) {
                out.push(DnsCache {
                    name: right.to_string(),
                    ip: left.to_string(),
                });
            }
        }
    }

    out
}

fn is_ipv4(candidate: &str) -> bool {
    let parts: Vec<&str> = candidate.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|part| part.parse::<u8>().is_ok())
}

#[derive(Debug, Clone, Default)]
pub struct DnsCache {
    pub name: String,
    pub ip: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipconfig_displaydns_style() {
        let data = r#"
Record Name . . . . . : example.com
A (Host) Record . . . : 1.2.3.4
"#;
        let rows = parse_dns_cache_text(data);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "example.com");
        assert_eq!(rows[0].ip, "1.2.3.4");
    }
}
