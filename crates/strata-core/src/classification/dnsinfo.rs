use std::env;
use std::path::{Path, PathBuf};

use super::reg_export::{decode_reg_string, default_reg_path, key_leaf, load_reg_records};

pub fn get_dns_zones() -> Vec<DnsZone> {
    let path = env::var("FORENSIC_DNS_REG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_reg_path("dns.reg"));
    get_dns_zones_from_reg(&path)
}

pub fn get_dns_zones_from_reg(path: &Path) -> Vec<DnsZone> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records.iter().filter(|r| {
        let p = r.path.to_ascii_lowercase();
        p.contains("\\dns\\zones\\") || p.contains("\\dnsserver\\zones\\")
    }) {
        let name = record
            .values
            .get("ZoneName")
            .and_then(|v| decode_reg_string(v))
            .unwrap_or_else(|| key_leaf(&record.path));
        let zone_type = record
            .values
            .get("Type")
            .and_then(|v| decode_reg_string(v))
            .unwrap_or_else(|| infer_zone_type(&record.path));

        out.push(DnsZone { name, zone_type });
    }

    out
}

fn infer_zone_type(path: &str) -> String {
    let p = path.to_ascii_lowercase();
    if p.contains("reverse") || p.contains("in-addr.arpa") {
        "reverse".to_string()
    } else if p.contains("stub") {
        "stub".to_string()
    } else if p.contains("forward") {
        "forward".to_string()
    } else {
        "primary".to_string()
    }
}

#[derive(Debug, Clone, Default)]
pub struct DnsZone {
    pub name: String,
    pub zone_type: String,
}
