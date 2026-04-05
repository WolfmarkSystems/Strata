use std::env;
use std::path::{Path, PathBuf};

use super::reg_export::{decode_reg_string, default_reg_path, key_leaf, load_reg_records};

pub fn get_network_cards() -> Vec<NetworkCard> {
    let path = env::var("FORENSIC_NET_REG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_reg_path("net.reg"));
    get_network_cards_from_reg(&path)
}

pub fn get_network_cards_from_reg(path: &Path) -> Vec<NetworkCard> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records.iter().filter(|r| {
        let p = r.path.to_ascii_lowercase();
        p.contains("\\networkcards\\")
            || p.contains("\\network\\{4d36e972-e325-11ce-bfc1-08002be10318}\\")
    }) {
        out.push(NetworkCard {
            guid: key_leaf(&record.path),
            description: record
                .values
                .get("Description")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
            mac_address: record
                .values
                .get("NetworkAddress")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
        });
    }

    out
}

#[derive(Debug, Clone, Default)]
pub struct NetworkCard {
    pub guid: String,
    pub description: String,
    pub mac_address: String,
}

pub fn get_tcpip_params() -> TcpipParams {
    let path = env::var("FORENSIC_NET_REG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_reg_path("net.reg"));
    get_tcpip_params_from_reg(&path)
}

pub fn get_tcpip_params_from_reg(path: &Path) -> TcpipParams {
    let records = load_reg_records(path);
    if let Some(record) = records.iter().find(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("services\\tcpip\\parameters")
    }) {
        return TcpipParams {
            domain: record
                .values
                .get("Domain")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
            dns_servers: record
                .values
                .get("NameServer")
                .and_then(|v| decode_reg_string(v))
                .map(|v| {
                    v.split(',')
                        .map(|p| p.trim().to_string())
                        .filter(|p| !p.is_empty())
                        .collect::<Vec<String>>()
                })
                .unwrap_or_default(),
        };
    }
    TcpipParams::default()
}

#[derive(Debug, Clone, Default)]
pub struct TcpipParams {
    pub domain: String,
    pub dns_servers: Vec<String>,
}

pub fn get_network_interfaces() -> Vec<NetInterface> {
    let path = env::var("FORENSIC_NET_REG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_reg_path("net.reg"));
    get_network_interfaces_from_reg(&path)
}

pub fn get_network_interfaces_from_reg(path: &Path) -> Vec<NetInterface> {
    let records = load_reg_records(path);
    let mut out = Vec::new();
    for record in records.iter().filter(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("services\\tcpip\\parameters\\interfaces\\")
    }) {
        let ip = record
            .values
            .get("DhcpIPAddress")
            .and_then(|v| decode_reg_string(v))
            .or_else(|| {
                record
                    .values
                    .get("IPAddress")
                    .and_then(|v| decode_reg_string(v))
            })
            .unwrap_or_default();
        let subnet = record
            .values
            .get("DhcpSubnetMask")
            .and_then(|v| decode_reg_string(v))
            .or_else(|| {
                record
                    .values
                    .get("SubnetMask")
                    .and_then(|v| decode_reg_string(v))
            })
            .unwrap_or_default();

        out.push(NetInterface {
            name: key_leaf(&record.path),
            ip_address: ip,
            subnet,
        });
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct NetInterface {
    pub name: String,
    pub ip_address: String,
    pub subnet: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_tcpip_params_from_reg_export() {
        let content = r#"
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters]
"Domain"="corp.example"
"NameServer"="8.8.8.8,1.1.1.1"
"#;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("net.reg");
        strata_fs::write(&file, content).unwrap();

        let params = get_tcpip_params_from_reg(&file);
        assert_eq!(params.domain, "corp.example");
        assert_eq!(params.dns_servers, vec!["8.8.8.8", "1.1.1.1"]);
    }
}
