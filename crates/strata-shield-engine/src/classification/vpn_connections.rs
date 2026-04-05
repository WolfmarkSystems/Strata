use std::path::Path;

use super::reg_export::{
    decode_reg_string, default_reg_path, key_leaf, load_reg_records, parse_reg_u32, parse_reg_u64,
};

pub fn get_vpn_connections() -> Vec<VpnConnection> {
    get_vpn_connections_from_reg(&default_reg_path("vpn.reg"))
}

pub fn get_vpn_connections_from_reg(path: &Path) -> Vec<VpnConnection> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records.iter().filter(|r| {
        let p = r.path.to_ascii_lowercase();
        p.contains("rasman\\config") || p.contains("\\vpn\\") || p.contains("networklist\\profiles")
    }) {
        let profile_name = record
            .values
            .get("ProfileName")
            .and_then(|v| decode_reg_string(v))
            .unwrap_or_else(|| key_leaf(&record.path));
        let server = record
            .values
            .get("ServerName")
            .and_then(|v| decode_reg_string(v))
            .or_else(|| {
                record
                    .values
                    .get("PhoneNumber")
                    .and_then(|v| decode_reg_string(v))
            })
            .unwrap_or_default();
        let protocol = record
            .values
            .get("TunnelType")
            .and_then(|v| decode_reg_string(v))
            .unwrap_or_else(|| "unknown".to_string());

        out.push(VpnConnection {
            profile_name,
            server,
            protocol,
            connected: record
                .values
                .get("LastConnected")
                .and_then(|v| parse_reg_u64(v))
                .unwrap_or(0),
            disconnected: record
                .values
                .get("LastDisconnected")
                .and_then(|v| parse_reg_u64(v)),
            bytes_sent: record
                .values
                .get("BytesSent")
                .and_then(|v| parse_reg_u64(v))
                .unwrap_or(0),
            bytes_received: record
                .values
                .get("BytesReceived")
                .and_then(|v| parse_reg_u64(v))
                .unwrap_or(0),
        });
    }

    out
}

#[derive(Debug, Clone, Default)]
pub struct VpnConnection {
    pub profile_name: String,
    pub server: String,
    pub protocol: String,
    pub connected: u64,
    pub disconnected: Option<u64>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

pub fn get_vpn_tunnels() -> Vec<VpnTunnel> {
    get_vpn_connections()
        .into_iter()
        .map(|c| VpnTunnel {
            connection_name: c.profile_name,
            tunnel_interface: "ras".to_string(),
            remote_endpoint: c.server,
            tunnel_protocol: c.protocol,
            encryption: "unknown".to_string(),
        })
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct VpnTunnel {
    pub connection_name: String,
    pub tunnel_interface: String,
    pub remote_endpoint: String,
    pub tunnel_protocol: String,
    pub encryption: String,
}

pub fn get_vpn_profiles() -> Vec<VpnProfile> {
    get_vpn_connections()
        .into_iter()
        .map(|c| VpnProfile {
            name: c.profile_name,
            server: c.server,
            protocol: c.protocol,
            authentication_type: "unknown".to_string(),
            remember_credentials: false,
        })
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct VpnProfile {
    pub name: String,
    pub server: String,
    pub protocol: String,
    pub authentication_type: String,
    pub remember_credentials: bool,
}

pub fn get_vpn_ipsec() -> Vec<VpnIpsec> {
    let records = load_reg_records(&default_reg_path("vpn.reg"));
    let mut out = Vec::new();
    for record in records
        .iter()
        .filter(|r| r.path.to_ascii_lowercase().contains("ipsec"))
    {
        out.push(VpnIpsec {
            connection_name: key_leaf(&record.path),
            ike_version: record
                .values
                .get("IKEVersion")
                .and_then(|v| parse_reg_u32(v))
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            encryption: record
                .values
                .get("Encryption")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_else(|| "unknown".to_string()),
            integrity: record
                .values
                .get("Integrity")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_else(|| "unknown".to_string()),
            dh_group: record
                .values
                .get("DHGroup")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_else(|| "unknown".to_string()),
        });
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct VpnIpsec {
    pub connection_name: String,
    pub ike_version: String,
    pub encryption: String,
    pub integrity: String,
    pub dh_group: String,
}
