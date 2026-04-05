use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct NetworkParser;

impl NetworkParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DnsQueryEntry {
    pub timestamp: Option<i64>,
    pub query_name: Option<String>,
    pub query_type: Option<String>,
    pub response_ip: Option<String>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HttpRequestEntry {
    pub timestamp: Option<i64>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub method: Option<String>,
    pub host: Option<String>,
    pub uri: Option<String>,
    pub user_agent: Option<String>,
    pub referer: Option<String>,
    pub status_code: Option<u16>,
    pub content_type: Option<String>,
    pub content_length: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectionEntry {
    pub timestamp: Option<i64>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Option<String>,
    pub state: Option<String>,
    pub bytes_sent: Option<i64>,
    pub bytes_received: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProxyLogEntry {
    pub timestamp: Option<i64>,
    pub src_ip: Option<String>,
    pub method: Option<String>,
    pub url: Option<String>,
    pub status_code: Option<u16>,
    pub content_type: Option<String>,
    pub content_length: Option<i64>,
    pub user: Option<String>,
    pub destination: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VpnConnectionEntry {
    pub timestamp: Option<i64>,
    pub vpn_server: Option<String>,
    pub src_ip: Option<String>,
    pub assigned_ip: Option<String>,
    pub protocol: Option<String>,
    pub bytes_sent: Option<i64>,
    pub bytes_received: Option<i64>,
    pub duration_seconds: Option<i64>,
    pub disconnect_time: Option<i64>,
}

impl Default for NetworkParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for NetworkParser {
    fn name(&self) -> &str {
        "Network"
    }

    fn artifact_type(&self) -> &str {
        "network"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["dns", "pcap", "network", "proxy", "vpn"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if !data.is_empty() {
            let entry = DnsQueryEntry {
                timestamp: None,
                query_name: Some(
                    path.file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default(),
                ),
                query_type: None,
                response_ip: None,
                src_ip: None,
                dst_ip: None,
                src_port: None,
                dst_port: None,
                protocol: None,
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "network".to_string(),
                description: "Network artifact".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&entry).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}
