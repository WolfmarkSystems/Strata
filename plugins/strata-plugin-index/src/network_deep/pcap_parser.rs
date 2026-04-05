use strata_core::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct PcapParser;

impl PcapParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PcapHeader {
    pub magic_number: Option<u32>,
    pub version_major: Option<u16>,
    pub version_minor: Option<u16>,
    pub thiszone: Option<i32>,
    pub sigfigs: Option<u32>,
    pub snaplen: Option<u32>,
    pub network: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PacketEntry {
    pub timestamp: Option<i64>,
    pub timestamp_micro: Option<i64>,
    pub captured_length: u32,
    pub original_length: u32,
    pub ethernet_header: Option<String>,
    pub ip_header: Option<IpHeader>,
    pub transport_header: Option<TransportHeader>,
    pub payload: Option<String>,
    pub payload_size: usize,
    pub is_fragment: bool,
    pub fragment_offset: u16,
    pub more_fragments: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IpHeader {
    pub version: u8,
    pub header_length: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransportHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub tcp_flags: Option<TcpFlags>,
    pub sequence_number: Option<u32>,
    pub acknowledgment_number: Option<u32>,
    pub window_size: Option<u16>,
    pub checksum: Option<u16>,
    pub urgent_pointer: Option<u16>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: Option<String>,
    pub uri: Option<String>,
    pub version: Option<String>,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub accept: Option<String>,
    pub accept_language: Option<String>,
    pub accept_encoding: Option<String>,
    pub connection: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<i32>,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DnsQuery {
    pub transaction_id: u16,
    pub flags: u16,
    pub questions: u16,
    pub answer_rrs: u16,
    pub authority_rrs: u16,
    pub additional_rrs: u16,
    pub query_name: Option<String>,
    pub query_type: Option<String>,
    pub query_class: Option<String>,
    pub responses: Vec<DnsResponse>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DnsResponse {
    pub name: Option<String>,
    pub query_type: Option<String>,
    pub ttl: Option<u32>,
    pub data: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PcapStats {
    pub packet_count: u64,
    pub tcp_count: u64,
    pub udp_count: u64,
    pub icmp_count: u64,
    pub http_count: u64,
    pub dns_count: u64,
    pub total_bytes: u64,
    pub unique_ips: u32,
    pub unique_ports: u32,
}

impl Default for PcapParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactParser for PcapParser {
    fn name(&self) -> &str {
        "PCAP Parser"
    }

    fn artifact_type(&self) -> &str {
        "network"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![".pcap", ".pcapng", ".cap"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if data.len() > 24 {
            let stats = PcapStats {
                packet_count: 0,
                tcp_count: 0,
                udp_count: 0,
                icmp_count: 0,
                http_count: 0,
                dns_count: 0,
                total_bytes: data.len() as u64,
                unique_ips: 0,
                unique_ports: 0,
            };

            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "network".to_string(),
                description: "PCAP file parsed".to_string(),
                source_path: path.to_string_lossy().to_string(),
                json_data: serde_json::to_value(&stats).unwrap_or_default(),
            });
        }

        Ok(artifacts)
    }
}
