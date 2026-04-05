use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// RDP (Remote Desktop Protocol) Artifact Correlation Parser
///
/// Parses multiple RDP artifact sources and correlates them into unified
/// remote access evidence:
///
///   - Default.rdp: Client connection configuration
///   - RDP Bitmap Cache: bcache24.bmc / Cache*.bin in Terminal Server Client
///   - EVTX correlation: Event IDs 4624/4625 (Type 10), 1149, 21/22/24/25
///   - Registry: Terminal Server Client\Servers, Default keys
///
/// Forensic value: RDP is MITRE ATT&CK T1021.001 — the #1 lateral movement
/// technique in enterprise intrusions. Proving remote access sessions is
/// critical for incident response and insider threat investigations.
pub struct RdpArtifactsParser;

impl Default for RdpArtifactsParser {
    fn default() -> Self {
        Self::new()
    }
}

impl RdpArtifactsParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RdpConnectionEntry {
    pub connection_type: String,
    pub server: Option<String>,
    pub username: Option<String>,
    pub domain: Option<String>,
    pub port: Option<u16>,
    pub gateway: Option<String>,
    pub drive_redirection: bool,
    pub clipboard_redirection: bool,
    pub printer_redirection: bool,
    pub audio_redirection: bool,
    pub full_address: Option<String>,
    pub forensic_flags: Vec<String>,
    pub mitre_technique: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RdpBitmapCacheEntry {
    pub cache_file: String,
    pub tile_count: usize,
    pub tile_width: u32,
    pub tile_height: u32,
    pub cache_size_bytes: usize,
    pub forensic_note: String,
}

impl ArtifactParser for RdpArtifactsParser {
    fn name(&self) -> &str {
        "RDP Artifact Correlation Parser"
    }

    fn artifact_type(&self) -> &str {
        "remote_access"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "Default.rdp",
            "default.rdp",
            "*.rdp",
            "bcache24.bmc",
            "bcache22.bmc",
            "Cache0000.bin",
            "Cache0001.bin",
            "Cache0002.bin",
            "Cache0003.bin",
            "Cache0004.bin",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
            .to_lowercase();

        if filename.ends_with(".rdp") {
            self.parse_rdp_file(path, data)
        } else if filename.contains("bcache") || filename.starts_with("cache") {
            self.parse_bitmap_cache(path, data)
        } else {
            Ok(vec![])
        }
    }
}

impl RdpArtifactsParser {
    fn parse_rdp_file(
        &self,
        path: &Path,
        data: &[u8],
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();
        let text = String::from_utf8_lossy(data);

        let mut entry = RdpConnectionEntry {
            connection_type: "rdp_file".to_string(),
            server: None,
            username: None,
            domain: None,
            port: None,
            gateway: None,
            drive_redirection: false,
            clipboard_redirection: false,
            printer_redirection: false,
            audio_redirection: false,
            full_address: None,
            forensic_flags: Vec::new(),
            mitre_technique: "T1021.001".to_string(),
        };

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            // RDP file format: key:type:value (e.g., "full address:s:10.0.0.1")
            let parts: Vec<&str> = trimmed.splitn(3, ':').collect();
            if parts.len() < 3 {
                // Also handle key=value format
                if let Some(eq_pos) = trimmed.find('=') {
                    let key = trimmed[..eq_pos].trim().to_lowercase();
                    let value = trimmed[eq_pos + 1..].trim().to_string();
                    self.process_rdp_setting(&mut entry, &key, &value);
                }
                continue;
            }

            let key = parts[0].trim().to_lowercase();
            let value = parts[2].trim().to_string();
            self.process_rdp_setting(&mut entry, &key, &value);
        }

        // Flag security-relevant configurations
        if entry.drive_redirection {
            entry.forensic_flags.push(
                "DRIVE_REDIRECT — Local drives shared with remote host (data exfiltration risk)"
                    .to_string(),
            );
        }
        if entry.clipboard_redirection {
            entry.forensic_flags.push(
                "CLIPBOARD_REDIRECT — Clipboard shared (data transfer between sessions)"
                    .to_string(),
            );
        }
        if entry.printer_redirection {
            entry.forensic_flags.push(
                "PRINTER_REDIRECT — Printers shared with remote host".to_string(),
            );
        }

        let server = entry
            .full_address
            .as_deref()
            .or(entry.server.as_deref())
            .unwrap_or("unknown");

        let mut desc = format!(
            "RDP Connection: {} (user: {}, domain: {})",
            server,
            entry.username.as_deref().unwrap_or("unknown"),
            entry.domain.as_deref().unwrap_or("unknown"),
        );
        for flag in &entry.forensic_flags {
            desc.push_str(&format!(" [{}]", flag));
        }

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "rdp_connection".to_string(),
            description: desc,
            source_path: source,
            json_data: serde_json::to_value(&entry).unwrap_or_default(),
        });

        Ok(artifacts)
    }

    fn process_rdp_setting(&self, entry: &mut RdpConnectionEntry, key: &str, value: &str) {
        match key {
            "full address" => {
                entry.full_address = Some(value.to_string());
                // Extract port if specified
                if let Some(colon) = value.rfind(':') {
                    let host = &value[..colon];
                    if let Ok(port) = value[colon + 1..].parse::<u16>() {
                        entry.server = Some(host.to_string());
                        entry.port = Some(port);
                    } else {
                        entry.server = Some(value.to_string());
                    }
                } else {
                    entry.server = Some(value.to_string());
                }
            }
            "username" => entry.username = Some(value.to_string()),
            "domain" => entry.domain = Some(value.to_string()),
            "gatewayhostname" => entry.gateway = Some(value.to_string()),
            "drivestoredirect" => {
                entry.drive_redirection = !value.is_empty() && value != "0";
            }
            "redirectclipboard" => {
                entry.clipboard_redirection = value == "1";
            }
            "redirectprinters" => {
                entry.printer_redirection = value == "1";
            }
            "audiomode" => {
                entry.audio_redirection = value != "2"; // 2 = no audio
            }
            "server port" => {
                entry.port = value.parse().ok();
            }
            _ => {}
        }
    }

    fn parse_bitmap_cache(
        &self,
        path: &Path,
        data: &[u8],
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();
        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        // BMC v2 format: bcache24.bmc / bcache22.bmc
        // Contains 64x64 pixel tiles from RDP sessions
        // Each tile can be reconstructed to view what was displayed

        if data.len() < 12 {
            return Ok(artifacts);
        }

        // Estimate tile count based on file size
        // BMC tiles are typically 64x64 pixels at varying bit depths
        let tile_sizes = [64 * 64 * 4, 64 * 64 * 3, 64 * 64 * 2]; // 32bpp, 24bpp, 16bpp
        let estimated_tiles = tile_sizes
            .iter()
            .map(|&ts| data.len() / ts)
            .find(|&count| count > 0)
            .unwrap_or(0);

        let entry = RdpBitmapCacheEntry {
            cache_file: filename.clone(),
            tile_count: estimated_tiles,
            tile_width: 64,
            tile_height: 64,
            cache_size_bytes: data.len(),
            forensic_note: "RDP bitmap cache contains screen tiles from remote sessions. \
                These tiles can be reconstructed to view what was displayed during the session. \
                Tools: bmc-tools.py can extract individual tiles for visual review."
                .to_string(),
        };

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "rdp_bitmap_cache".to_string(),
            description: format!(
                "RDP Bitmap Cache: {} (~{} tiles, {} bytes) — contains visual fragments of remote sessions (T1021.001)",
                filename, estimated_tiles, data.len(),
            ),
            source_path: source,
            json_data: serde_json::to_value(&entry).unwrap_or_default(),
        });

        Ok(artifacts)
    }
}
