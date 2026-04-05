use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Volatility 3 Output Import Parser
///
/// Imports JSON/CSV output from Volatility 3 memory forensics framework.
/// Supports: pslist, netscan, malfind, dlllist, cmdline, handles, filescan,
/// hivelist, hashdump, timeliner.
///
/// Forensic value: Memory forensics without building a full Volatility
/// competitor. Import existing Volatility results into the Strata timeline
/// and correlation engine. Examiners run Volatility separately and import
/// results for unified analysis.
pub struct VolatilityImportParser;

impl Default for VolatilityImportParser {
    fn default() -> Self {
        Self::new()
    }
}

impl VolatilityImportParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VolProcess {
    pub pid: Option<i64>,
    pub ppid: Option<i64>,
    pub image_name: Option<String>,
    pub create_time: Option<String>,
    pub exit_time: Option<String>,
    pub threads: Option<i64>,
    pub handles: Option<i64>,
    pub session_id: Option<i64>,
    pub wow64: Option<bool>,
    pub offset: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VolNetConnection {
    pub protocol: Option<String>,
    pub local_addr: Option<String>,
    pub local_port: Option<i64>,
    pub foreign_addr: Option<String>,
    pub foreign_port: Option<i64>,
    pub state: Option<String>,
    pub pid: Option<i64>,
    pub owner: Option<String>,
    pub created: Option<String>,
}

impl ArtifactParser for VolatilityImportParser {
    fn name(&self) -> &str {
        "Volatility 3 Output Import"
    }

    fn artifact_type(&self) -> &str {
        "memory_forensics"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "vol3_*.json",
            "volatility_*.json",
            "vol_pslist*.json",
            "vol_netscan*.json",
            "vol_malfind*.json",
            "vol_cmdline*.json",
            "vol_dlllist*.json",
            "vol_filescan*.json",
            "vol_timeliner*.json",
            "vol_handles*.json",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();
        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
            .to_lowercase();

        let Ok(json) = serde_json::from_slice::<serde_json::Value>(data) else {
            return Ok(artifacts);
        };

        // Detect Volatility output format
        let rows = if let Some(arr) = json.as_array() {
            arr.clone()
        } else if let Some(arr) = json.get("rows").and_then(|r| r.as_array()) {
            arr.clone()
        } else if let Some(arr) = json.get("data").and_then(|r| r.as_array()) {
            arr.clone()
        } else {
            vec![json.clone()]
        };

        // Detect plugin type from filename or content
        let plugin_type = detect_volatility_plugin(&filename, &rows);

        match plugin_type {
            "pslist" | "psscan" | "pstree" => {
                for row in rows.iter().take(10000) {
                    let proc = parse_vol_process(row);
                    let mut desc = format!(
                        "Memory [{}]: PID {} — {} (PPID: {})",
                        plugin_type,
                        proc.pid.unwrap_or(-1),
                        proc.image_name.as_deref().unwrap_or("unknown"),
                        proc.ppid.unwrap_or(-1),
                    );
                    if proc.wow64 == Some(true) {
                        desc.push_str(" [WOW64]");
                    }

                    artifacts.push(ParsedArtifact {
                        timestamp: None,
                        artifact_type: "memory_process".to_string(),
                        description: desc,
                        source_path: source.clone(),
                        json_data: serde_json::to_value(&proc).unwrap_or_default(),
                    });
                }
            }
            "netscan" | "netstat" => {
                for row in rows.iter().take(10000) {
                    let conn = parse_vol_netconn(row);
                    artifacts.push(ParsedArtifact {
                        timestamp: None,
                        artifact_type: "memory_network".to_string(),
                        description: format!(
                            "Memory [{}]: {} {}:{} -> {}:{} [{}] PID={}",
                            plugin_type,
                            conn.protocol.as_deref().unwrap_or("?"),
                            conn.local_addr.as_deref().unwrap_or("*"),
                            conn.local_port.unwrap_or(0),
                            conn.foreign_addr.as_deref().unwrap_or("*"),
                            conn.foreign_port.unwrap_or(0),
                            conn.state.as_deref().unwrap_or("?"),
                            conn.pid.unwrap_or(-1),
                        ),
                        source_path: source.clone(),
                        json_data: serde_json::to_value(&conn).unwrap_or_default(),
                    });
                }
            }
            "malfind" => {
                for row in rows.iter().take(10000) {
                    let pid = row.get("PID").or(row.get("pid")).and_then(|v| v.as_i64());
                    let process = row.get("Process").or(row.get("process")).and_then(|v| v.as_str());
                    let protection = row.get("Protection").and_then(|v| v.as_str());
                    let hex_dump = row.get("Hexdump").or(row.get("hexdump")).and_then(|v| v.as_str());

                    artifacts.push(ParsedArtifact {
                        timestamp: None,
                        artifact_type: "memory_injection".to_string(),
                        description: format!(
                            "Memory [malfind]: PID {} ({}) — suspicious memory region [{}]",
                            pid.unwrap_or(-1),
                            process.unwrap_or("unknown"),
                            protection.unwrap_or("unknown"),
                        ),
                        source_path: source.clone(),
                        json_data: serde_json::json!({
                            "pid": pid,
                            "process": process,
                            "protection": protection,
                            "hexdump_preview": hex_dump.map(|h| &h[..h.len().min(200)]),
                            "mitre_technique": "T1055",
                        }),
                    });
                }
            }
            "cmdline" => {
                for row in rows.iter().take(10000) {
                    let pid = row.get("PID").or(row.get("pid")).and_then(|v| v.as_i64());
                    let process = row.get("Process").or(row.get("process")).and_then(|v| v.as_str());
                    let args = row.get("Args").or(row.get("args")).and_then(|v| v.as_str());

                    if let Some(cmdline) = args {
                        artifacts.push(ParsedArtifact {
                            timestamp: None,
                            artifact_type: "memory_cmdline".to_string(),
                            description: format!(
                                "Memory [cmdline]: PID {} ({}) — {}",
                                pid.unwrap_or(-1),
                                process.unwrap_or("unknown"),
                                if cmdline.len() > 150 { format!("{}...", &cmdline[..150]) } else { cmdline.to_string() },
                            ),
                            source_path: source.clone(),
                            json_data: serde_json::json!({
                                "pid": pid,
                                "process": process,
                                "cmdline": cmdline,
                            }),
                        });
                    }
                }
            }
            _ => {
                // Generic import — just capture all rows
                for (idx, row) in rows.iter().enumerate().take(5000) {
                    artifacts.push(ParsedArtifact {
                        timestamp: None,
                        artifact_type: "memory_artifact".to_string(),
                        description: format!(
                            "Memory [{}]: entry {} of {}",
                            plugin_type,
                            idx + 1,
                            rows.len(),
                        ),
                        source_path: source.clone(),
                        json_data: row.clone(),
                    });
                }
            }
        }

        // Summary artifact
        if !artifacts.is_empty() {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "memory_import_summary".to_string(),
                description: format!(
                    "Volatility Import: {} plugin — {} entries from {}",
                    plugin_type,
                    artifacts.len() - 1,
                    filename,
                ),
                source_path: source,
                json_data: serde_json::json!({
                    "plugin": plugin_type,
                    "entry_count": artifacts.len() - 1,
                    "source_file": filename,
                }),
            });
        }

        Ok(artifacts)
    }
}

fn detect_volatility_plugin(filename: &str, rows: &[serde_json::Value]) -> &'static str {
    // Check filename patterns
    if filename.contains("pslist") || filename.contains("psscan") {
        return "pslist";
    }
    if filename.contains("netscan") || filename.contains("netstat") {
        return "netscan";
    }
    if filename.contains("malfind") {
        return "malfind";
    }
    if filename.contains("cmdline") {
        return "cmdline";
    }
    if filename.contains("dlllist") {
        return "dlllist";
    }
    if filename.contains("filescan") {
        return "filescan";
    }
    if filename.contains("timeliner") {
        return "timeliner";
    }
    if filename.contains("handles") {
        return "handles";
    }

    // Detect from content structure
    if let Some(first) = rows.first() {
        if first.get("PID").is_some() && first.get("ImageFileName").is_some() {
            return "pslist";
        }
        if first.get("LocalAddr").is_some() || first.get("ForeignAddr").is_some() {
            return "netscan";
        }
        if first.get("Hexdump").is_some() || first.get("Protection").is_some() {
            return "malfind";
        }
        if first.get("Args").is_some() && first.get("PID").is_some() {
            return "cmdline";
        }
    }

    "unknown"
}

fn parse_vol_process(row: &serde_json::Value) -> VolProcess {
    VolProcess {
        pid: row.get("PID").or(row.get("pid")).and_then(|v| v.as_i64()),
        ppid: row.get("PPID").or(row.get("ppid")).and_then(|v| v.as_i64()),
        image_name: row
            .get("ImageFileName")
            .or(row.get("Name"))
            .or(row.get("process"))
            .and_then(|v| v.as_str())
            .map(String::from),
        create_time: row.get("CreateTime").and_then(|v| v.as_str()).map(String::from),
        exit_time: row.get("ExitTime").and_then(|v| v.as_str()).map(String::from),
        threads: row.get("Threads").and_then(|v| v.as_i64()),
        handles: row.get("HandleCount").and_then(|v| v.as_i64()),
        session_id: row.get("SessionId").and_then(|v| v.as_i64()),
        wow64: row.get("Wow64").and_then(|v| v.as_bool()),
        offset: row.get("Offset").and_then(|v| v.as_str()).map(String::from),
    }
}

fn parse_vol_netconn(row: &serde_json::Value) -> VolNetConnection {
    VolNetConnection {
        protocol: row.get("Proto").or(row.get("protocol")).and_then(|v| v.as_str()).map(String::from),
        local_addr: row.get("LocalAddr").and_then(|v| v.as_str()).map(String::from),
        local_port: row.get("LocalPort").and_then(|v| v.as_i64()),
        foreign_addr: row.get("ForeignAddr").and_then(|v| v.as_str()).map(String::from),
        foreign_port: row.get("ForeignPort").and_then(|v| v.as_i64()),
        state: row.get("State").and_then(|v| v.as_str()).map(String::from),
        pid: row.get("PID").or(row.get("pid")).and_then(|v| v.as_i64()),
        owner: row.get("Owner").and_then(|v| v.as_str()).map(String::from),
        created: row.get("Created").and_then(|v| v.as_str()).map(String::from),
    }
}
