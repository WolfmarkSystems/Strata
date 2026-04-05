use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use crate::parsers::sqlite_utils::{table_exists, with_sqlite_connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Tor Browser Artifact Parser
///
/// Parses Tor Browser artifacts:
///   - places.sqlite: Browsing history (usually cleared, but may have residual data)
///   - torrc: Tor configuration (bridges, entry guards, exit policies)
///   - state: Tor relay state and guard information
///   - pluggable_transports: Bridge/obfuscation configuration
///
/// Forensic value: Tor Browser usage indicates intent to conceal activity.
/// The torrc file reveals bridge configurations, and state files contain
/// guard relay fingerprints. Even with Tor's anti-forensic design, artifacts
/// persist in filesystem metadata, prefetch, and memory.
pub struct TorBrowserParser;

impl Default for TorBrowserParser {
    fn default() -> Self {
        Self::new()
    }
}

impl TorBrowserParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TorConfigEntry {
    pub config_type: String,
    pub bridges: Vec<String>,
    pub entry_guards: Vec<String>,
    pub socks_port: Option<String>,
    pub control_port: Option<String>,
    pub hidden_service_dirs: Vec<String>,
    pub transport_plugins: Vec<String>,
    pub forensic_flags: Vec<String>,
}

impl ArtifactParser for TorBrowserParser {
    fn name(&self) -> &str {
        "Tor Browser Artifact Parser"
    }

    fn artifact_type(&self) -> &str {
        "anti_forensics"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "torrc",
            "torrc-defaults",
            "state",
            "places.sqlite",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
            .to_lowercase();

        let path_str = path.to_string_lossy().to_lowercase();

        // Only parse if path suggests Tor Browser
        let is_tor_related = path_str.contains("tor")
            || path_str.contains("tbb")
            || filename == "torrc"
            || filename == "torrc-defaults";

        if !is_tor_related {
            return Ok(vec![]);
        }

        if filename.starts_with("torrc") {
            self.parse_torrc(path, data)
        } else if filename == "state" {
            self.parse_tor_state(path, data)
        } else if filename == "places.sqlite" {
            self.parse_tor_places(path, data)
        } else {
            Ok(vec![])
        }
    }
}

impl TorBrowserParser {
    fn parse_torrc(
        &self,
        path: &Path,
        data: &[u8],
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();
        let text = String::from_utf8_lossy(data);

        let mut entry = TorConfigEntry {
            config_type: "torrc".to_string(),
            bridges: Vec::new(),
            entry_guards: Vec::new(),
            socks_port: None,
            control_port: None,
            hidden_service_dirs: Vec::new(),
            transport_plugins: Vec::new(),
            forensic_flags: Vec::new(),
        };

        entry.forensic_flags.push("TOR_USAGE — Tor configuration detected".to_string());

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
            if parts.len() < 2 {
                continue;
            }

            let key = parts[0].to_lowercase();
            let value = parts[1].trim();

            match key.as_str() {
                "bridge" => {
                    entry.bridges.push(value.to_string());
                    entry.forensic_flags.push(format!("BRIDGE: {}", value));
                }
                "usebridges" if value == "1" => {
                    entry.forensic_flags.push("BRIDGES_ENABLED — Using bridges to circumvent censorship".to_string());
                }
                "socksport" => entry.socks_port = Some(value.to_string()),
                "controlport" => entry.control_port = Some(value.to_string()),
                "hiddenservicedir" => {
                    entry.hidden_service_dirs.push(value.to_string());
                    entry.forensic_flags.push(format!(
                        "HIDDEN_SERVICE — Hosting .onion service at {}",
                        value
                    ));
                }
                "clienttransportplugin" | "servertransportplugin" => {
                    entry.transport_plugins.push(value.to_string());
                }
                "entryguardrestriction" | "entrynodes" => {
                    entry.entry_guards.push(value.to_string());
                }
                _ => {}
            }
        }

        let mut desc = format!(
            "Tor Config: {} bridges, {} hidden services",
            entry.bridges.len(),
            entry.hidden_service_dirs.len(),
        );
        for flag in &entry.forensic_flags {
            desc.push_str(&format!(" [{}]", flag));
        }

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "tor_config".to_string(),
            description: desc,
            source_path: source,
            json_data: serde_json::to_value(&entry).unwrap_or_default(),
        });

        Ok(artifacts)
    }

    fn parse_tor_state(
        &self,
        path: &Path,
        data: &[u8],
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();
        let text = String::from_utf8_lossy(data);

        let mut guards = Vec::new();
        let mut last_written = None;

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("Guard ") || trimmed.starts_with("EntryGuard ") {
                guards.push(trimmed.to_string());
            }
            if let Some(rest) = trimmed.strip_prefix("LastWritten ") {
                last_written = Some(rest.trim().to_string());
            }
        }

        let mut desc = format!(
            "Tor State: {} entry guards",
            guards.len(),
        );
        if let Some(ref lw) = last_written {
            desc.push_str(&format!(" (last written: {})", lw));
        }

        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "tor_state".to_string(),
            description: desc,
            source_path: source,
            json_data: serde_json::json!({
                "entry_guards": guards,
                "guard_count": guards.len(),
                "last_written": last_written,
                "forensic_note": "Guard relay fingerprints identify Tor entry points used by this client",
            }),
        });

        Ok(artifacts)
    }

    fn parse_tor_places(
        &self,
        path: &Path,
        data: &[u8],
    ) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();

        let sqlite_result = with_sqlite_connection(path, data, |conn| {
            let mut entries = Vec::new();

            if table_exists(conn, "moz_places") {
                let mut stmt = conn
                    .prepare(
                        "SELECT url, title, visit_count, last_visit_date
                         FROM moz_places
                         WHERE visit_count > 0
                         ORDER BY last_visit_date DESC
                         LIMIT 5000",
                    )
                    .map_err(|e| ParserError::Database(e.to_string()))?;

                let rows = stmt
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, String>(0).unwrap_or_default(),
                            row.get::<_, String>(1).ok(),
                            row.get::<_, i32>(2).unwrap_or(0),
                            row.get::<_, i64>(3).ok(),
                        ))
                    })
                    .map_err(|e| ParserError::Database(e.to_string()))?;

                for row in rows.flatten() {
                    // Firefox timestamps are microseconds since epoch
                    let ts = row.3.map(|us| us / 1_000_000);

                    let mut desc = format!(
                        "Tor Browser History: {} (visited {} times)",
                        row.0,
                        row.2,
                    );

                    // Flag .onion addresses
                    if row.0.contains(".onion") {
                        desc.push_str(" [ONION_SERVICE]");
                    }

                    entries.push(ParsedArtifact {
                        timestamp: ts,
                        artifact_type: "tor_browsing".to_string(),
                        description: desc,
                        source_path: source.clone(),
                        json_data: serde_json::json!({
                            "url": row.0,
                            "title": row.1,
                            "visit_count": row.2,
                            "last_visit": ts,
                            "is_onion": row.0.contains(".onion"),
                        }),
                    });
                }
            }

            Ok(entries)
        });

        if let Ok(mut entries) = sqlite_result {
            artifacts.append(&mut entries);
        }

        Ok(artifacts)
    }
}
