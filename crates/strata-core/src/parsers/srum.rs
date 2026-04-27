use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Maximum bytes to scan from the raw ESE data for string extraction.
/// Real SRUDB.dat files are typically 10-200 MB.
const MAX_SCAN_BYTES: usize = 4 * 1024 * 1024;

pub struct SrumParser;

impl Default for SrumParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SrumParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SrumEntry {
    pub app_id: String,
    pub app_name: Option<String>,
    pub user_id: String,
    pub session_id: Option<String>,
    pub start_time: Option<i64>,
    pub end_time: Option<i64>,
    pub foreground_time: Option<i64>,
    pub background_time: Option<i64>,
    pub usage_count: i32,
}

impl ArtifactParser for SrumParser {
    fn name(&self) -> &str {
        "Windows SRUM Deep Parser"
    }

    fn artifact_type(&self) -> &str {
        "srum"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["SRUDB.dat", "srumdb.dat", "SRUMDB.DAT"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let source = path.to_string_lossy().to_string();
        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let filename_lower = filename.to_lowercase();

        if !filename_lower.contains("srudb") && !filename_lower.contains("srum") {
            return Ok(Vec::new());
        }

        let mut artifacts = Vec::new();

        if data.len() < 668 {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "srum".to_string(),
                description: format!(
                    "SRUM database detected but too small to parse ({} bytes): {}",
                    data.len(),
                    filename
                ),
                source_path: source,
                json_data: serde_json::json!({
                    "file_name": filename,
                    "file_size": data.len(),
                    "forensic_value": "Critical",
                }),
            });
            return Ok(artifacts);
        }

        let scan_len = data.len().min(MAX_SCAN_BYTES);
        let scan_data = &data[..scan_len];

        // ESE header fields
        let page_size = read_u32_le(data, 236).unwrap_or(0);
        let db_state = read_u32_le(data, 344).unwrap_or(0);
        let state_name = match db_state {
            1 => "JustCreated",
            2 => "DirtyShutdown",
            3 => "CleanShutdown",
            4 => "BeingConverted",
            5 => "ForceDetach",
            _ => "Unknown",
        };

        // Detect which SRUM tables are present by scanning for table name strings
        let tables_found = detect_srum_tables(scan_data);

        // Extract application identifiers (EXE paths and package names)
        let app_ids = extract_app_identifiers(scan_data);

        // Extract SID patterns (S-1-5-21-... user identifiers)
        let user_sids = extract_sids(scan_data);

        // Extract network-related data patterns
        let network_indicators = extract_network_indicators(scan_data);

        // Main SRUM artifact
        artifacts.push(ParsedArtifact {
            timestamp: None,
            artifact_type: "srum".to_string(),
            description: format!(
                "CRITICAL: SRUM database ({} bytes, state={}) — {} tables detected, \
                 {} app identifiers, {} user SIDs, {} network indicators",
                data.len(),
                state_name,
                tables_found.len(),
                app_ids.len(),
                user_sids.len(),
                network_indicators.len(),
            ),
            source_path: source.clone(),
            json_data: serde_json::json!({
                "file_name": filename,
                "file_size": data.len(),
                "ese_page_size": page_size,
                "database_state": state_name,
                "scanned_bytes": scan_len,
                "tables_detected": tables_found,
                "forensic_value": "Critical",
                "forensic_note": "SRUM tracks 30 days of per-application resource usage: network bytes sent/received, CPU time, energy consumption. Even after app uninstall, historical usage data persists."
            }),
        });

        // Application Resource Usage
        if !app_ids.is_empty() {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "srum_app_usage".to_string(),
                description: format!(
                    "SRUM Application Usage: {} applications identified in resource tracking",
                    app_ids.len()
                ),
                source_path: source.clone(),
                json_data: serde_json::json!({
                    "application_count": app_ids.len(),
                    "applications": app_ids,
                    "forensic_note": "Applications tracked by SRUM — includes CPU time, memory usage, and foreground/background execution time per app. Persists after app deletion."
                }),
            });
        }

        // Network Usage
        if tables_found.contains(&"NetworkUsage".to_string())
            || tables_found.contains(&"NetworkConnections".to_string())
        {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "srum_network_usage".to_string(),
                description: format!(
                    "SRUM Network Usage: {} network indicators (bytes sent/received per app tracked)",
                    network_indicators.len()
                ),
                source_path: source.clone(),
                json_data: serde_json::json!({
                    "network_indicators": network_indicators,
                    "tables_present": {
                        "NetworkUsage": tables_found.contains(&"NetworkUsage".to_string()),
                        "NetworkConnections": tables_found.contains(&"NetworkConnections".to_string()),
                    },
                    "forensic_note": "SRUM NetworkUsage table records bytes sent and received per application per interface. Invaluable for detecting data exfiltration — shows which app transferred how much data over which network interface."
                }),
            });
        }

        // Energy Usage
        if tables_found.contains(&"EnergyUsage".to_string()) {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "srum_energy_usage".to_string(),
                description: "SRUM Energy Usage table detected — per-app battery/power consumption tracked".to_string(),
                source_path: source.clone(),
                json_data: serde_json::json!({
                    "table_present": true,
                    "forensic_note": "Energy Usage table tracks per-application power consumption. Can identify apps that were actively running (high energy use = active foreground execution) vs. background processes."
                }),
            });
        }

        // User SIDs
        if !user_sids.is_empty() {
            artifacts.push(ParsedArtifact {
                timestamp: None,
                artifact_type: "srum_user_sids".to_string(),
                description: format!(
                    "SRUM User SIDs: {} unique user identifiers in resource tracking",
                    user_sids.len()
                ),
                source_path: source,
                json_data: serde_json::json!({
                    "user_sid_count": user_sids.len(),
                    "user_sids": user_sids,
                    "forensic_note": "Windows SIDs identify which user accounts had app usage tracked. Cross-reference with registry SAM hive to map SID → username."
                }),
            });
        }

        Ok(artifacts)
    }
}

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
}

/// Detect which SRUM tables exist by scanning for known table name strings.
fn detect_srum_tables(data: &[u8]) -> Vec<String> {
    let known_tables = [
        "SruDbIdMapTable",
        "AppRuntime",
        "AppTimeline",
        "NetworkUsage",
        "NetworkConnections",
        "EnergyUsage",
        "EnergyEstimator",
        "StorageUsage",
        "WindowsPushNotifications",
        "ApplicationTimeline",
    ];

    let mut found = Vec::new();
    for name in &known_tables {
        if find_ascii(data, name.as_bytes()) {
            found.push(name.to_string());
        }
    }
    found
}

fn find_ascii(data: &[u8], needle: &[u8]) -> bool {
    data.windows(needle.len()).any(|w| w == needle)
}

/// Extract application identifiers (EXE paths, package names).
fn extract_app_identifiers(data: &[u8]) -> Vec<String> {
    let mut apps = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Scan for .exe paths
    let mut i = 0;
    while i + 4 < data.len() && apps.len() < 500 {
        if data[i].is_ascii_alphabetic() && data[i + 1] == b':' && data[i + 2] == b'\\' {
            let start = i;
            let mut end = i + 3;
            while end < data.len()
                && (data[end].is_ascii_alphanumeric()
                    || data[end] == b'\\'
                    || data[end] == b'.'
                    || data[end] == b'-'
                    || data[end] == b'_'
                    || data[end] == b' '
                    || data[end] == b'('
                    || data[end] == b')')
            {
                end += 1;
            }
            if end - start >= 8 {
                let path_str = String::from_utf8_lossy(&data[start..end]).to_string();
                let lower = path_str.to_lowercase();
                if (lower.ends_with(".exe")
                    || lower.contains("\\windows\\")
                    || lower.contains("\\program files"))
                    && seen.insert(path_str.clone())
                {
                    apps.push(path_str);
                }
            }
            i = end;
        } else {
            i += 1;
        }
    }
    apps
}

/// Extract Windows SIDs from the data (S-1-5-21-...).
fn extract_sids(data: &[u8]) -> Vec<String> {
    let mut sids = Vec::new();
    let text = String::from_utf8_lossy(&data[..data.len().min(MAX_SCAN_BYTES)]);

    let pattern = "S-1-5-21-";
    let mut search_from = 0;
    while let Some(pos) = text[search_from..].find(pattern) {
        let abs_pos = search_from + pos;
        let mut end = abs_pos + pattern.len();
        while end < text.len()
            && (text.as_bytes()[end].is_ascii_digit() || text.as_bytes()[end] == b'-')
        {
            end += 1;
        }
        let sid = &text[abs_pos..end];
        if sid.len() >= 20 && !sids.contains(&sid.to_string()) {
            sids.push(sid.to_string());
        }
        if sids.len() >= 50 {
            break;
        }
        search_from = end;
    }
    sids
}

/// Extract network-related indicators (interface names, SSIDs).
fn extract_network_indicators(data: &[u8]) -> Vec<String> {
    let mut indicators = Vec::new();
    let text = String::from_utf8_lossy(&data[..data.len().min(MAX_SCAN_BYTES)]);

    // Look for network interface identifiers
    let patterns = [
        "Wi-Fi",
        "Ethernet",
        "Bluetooth",
        "Local Area Connection",
        "Wireless Network Connection",
        "wlan",
    ];
    for pat in &patterns {
        if text.contains(pat) && !indicators.contains(&pat.to_string()) {
            indicators.push(pat.to_string());
        }
    }

    // Look for SSID-like strings near "Wi-Fi" markers
    let wifi_pattern = "Wi-Fi";
    if let Some(pos) = text.find(wifi_pattern) {
        let context_end = (pos + 200).min(text.len());
        let context = &text[pos..context_end];
        // Just note that Wi-Fi data is present
        if !indicators.contains(&format!("wifi_context_at_offset_{}", pos)) {
            indicators.push(format!("wifi_data_present_at_offset_{}", pos));
        }
        let _ = context; // used for the offset marker above
    }

    indicators
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_srudb() -> Vec<u8> {
        let mut data = vec![0u8; 8192];

        // ESE header — page size at offset 236
        data[236..240].copy_from_slice(&4096u32.to_le_bytes());
        // Database state at offset 344 = DirtyShutdown (2)
        data[344..348].copy_from_slice(&2u32.to_le_bytes());

        // Embed SRUM table names
        let tables = [
            b"SruDbIdMapTable" as &[u8],
            b"AppRuntime",
            b"NetworkUsage",
            b"NetworkConnections",
            b"EnergyUsage",
        ];
        let mut offset = 1000;
        for table in &tables {
            data[offset..offset + table.len()].copy_from_slice(table);
            offset += table.len() + 20;
        }

        // Embed app identifiers
        let app1 = b"C:\\Program Files\\Mozilla Firefox\\firefox.exe";
        data[3000..3000 + app1.len()].copy_from_slice(app1);
        let app2 = b"C:\\Windows\\System32\\svchost.exe";
        data[3200..3200 + app2.len()].copy_from_slice(app2);
        let app3 = b"C:\\Users\\suspect\\AppData\\Local\\tor.exe";
        data[3400..3400 + app3.len()].copy_from_slice(app3);

        // Embed a SID
        let sid = b"S-1-5-21-1234567890-9876543210-1111111111-1001";
        data[4000..4000 + sid.len()].copy_from_slice(sid);

        // Embed a network indicator
        let wifi = b"Wi-Fi";
        data[5000..5000 + wifi.len()].copy_from_slice(wifi);
        let eth = b"Ethernet";
        data[5100..5100 + eth.len()].copy_from_slice(eth);

        data
    }

    #[test]
    fn parses_srum_header_and_detects_tables() {
        let parser = SrumParser::new();
        let data = make_srudb();
        let path = Path::new("/evidence/C/Windows/System32/sru/SRUDB.dat");
        let result = parser.parse_file(path, &data).unwrap();
        assert!(!result.is_empty());
        let main = &result[0];
        assert!(main.description.contains("CRITICAL"));
        assert!(main.description.contains("DirtyShutdown"));

        let tables = main.json_data["tables_detected"].as_array().unwrap();
        assert!(tables.iter().any(|t| t == "NetworkUsage"));
        assert!(tables.iter().any(|t| t == "EnergyUsage"));
        assert!(tables.iter().any(|t| t == "AppRuntime"));
    }

    #[test]
    fn extracts_app_identifiers() {
        let parser = SrumParser::new();
        let data = make_srudb();
        let path = Path::new("/evidence/SRUDB.dat");
        let result = parser.parse_file(path, &data).unwrap();
        let app_artifact = result.iter().find(|a| a.artifact_type == "srum_app_usage");
        assert!(app_artifact.is_some());
        let apps = app_artifact.unwrap().json_data["applications"]
            .as_array()
            .unwrap();
        assert!(apps
            .iter()
            .any(|a| a.as_str().unwrap().contains("firefox.exe")));
        assert!(apps
            .iter()
            .any(|a| a.as_str().unwrap().contains("svchost.exe")));
        assert!(apps.iter().any(|a| a.as_str().unwrap().contains("tor.exe")));
    }

    #[test]
    fn extracts_user_sids() {
        let parser = SrumParser::new();
        let data = make_srudb();
        let path = Path::new("/evidence/SRUDB.dat");
        let result = parser.parse_file(path, &data).unwrap();
        let sid_artifact = result.iter().find(|a| a.artifact_type == "srum_user_sids");
        assert!(sid_artifact.is_some());
        let sids = sid_artifact.unwrap().json_data["user_sids"]
            .as_array()
            .unwrap();
        assert!(sids
            .iter()
            .any(|s| s.as_str().unwrap().starts_with("S-1-5-21-")));
    }

    #[test]
    fn generates_network_usage_artifact_when_table_present() {
        let parser = SrumParser::new();
        let data = make_srudb();
        let path = Path::new("/evidence/SRUDB.dat");
        let result = parser.parse_file(path, &data).unwrap();
        let net_artifact = result
            .iter()
            .find(|a| a.artifact_type == "srum_network_usage");
        assert!(net_artifact.is_some());
        assert!(net_artifact.unwrap().json_data["tables_present"]["NetworkUsage"] == true);
    }

    #[test]
    fn generates_energy_usage_artifact_when_table_present() {
        let parser = SrumParser::new();
        let data = make_srudb();
        let path = Path::new("/evidence/SRUDB.dat");
        let result = parser.parse_file(path, &data).unwrap();
        let energy_artifact = result
            .iter()
            .find(|a| a.artifact_type == "srum_energy_usage");
        assert!(energy_artifact.is_some());
    }

    #[test]
    fn detects_network_interfaces() {
        let parser = SrumParser::new();
        let data = make_srudb();
        let path = Path::new("/evidence/SRUDB.dat");
        let result = parser.parse_file(path, &data).unwrap();
        let net_artifact = result
            .iter()
            .find(|a| a.artifact_type == "srum_network_usage")
            .unwrap();
        let indicators = net_artifact.json_data["network_indicators"]
            .as_array()
            .unwrap();
        assert!(indicators
            .iter()
            .any(|i| i.as_str().unwrap().contains("Wi-Fi")));
        assert!(indicators
            .iter()
            .any(|i| i.as_str().unwrap().contains("Ethernet")));
    }

    #[test]
    fn skips_non_srudb_filename() {
        let parser = SrumParser::new();
        let data = vec![0u8; 1024];
        let path = Path::new("/evidence/random.dat");
        let result = parser.parse_file(path, &data).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn handles_undersized_file() {
        let parser = SrumParser::new();
        let data = vec![0u8; 100];
        let path = Path::new("/evidence/SRUDB.dat");
        let result = parser.parse_file(path, &data).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].description.contains("too small"));
    }
}
