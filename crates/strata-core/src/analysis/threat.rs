use crate::errors::ForensicError;
use crate::parser::ParsedArtifact;
use regex::Regex;

#[derive(Debug, Clone, Default)]
pub struct ThreatIndicator {
    pub indicator_type: IndicatorType,
    pub value: String,
    pub confidence: f32,
    pub source: String,
}

#[derive(Debug, Clone, Default)]
pub enum IndicatorType {
    #[default]
    Hash,
    IpAddress,
    Domain,
    Url,
    FilePath,
    Registry,
    Process,
}

/// Analyze parsed artifacts for threat indicators using behavioral heuristics,
/// path-based detection, and MITRE ATT&CK technique correlation.
pub fn analyze_threat_indicators(
    artifacts: &[ParsedArtifact],
) -> Result<ThreatAnalysis, ForensicError> {
    let mut indicators = Vec::new();

    for artifact in artifacts {
        let json_str = artifact.json_data.to_string();
        let desc_lower = artifact.description.to_lowercase();
        let source_lower = artifact.source_path.to_lowercase();

        // File path-based indicators
        for (pattern, indicator_name, confidence) in SUSPICIOUS_PATH_PATTERNS {
            if source_lower.contains(pattern) || json_str.to_lowercase().contains(pattern) {
                indicators.push(ThreatIndicator {
                    indicator_type: IndicatorType::FilePath,
                    value: indicator_name.to_string(),
                    confidence: *confidence,
                    source: artifact.source_path.clone(),
                });
            }
        }

        // Process/execution indicators
        for (keyword, indicator_name, confidence) in SUSPICIOUS_EXECUTION_PATTERNS {
            if desc_lower.contains(keyword) || json_str.to_lowercase().contains(keyword) {
                indicators.push(ThreatIndicator {
                    indicator_type: IndicatorType::Process,
                    value: indicator_name.to_string(),
                    confidence: *confidence,
                    source: artifact.source_path.clone(),
                });
            }
        }

        // Registry persistence indicators
        if artifact.artifact_type == "registry" || artifact.artifact_type == "persistence" {
            for (pattern, indicator_name, confidence) in PERSISTENCE_REGISTRY_PATTERNS {
                if json_str.to_lowercase().contains(pattern) {
                    indicators.push(ThreatIndicator {
                        indicator_type: IndicatorType::Registry,
                        value: indicator_name.to_string(),
                        confidence: *confidence,
                        source: artifact.source_path.clone(),
                    });
                }
            }
        }

        // Network indicators: extract IPs, domains, URLs
        extract_network_indicators(&json_str, &artifact.source_path, &mut indicators);
    }

    // Deduplicate indicators by value
    indicators.sort_by(|a, b| a.value.cmp(&b.value));
    indicators.dedup_by(|a, b| a.value == b.value && a.source == b.source);

    let risk_score = calculate_risk_from_indicators(&indicators);

    Ok(ThreatAnalysis {
        indicators,
        risk_score,
    })
}

#[derive(Debug, Clone, Default)]
pub struct ThreatAnalysis {
    pub indicators: Vec<ThreatIndicator>,
    pub risk_score: f32,
}

/// Check raw byte data for known malware signatures (magic bytes, PE anomalies, etc.)
pub fn check_malware_signatures(data: &[u8]) -> Result<Vec<MalwareMatch>, ForensicError> {
    let mut matches = Vec::new();

    if data.len() < 4 {
        return Ok(matches);
    }

    // Check for PE files with suspicious characteristics
    if data.len() > 64 && data[0] == 0x4D && data[1] == 0x5A {
        // MZ header — PE file
        let pe_offset = if data.len() > 0x3C + 4 {
            u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize
        } else {
            0
        };

        if pe_offset > 0
            && pe_offset + 6 < data.len()
            && &data[pe_offset..pe_offset + 4] == b"PE\x00\x00"
        {
            // Valid PE — check for packed/encrypted sections
            let section_count =
                u16::from_le_bytes([data[pe_offset + 6], data[pe_offset + 7]]) as usize;

            if section_count > 20 {
                matches.push(MalwareMatch {
                    signature_name: "Suspicious PE: excessive section count".to_string(),
                    match_offset: pe_offset as u64,
                    confidence: 0.6,
                });
            }

            // Check for UPX packer signature
            if data.windows(3).any(|w| w == b"UPX") {
                matches.push(MalwareMatch {
                    signature_name: "UPX packed executable".to_string(),
                    match_offset: 0,
                    confidence: 0.5,
                });
            }
        }
    }

    // Encoded PowerShell detection
    for sig in ENCODED_POWERSHELL_SIGS {
        if let Some(pos) = find_bytes(data, sig.as_bytes()) {
            matches.push(MalwareMatch {
                signature_name: format!("Encoded PowerShell: {}", sig),
                match_offset: pos as u64,
                confidence: 0.85,
            });
        }
    }

    // Shellcode signatures (common NOP sleds, egg hunters)
    if data.len() > 100 {
        // NOP sled detection (16+ consecutive 0x90 bytes)
        let mut nop_count = 0;
        for (i, &byte) in data.iter().enumerate() {
            if byte == 0x90 {
                nop_count += 1;
                if nop_count >= 16 {
                    matches.push(MalwareMatch {
                        signature_name: "Possible NOP sled (shellcode)".to_string(),
                        match_offset: (i - nop_count + 1) as u64,
                        confidence: 0.4,
                    });
                    break;
                }
            } else {
                nop_count = 0;
            }
        }
    }

    // Known malicious strings
    for (sig, name, confidence) in MALWARE_STRING_SIGS {
        if let Some(pos) = find_bytes(data, sig.as_bytes()) {
            matches.push(MalwareMatch {
                signature_name: name.to_string(),
                match_offset: pos as u64,
                confidence: *confidence,
            });
        }
    }

    Ok(matches)
}

#[derive(Debug, Clone, Default)]
pub struct MalwareMatch {
    pub signature_name: String,
    pub match_offset: u64,
    pub confidence: f32,
}

/// Analyze parsed artifacts for suspicious behavioral patterns
pub fn analyze_behavior(artifacts: &[ParsedArtifact]) -> Result<BehaviorReport, ForensicError> {
    let mut behaviors = Vec::new();

    // Collect artifact sources for correlation
    let mut execution_artifacts = Vec::new();
    let mut persistence_artifacts = Vec::new();
    let mut network_artifacts = Vec::new();
    let mut credential_artifacts = Vec::new();
    let mut exfiltration_artifacts = Vec::new();

    for artifact in artifacts {
        let desc_lower = artifact.description.to_lowercase();
        let json_str = artifact.json_data.to_string().to_lowercase();

        // Categorize artifacts
        if desc_lower.contains("powershell")
            || desc_lower.contains("cmd.exe")
            || desc_lower.contains("wscript")
            || desc_lower.contains("cscript")
            || desc_lower.contains("mshta")
            || desc_lower.contains("rundll32")
            || desc_lower.contains("regsvr32")
        {
            execution_artifacts.push(artifact.description.clone());
        }

        if artifact.artifact_type == "persistence"
            || desc_lower.contains("run key")
            || desc_lower.contains("startup")
            || desc_lower.contains("scheduled task")
            || desc_lower.contains("service")
        {
            persistence_artifacts.push(artifact.description.clone());
        }

        if desc_lower.contains("rdp")
            || desc_lower.contains("ssh")
            || desc_lower.contains("remote")
            || desc_lower.contains("psexec")
            || desc_lower.contains("wmi")
        {
            network_artifacts.push(artifact.description.clone());
        }

        if desc_lower.contains("credential")
            || desc_lower.contains("password")
            || desc_lower.contains("mimikatz")
            || desc_lower.contains("lsass")
            || desc_lower.contains("sam")
            || desc_lower.contains("ntds")
        {
            credential_artifacts.push(artifact.description.clone());
        }

        if desc_lower.contains("usb")
            || desc_lower.contains("removable")
            || json_str.contains("cloud")
            || desc_lower.contains("upload")
            || desc_lower.contains("exfil")
        {
            exfiltration_artifacts.push(artifact.description.clone());
        }
    }

    // Generate behavioral assessments

    if !execution_artifacts.is_empty() {
        behaviors.push(SuspiciousBehavior {
            behavior_type: "T1059 — Command and Scripting Interpreter".to_string(),
            description: format!(
                "Detected {} execution artifacts involving scripting interpreters",
                execution_artifacts.len()
            ),
            artifacts: execution_artifacts
                .into_iter()
                .take(10)
                .collect(),
        });
    }

    if !persistence_artifacts.is_empty() {
        behaviors.push(SuspiciousBehavior {
            behavior_type: "T1547 — Boot or Logon Autostart Execution".to_string(),
            description: format!(
                "Detected {} persistence mechanisms",
                persistence_artifacts.len()
            ),
            artifacts: persistence_artifacts
                .into_iter()
                .take(10)
                .collect(),
        });
    }

    if !network_artifacts.is_empty() {
        behaviors.push(SuspiciousBehavior {
            behavior_type: "T1021 — Remote Services".to_string(),
            description: format!(
                "Detected {} remote access artifacts",
                network_artifacts.len()
            ),
            artifacts: network_artifacts
                .into_iter()
                .take(10)
                .collect(),
        });
    }

    if !credential_artifacts.is_empty() {
        behaviors.push(SuspiciousBehavior {
            behavior_type: "T1003 — OS Credential Dumping".to_string(),
            description: format!(
                "Detected {} credential access artifacts",
                credential_artifacts.len()
            ),
            artifacts: credential_artifacts
                .into_iter()
                .take(10)
                .collect(),
        });
    }

    if !exfiltration_artifacts.is_empty() {
        behaviors.push(SuspiciousBehavior {
            behavior_type: "T1052 — Exfiltration Over Physical Medium".to_string(),
            description: format!(
                "Detected {} potential data exfiltration artifacts",
                exfiltration_artifacts.len()
            ),
            artifacts: exfiltration_artifacts
                .into_iter()
                .take(10)
                .collect(),
        });
    }

    let risk_level = match behaviors.len() {
        0 => RiskLevel::Low,
        1..=2 => RiskLevel::Medium,
        3..=4 => RiskLevel::High,
        _ => RiskLevel::Critical,
    };

    Ok(BehaviorReport {
        suspicious_behaviors: behaviors,
        risk_level,
    })
}

#[derive(Debug, Clone, Default)]
pub struct BehaviorReport {
    pub suspicious_behaviors: Vec<SuspiciousBehavior>,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, Default)]
pub enum RiskLevel {
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Default)]
pub struct SuspiciousBehavior {
    pub behavior_type: String,
    pub description: String,
    pub artifacts: Vec<String>,
}

/// Calculate aggregate risk score from parsed artifacts
pub fn calculate_risk_score(artifacts: &[ParsedArtifact]) -> f32 {
    let mut score: f32 = 0.0;

    for artifact in artifacts {
        let desc_lower = artifact.description.to_lowercase();

        // Weight by artifact type and content
        if desc_lower.contains("mimikatz") || desc_lower.contains("cobalt strike") {
            score += 25.0;
        }
        if desc_lower.contains("[critical]") {
            score += 15.0;
        }
        if desc_lower.contains("[high]") {
            score += 10.0;
        }
        if desc_lower.contains("timestomp") || desc_lower.contains("anti_forensics") {
            score += 12.0;
        }
        if desc_lower.contains("persistence") || desc_lower.contains("autostart") {
            score += 8.0;
        }
        if desc_lower.contains("encoded powershell") || desc_lower.contains("-encodedcommand") {
            score += 15.0;
        }
        if desc_lower.contains("rdp") && desc_lower.contains("lateral") {
            score += 10.0;
        }
        if artifact.artifact_type == "ssh_authorized_key" && desc_lower.contains("forced_command") {
            score += 5.0;
        }
        if artifact.artifact_type == "timestomp_anomaly" {
            score += 10.0;
        }
    }

    // Normalize to 0-100 range
    score.min(100.0)
}

// ---------------------------------------------------------------------------
// Threat intelligence pattern databases
// ---------------------------------------------------------------------------

/// Suspicious file paths that indicate malware staging or tool deployment
/// (pattern, indicator_name, confidence)
const SUSPICIOUS_PATH_PATTERNS: &[(&str, &str, f32)] = &[
    ("\\temp\\", "File in temp directory", 0.3),
    ("\\appdata\\local\\temp\\", "File in user temp", 0.4),
    ("\\windows\\temp\\", "File in system temp", 0.5),
    ("\\programdata\\", "File in ProgramData", 0.3),
    ("\\recycle", "File in Recycle Bin area", 0.3),
    ("\\public\\", "File in Public directory", 0.4),
    ("\\perflogs\\", "File in PerfLogs (common staging)", 0.7),
    ("c:\\intel\\", "File in C:\\Intel (malware staging)", 0.8),
    ("c:\\recovery\\", "File in C:\\Recovery (hidden exec)", 0.6),
    ("\\sysvol\\", "File in SYSVOL (domain-wide persistence)", 0.7),
    ("\\debug\\wia\\", "File in Debug\\WIA (T1036)", 0.8),
    ("/tmp/", "File in Unix /tmp", 0.3),
    ("/dev/shm/", "File in /dev/shm (memory-only exec)", 0.8),
    ("/var/tmp/", "File in /var/tmp", 0.4),
    ("\\users\\default\\", "File in Default user profile", 0.5),
    ("\\windows\\fonts\\", "EXE in Fonts directory (T1036)", 0.7),
    ("\\windows\\help\\", "File in Windows Help (staging)", 0.6),
    ("\\windows\\addins\\", "File in Windows Addins", 0.6),
    ("\\windows\\ime\\", "File in Windows IME (rare, suspicious)", 0.7),
];

/// Suspicious execution patterns in artifact descriptions
const SUSPICIOUS_EXECUTION_PATTERNS: &[(&str, &str, f32)] = &[
    ("powershell -e", "Encoded PowerShell execution", 0.85),
    ("powershell -enc", "Encoded PowerShell execution", 0.85),
    ("-encodedcommand", "Encoded PowerShell execution", 0.9),
    ("invoke-mimikatz", "Mimikatz execution (T1003)", 0.95),
    ("invoke-expression", "PowerShell IEX (download cradle)", 0.7),
    ("downloadstring", "PowerShell download cradle", 0.8),
    ("net.webclient", "PowerShell download cradle", 0.7),
    ("mshta.exe", "MSHTA execution (T1218.005)", 0.7),
    ("certutil -urlcache", "CertUtil download (T1105)", 0.8),
    ("certutil -decode", "CertUtil decode (T1140)", 0.7),
    ("bitsadmin /transfer", "BITS transfer (T1197)", 0.6),
    ("psexec", "PsExec lateral movement (T1021)", 0.7),
    ("wmic process", "WMI process creation (T1047)", 0.6),
    ("schtasks /create", "Scheduled task creation (T1053)", 0.5),
    ("reg add", "Registry modification", 0.3),
    ("vssadmin delete", "VSS deletion (T1490, ransomware)", 0.9),
    ("bcdedit /set", "Boot config modification (T1490)", 0.8),
    ("wbadmin delete", "Backup deletion (T1490)", 0.9),
    ("ntdsutil", "NTDS.dit access (T1003.003)", 0.9),
    ("procdump", "Process dumping (T1003.001)", 0.8),
    ("mimikatz", "Mimikatz tool (T1003)", 0.95),
    ("cobalt strike", "Cobalt Strike C2 framework", 0.95),
    ("meterpreter", "Metasploit Meterpreter", 0.95),
    ("empire", "PowerShell Empire C2", 0.7),
    ("covenant", "Covenant C2 framework", 0.8),
    ("rubeus", "Rubeus Kerberos tool (T1558)", 0.9),
    ("sharphound", "BloodHound collector (T1087)", 0.9),
    ("bloodhound", "BloodHound AD recon", 0.8),
    ("lazagne", "LaZagne credential harvester", 0.9),
    ("pypykatz", "Pypykatz credential dumper", 0.9),
];

/// Registry paths associated with persistence mechanisms
const PERSISTENCE_REGISTRY_PATTERNS: &[(&str, &str, f32)] = &[
    ("currentversion\\run", "Run key persistence (T1547.001)", 0.6),
    ("currentversion\\runonce", "RunOnce persistence (T1547.001)", 0.6),
    (
        "winlogon\\shell",
        "Winlogon shell hijack (T1547.004)",
        0.8,
    ),
    (
        "winlogon\\userinit",
        "Winlogon Userinit hijack (T1547.004)",
        0.8,
    ),
    (
        "image file execution",
        "IFEO debugger persistence (T1546.012)",
        0.7,
    ),
    (
        "appinit_dlls",
        "AppInit DLL injection (T1546.010)",
        0.8,
    ),
    (
        "servicedll",
        "Service DLL modification (T1543.003)",
        0.7,
    ),
    (
        "security\\policy\\secrets",
        "LSA secrets access (T1003.004)",
        0.9,
    ),
    ("sam\\domains", "SAM database access (T1003.002)", 0.8),
    (
        "classes\\clsid",
        "COM object hijacking (T1546.015)",
        0.5,
    ),
];

/// Encoded PowerShell signatures to detect in binary data
const ENCODED_POWERSHELL_SIGS: &[&str] = &[
    "-EncodedCommand",
    "-encodedcommand",
    "-enc ",
    "-EC ",
    "FromBase64String",
    "Convert]::FromBase64",
    "IEX(",
    "Invoke-Expression",
    "New-Object Net.WebClient",
    "DownloadString(",
    "DownloadFile(",
    "Start-BitsTransfer",
    "Invoke-WebRequest",
    "[System.Reflection.Assembly]::Load",
];

/// Known malicious string signatures
/// (signature, name, confidence)
const MALWARE_STRING_SIGS: &[(&str, &str, f32)] = &[
    ("This program cannot be run in DOS mode", "PE executable", 0.1),
    ("ReflectiveLoader", "Reflective DLL injection", 0.9),
    ("beacon.dll", "Cobalt Strike beacon", 0.95),
    ("beacon.x64.dll", "Cobalt Strike x64 beacon", 0.95),
    ("meterpreter", "Metasploit Meterpreter", 0.9),
    ("WinHTTP.WinHTTPRequest", "HTTP downloader component", 0.5),
    ("COMSPEC", "Shell execution via COMSPEC", 0.3),
    ("ShellExecute", "Shell execution API", 0.2),
    ("VirtualAlloc", "Memory allocation (potential shellcode)", 0.2),
    ("CreateRemoteThread", "Remote thread injection", 0.6),
    ("NtCreateThreadEx", "Native API thread creation", 0.7),
    ("WriteProcessMemory", "Process memory write (injection)", 0.5),
];

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn extract_network_indicators(
    text: &str,
    source: &str,
    indicators: &mut Vec<ThreatIndicator>,
) {
    // IPv4 extraction
    if let Ok(re) = Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b") {
        for cap in re.captures_iter(text) {
            let ip = &cap[1];
            // Skip private/localhost IPs
            if !ip.starts_with("10.")
                && !ip.starts_with("192.168.")
                && !ip.starts_with("172.")
                && !ip.starts_with("127.")
                && !ip.starts_with("0.")
                && ip != "255.255.255.255"
            {
                // Validate octets
                let octets: Vec<u32> = ip.split('.').filter_map(|o| o.parse().ok()).collect();
                if octets.len() == 4 && octets.iter().all(|&o| o <= 255) {
                    indicators.push(ThreatIndicator {
                        indicator_type: IndicatorType::IpAddress,
                        value: ip.to_string(),
                        confidence: 0.3,
                        source: source.to_string(),
                    });
                }
            }
        }
    }
}

fn calculate_risk_from_indicators(indicators: &[ThreatIndicator]) -> f32 {
    if indicators.is_empty() {
        return 0.0;
    }

    let sum: f32 = indicators.iter().map(|i| i.confidence * 10.0).sum();
    (sum / indicators.len() as f32).min(100.0)
}
