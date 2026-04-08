use std::collections::HashSet;
use std::path::Path;
use strata_plugin_sdk::{
    Artifact, ArtifactCategory, ArtifactRecord, ForensicValue, PluginCapability, PluginContext,
    PluginError, PluginOutput, PluginResult, PluginSummary, PluginType, StrataPlugin,
};

pub struct VectorPlugin {
    name: String,
    version: String,
}

impl Default for VectorPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl VectorPlugin {
    pub fn new() -> Self {
        Self {
            name: "Strata Vector".to_string(),
            version: "1.0.0".to_string(),
        }
    }

    /// Suspicious import strings that indicate process injection or crypto usage.
    const SUSPICIOUS_IMPORTS: &'static [&'static str] = &[
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "CryptEncrypt",
        "WSAStartup",
    ];

    /// Known malware-related strings.
    const MALWARE_STRINGS: &'static [&'static str] = &[
        "mimikatz", "meterpreter", "cobalt strike", "beacon", "bloodhound", "rubeus",
    ];

    /// Suspicious script indicators.
    const SCRIPT_INDICATORS: &'static [&'static str] = &[
        "-EncodedCommand",
        "-encodedcommand",
        "-enc ",
        "IEX",
        "Invoke-Expression",
        "DownloadString",
        "DownloadFile",
        "-WindowStyle Hidden",
        "-windowstyle hidden",
        "certutil -decode",
        "certutil.exe -decode",
        "FromBase64String",
        "Net.WebClient",
        "Start-Process",
        "Invoke-WebRequest",
    ];

    fn analyze_pe(path: &Path, name: &str, data: &[u8]) -> Vec<Artifact> {
        let mut results = Vec::new();
        let path_str = path.to_string_lossy();

        // Check MZ header
        if data.len() < 64 || data[0] != b'M' || data[1] != b'Z' {
            return results;
        }

        let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;

        let mut flags = Vec::new();

        // Check PE timestamp
        let ts_offset = e_lfanew + 8;
        if ts_offset + 4 <= data.len() {
            let compile_ts = u32::from_le_bytes([
                data[ts_offset],
                data[ts_offset + 1],
                data[ts_offset + 2],
                data[ts_offset + 3],
            ]);
            let is_future = compile_ts > 1_901_232_000;
            let is_ancient = compile_ts < 946_684_800;
            if is_future {
                flags.push(format!("FUTURE PE timestamp (epoch {})", compile_ts));
            } else if is_ancient {
                flags.push(format!("ANCIENT PE timestamp (epoch {})", compile_ts));
            }
        }

        // Scan first 4KB for suspicious imports
        let scan_len = data.len().min(4096);
        let scan_region = &data[..scan_len];
        let scan_text = String::from_utf8_lossy(scan_region);
        let mut found_imports = Vec::new();
        for imp in Self::SUSPICIOUS_IMPORTS {
            if scan_text.contains(imp) {
                found_imports.push(*imp);
            }
        }
        if !found_imports.is_empty() {
            flags.push(format!("Suspicious imports: {}", found_imports.join(", ")));
        }

        let is_flagged = !flags.is_empty();

        let mut artifact = Artifact::new("ExecutionHistory", &path_str);
        artifact.add_field("title", &format!("Suspicious PE Analysis: {}", name));
        artifact.add_field("file_type", "Suspicious PE Analysis");
        artifact.add_field("detail", &if is_flagged {
            flags.join(" | ")
        } else {
            "Valid PE file — no anomalies detected in header".to_string()
        });
        if is_flagged {
            artifact.add_field("suspicious", "true");
        }
        results.push(artifact);

        results
    }

    fn analyze_ole(path: &Path, name: &str, data: &[u8]) -> Vec<Artifact> {
        let mut results = Vec::new();
        let path_str = path.to_string_lossy();

        // Check OLE2 magic: D0 CF 11 E0 A1 B1 1A E1
        if data.len() < 8 {
            return results;
        }
        let ole_magic: [u8; 4] = [0xD0, 0xCF, 0x11, 0xE0];
        if data[0..4] != ole_magic {
            return results;
        }

        // Scan for VBA/Macros strings
        let scan_len = data.len().min(262144); // 256 KB scan window
        let scan_text = String::from_utf8_lossy(&data[..scan_len]).to_lowercase();
        let has_macros = scan_text.contains("vba")
            || scan_text.contains("macros")
            || scan_text.contains("macro");

        if has_macros {
            // ── v1.1.0: deep macro indicator analysis ──
            let critical: &[(&str, &str)] = &[
                ("shell(", "T1059.005"),
                ("wscript.shell", "T1059.005"),
                ("createobject(\"wscript", "T1059.005"),
                ("createobject(\"scripting", "T1059.005"),
                ("urldownloadtofile", "T1105"),
                ("downloadfile", "T1105"),
                ("xmlhttp", "T1105"),
                ("powershell", "T1059.001"),
            ];
            let high: &[(&str, &str)] = &[
                ("auto_open", "T1204.002"),
                ("autoopen", "T1204.002"),
                ("document_open", "T1204.002"),
                ("workbook_open", "T1204.002"),
                ("environ(\"username\")", "T1033"),
                ("environ(\"computername\")", "T1082"),
            ];

            let mut critical_hits = Vec::new();
            let mut high_hits = Vec::new();
            for (kw, mitre) in critical {
                if scan_text.contains(kw) {
                    critical_hits.push(format!("{} ({})", kw, mitre));
                }
            }
            for (kw, mitre) in high {
                if scan_text.contains(kw) {
                    high_hits.push(format!("{} ({})", kw, mitre));
                }
            }

            let severity = if !critical_hits.is_empty() {
                "Critical"
            } else if high_hits.len() >= 2 {
                "High"
            } else {
                "Medium"
            };

            let mut indicators_summary = Vec::new();
            if !critical_hits.is_empty() {
                indicators_summary.push(format!("CRITICAL: {}", critical_hits.join(", ")));
            }
            if !high_hits.is_empty() {
                indicators_summary.push(format!("HIGH: {}", high_hits.join(", ")));
            }
            if indicators_summary.is_empty() {
                indicators_summary.push("VBA/Macro present (no specific indicators)".to_string());
            }

            let mut artifact = Artifact::new("ExecutionHistory", &path_str);
            artifact.add_field("title", &format!("Office Macro Detected: {}", name));
            artifact.add_field("file_type", "Office Macro Detected");
            artifact.add_field(
                "detail",
                &format!(
                    "OLE2 document with VBA/Macro content. {}",
                    indicators_summary.join(" | ")
                ),
            );
            artifact.add_field("mitre", "T1137.001");
            artifact.add_field("suspicious", "true");
            artifact.add_field("forensic_value", severity);
            results.push(artifact);
        }

        results
    }

    fn analyze_script(path: &Path, name: &str) -> Vec<Artifact> {
        let mut results = Vec::new();
        let path_str = path.to_string_lossy();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return results,
        };
        let content_lower = content.to_lowercase();

        let mut found_indicators = Vec::new();
        for indicator in Self::SCRIPT_INDICATORS {
            if content.contains(indicator) {
                found_indicators.push(*indicator);
            }
        }

        // ── v1.1.0: language-specific keyword detection ──
        let mut critical: Vec<(&str, &str)> = Vec::new();
        let mut high: Vec<(&str, &str)> = Vec::new();

        match ext.as_str() {
            "ps1" => {
                let ps_critical: &[(&str, &str)] = &[
                    ("invoke-mimikatz", "T1003"),
                    ("invoke-bloodhound", "T1087"),
                    ("invoke-kerberoast", "T1558.003"),
                    ("dumpcreds", "T1003"),
                    ("get-keystrokes", "T1056.001"),
                    ("invoke-shellcode", "T1059.001"),
                ];
                let ps_high: &[(&str, &str)] = &[
                    ("add-mppreference -exclusionpath", "T1562.001"),
                    ("set-mppreference -disable", "T1562.001"),
                    ("new-scheduledtask", "T1053.005"),
                    ("register-scheduledtask", "T1053.005"),
                    ("net user /add", "T1136.001"),
                    ("invoke-webrequest", "T1105"),
                    ("downloadstring", "T1105"),
                    ("downloadfile", "T1105"),
                    ("frombase64string", "T1140"),
                    ("-encodedcommand", "T1027"),
                    ("invoke-expression", "T1059.001"),
                    ("iex (", "T1059.001"),
                    ("[reflection.assembly]::load", "T1620"),
                    ("vssadmin delete shadows", "T1490"),
                    ("wevtutil cl", "T1070.001"),
                ];
                for (kw, m) in ps_critical {
                    if content_lower.contains(kw) {
                        critical.push((*kw, *m));
                    }
                }
                for (kw, m) in ps_high {
                    if content_lower.contains(kw) {
                        high.push((*kw, *m));
                    }
                }
            }
            "vbs" => {
                let vbs_high: &[(&str, &str)] = &[
                    ("wscript.shell", "T1059.005"),
                    (".run(", "T1059.005"),
                    ("createobject(\"scripting.filesystemobject\")", "T1059.005"),
                    ("getobject(\"winmgmts", "T1047"),
                    ("xmlhttp", "T1105"),
                ];
                for (kw, m) in vbs_high {
                    if content_lower.contains(kw) {
                        high.push((*kw, *m));
                    }
                }
            }
            "js" => {
                let js_high: &[(&str, &str)] = &[
                    ("wscript.shell", "T1059.007"),
                    ("activexobject", "T1059.007"),
                    (".run(", "T1059.007"),
                    ("xmlhttprequest", "T1105"),
                ];
                for (kw, m) in js_high {
                    if content_lower.contains(kw) {
                        high.push((*kw, *m));
                    }
                }
            }
            "bat" | "cmd" => {
                let bat_high: &[(&str, &str)] = &[
                    ("vssadmin delete shadows", "T1490"),
                    ("wevtutil cl", "T1070.001"),
                    ("net user /add", "T1136.001"),
                    ("netsh advfirewall set", "T1562.004"),
                    ("certutil -urlcache", "T1105"),
                    ("certutil -decode", "T1140"),
                ];
                for (kw, m) in bat_high {
                    if content_lower.contains(kw) {
                        high.push((*kw, *m));
                    }
                }
            }
            _ => {}
        }

        if !found_indicators.is_empty() || !critical.is_empty() || !high.is_empty() {
            let severity = if !critical.is_empty() {
                "Critical"
            } else if high.len() >= 2 || !found_indicators.is_empty() {
                "High"
            } else {
                "Medium"
            };
            let mut detail_parts = Vec::new();
            if !critical.is_empty() {
                let cs: Vec<String> =
                    critical.iter().map(|(k, m)| format!("{} ({})", k, m)).collect();
                detail_parts.push(format!("CRITICAL: {}", cs.join(", ")));
            }
            if !high.is_empty() {
                let hs: Vec<String> =
                    high.iter().map(|(k, m)| format!("{} ({})", k, m)).collect();
                detail_parts.push(format!("HIGH: {}", hs.join(", ")));
            }
            if !found_indicators.is_empty() {
                detail_parts.push(format!("Generic: {}", found_indicators.join(", ")));
            }
            let primary_mitre = critical
                .first()
                .or(high.first())
                .map(|(_, m)| m.to_string())
                .unwrap_or_else(|| "T1059".to_string());

            let mut artifact = Artifact::new("ExecutionHistory", &path_str);
            artifact.add_field("title", &format!("Suspicious Script: {}", name));
            artifact.add_field("file_type", "Suspicious Script");
            artifact.add_field("detail", &detail_parts.join(" | "));
            artifact.add_field("suspicious", "true");
            artifact.add_field("forensic_value", severity);
            artifact.add_field("mitre", &primary_mitre);
            results.push(artifact);
        }

        results
    }

    fn scan_for_malware_strings(path: &Path, name: &str, data: &[u8]) -> Vec<Artifact> {
        let mut results = Vec::new();
        let path_str = path.to_string_lossy();

        let scan_text = String::from_utf8_lossy(data).to_lowercase();
        let mut found = Vec::new();

        for malware in Self::MALWARE_STRINGS {
            if scan_text.contains(malware) {
                found.push(*malware);
            }
        }

        if !found.is_empty() {
            let mut artifact = Artifact::new("ExecutionHistory", &path_str);
            artifact.add_field("title", &format!("Known Malware String: {}", name));
            artifact.add_field("file_type", "Known Malware String");
            artifact.add_field("detail", &format!(
                "File contains known malware tool strings: {}",
                found.join(", ")
            ));
            artifact.add_field("suspicious", "true");
            results.push(artifact);
        }

        results
    }

    fn analyze_file(path: &Path) -> Vec<Artifact> {
        let mut results = Vec::new();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        let ext_lower = ext.to_lowercase();

        // PE analysis for .exe/.dll
        if ext_lower == "exe" || ext_lower == "dll" {
            if let Ok(data) = std::fs::read(path) {
                let read_len = data.len().min(4096);
                results.extend(Self::analyze_pe(path, name, &data[..read_len]));
                // Also scan for malware strings in first 64KB
                let malware_len = data.len().min(65536);
                results.extend(Self::scan_for_malware_strings(path, name, &data[..malware_len]));
            }
        }

        // Office document analysis
        if ext_lower == "doc" || ext_lower == "xls" || ext_lower == "ppt" {
            if let Ok(data) = std::fs::read(path) {
                results.extend(Self::analyze_ole(path, name, &data));
            }
        }

        // Script analysis
        if matches!(ext_lower.as_str(), "ps1" | "vbs" | "js" | "bat" | "cmd") {
            results.extend(Self::analyze_script(path, name));
            // Also scan script content for malware strings
            if let Ok(data) = std::fs::read(path) {
                let scan_len = data.len().min(65536);
                results.extend(Self::scan_for_malware_strings(path, name, &data[..scan_len]));
            }
        }

        // For all other files, do a malware string scan on first 4KB
        if !matches!(ext_lower.as_str(), "exe" | "dll" | "doc" | "xls" | "ppt" | "ps1" | "vbs" | "js" | "bat" | "cmd") {
            // Only scan small-to-medium files to avoid performance issues
            if let Ok(metadata) = path.metadata() {
                if metadata.len() < 1_048_576 {
                    if let Ok(data) = std::fs::read(path) {
                        let scan_len = data.len().min(4096);
                        results.extend(Self::scan_for_malware_strings(path, name, &data[..scan_len]));
                    }
                }
            }
        }

        results
    }
}

impl StrataPlugin for VectorPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn supported_inputs(&self) -> Vec<String> {
        vec!["*".to_string()]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Analyzer
    }

    fn capabilities(&self) -> Vec<PluginCapability> {
        vec![
            PluginCapability::ArtifactExtraction,
            PluginCapability::ExecutionTracking,
        ]
    }

    fn description(&self) -> &str {
        "Static malware analysis on executables and documents"
    }

    fn run(&self, ctx: PluginContext) -> PluginResult {
        let root = Path::new(&ctx.root_path);
        let mut results = Vec::new();

        if let Ok(entries) = walk_dir(root) {
            for entry_path in entries {
                results.extend(Self::analyze_file(&entry_path));
            }
        }

        Ok(results)
    }

    fn execute(&self, context: PluginContext) -> Result<PluginOutput, PluginError> {
        let start = std::time::Instant::now();
        let artifacts = self.run(context)?;

        let mut records = Vec::new();
        for artifact in &artifacts {
            let file_type = artifact.data.get("file_type").cloned().unwrap_or_default();
            let is_suspicious = artifact
                .data
                .get("suspicious")
                .map(|v| v == "true")
                .unwrap_or(false);

            let forensic_value = match file_type.as_str() {
                "Suspicious PE Analysis" => {
                    if is_suspicious { ForensicValue::Critical } else { ForensicValue::Medium }
                }
                "Office Macro Detected" => ForensicValue::Critical,
                "Suspicious Script" => ForensicValue::Critical,
                "Known Malware String" => ForensicValue::Critical,
                _ => ForensicValue::Medium,
            };

            records.push(ArtifactRecord {
                category: ArtifactCategory::ExecutionHistory,
                subcategory: file_type,
                timestamp: artifact.timestamp.map(|t| t as i64),
                title: artifact
                    .data
                    .get("title")
                    .cloned()
                    .unwrap_or_else(|| artifact.source.clone()),
                detail: artifact
                    .data
                    .get("detail")
                    .cloned()
                    .unwrap_or_default(),
                source_path: artifact.source.clone(),
                forensic_value,
                mitre_technique: artifact.data.get("mitre").cloned(),
                is_suspicious,
                raw_data: None,
            });
        }

        let suspicious_count = records.iter().filter(|r| r.is_suspicious).count();
        let categories: Vec<String> = records
            .iter()
            .map(|r| r.category.as_str().to_string())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        let critical_count = records
            .iter()
            .filter(|r| r.forensic_value == ForensicValue::Critical)
            .count();

        Ok(PluginOutput {
            plugin_name: self.name().to_string(),
            plugin_version: self.version().to_string(),
            executed_at: String::new(),
            duration_ms: start.elapsed().as_millis() as u64,
            artifacts: records.clone(),
            summary: PluginSummary {
                total_artifacts: records.len(),
                suspicious_count,
                categories_populated: categories,
                headline: format!(
                    "Vector: {} files analyzed, {} critical, {} suspicious",
                    records.len(),
                    critical_count,
                    suspicious_count,
                ),
            },
            warnings: vec![],
        })
    }
}

fn walk_dir(dir: &Path) -> Result<Vec<std::path::PathBuf>, std::io::Error> {
    let mut paths = Vec::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                if let Ok(sub) = walk_dir(&path) {
                    paths.extend(sub);
                }
            } else {
                paths.push(path);
            }
        }
    }
    Ok(paths)
}

#[no_mangle]
pub extern "C" fn create_plugin_vector() -> *mut std::ffi::c_void {
    let plugin: Box<dyn StrataPlugin> = Box::new(VectorPlugin::new());
    Box::into_raw(Box::new(plugin)) as *mut std::ffi::c_void
}
