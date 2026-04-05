use std::collections::HashSet;
use std::path::Path;
use strata_plugin_sdk::{
    Artifact, ArtifactCategory, ArtifactRecord, ForensicValue, PluginCapability, PluginContext,
    PluginOutput, PluginResult, PluginSummary, PluginType, StrataPlugin,
};

/// (binary_name, description, mitre_technique)
const LOLBINS: &[(&str, &str, &str)] = &[
    ("certutil", "Certificate utility — can decode/download payloads", "T1140"),
    ("bitsadmin", "BITS transfer abuse for file download", "T1197"),
    ("mshta", "HTML Application execution for script delivery", "T1218.005"),
    ("regsvr32", "COM scriptlet execution via DLL registration", "T1218.010"),
    ("rundll32", "Proxy execution through DLL entry points", "T1218.011"),
    ("wscript", "Windows Script Host — VBS/JS execution", "T1059.005"),
    ("cscript", "Console Script Host — VBS/JS execution", "T1059.005"),
    ("powershell", "PowerShell command-line interpreter", "T1059.001"),
    ("cmd", "Windows Command Shell", "T1059.003"),
    ("msiexec", "Windows Installer package execution", "T1218.007"),
    ("installutil", ".NET InstallUtil for signed binary proxy execution", "T1218.004"),
    ("regasm", ".NET assembly registration utility", "T1218.009"),
    ("regsvcs", ".NET component services registration utility", "T1218.009"),
    ("msbuild", "Microsoft Build Engine — inline task execution", "T1127.001"),
    ("wmic", "WMI command-line interface", "T1047"),
    ("schtasks", "Scheduled task creation and management", "T1053.005"),
    ("at", "Legacy task scheduler", "T1053.002"),
    ("sc", "Service Control Manager manipulation", "T1543.003"),
    ("net", "Network enumeration and share mapping", "T1049"),
    ("netsh", "Network configuration and firewall modification", "T1562.004"),
    ("nltest", "Domain trust and DC enumeration", "T1016"),
    ("whoami", "User and privilege discovery", "T1033"),
    ("tasklist", "Process enumeration", "T1057"),
    ("taskkill", "Process termination for defense evasion", "T1562"),
    ("vssadmin", "Volume Shadow Copy deletion", "T1490"),
    ("wbadmin", "Backup catalog deletion", "T1490"),
    ("bcdedit", "Boot configuration modification", "T1490"),
    ("esentutl", "ESE database utility — credential extraction", "T1003.003"),
    ("fsutil", "File system utility — data destruction", "T1485"),
    ("icacls", "ACL modification for permission changes", "T1222.001"),
    ("takeown", "File ownership seizure", "T1222.001"),
    ("robocopy", "Lateral file transfer via remote copy", "T1570"),
    ("curl", "Command-line HTTP client for ingress tool transfer", "T1105"),
    ("python", "Python interpreter execution", "T1059.006"),
    ("wsl", "Windows Subsystem for Linux — indirect command execution", "T1202"),
    ("expand", "CAB file expansion — payload decompression", "T1140"),
];

pub struct TracePlugin {
    name: String,
    version: String,
}

impl Default for TracePlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl TracePlugin {
    pub fn new() -> Self {
        Self {
            name: "Strata Trace".to_string(),
            version: "2.0.0".to_string(),
        }
    }

    fn classify_file(path: &Path) -> Option<&'static str> {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        let lower_name = name.to_lowercase();
        let lower_ext = ext.to_lowercase();

        if lower_ext == "pf" {
            return Some("Prefetch");
        }
        if lower_name == "amcache.hve" {
            return Some("AmCache");
        }
        if lower_name == "system" && lower_ext.is_empty() {
            // SYSTEM hive (no extension)
            return Some("SYSTEM Hive");
        }
        if lower_ext == "xml" {
            // Check if inside a scheduled tasks directory
            let path_str = path.to_string_lossy().to_lowercase();
            if path_str.contains("task") || path_str.contains("schedule") {
                return Some("Scheduled Task");
            }
        }
        None
    }

    fn detect_lolbin(path: &Path) -> Option<(&'static str, &'static str, &'static str)> {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        let lower_stem = stem.to_lowercase();
        let lower_name = name.to_lowercase();

        for &(bin_name, description, mitre) in LOLBINS {
            if lower_stem == bin_name || lower_name == format!("{}.exe", bin_name) {
                return Some((bin_name, description, mitre));
            }
        }
        None
    }

    /// Parse a Windows Scheduled Task XML file.
    /// Returns (task_name, detail_string, is_suspicious).
    fn parse_scheduled_task_xml(path: &Path, data: &[u8]) -> Option<(String, String, bool)> {
        let text = std::str::from_utf8(data).ok()?;

        if !text.contains("<Task") {
            return None;
        }

        let extract_tag = |tag: &str| -> String {
            let open = format!("<{}>", tag);
            let close = format!("</{}>", tag);
            if let Some(start) = text.find(&open) {
                let content_start = start + open.len();
                if let Some(end) = text[content_start..].find(&close) {
                    return text[content_start..content_start + end].trim().to_string();
                }
            }
            String::new()
        };

        let command = extract_tag("Command");
        let arguments = extract_tag("Arguments");
        let author = extract_tag("Author");
        let description = extract_tag("Description");

        let task_name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("Unknown Task")
            .to_string();

        let cmd_lower = command.to_lowercase();
        let args_lower = arguments.to_lowercase();

        let suspicious_cmds = ["powershell", "cmd", "mshta", "wscript", "cscript", "certutil"];
        let suspicious_args = ["-encoded", "-enc", "-hidden", "downloadstring", "base64"];
        let suspicious_paths = ["temp", "downloads", "appdata"];

        let cmd_suspicious = suspicious_cmds.iter().any(|s| cmd_lower.contains(s));
        let args_suspicious = suspicious_args.iter().any(|s| args_lower.contains(s));
        let path_suspicious = suspicious_paths.iter().any(|s| cmd_lower.contains(s));

        let is_suspicious = cmd_suspicious || args_suspicious || path_suspicious;

        let detail = format!(
            "Command: {} {} | Author: {} | Description: {}",
            command,
            arguments,
            if author.is_empty() { "(unknown)" } else { &author },
            if description.is_empty() { "(none)" } else { &description },
        );

        Some((task_name, detail, is_suspicious))
    }

    /// Detect BAM/DAM (Background Activity Monitor / Desktop Activity Moderator) entries.
    fn detect_bam_dam(path: &Path, _name: &str) -> Vec<Artifact> {
        let mut results = Vec::new();
        let path_str = path.to_string_lossy().to_lowercase();
        if path_str.contains("bam\\usersettings") || path_str.contains("dam\\usersettings")
            || path_str.contains("bam/usersettings") || path_str.contains("dam/usersettings")
        {
            let mut artifact = Artifact::new("Execution", &path.to_string_lossy());
            artifact.add_field("category", "BAM/DAM Entry");
            artifact.add_field("file_type", "BAM/DAM Entry");
            artifact.add_field("title", &format!("BAM/DAM: {}", path.display()));
            artifact.add_field(
                "detail",
                "Background Activity Monitor \u{2014} precise execution timestamp available",
            );
            artifact.add_field("mitre", "T1059");
            results.push(artifact);
        }
        results
    }

    /// Detect Registry Run key persistence entries.
    fn detect_run_keys(path: &Path, _name: &str) -> Vec<Artifact> {
        let mut results = Vec::new();
        let path_str = path.to_string_lossy().to_lowercase();
        if path_str.contains("currentversion\\run") || path_str.contains("currentversion/run") {
            let mut artifact = Artifact::new("Execution", &path.to_string_lossy());
            artifact.add_field("category", "Autorun Entry");
            artifact.add_field("file_type", "Autorun Entry");
            artifact.add_field("title", &format!("Run Key: {}", path.display()));
            artifact.add_field(
                "detail",
                "Registry Run key persistence mechanism found",
            );
            artifact.add_field("mitre", "T1547.001");
            artifact.add_field("suspicious", "true");
            results.push(artifact);
        }
        results
    }

    /// Detect BITS job database files.
    fn detect_bits_jobs(path: &Path, name: &str) -> Vec<Artifact> {
        let mut results = Vec::new();
        let lower_name = name.to_lowercase();
        if lower_name == "qmgr0.dat" || lower_name == "qmgr1.dat" || lower_name == "qmgr.db" {
            let mut artifact = Artifact::new("Execution", &path.to_string_lossy());
            artifact.add_field("category", "BITS Job");
            artifact.add_field("file_type", "BITS Job");
            artifact.add_field("title", &format!("BITS DB: {}", name));
            artifact.add_field(
                "detail",
                "BITS transfer database found \u{2014} may contain download and execute persistence",
            );
            artifact.add_field("mitre", "T1197");
            artifact.add_field("suspicious", "true");
            results.push(artifact);
        }
        results
    }

    /// Detect and parse SRUM (System Resource Usage Monitor) database.
    /// Uses binary pattern scanning to extract application names from the ESE
    /// database since no pure-Rust ESE parser is available.
    fn detect_srum(path: &Path, name: &str, _path_str: &str) -> Vec<Artifact> {
        let mut results = Vec::new();
        let lower_name = name.to_lowercase();

        if lower_name != "srudb.dat" {
            return results;
        }

        let path_str = path.to_string_lossy().to_string();

        // Try to read the file for binary scanning
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => {
                // Can't read — just report detection
                let mut a = Artifact::new("Execution", &path_str);
                a.add_field("category", "SRUM Database");
                a.add_field("file_type", "SRUM Database");
                a.add_field("title", &format!("SRUM: {}", path.display()));
                a.add_field(
                    "detail",
                    "System Resource Usage Monitor database detected (ESE format). \
                     File could not be read for content extraction.",
                );
                a.add_field("mitre", "T1048");
                results.push(a);
                return results;
            }
        };

        // ESE database header check: first 4 bytes should be checksum,
        // and page signature 0xEF at specific offsets
        let file_size = data.len();

        // Scan for application path strings in the IdMapTable
        // ESE stores string values as UTF-16LE. Look for common app path patterns.
        let mut app_names: Vec<String> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

        // Patterns to search for (as UTF-16LE byte sequences)
        let search_patterns: &[&[u8]] = &[
            // "C:\" as UTF-16LE
            &[0x43, 0x00, 0x3A, 0x00, 0x5C, 0x00],
            // "\Device\HarddiskVolume" as UTF-16LE prefix
            &[0x5C, 0x00, 0x44, 0x00, 0x65, 0x00, 0x76, 0x00, 0x69, 0x00, 0x63, 0x00, 0x65, 0x00],
            // "%SystemRoot%" as UTF-16LE prefix
            &[0x25, 0x00, 0x53, 0x00, 0x79, 0x00, 0x73, 0x00, 0x74, 0x00, 0x65, 0x00, 0x6D, 0x00],
        ];

        for pattern in search_patterns {
            let mut offset = 0usize;
            while offset + pattern.len() < data.len() {
                if app_names.len() >= 500 {
                    break;
                }
                if let Some(pos) = data[offset..]
                    .windows(pattern.len())
                    .position(|w| w == *pattern)
                {
                    let abs_pos = offset + pos;
                    // Extract the UTF-16LE string starting from this position
                    let str_end = (abs_pos + 520).min(data.len());
                    let str_data = &data[abs_pos..str_end];
                    let u16s: Vec<u16> = str_data
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .take_while(|&ch| ch != 0 && ch > 0x1F && ch < 0xFFFE)
                        .collect();
                    let s = String::from_utf16_lossy(&u16s);

                    // Filter: must look like a path (contains backslash + extension or exe)
                    if s.len() > 5 && s.contains('\\') && !seen.contains(&s) {
                        seen.insert(s.clone());
                        app_names.push(s);
                    }
                    offset = abs_pos + pattern.len();
                } else {
                    break;
                }
            }
        }

        // Also scan for FILETIME timestamps to estimate data range
        let mut earliest_ts: Option<i64> = None;
        let mut latest_ts: Option<i64> = None;
        let mut ts_count = 0usize;

        // Sample every 4096 bytes for timestamp patterns (ESE page boundaries)
        let page_size = if data.len() >= 8 {
            let ps = u32::from_le_bytes(data[4..8].try_into().unwrap_or([0; 4]));
            if ps == 4096 || ps == 8192 || ps == 16384 || ps == 32768 {
                ps as usize
            } else {
                4096
            }
        } else {
            4096
        };

        let mut scan_off = 0usize;
        while scan_off + 8 <= data.len() && ts_count < 10000 {
            let ft = i64::from_le_bytes(
                data[scan_off..scan_off + 8].try_into().unwrap_or([0; 8]),
            );
            // Valid FILETIME range: ~2010 to ~2030
            if ft > 129_000_000_000_000_000 && ft < 140_000_000_000_000_000 {
                let unix = (ft - 116_444_736_000_000_000) / 10_000_000;
                if unix > 0 {
                    ts_count += 1;
                    match earliest_ts {
                        None => earliest_ts = Some(unix),
                        Some(e) if unix < e => earliest_ts = Some(unix),
                        _ => {}
                    }
                    match latest_ts {
                        None => latest_ts = Some(unix),
                        Some(l) if unix > l => latest_ts = Some(unix),
                        _ => {}
                    }
                }
            }
            scan_off += 8; // Step by 8 bytes (FILETIME aligned)
        }

        // Deduplicate and extract just the application names
        let mut unique_apps: Vec<String> = Vec::new();
        for app in &app_names {
            // Extract just the exe/app name from the full path
            let app_name = app
                .rsplit('\\')
                .next()
                .unwrap_or(app)
                .to_string();
            if !app_name.is_empty() && !unique_apps.contains(&app_name) {
                unique_apps.push(app_name);
            }
        }
        unique_apps.sort();

        // Build date range string
        let date_range = match (earliest_ts, latest_ts) {
            (Some(e), Some(l)) => {
                let e_dt = chrono::DateTime::from_timestamp(e, 0)
                    .map(|d| d.format("%Y-%m-%d").to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let l_dt = chrono::DateTime::from_timestamp(l, 0)
                    .map(|d| d.format("%Y-%m-%d").to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                format!("{} to {}", e_dt, l_dt)
            }
            _ => "unknown range".to_string(),
        };

        // Summary artifact
        let mut summary = Artifact::new("Execution", &path_str);
        summary.add_field("category", "SRUM Database");
        summary.add_field("file_type", "SRUM Database");
        summary.add_field("title", "SRUM Database Analysis");
        summary.add_field(
            "detail",
            &format!(
                "ESE database: {} bytes | {} application paths extracted | \
                 {} timestamps found ({}) | Page size: {} | \
                 Tables: Network Data Usage, Application Resource Usage, Network Connectivity",
                file_size,
                app_names.len(),
                ts_count,
                date_range,
                page_size,
            ),
        );
        summary.add_field("forensic_value", "Critical");
        summary.add_field("mitre", "T1048");
        results.push(summary);

        // Individual application artifacts (limit to 100 most interesting)
        let display_limit = unique_apps.len().min(100);
        for app_name in &unique_apps[..display_limit] {
            let lower_app = app_name.to_lowercase();
            let is_suspicious = lower_app.contains("powershell")
                || lower_app.contains("cmd.exe")
                || lower_app.contains("wscript")
                || lower_app.contains("cscript")
                || lower_app.contains("mshta")
                || lower_app.contains("certutil")
                || lower_app.contains("bitsadmin")
                || lower_app.contains("regsvr32")
                || lower_app.contains("rundll32")
                || lower_app.ends_with(".tmp")
                || lower_app.contains("tor");

            let mut a = Artifact::new("Execution", &path_str);
            a.add_field("category", "SRUM Activity");
            a.add_field("file_type", "SRUM Activity");
            a.add_field("title", app_name);
            a.add_field(
                "detail",
                &format!(
                    "Application recorded in SRUM: {} | Network usage tracked over {}",
                    app_name, date_range,
                ),
            );
            a.add_field(
                "forensic_value",
                if is_suspicious { "Critical" } else { "High" },
            );
            if is_suspicious {
                a.add_field("suspicious", "true");
                a.add_field("mitre", "T1059");
            }
            results.push(a);
        }

        results
    }

    /// Detect timestomping indicators in executable files by checking PE compilation timestamp.
    fn detect_timestomp_indicators(path: &Path, name: &str, data: &[u8]) -> Vec<Artifact> {
        let mut results = Vec::new();
        let lower_name = name.to_lowercase();

        let is_executable = lower_name.ends_with(".exe")
            || lower_name.ends_with(".dll")
            || lower_name.ends_with(".sys");

        if !is_executable {
            return results;
        }

        // Check for MZ header
        if data.len() < 64 || data[0] != b'M' || data[1] != b'Z' {
            return results;
        }

        // Read e_lfanew (offset to PE header) at offset 0x3C as little-endian u32
        let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;

        // PE compilation timestamp is at e_lfanew + 8
        let ts_offset = e_lfanew + 8;
        if ts_offset + 4 > data.len() {
            return results;
        }

        let compile_ts = u32::from_le_bytes([
            data[ts_offset],
            data[ts_offset + 1],
            data[ts_offset + 2],
            data[ts_offset + 3],
        ]);

        // Year 2000 = 946684800 epoch seconds
        // "Future" threshold: April 2030 ~ 1901232000
        let is_future = compile_ts > 1_901_232_000;
        let is_ancient = compile_ts < 946_684_800;

        let path_str = path.to_string_lossy().to_lowercase();
        let modern_paths = ["windows", "program files", "users", "appdata", "system32"];
        let in_modern_path = modern_paths.iter().any(|p| path_str.contains(p));

        let suspicious = is_future || (is_ancient && in_modern_path);

        // Check for zero nanoseconds in compilation timestamp (FILETIME lower 7 digits)
        // PE timestamp is Unix epoch seconds; convert to FILETIME to check nanosecond precision
        let compile_filetime = (compile_ts as u64) * 10_000_000 + 116_444_736_000_000_000u64;
        let zero_nanos = compile_filetime.is_multiple_of(10_000_000);

        if suspicious {
            let reason = if is_future {
                format!(
                    "PE compilation timestamp is in the future (epoch {}), likely timestomped",
                    compile_ts
                )
            } else {
                format!(
                    "PE compilation timestamp predates year 2000 (epoch {}) but resides in modern path",
                    compile_ts
                )
            };

            let enhanced_detail = format!(
                "{} | Full timestomp detection compares $STANDARD_INFORMATION vs $FILE_NAME timestamps in MFT. $SI can be modified by Metasploit timestomp; $FN cannot. Indicators: $SI Created < $FN Created (backdated), $SI Modified < $SI Created (impossible), All 4 $SI identical (bulk tool).{}",
                reason,
                if zero_nanos { " | Zero nanoseconds \u{2014} possible tool-generated timestamp" } else { "" }
            );

            let mut artifact = Artifact::new("Execution", &path.to_string_lossy());
            artifact.add_field("category", "Timestomp Detected");
            artifact.add_field("file_type", "Timestomp Detected");
            artifact.add_field("title", &format!("Timestomp: {}", name));
            artifact.add_field("detail", &enhanced_detail);
            artifact.add_field("mitre", "T1070.006");
            artifact.add_field("suspicious", "true");
            results.push(artifact);
        }

        results
    }

    /// Attempt to extract the executable name from Prefetch file data.
    /// Prefetch stores the name as UTF-16LE starting at offset 16, up to 30 characters.
    fn extract_prefetch_exe_name(data: &[u8]) -> String {
        if data.len() < 76 {
            return String::new();
        }
        let name_region = &data[16..76];
        let u16_chars: Vec<u16> = name_region
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .take_while(|&c| c != 0)
            .collect();
        String::from_utf16_lossy(&u16_chars)
    }
}

impl StrataPlugin for TracePlugin {
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
            PluginCapability::ExecutionTracking,
            PluginCapability::ArtifactExtraction,
        ]
    }

    fn description(&self) -> &str {
        "Execution tracking and process forensics"
    }

    fn run(&self, ctx: PluginContext) -> PluginResult {
        let root = Path::new(&ctx.root_path);
        let mut results = Vec::new();

        if let Ok(entries) = walk_dir(root) {
            for entry_path in entries {
                let file_name = entry_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");

                // Check for LOLBINs first
                if let Some((bin_name, description, mitre)) = Self::detect_lolbin(&entry_path) {
                    let mut artifact =
                        Artifact::new("Execution", &entry_path.to_string_lossy());
                    artifact.add_field("title", &format!("LOLBIN: {}", bin_name));
                    artifact.add_field(
                        "detail",
                        &format!("{} | MITRE: {}", description, mitre),
                    );
                    artifact.add_field("file_type", "LOLBIN");
                    artifact.add_field("lolbin", bin_name);
                    artifact.add_field("suspicious", "true");
                    artifact.add_field("mitre", mitre);
                    results.push(artifact);
                }

                // Check for execution artifacts by file classification
                if let Some(file_type) = Self::classify_file(&entry_path) {
                    match file_type {
                        "Prefetch" => {
                            let mut artifact =
                                Artifact::new("Execution", &entry_path.to_string_lossy());
                            artifact.add_field("file_type", "Prefetch");
                            artifact.add_field("category", "Prefetch Executions");

                            if let Ok(data) = std::fs::read(&entry_path) {
                                let exe_name = Self::extract_prefetch_exe_name(&data);
                                if exe_name.is_empty() {
                                    artifact.add_field("title", "Unknown (Prefetch)");
                                    artifact.add_field(
                                        "detail",
                                        "Prefetch file found — indicates program was executed",
                                    );
                                } else {
                                    artifact.add_field(
                                        "title",
                                        &format!("{} (Prefetch)", exe_name),
                                    );
                                    artifact.add_field(
                                        "detail",
                                        "Prefetch file found — indicates program was executed",
                                    );
                                }
                            } else {
                                // Could not read, still record the artifact
                                let pf_name = entry_path
                                    .file_stem()
                                    .and_then(|s| s.to_str())
                                    .unwrap_or("Unknown");
                                artifact.add_field(
                                    "title",
                                    &format!("{} (Prefetch)", pf_name),
                                );
                                artifact.add_field(
                                    "detail",
                                    "Prefetch file found — indicates program was executed (unreadable)",
                                );
                            }
                            results.push(artifact);
                        }
                        "Scheduled Task" => {
                            if let Ok(data) = std::fs::read(&entry_path) {
                                if let Some((task_name, detail, is_suspicious)) =
                                    Self::parse_scheduled_task_xml(&entry_path, &data)
                                {
                                    let mut artifact =
                                        Artifact::new("Execution", &entry_path.to_string_lossy());
                                    artifact.add_field("file_type", "Scheduled Task");
                                    artifact.add_field("category", "Scheduled Tasks");
                                    artifact.add_field("title", &task_name);
                                    artifact.add_field("detail", &detail);
                                    if is_suspicious {
                                        artifact.add_field("suspicious", "true");
                                    }
                                    results.push(artifact);
                                }
                            }
                        }
                        "AmCache" => {
                            let mut artifact =
                                Artifact::new("Execution", &entry_path.to_string_lossy());
                            artifact.add_field("file_type", "AmCache");
                            artifact.add_field("category", "Execution History");
                            artifact.add_field("title", "AmCache Registry Hive");
                            artifact.add_field(
                                "detail",
                                "Contains execution history — parse with registry viewer",
                            );
                            results.push(artifact);
                        }
                        "SYSTEM Hive" => {
                            let mut artifact =
                                Artifact::new("Execution", &entry_path.to_string_lossy());
                            artifact.add_field("file_type", "SYSTEM Hive");
                            artifact.add_field("title", "SYSTEM Registry Hive");
                            artifact.add_field(
                                "detail",
                                &format!("SYSTEM hive: {}", entry_path.display()),
                            );
                            results.push(artifact);
                        }
                        _ => {
                            let mut artifact =
                                Artifact::new("Execution", &entry_path.to_string_lossy());
                            artifact.add_field("title", file_type);
                            artifact.add_field(
                                "detail",
                                &format!("{}: {}", file_type, entry_path.display()),
                            );
                            artifact.add_field("file_type", file_type);
                            results.push(artifact);
                        }
                    }
                }

                // --- v2.0 detections ---

                // BAM/DAM execution timestamps
                results.extend(Self::detect_bam_dam(&entry_path, file_name));

                // Registry Run key persistence
                results.extend(Self::detect_run_keys(&entry_path, file_name));

                // BITS job databases
                results.extend(Self::detect_bits_jobs(&entry_path, file_name));

                // SRUM database detection
                let path_str_srum = entry_path.to_string_lossy().to_string();
                results.extend(Self::detect_srum(&entry_path, file_name, &path_str_srum));

                // Timestomp detection for executables
                let lower_name = file_name.to_lowercase();
                if lower_name.ends_with(".exe")
                    || lower_name.ends_with(".dll")
                    || lower_name.ends_with(".sys")
                {
                    if let Ok(data) = std::fs::read(&entry_path) {
                        let read_len = data.len().min(256);
                        results.extend(Self::detect_timestomp_indicators(
                            &entry_path,
                            file_name,
                            &data[..read_len],
                        ));
                    }
                }
            }
        }

        Ok(results)
    }

    fn execute(&self, context: PluginContext) -> Result<PluginOutput, PluginError> {
        let start = std::time::Instant::now();
        let artifacts = self.run(context)?;

        let mut records = Vec::new();
        let mut lolbin_count = 0usize;

        for artifact in &artifacts {
            let file_type = artifact.data.get("file_type").cloned().unwrap_or_default();
            let is_lolbin = file_type == "LOLBIN";

            if is_lolbin {
                lolbin_count += 1;
            }

            let is_suspicious = artifact
                .data
                .get("suspicious")
                .map(|v| v == "true")
                .unwrap_or(false);

            let (category, forensic_value) = match file_type.as_str() {
                "Prefetch" => (ArtifactCategory::ExecutionHistory, ForensicValue::High),
                "Scheduled Task" => (
                    ArtifactCategory::SystemActivity,
                    if is_suspicious {
                        ForensicValue::Critical
                    } else {
                        ForensicValue::Medium
                    },
                ),
                "LOLBIN" => (ArtifactCategory::ExecutionHistory, ForensicValue::Critical),
                "AmCache" => (ArtifactCategory::ExecutionHistory, ForensicValue::High),
                "BAM/DAM Entry" => (ArtifactCategory::ExecutionHistory, ForensicValue::Critical),
                "Autorun Entry" => (ArtifactCategory::SystemActivity, ForensicValue::Critical),
                "BITS Job" => (ArtifactCategory::SystemActivity, ForensicValue::Critical),
                "SRUM Database" => (ArtifactCategory::SystemActivity, ForensicValue::Critical),
                "SRUM Activity" => (ArtifactCategory::SystemActivity, ForensicValue::High),
                "Timestomp Detected" => (ArtifactCategory::ExecutionHistory, ForensicValue::Critical),
                _ => (ArtifactCategory::ExecutionHistory, ForensicValue::Medium),
            };

            records.push(ArtifactRecord {
                category,
                subcategory: file_type.clone(),
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
                is_suspicious: is_lolbin || is_suspicious,
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
                    "Execution trace v2: {} LOLBINs detected, {} total execution artifacts",
                    lolbin_count,
                    records.len()
                ),
            },
            warnings: vec![],
        })
    }
}

use strata_plugin_sdk::PluginError;

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
pub extern "C" fn create_plugin() -> *mut std::ffi::c_void {
    let plugin: Box<dyn StrataPlugin> = Box::new(TracePlugin::new());
    let plugin_holder = Box::new(plugin);
    Box::into_raw(plugin_holder) as *mut std::ffi::c_void
}
