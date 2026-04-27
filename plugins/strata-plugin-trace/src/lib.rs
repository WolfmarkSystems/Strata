use std::collections::HashSet;
use std::path::Path;
use strata_plugin_sdk::{
    Artifact, ArtifactCategory, ArtifactRecord, ForensicValue, PluginCapability, PluginContext,
    PluginOutput, PluginResult, PluginSummary, PluginType, StrataPlugin,
};

pub mod bits;
pub mod pca;
pub mod srum;

/// (binary_name, description, mitre_technique)
const LOLBINS: &[(&str, &str, &str)] = &[
    (
        "certutil",
        "Certificate utility — can decode/download payloads",
        "T1140",
    ),
    (
        "bitsadmin",
        "BITS transfer abuse for file download",
        "T1197",
    ),
    (
        "mshta",
        "HTML Application execution for script delivery",
        "T1218.005",
    ),
    (
        "regsvr32",
        "COM scriptlet execution via DLL registration",
        "T1218.010",
    ),
    (
        "rundll32",
        "Proxy execution through DLL entry points",
        "T1218.011",
    ),
    (
        "wscript",
        "Windows Script Host — VBS/JS execution",
        "T1059.005",
    ),
    (
        "cscript",
        "Console Script Host — VBS/JS execution",
        "T1059.005",
    ),
    (
        "powershell",
        "PowerShell command-line interpreter",
        "T1059.001",
    ),
    ("cmd", "Windows Command Shell", "T1059.003"),
    (
        "msiexec",
        "Windows Installer package execution",
        "T1218.007",
    ),
    (
        "installutil",
        ".NET InstallUtil for signed binary proxy execution",
        "T1218.004",
    ),
    ("regasm", ".NET assembly registration utility", "T1218.009"),
    (
        "regsvcs",
        ".NET component services registration utility",
        "T1218.009",
    ),
    (
        "msbuild",
        "Microsoft Build Engine — inline task execution",
        "T1127.001",
    ),
    ("wmic", "WMI command-line interface", "T1047"),
    (
        "schtasks",
        "Scheduled task creation and management",
        "T1053.005",
    ),
    ("at", "Legacy task scheduler", "T1053.002"),
    ("sc", "Service Control Manager manipulation", "T1543.003"),
    ("net", "Network enumeration and share mapping", "T1049"),
    (
        "netsh",
        "Network configuration and firewall modification",
        "T1562.004",
    ),
    ("nltest", "Domain trust and DC enumeration", "T1016"),
    ("whoami", "User and privilege discovery", "T1033"),
    ("tasklist", "Process enumeration", "T1057"),
    (
        "taskkill",
        "Process termination for defense evasion",
        "T1562",
    ),
    ("vssadmin", "Volume Shadow Copy deletion", "T1490"),
    ("wbadmin", "Backup catalog deletion", "T1490"),
    ("bcdedit", "Boot configuration modification", "T1490"),
    (
        "esentutl",
        "ESE database utility — credential extraction",
        "T1003.003",
    ),
    ("fsutil", "File system utility — data destruction", "T1485"),
    (
        "icacls",
        "ACL modification for permission changes",
        "T1222.001",
    ),
    ("takeown", "File ownership seizure", "T1222.001"),
    ("robocopy", "Lateral file transfer via remote copy", "T1570"),
    (
        "curl",
        "Command-line HTTP client for ingress tool transfer",
        "T1105",
    ),
    ("python", "Python interpreter execution", "T1059.006"),
    (
        "wsl",
        "Windows Subsystem for Linux — indirect command execution",
        "T1202",
    ),
    (
        "expand",
        "CAB file expansion — payload decompression",
        "T1140",
    ),
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
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
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
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
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

        let suspicious_cmds = [
            "powershell",
            "cmd",
            "mshta",
            "wscript",
            "cscript",
            "certutil",
        ];
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
            if author.is_empty() {
                "(unknown)"
            } else {
                &author
            },
            if description.is_empty() {
                "(none)"
            } else {
                &description
            },
        );

        Some((task_name, detail, is_suspicious))
    }

    /// Detect BAM/DAM (Background Activity Monitor / Desktop Activity Moderator) entries.
    fn detect_bam_dam(path: &Path, _name: &str) -> Vec<Artifact> {
        let mut results = Vec::new();
        let path_str = path.to_string_lossy().to_lowercase();
        if path_str.contains("bam\\usersettings")
            || path_str.contains("dam\\usersettings")
            || path_str.contains("bam/usersettings")
            || path_str.contains("dam/usersettings")
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
            artifact.add_field("detail", "Registry Run key persistence mechanism found");
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
    ///
    /// Delegates the structural parsing to [`crate::srum::SrumDatabase`],
    /// which validates the ESE header, walks pages, and extracts:
    ///   - Application paths and basenames
    ///   - User SIDs
    ///   - Which SRUM extension table providers are present
    ///   - The FILETIME range observed across pages
    ///
    /// On parse failure (bad magic, wrong file type, implausible page
    /// size, unreadable file) Strata still emits a single detection
    /// artifact so the examiner sees that a SRUM file existed.
    fn detect_srum(path: &Path, name: &str, _path_str: &str) -> Vec<Artifact> {
        let mut results = Vec::new();
        let lower_name = name.to_lowercase();

        if lower_name != "srudb.dat" {
            return results;
        }

        let path_str = path.to_string_lossy().to_string();

        let parsed = match crate::srum::SrumDatabase::parse(path) {
            Ok(p) => p,
            Err(reason) => {
                // Detection-only fallback: file exists but can't be parsed.
                let mut a = Artifact::new("Execution", &path_str);
                a.add_field("category", "SRUM Database");
                a.add_field("file_type", "SRUM Database");
                a.add_field("title", &format!("SRUM: {}", path.display()));
                a.add_field(
                    "detail",
                    &format!(
                        "System Resource Usage Monitor database detected (ESE format). \
                         Structural parse failed: {reason}"
                    ),
                );
                a.add_field("mitre", "T1048");
                results.push(a);
                return results;
            }
        };

        let date_range = parsed.date_range();
        let providers_listed = if parsed.providers_present.is_empty() {
            "(none detected)".to_string()
        } else {
            parsed.providers_present.join(", ")
        };
        let sids_listed = if parsed.user_sids.is_empty() {
            "(none recovered)".to_string()
        } else {
            parsed.user_sids.join(", ")
        };

        // Database summary artifact.
        let mut summary = Artifact::new("Execution", &path_str);
        summary.add_field("category", "SRUM Database");
        summary.add_field("file_type", "SRUM Database");
        summary.add_field("title", "SRUM Database Analysis");
        summary.add_field(
            "detail",
            &format!(
                "ESE database parsed: {} bytes | format 0x{:X} | page size {} | \
                 {} pages walked ({} long-value pages) | {} application paths | \
                 {} user SIDs recovered | {} FILETIMEs sampled ({}) | \
                 Providers present: {}",
                parsed.file_size,
                parsed.format_version,
                parsed.page_size,
                parsed.page_count,
                parsed.long_value_pages,
                parsed.apps.len(),
                parsed.user_sids.len(),
                parsed.timestamp_count,
                date_range,
                providers_listed,
            ),
        );
        summary.add_field("forensic_value", "Critical");
        summary.add_field("mitre", "T1048");
        results.push(summary);

        // One artifact per detected SRUM extension provider so the
        // examiner sees exactly which datasets are available.
        for provider in &parsed.providers_present {
            let mut a = Artifact::new("Execution", &path_str);
            a.add_field("category", "SRUM Provider");
            a.add_field("file_type", "SRUM Provider");
            a.add_field("title", &format!("SRUM Provider: {provider}"));
            a.add_field(
                "detail",
                &format!(
                    "Extension table {provider} detected in {}. \
                     Date range: {date_range}.",
                    path.display()
                ),
            );
            a.add_field("forensic_value", "High");
            a.add_field("mitre", "T1048");
            results.push(a);
        }

        // One artifact per recovered user SID — useful for attribution
        // when SRUM is the only artifact a host has retained.
        for sid in &parsed.user_sids {
            let mut a = Artifact::new("Execution", &path_str);
            a.add_field("category", "SRUM User");
            a.add_field("file_type", "SRUM User");
            a.add_field("title", &format!("SRUM User: {sid}"));
            a.add_field(
                "detail",
                &format!(
                    "User SID recovered from SRUM IdMap: {sid}. \
                     This user owned at least one SRUM-tracked process \
                     during {date_range}."
                ),
            );
            a.add_field("forensic_value", "High");
            a.add_field("mitre", "T1087.001");
            results.push(a);
        }

        // Individual application artifacts (cap at 200 to bound report size).
        let display_limit = parsed.apps.len().min(200);
        for app in parsed.apps.iter().take(display_limit) {
            let mut a = Artifact::new("Execution", &path_str);
            a.add_field("category", "SRUM Activity");
            a.add_field("file_type", "SRUM Activity");
            a.add_field("title", &app.basename);
            a.add_field(
                "detail",
                &format!(
                    "Application recovered from SRUM: {} | Database date range: {date_range} | \
                     Detected providers: {providers_listed} | User scope: {sids_listed}",
                    app.full_path,
                ),
            );
            a.add_field(
                "forensic_value",
                if app.is_suspicious {
                    "Critical"
                } else {
                    "High"
                },
            );
            if app.is_suspicious {
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
        let e_lfanew =
            u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;

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
                    let mut artifact = Artifact::new("Execution", &entry_path.to_string_lossy());
                    artifact.add_field("title", &format!("LOLBIN: {}", bin_name));
                    artifact.add_field("detail", &format!("{} | MITRE: {}", description, mitre));
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
                                    artifact
                                        .add_field("title", &format!("{} (Prefetch)", exe_name));
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
                                artifact.add_field("title", &format!("{} (Prefetch)", pf_name));
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

                // BITS job databases (surface-level + deep-parse).
                // The surface-level detect_bits_jobs emits a single
                // status record per qmgr file; the deep-parse path
                // (post-v16 Sprint 3 wiring) walks the blob via
                // crate::bits::parse_qmgr_binary and emits one
                // BITS Transfer record per carved URL/destination/
                // GUID tuple. Suspicion is surfaced via
                // bits::check_suspicion (non-Microsoft source URLs,
                // NotifyUrl present, user-writable destinations).
                results.extend(Self::detect_bits_jobs(&entry_path, file_name));
                if crate::bits::is_bits_path(&entry_path) {
                    if let Ok(bytes) = std::fs::read(&entry_path) {
                        for job in crate::bits::parse_qmgr_binary(&bytes) {
                            let mut a = Artifact::new("Execution", &entry_path.to_string_lossy());
                            a.add_field("file_type", "BITS Transfer");
                            a.add_field("category", "BITS Transfer");
                            a.add_field(
                                "title",
                                &format!(
                                    "BITS transfer: {} → {}",
                                    job.source_url.as_deref().unwrap_or("(unknown url)"),
                                    job.destination_path.as_deref().unwrap_or("(unknown dest)"),
                                ),
                            );
                            let mut detail = format!("job_id={}", job.job_id);
                            if let Some(u) = &job.source_url {
                                detail.push_str(&format!(" | source_url={u}"));
                            }
                            if let Some(d) = &job.destination_path {
                                detail.push_str(&format!(" | destination={d}"));
                            }
                            if let Some(s) = crate::bits::check_suspicion(&job) {
                                detail.push_str(&format!(" | SUSPICION: {s}"));
                                a.add_field("suspicious", "true");
                            }
                            a.add_field("detail", &detail);
                            a.add_field("mitre", "T1197");
                            results.push(a);
                        }
                    }
                }

                // PCA (Program Compatibility Assistant) execution
                // log parser. Windows 11 22H2+ records executables
                // that triggered compat shims in
                // `C:\Windows\appcompat\pca\PcaAppLaunchDic.txt`
                // and `PcaGeneralDb2.txt`. Charlie + Jo are XP/Win7
                // — correctly produce zero records on these images
                // (Scenario A, pinned by tripwire).
                if crate::pca::is_pca_path(&entry_path) {
                    if let Ok(body) = std::fs::read_to_string(&entry_path) {
                        let name_lc = file_name.to_ascii_lowercase();
                        let entries = if name_lc == "pcaapplaunchdic.txt" {
                            crate::pca::parse_launch_dic(&body, file_name)
                        } else {
                            crate::pca::parse_general_db(&body, file_name)
                        };
                        for entry in entries {
                            let mut a = Artifact::new("Execution", &entry_path.to_string_lossy());
                            a.add_field("file_type", "PCA Execution");
                            a.add_field("category", "PCA Execution");
                            a.add_field("title", &format!("PCA: {}", entry.exe_name));
                            let mut detail = format!(
                                "exe_path={} | last_executed={} | source={}",
                                entry.exe_path,
                                entry.last_executed.format("%Y-%m-%d %H:%M:%S UTC"),
                                entry.source_file,
                            );
                            if let Some(s) = crate::pca::check_suspicion(&entry) {
                                detail.push_str(&format!(" | SUSPICION: {s}"));
                                a.add_field("suspicious", "true");
                            }
                            a.add_field("detail", &detail);
                            a.add_field("mitre", "T1059");
                            a.timestamp = Some(entry.last_executed.timestamp() as u64);
                            results.push(a);
                        }
                    }
                }

                // SRUM database detection
                let path_str_srum = entry_path.to_string_lossy().to_string();
                results.extend(Self::detect_srum(&entry_path, file_name, &path_str_srum));

                // Timestomp detection for executables — bounded 256-byte read.
                // Only the PE header (MZ + e_lfanew + compilation timestamp)
                // is examined. Never load the full file — system DLLs can be
                // hundreds of MB and there are thousands per image.
                let lower_name = file_name.to_lowercase();
                if lower_name.ends_with(".exe")
                    || lower_name.ends_with(".dll")
                    || lower_name.ends_with(".sys")
                {
                    if let Ok(mut f) = std::fs::File::open(&entry_path) {
                        use std::io::Read;
                        let mut buf = [0u8; 256];
                        let n = f.read(&mut buf).unwrap_or(0);
                        if n > 0 {
                            results.extend(Self::detect_timestomp_indicators(
                                &entry_path,
                                file_name,
                                &buf[..n],
                            ));
                        }
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
                "BITS Transfer" => (ArtifactCategory::SystemActivity, ForensicValue::Critical),
                "PCA Execution" => (
                    ArtifactCategory::ExecutionHistory,
                    if is_suspicious {
                        ForensicValue::Critical
                    } else {
                        ForensicValue::High
                    },
                ),
                "SRUM Database" => (ArtifactCategory::SystemActivity, ForensicValue::Critical),
                "SRUM Provider" => (ArtifactCategory::SystemActivity, ForensicValue::High),
                "SRUM User" => (ArtifactCategory::SystemActivity, ForensicValue::High),
                "SRUM Activity" => (ArtifactCategory::SystemActivity, ForensicValue::High),
                "Timestomp Detected" => {
                    (ArtifactCategory::ExecutionHistory, ForensicValue::Critical)
                }
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
                detail: artifact.data.get("detail").cloned().unwrap_or_default(),
                source_path: artifact.source.clone(),
                forensic_value,
                mitre_technique: artifact.data.get("mitre").cloned(),
                is_suspicious: is_lolbin || is_suspicious,
                raw_data: None,
                confidence: 0,
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

// ── post-v16 Sprint 3 tripwires — BITS deep-parse + PCA wiring ──

#[cfg(test)]
mod sprint3_wiring_tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn run_trace(root: &Path) -> Vec<Artifact> {
        let p = TracePlugin::new();
        let ctx = PluginContext {
            root_path: root.to_string_lossy().to_string(),
            vfs: None,
            config: std::collections::HashMap::new(),
            prior_results: Vec::new(),
        };
        p.run(ctx).expect("trace run")
    }

    #[test]
    fn trace_wires_bits_deep_parse_via_bits_submodule() {
        // Sprint 3 Fix 1 tripwire. Confirms the bits submodule's
        // parse_qmgr_binary is invoked when a qmgr0.dat / qmgr1.dat
        // file is encountered (beyond the surface-level
        // detect_bits_jobs status record). The synthetic blob
        // carries one HTTP URL + one Windows path + one GUID so
        // parse_qmgr_binary emits exactly one BITS Transfer record.
        //
        // If this test fails with zero BITS Transfer records, the
        // wiring regressed to the pre-Sprint-3 state where the
        // deep parser sat unreached.
        let dir = tempdir().expect("tempdir");
        let qmgr_path = dir.path().join("qmgr0.dat");
        // Ascii runs: URL + destination path + GUID. is_bits_path()
        // keys on the filename so magic bytes are irrelevant.
        let mut blob = Vec::new();
        blob.extend_from_slice(b"\x00\x00\x00\x00");
        blob.extend_from_slice(b"https://evil.example.com/payload.exe");
        blob.extend_from_slice(b"\x00\x00");
        blob.extend_from_slice(b"C:\\Users\\alice\\AppData\\Local\\Temp\\payload.exe");
        blob.extend_from_slice(b"\x00\x00");
        blob.extend_from_slice(b"{12345678-1234-1234-1234-123456789012}");
        blob.extend_from_slice(b"\x00\x00");
        fs::write(&qmgr_path, &blob).expect("write qmgr");

        let arts = run_trace(dir.path());
        let bits_transfers: Vec<&Artifact> = arts
            .iter()
            .filter(|a| {
                a.data
                    .get("file_type")
                    .map(|v| v == "BITS Transfer")
                    .unwrap_or(false)
            })
            .collect();
        assert!(
            !bits_transfers.is_empty(),
            "expected ≥1 BITS Transfer record on qmgr0.dat fixture; got {} total artifacts",
            arts.len()
        );
        // The synthetic source URL is evil.example.com, not a
        // MS CDN — check_suspicion must flag it.
        let any_suspicious = bits_transfers.iter().any(|a| {
            a.data
                .get("suspicious")
                .map(|v| v == "true")
                .unwrap_or(false)
        });
        assert!(
            any_suspicious,
            "BITS Transfer with non-MS source URL must be suspicious"
        );
    }

    #[test]
    fn trace_wires_pca_launch_dic_parse() {
        // Sprint 3 Fix 1 tripwire. Confirms pca submodule's
        // parse_launch_dic is invoked for PcaAppLaunchDic.txt.
        let dir = tempdir().expect("tempdir");
        let pca_path = dir.path().join("PcaAppLaunchDic.txt");
        fs::write(
            &pca_path,
            "C:\\Users\\alice\\AppData\\Local\\Temp\\evil.exe|2024-06-01 12:00:00.000\n\
             C:\\Program Files\\App\\app.exe|2024-06-01 13:00:00\n",
        )
        .expect("write pca");
        let arts = run_trace(dir.path());
        let pca_entries: Vec<&Artifact> = arts
            .iter()
            .filter(|a| {
                a.data
                    .get("file_type")
                    .map(|v| v == "PCA Execution")
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(
            pca_entries.len(),
            2,
            "expected exactly 2 PCA Execution records on the fixture, got {}. Titles: {:?}",
            pca_entries.len(),
            pca_entries
                .iter()
                .map(|a| a.data.get("title").cloned().unwrap_or_default())
                .collect::<Vec<_>>()
        );
        // The evil.exe lives in AppData\Local\Temp — suspicious
        // per pca::check_suspicion.
        let evil_record = pca_entries
            .iter()
            .find(|a| {
                a.data
                    .get("title")
                    .map(|t| t.contains("evil.exe"))
                    .unwrap_or(false)
            })
            .expect("evil.exe record must exist");
        assert_eq!(
            evil_record.data.get("suspicious").map(|s| s.as_str()),
            Some("true"),
            "evil.exe in Temp path must be flagged suspicious"
        );
    }

    #[test]
    fn trace_pca_produces_zero_on_xp_or_win7_evidence_pending_win11_fixture() {
        // Positive-side tripwire pinning Scenario A: PCA is
        // Windows 11 22H2+. On XP / Win7 evidence (Charlie / Jo
        // canonical Windows test images), no PcaAppLaunchDic.txt
        // or PcaGeneralDb2.txt exists. The absence must produce
        // zero PCA Execution records — pinning the expected-zero
        // so a future change that accidentally starts emitting
        // PCA records on non-Win11 evidence fails loudly.
        //
        // When Win11 22H2+ evidence is added to the test corpus,
        // this test must be intentionally changed or deleted with
        // the commit message noting "Win11 PCA evidence added in
        // [commit]." The `_pending_win11_fixture` suffix makes the
        // deferral discoverable.
        let dir = tempdir().expect("tempdir");
        // Simulate Charlie-shape content: a SYSTEM hive fragment
        // with no PCA files in the tree.
        fs::create_dir_all(dir.path().join("Windows/System32/config")).expect("mk");
        fs::write(
            dir.path().join("Windows/System32/config/SYSTEM"),
            b"regf\x00",
        )
        .expect("w");
        let arts = run_trace(dir.path());
        let pca_count = arts
            .iter()
            .filter(|a| {
                a.data
                    .get("file_type")
                    .map(|v| v == "PCA Execution")
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(
            pca_count, 0,
            "PCA Execution records must not appear on non-Win11 evidence; got {pca_count}"
        );
    }
}

#[no_mangle]
pub extern "C" fn create_plugin_trace() -> *mut std::ffi::c_void {
    let plugin: Box<dyn StrataPlugin> = Box::new(TracePlugin::new());
    let plugin_holder = Box::new(plugin);
    Box::into_raw(plugin_holder) as *mut std::ffi::c_void
}
