use std::collections::HashSet;
use std::path::Path;
use strata_plugin_sdk::{
    Artifact, ArtifactCategory, ArtifactRecord, ForensicValue, PluginCapability, PluginContext,
    PluginError, PluginOutput, PluginResult, PluginSummary, PluginType, StrataPlugin,
};

pub struct WraithPlugin {
    name: String,
    version: String,
}

impl Default for WraithPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl WraithPlugin {
    pub fn new() -> Self {
        Self {
            name: "Strata Wraith".to_string(),
            version: "1.0.0".to_string(),
        }
    }

    /// Extract printable ASCII strings of minimum length from a byte slice.
    fn extract_strings(data: &[u8], min_len: usize) -> Vec<String> {
        let mut strings = Vec::new();
        let mut current = Vec::new();

        for &byte in data {
            if (0x20..=0x7E).contains(&byte) {
                current.push(byte);
            } else {
                if current.len() >= min_len {
                    if let Ok(s) = String::from_utf8(current.clone()) {
                        strings.push(s);
                    }
                }
                current.clear();
            }
        }
        if current.len() >= min_len {
            if let Ok(s) = String::from_utf8(current) {
                strings.push(s);
            }
        }

        strings
    }

    /// Check if a string looks like a URL.
    fn looks_like_url(s: &str) -> bool {
        s.starts_with("http://") || s.starts_with("https://") || s.starts_with("ftp://")
    }

    /// Check if a string looks like an IPv4 address.
    fn looks_like_ipv4(s: &str) -> bool {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 4 {
            return false;
        }
        parts.iter().all(|p| {
            !p.is_empty() && p.len() <= 3 && p.chars().all(|c| c.is_ascii_digit())
                && p.parse::<u32>().map(|n| n <= 255).unwrap_or(false)
        })
    }

    /// Known malware-related strings to look for in memory.
    const MALWARE_STRINGS: &'static [&'static str] = &[
        "mimikatz", "meterpreter", "cobalt strike", "beacon", "bloodhound",
        "rubeus", "lazagne", "empire", "covenant", "crackmapexec",
    ];

    fn analyze_file(path: &Path) -> Vec<Artifact> {
        let mut results = Vec::new();
        let path_str = path.to_string_lossy();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        let name_lower = name.to_lowercase();
        let path_lower = path_str.to_lowercase();

        // Hibernation file
        if name_lower == "hiberfil.sys" {
            let mut artifact = Artifact::new("SystemActivity", &path_str);
            artifact.add_field("title", "Hibernation File");
            artifact.add_field("file_type", "Hibernation File");

            let detail = if let Ok(mut f) = std::fs::File::open(path) {
                let mut magic = [0u8; 4];
                use std::io::Read;
                if f.read_exact(&mut magic).is_ok() {
                    let magic_str = String::from_utf8_lossy(&magic);
                    if magic_str == "HIBR" || magic_str == "RSTR" || magic_str == "hibr" || magic_str == "rstr" {
                        format!("Valid hibernation file (magic: {}) — contains full RAM snapshot for memory forensics", magic_str)
                    } else {
                        format!("Hibernation file found (magic: {:02X}{:02X}{:02X}{:02X}) — may be compressed or partial", magic[0], magic[1], magic[2], magic[3])
                    }
                } else {
                    "Hibernation file found — could not read magic bytes".to_string()
                }
            } else {
                "Hibernation file found — could not open".to_string()
            };

            artifact.add_field("detail", &detail);
            results.push(artifact);
            return results;
        }

        // Page/Swap file
        if name_lower == "pagefile.sys" || name_lower == "swapfile.sys" {
            let mut artifact = Artifact::new("SystemActivity", &path_str);
            artifact.add_field("title", "Page File Artifact");
            artifact.add_field("file_type", "Page File Artifact");
            artifact.add_field("detail", &format!(
                "{} — virtual memory paging file, may contain fragments of process memory, passwords, and decrypted data",
                name
            ));
            results.push(artifact);
            return results;
        }

        // Crash Dumps
        if name_lower.ends_with(".dmp") && (path_lower.contains("minidump") || name_lower == "memory.dmp") {
            let mut artifact = Artifact::new("SystemActivity", &path_str);
            artifact.add_field("file_type", "Crash Dump");

            let detail = if let Ok(mut f) = std::fs::File::open(path) {
                let mut magic = [0u8; 4];
                use std::io::Read;
                if f.read_exact(&mut magic).is_ok() && &magic == b"MDMP" {
                    "Valid minidump file (MDMP magic) — process crash dump with memory regions".to_string()
                } else {
                    format!("Dump file found (header: {:02X}{:02X}{:02X}{:02X})", magic[0], magic[1], magic[2], magic[3])
                }
            } else {
                "Crash dump file found — could not read header".to_string()
            };

            artifact.add_field("title", &format!("Crash Dump: {}", name));
            artifact.add_field("detail", &detail);
            results.push(artifact);
        }

        // String extraction from .dmp files
        if name_lower.ends_with(".dmp") {
            if let Ok(mut f) = std::fs::File::open(path) {
                use std::io::Read;
                let mut buf = vec![0u8; 1_048_576]; // 1MB
                let bytes_read = f.read(&mut buf).unwrap_or_default();
                if bytes_read > 0 {
                    let strings = Self::extract_strings(&buf[..bytes_read], 12);

                    let mut found_urls = Vec::new();
                    let mut found_ips = Vec::new();
                    let mut found_malware = Vec::new();

                    for s in &strings {
                        let s_lower = s.to_lowercase();
                        if Self::looks_like_url(s) {
                            found_urls.push(s.clone());
                        }
                        // Check for IP-like tokens within strings
                        for token in s.split(|c: char| !c.is_ascii_digit() && c != '.') {
                            if Self::looks_like_ipv4(token) {
                                found_ips.push(token.to_string());
                            }
                        }
                        for malware in Self::MALWARE_STRINGS {
                            if s_lower.contains(malware) {
                                found_malware.push((*malware).to_string());
                            }
                        }
                    }

                    let has_malware = !found_malware.is_empty();

                    if !found_urls.is_empty() || !found_ips.is_empty() || has_malware {
                        let mut artifact = Artifact::new("ExecutionHistory", &path_str);
                        artifact.add_field("title", &format!("Memory Strings: {}", name));
                        artifact.add_field("file_type", "Memory String");

                        let mut detail_parts = Vec::new();
                        if !found_urls.is_empty() {
                            detail_parts.push(format!("{} URLs extracted", found_urls.len()));
                        }
                        if !found_ips.is_empty() {
                            detail_parts.push(format!("{} IP addresses", found_ips.len()));
                        }
                        if has_malware {
                            let unique_malware: HashSet<&str> = found_malware.iter().map(|s| s.as_str()).collect();
                            detail_parts.push(format!(
                                "MALWARE STRINGS: {}",
                                unique_malware.into_iter().collect::<Vec<_>>().join(", ")
                            ));
                        }

                        artifact.add_field("detail", &detail_parts.join(" | "));
                        if has_malware {
                            artifact.add_field("suspicious", "true");
                        }
                        results.push(artifact);
                    }
                }
            }
        }

        results
    }
}

impl StrataPlugin for WraithPlugin {
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
        ]
    }

    fn description(&self) -> &str {
        "Memory artifact analysis \u{2014} hibernation, page files, crash dumps"
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

            let (category, forensic_value) = match file_type.as_str() {
                "Hibernation File" => (ArtifactCategory::SystemActivity, ForensicValue::Critical),
                "Page File Artifact" => (ArtifactCategory::SystemActivity, ForensicValue::High),
                "Crash Dump" => (ArtifactCategory::SystemActivity, ForensicValue::High),
                "Memory String" => (
                    ArtifactCategory::ExecutionHistory,
                    if is_suspicious { ForensicValue::Critical } else { ForensicValue::Medium },
                ),
                _ => (ArtifactCategory::SystemActivity, ForensicValue::Medium),
            };

            records.push(ArtifactRecord {
                category,
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
                    "Wraith: {} memory artifacts, {} suspicious",
                    records.len(),
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
pub extern "C" fn create_plugin_wraith() -> *mut std::ffi::c_void {
    let plugin: Box<dyn StrataPlugin> = Box::new(WraithPlugin::new());
    Box::into_raw(Box::new(plugin)) as *mut std::ffi::c_void
}
