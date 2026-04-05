use std::collections::HashSet;
use std::path::Path;
use strata_plugin_sdk::{
    Artifact, ArtifactCategory, ArtifactRecord, ForensicValue, PluginCapability, PluginContext,
    PluginError, PluginOutput, PluginResult, PluginSummary, PluginType, StrataPlugin,
};

pub struct ConduitPlugin {
    name: String,
    version: String,
}

impl Default for ConduitPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl ConduitPlugin {
    pub fn new() -> Self {
        Self {
            name: "Strata Conduit".to_string(),
            version: "1.0.0".to_string(),
        }
    }

    fn analyze_file(path: &Path) -> Vec<Artifact> {
        let mut results = Vec::new();
        let path_str = path.to_string_lossy();
        let path_lower = path_str.to_lowercase();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        let name_lower = name.to_lowercase();

        // Network Profile detection
        if path_lower.contains("networklist/profiles") || path_lower.contains("networklist\\profiles") {
            let mut artifact = Artifact::new("NetworkArtifacts", &path_str);
            artifact.add_field("title", &format!("Network Profile: {}", name));
            artifact.add_field("detail", "Windows network profile entry — records previously connected networks");
            artifact.add_field("file_type", "Network Profile");
            results.push(artifact);
        }

        // Network Interface Config
        if path_lower.contains("tcpip/parameters/interfaces") || path_lower.contains("tcpip\\parameters\\interfaces") {
            let mut artifact = Artifact::new("NetworkArtifacts", &path_str);
            artifact.add_field("title", &format!("Network Interface Config: {}", name));
            artifact.add_field("detail", "TCP/IP interface configuration — IP addresses, DNS servers, DHCP settings");
            artifact.add_field("file_type", "Network Interface Config");
            results.push(artifact);
        }

        // VPN Profile detection
        if path_lower.contains("anyconnect") || name_lower.contains("rasphone.pbk") {
            let mut artifact = Artifact::new("NetworkArtifacts", &path_str);
            artifact.add_field("title", &format!("VPN Profile: {}", name));
            artifact.add_field("detail", "VPN connection profile detected — may indicate remote access capability");
            artifact.add_field("file_type", "VPN Profile");
            artifact.add_field("mitre", "T1133");
            results.push(artifact);
        }

        // RDP Connection History
        if path_lower.contains("terminal server client") || path_lower.contains("terminal server client") {
            let mut artifact = Artifact::new("NetworkArtifacts", &path_str);
            artifact.add_field("title", &format!("RDP Connection History: {}", name));
            artifact.add_field("detail", "Remote Desktop connection history — lateral movement indicator");
            artifact.add_field("file_type", "RDP Connection History");
            artifact.add_field("mitre", "T1021.001");
            artifact.add_field("suspicious", "true");
            results.push(artifact);
        }

        // Hosts File Entry
        if name_lower == "hosts" && (path_lower.contains("drivers/etc") || path_lower.contains("drivers\\etc") || path_lower == "/etc/hosts") {
            let mut artifact = Artifact::new("NetworkArtifacts", &path_str);
            artifact.add_field("title", "Hosts File Entry");

            // Read content to check for suspicious entries
            let detail = if let Ok(content) = std::fs::read_to_string(path) {
                let custom_entries: Vec<&str> = content
                    .lines()
                    .filter(|l| {
                        let trimmed = l.trim();
                        !trimmed.is_empty() && !trimmed.starts_with('#') && !trimmed.contains("localhost")
                    })
                    .collect();
                if custom_entries.is_empty() {
                    "Hosts file found — no custom entries beyond localhost".to_string()
                } else {
                    format!(
                        "Hosts file with {} custom entries — possible DNS hijacking",
                        custom_entries.len()
                    )
                }
            } else {
                "Hosts file found — could not read contents".to_string()
            };

            artifact.add_field("detail", &detail);
            artifact.add_field("file_type", "Hosts File Entry");
            artifact.add_field("mitre", "T1565.001");
            results.push(artifact);
        }

        // Mounted Network Share
        if path_lower.contains("mountpoints2") {
            let mut artifact = Artifact::new("NetworkArtifacts", &path_str);
            artifact.add_field("title", &format!("Mounted Network Share: {}", name));
            artifact.add_field("detail", "MountPoints2 registry key — records mounted network shares and drives");
            artifact.add_field("file_type", "Mounted Network Share");
            artifact.add_field("mitre", "T1021.002");
            results.push(artifact);
        }

        // SRUM Network Usage
        if path_lower.contains("srudb") {
            let mut artifact = Artifact::new("NetworkArtifacts", &path_str);
            artifact.add_field("title", &format!("SRUM Network Usage: {}", name));
            artifact.add_field("detail", "System Resource Usage Monitor database — per-application network byte counts");
            artifact.add_field("file_type", "SRUM Network Usage");
            results.push(artifact);
        }

        results
    }
}

impl StrataPlugin for ConduitPlugin {
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
            PluginCapability::NetworkArtifacts,
            PluginCapability::ArtifactExtraction,
        ]
    }

    fn description(&self) -> &str {
        "Network connection and communication channel analysis"
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
                "RDP Connection History" => ForensicValue::Critical,
                "VPN Profile" => ForensicValue::High,
                "Hosts File Entry" => ForensicValue::High,
                "Mounted Network Share" => ForensicValue::High,
                "SRUM Network Usage" => ForensicValue::High,
                _ => ForensicValue::Medium,
            };

            records.push(ArtifactRecord {
                category: ArtifactCategory::NetworkArtifacts,
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
                    "Conduit: {} network artifacts, {} suspicious",
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
pub extern "C" fn create_plugin() -> *mut std::ffi::c_void {
    let plugin: Box<dyn StrataPlugin> = Box::new(ConduitPlugin::new());
    Box::into_raw(Box::new(plugin)) as *mut std::ffi::c_void
}
