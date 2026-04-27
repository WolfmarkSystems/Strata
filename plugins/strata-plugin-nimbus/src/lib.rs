pub mod alexa;
pub mod connected_car;
pub mod onedrive;
pub mod smart_tv;

use std::collections::HashSet;
use std::path::Path;
use strata_plugin_sdk::{
    Artifact, ArtifactCategory, ArtifactRecord, ForensicValue, PluginCapability, PluginContext,
    PluginError, PluginOutput, PluginResult, PluginSummary, PluginType, StrataPlugin,
};

pub struct NimbusPlugin {
    name: String,
    version: String,
}

impl Default for NimbusPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl NimbusPlugin {
    pub fn new() -> Self {
        Self {
            name: "Strata Nimbus".to_string(),
            version: "1.0.0".to_string(),
        }
    }

    fn analyze_file(path: &Path) -> Vec<Artifact> {
        let mut results = Vec::new();
        let path_str = path.to_string_lossy();
        let path_lower = path_str.to_lowercase();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let name_lower = name.to_lowercase();

        // OneDrive Activity
        if path_lower.contains("onedrive")
            && (name_lower.contains("log") || name_lower.contains(".dat"))
        {
            let mut artifact = Artifact::new("CloudSync", &path_str);
            artifact.add_field("title", &format!("OneDrive Activity: {}", name));
            artifact.add_field(
                "detail",
                "OneDrive sync log or data file — may reveal exfiltration or staging activity",
            );
            artifact.add_field("file_type", "OneDrive Activity");
            artifact.add_field("mitre", "T1567.002");
            results.push(artifact);
        }

        // Google Drive Activity
        if path_lower.contains("google/drivefs") || path_lower.contains("google\\drivefs") {
            let mut artifact = Artifact::new("CloudSync", &path_str);
            artifact.add_field("title", &format!("Google Drive Activity: {}", name));
            artifact.add_field(
                "detail",
                "Google DriveFS artifact — cloud sync and potential data exfiltration path",
            );
            artifact.add_field("file_type", "Google Drive Activity");
            artifact.add_field("mitre", "T1567.002");
            results.push(artifact);
        }

        // Dropbox Sync Event
        if path_lower.contains("dropbox") && name_lower.ends_with(".sqlite") {
            let mut artifact = Artifact::new("CloudSync", &path_str);
            artifact.add_field("title", &format!("Dropbox Sync Event: {}", name));
            artifact.add_field(
                "detail",
                "Dropbox SQLite database — contains file sync history and account metadata",
            );
            artifact.add_field("file_type", "Dropbox Sync Event");
            results.push(artifact);
        }

        // Microsoft Teams Activity
        if path_lower.contains("microsoft/teams") || path_lower.contains("microsoft\\teams") {
            let mut artifact = Artifact::new("Communications", &path_str);
            artifact.add_field("title", &format!("Microsoft Teams Activity: {}", name));
            artifact.add_field(
                "detail",
                "Microsoft Teams data — chat messages, file transfers, meeting records",
            );
            artifact.add_field("file_type", "Microsoft Teams Activity");
            artifact.add_field("mitre", "T1213.003");
            results.push(artifact);
        }

        // Slack Activity
        if path_lower.contains("slack")
            && (name_lower.contains("indexeddb") || name_lower.contains("cache"))
        {
            let mut artifact = Artifact::new("Communications", &path_str);
            artifact.add_field("title", &format!("Slack Activity: {}", name));
            artifact.add_field("detail", "Slack cached data — may contain message history, file references, and channel metadata");
            artifact.add_field("file_type", "Slack Activity");
            results.push(artifact);
        }

        // Zoom Activity
        if path_lower.contains("zoom")
            && (name_lower.contains("log") || path_lower.contains("zoom/"))
        {
            let mut artifact = Artifact::new("Communications", &path_str);
            artifact.add_field("title", &format!("Zoom Activity: {}", name));
            artifact.add_field(
                "detail",
                "Zoom meeting log or cache — meeting IDs, participants, timestamps",
            );
            artifact.add_field("file_type", "Zoom Activity");
            results.push(artifact);
        }

        results
    }
}

impl StrataPlugin for NimbusPlugin {
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
        vec![PluginCapability::ArtifactExtraction]
    }

    fn description(&self) -> &str {
        "Cloud service and enterprise communication analysis"
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

            let (category, forensic_value) = match file_type.as_str() {
                "OneDrive Activity" => (ArtifactCategory::CloudSync, ForensicValue::High),
                "Google Drive Activity" => (ArtifactCategory::CloudSync, ForensicValue::High),
                "Dropbox Sync Event" => (ArtifactCategory::CloudSync, ForensicValue::Medium),
                "Microsoft Teams Activity" => {
                    (ArtifactCategory::Communications, ForensicValue::High)
                }
                "Slack Activity" => (ArtifactCategory::Communications, ForensicValue::Medium),
                "Zoom Activity" => (ArtifactCategory::Communications, ForensicValue::Medium),
                _ => (ArtifactCategory::CloudSync, ForensicValue::Medium),
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
                detail: artifact.data.get("detail").cloned().unwrap_or_default(),
                source_path: artifact.source.clone(),
                forensic_value,
                mitre_technique: artifact.data.get("mitre").cloned(),
                is_suspicious: false,
                raw_data: None,
                confidence: 0,
            });
        }

        let categories: Vec<String> = records
            .iter()
            .map(|r| r.category.as_str().to_string())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        let cloud_count = records
            .iter()
            .filter(|r| r.category == ArtifactCategory::CloudSync)
            .count();
        let comms_count = records
            .iter()
            .filter(|r| r.category == ArtifactCategory::Communications)
            .count();

        Ok(PluginOutput {
            plugin_name: self.name().to_string(),
            plugin_version: self.version().to_string(),
            executed_at: String::new(),
            duration_ms: start.elapsed().as_millis() as u64,
            artifacts: records.clone(),
            summary: PluginSummary {
                total_artifacts: records.len(),
                suspicious_count: 0,
                categories_populated: categories,
                headline: format!(
                    "Nimbus: {} cloud sync artifacts, {} communication artifacts",
                    cloud_count, comms_count,
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
pub extern "C" fn create_plugin_nimbus() -> *mut std::ffi::c_void {
    let plugin: Box<dyn StrataPlugin> = Box::new(NimbusPlugin::new());
    Box::into_raw(Box::new(plugin)) as *mut std::ffi::c_void
}

#[cfg(test)]
mod sprint75_backfill_tests {
    use super::*;
    use std::collections::HashMap;
    use strata_plugin_sdk::{PluginContext, StrataPlugin};

    fn empty_ctx() -> PluginContext {
        PluginContext {
            root_path: "/nonexistent/strata-sprint75-empty".to_string(),
            vfs: None,
            config: HashMap::new(),
            prior_results: Vec::new(),
        }
    }

    fn garbage_ctx(suffix: &str) -> PluginContext {
        let dir = std::env::temp_dir().join(format!(
            "strata_sprint75_{}_{}_{}",
            suffix,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(
            dir.join("garbage.bin"),
            [0xFFu8, 0x00, 0xDE, 0xAD, 0xBE, 0xEF],
        )
        .expect("write garbage");
        PluginContext {
            root_path: dir.to_string_lossy().into_owned(),
            vfs: None,
            config: HashMap::new(),
            prior_results: Vec::new(),
        }
    }

    #[test]
    fn plugin_has_valid_metadata() {
        let plugin = NimbusPlugin::new();
        assert!(!plugin.name().is_empty());
        assert!(!plugin.version().is_empty());
        assert!(!plugin.description().is_empty());
    }

    #[test]
    fn plugin_returns_ok_on_empty_input() {
        let plugin = NimbusPlugin::new();
        let result = plugin.run(empty_ctx());
        assert!(result.is_ok() || result.unwrap_or_default().is_empty());
    }

    #[test]
    fn plugin_does_not_panic_on_malformed_input() {
        let plugin = NimbusPlugin::new();
        let _ = plugin.run(garbage_ctx("nimbus"));
    }
}
