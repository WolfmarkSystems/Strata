//! # ARBOR — Linux and Unix system forensic artifacts.
//!
//! Owns shell history, persistence mechanisms, user activity, and
//! system configuration changes on Linux/Unix evidence.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub mod logs;
pub mod persistence;
pub mod shell_artifacts;
pub mod system_artifacts;

use strata_plugin_sdk::{
    ArtifactCategory, ArtifactRecord, ForensicValue, PluginCapability, PluginContext, PluginError,
    PluginOutput, PluginResult, PluginSummary, PluginType, StrataPlugin,
};

pub fn name() -> &'static str {
    "ARBOR"
}

pub fn description() -> &'static str {
    "Linux and Unix system forensic artifacts. Shell history, persistence mechanisms, \
     user activity, and system configuration changes."
}

pub fn color() -> &'static str {
    "#22d3ee"
}

pub struct ArborPlugin {
    name: String,
    version: String,
}

impl Default for ArborPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl ArborPlugin {
    pub fn new() -> Self {
        Self {
            name: "Strata ARBOR".to_string(),
            version: "1.0.0".to_string(),
        }
    }
}

impl StrataPlugin for ArborPlugin {
    fn name(&self) -> &str {
        &self.name
    }
    fn version(&self) -> &str {
        &self.version
    }
    fn supported_inputs(&self) -> Vec<String> {
        vec!["bash_history".into(), "zsh_history".into(), "fish_history".into()]
    }
    fn plugin_type(&self) -> PluginType {
        PluginType::Analyzer
    }
    fn capabilities(&self) -> Vec<PluginCapability> {
        vec![PluginCapability::ArtifactExtraction]
    }
    fn description(&self) -> &str {
        description()
    }

    fn run(&self, ctx: PluginContext) -> PluginResult {
        let root = Path::new(&ctx.root_path);
        let mut out = Vec::new();
        for path in walk_dir(root).unwrap_or_default() {
            out.extend(crate::shell_artifacts::scan(&path));
        }
        Ok(out)
    }

    fn execute(&self, context: PluginContext) -> Result<PluginOutput, PluginError> {
        let start = std::time::Instant::now();
        let artifacts = self.run(context)?;
        let mut records = Vec::new();
        let mut cats: HashSet<String> = HashSet::new();
        let mut suspicious = 0usize;
        for a in &artifacts {
            let ft = a.data.get("file_type").cloned().unwrap_or_default();
            let is_sus = a.data.get("suspicious").map(|s| s == "true").unwrap_or(false);
            if is_sus {
                suspicious += 1;
            }
            let category = ArtifactCategory::SystemActivity;
            cats.insert(category.as_str().to_string());
            let fv = match a.data.get("forensic_value").map(|s| s.as_str()) {
                Some("High") => ForensicValue::High,
                Some("Critical") => ForensicValue::Critical,
                _ => ForensicValue::Medium,
            };
            records.push(ArtifactRecord {
                category,
                subcategory: ft,
                timestamp: a.timestamp.map(|t| t as i64),
                title: a.data.get("title").cloned().unwrap_or_else(|| a.source.clone()),
                detail: a.data.get("detail").cloned().unwrap_or_default(),
                source_path: a.source.clone(),
                forensic_value: fv,
                mitre_technique: a.data.get("mitre").cloned(),
                is_suspicious: is_sus,
                raw_data: None,
                confidence: 0,
            });
        }
        let total = records.len();
        Ok(PluginOutput {
            plugin_name: self.name().to_string(),
            plugin_version: self.version().to_string(),
            executed_at: chrono::Utc::now().to_rfc3339(),
            duration_ms: start.elapsed().as_millis() as u64,
            artifacts: records,
            summary: PluginSummary {
                total_artifacts: total,
                suspicious_count: suspicious,
                categories_populated: cats.into_iter().collect(),
                headline: format!("ARBOR: {} Linux artifacts ({} suspicious)", total, suspicious),
            },
            warnings: vec![],
        })
    }
}

pub fn walk_dir(dir: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut paths = Vec::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let p = entry.path();
            if p.is_dir() {
                if let Ok(sub) = walk_dir(&p) {
                    paths.extend(sub);
                }
            } else {
                paths.push(p);
            }
        }
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_metadata_shape() {
        let p = ArborPlugin::new();
        assert_eq!(p.name(), "Strata ARBOR");
        assert_eq!(color(), "#22d3ee");
    }
}
