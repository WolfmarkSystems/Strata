//! # Vault — hidden storage, encryption tools, anti-forensic applications.
//!
//! "Find what they tried to hide." Vault specialises in artifacts the
//! subject took deliberate action to conceal: VeraCrypt / TrueCrypt
//! volumes, photo vault apps, anti-forensic tool usage, hidden
//! partitions, steganography indicators, Tor Browser history, and
//! encrypted archives.
//!
//! VAULT-1 scaffolds the plugin; VAULT-2 through VAULT-6 add the
//! per-artifact parsers.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use strata_plugin_sdk::{
    ArtifactCategory, ArtifactRecord, ForensicValue, PluginCapability, PluginContext, PluginError,
    PluginOutput, PluginResult, PluginSummary, PluginType, StrataPlugin,
};

pub mod antiforensic;
pub mod crypto_wallets;
pub mod encrypted_artifacts;
pub mod hidden_partition;
pub mod photo_vault;
pub mod veracrypt;

pub fn name() -> &'static str {
    "Vault"
}

pub fn version() -> &'static str {
    "1.0.0"
}

pub fn description() -> &'static str {
    "Detects hidden storage, encryption tools, anti-forensic applications, \
     and data concealment artifacts. Find what they tried to hide."
}

pub fn color() -> &'static str {
    "#a855f7"
}

pub struct VaultPlugin {
    name: String,
    version: String,
}

impl Default for VaultPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultPlugin {
    pub fn new() -> Self {
        Self {
            name: format!("Strata {}", name()),
            version: version().to_string(),
        }
    }
}

impl StrataPlugin for VaultPlugin {
    fn name(&self) -> &str {
        &self.name
    }
    fn version(&self) -> &str {
        &self.version
    }
    fn supported_inputs(&self) -> Vec<String> {
        vec![
            "vc".to_string(),
            "hc".to_string(),
            "tc".to_string(),
            "axx".to_string(),
            "veracrypt.xml".to_string(),
        ]
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
        let files = match walk_dir(root) {
            Ok(f) => f,
            Err(_) => return Ok(out),
        };
        for path in files {
            out.extend(crate::veracrypt::scan(&path));
            out.extend(crate::photo_vault::scan(&path));
            out.extend(crate::antiforensic::scan(&path));
            out.extend(crate::hidden_partition::scan(&path));
            out.extend(crate::encrypted_artifacts::scan(&path));
            out.extend(crate::crypto_wallets::scan(&path));
        }
        Ok(out)
    }

    fn execute(&self, context: PluginContext) -> Result<PluginOutput, PluginError> {
        let start = std::time::Instant::now();
        let artifacts = self.run(context)?;
        let mut records: Vec<ArtifactRecord> = Vec::new();
        let mut cats: HashSet<String> = HashSet::new();
        let mut suspicious = 0usize;
        for a in &artifacts {
            let file_type = a.data.get("file_type").cloned().unwrap_or_default();
            let is_sus = a.data.get("suspicious").map(|v| v == "true").unwrap_or(false);
            if is_sus {
                suspicious += 1;
            }
            let category = match file_type.as_str() {
                "Secure Messaging App" | "Tor Browser History" => ArtifactCategory::Communications,
                "Photo Vault App" => ArtifactCategory::UserActivity,
                _ => ArtifactCategory::SystemActivity,
            };
            cats.insert(category.as_str().to_string());
            let fv = match a.data.get("forensic_value").map(|s| s.as_str()) {
                Some("Critical") => ForensicValue::Critical,
                Some("High") => ForensicValue::High,
                _ => ForensicValue::Medium,
            };
            records.push(ArtifactRecord {
                category,
                subcategory: file_type,
                timestamp: a.timestamp.map(|t| t as i64),
                title: a
                    .data
                    .get("title")
                    .cloned()
                    .unwrap_or_else(|| a.source.clone()),
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
                headline: format!(
                    "Vault: {} concealment artifacts ({} suspicious)",
                    total, suspicious
                ),
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
        let p = VaultPlugin::new();
        assert_eq!(p.name(), "Strata Vault");
        assert_eq!(p.version(), "1.0.0");
        assert_eq!(color(), "#a855f7");
        assert!(!p.description().is_empty());
    }
}
