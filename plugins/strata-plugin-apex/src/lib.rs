//! # Apex — Apple-built app artifacts.
//!
//! Apex owns EXIF, Mail, Calendar, Contacts, Notes (native), Siri,
//! iCloud Drive internals, FaceTime logs. EXIF-1 lands first.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub mod ai_content;
pub mod exif;

use strata_plugin_sdk::{
    Artifact, ArtifactCategory, ArtifactRecord, ForensicValue, PluginCapability, PluginContext,
    PluginError, PluginOutput, PluginResult, PluginSummary, PluginType, StrataPlugin,
};

pub struct ApexPlugin {
    name: String,
    version: String,
}

impl Default for ApexPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl ApexPlugin {
    pub fn new() -> Self {
        Self {
            name: "Strata Apex".to_string(),
            version: "1.0.0".to_string(),
        }
    }
}

impl StrataPlugin for ApexPlugin {
    fn name(&self) -> &str {
        &self.name
    }
    fn version(&self) -> &str {
        &self.version
    }
    fn supported_inputs(&self) -> Vec<String> {
        vec![
            "jpg".to_string(),
            "jpeg".to_string(),
            "heic".to_string(),
            "tif".to_string(),
        ]
    }
    fn plugin_type(&self) -> PluginType {
        PluginType::Analyzer
    }
    fn capabilities(&self) -> Vec<PluginCapability> {
        vec![PluginCapability::ArtifactExtraction]
    }
    fn description(&self) -> &str {
        "Apple-built app artifacts — EXIF, Mail, Calendar, Contacts"
    }

    fn run(&self, ctx: PluginContext) -> PluginResult {
        let root = Path::new(&ctx.root_path);
        let mut out = Vec::new();
        let files = match walk_dir(root) {
            Ok(f) => f,
            Err(_) => return Ok(out),
        };
        for path in files {
            if let Some(rec) = crate::exif::parse(&path) {
                let path_str = rec.path.clone();
                let mut a = Artifact::new("EXIF Metadata", &path_str);
                a.timestamp = rec.date_taken.map(|d| d.timestamp() as u64);
                a.add_field(
                    "title",
                    &format!(
                        "EXIF: {} ({})",
                        rec.device_model.as_deref().unwrap_or("unknown device"),
                        path_str
                    ),
                );
                a.add_field(
                    "detail",
                    &format!(
                        "Make: {} | Model: {} | Software: {} | GPS: {} | Taken: {} | Modified: {} | Size: {}x{}",
                        rec.device_make.as_deref().unwrap_or("-"),
                        rec.device_model.as_deref().unwrap_or("-"),
                        rec.software.as_deref().unwrap_or("-"),
                        if rec.has_gps {
                            format!(
                                "{:.6},{:.6}",
                                rec.gps_latitude.unwrap_or(0.0),
                                rec.gps_longitude.unwrap_or(0.0)
                            )
                        } else {
                            "none".to_string()
                        },
                        rec.date_taken
                            .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                            .unwrap_or_else(|| "-".to_string()),
                        rec.date_modified
                            .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                            .unwrap_or_else(|| "-".to_string()),
                        rec.width.unwrap_or(0),
                        rec.height.unwrap_or(0),
                    ),
                );
                a.add_field("file_type", "EXIF Metadata");
                if let Some(v) = &rec.device_make {
                    a.add_field("device_make", v);
                }
                if let Some(v) = &rec.device_model {
                    a.add_field("device_model", v);
                }
                if let Some(v) = &rec.software {
                    a.add_field("software", v);
                }
                if let Some(v) = rec.gps_latitude {
                    a.add_field("gps_latitude", &format!("{:.6}", v));
                }
                if let Some(v) = rec.gps_longitude {
                    a.add_field("gps_longitude", &format!("{:.6}", v));
                }
                if rec.has_gps {
                    a.add_field("has_gps", "true");
                    a.add_field("mitre", "T1430");
                    a.add_field("forensic_value", "High");
                } else {
                    a.add_field("mitre", "T1592.001");
                    a.add_field("forensic_value", "Medium");
                }
                if rec.timestamp_mismatch {
                    a.add_field("timestamp_mismatch", "true");
                    a.add_field("suspicious", "true");
                }
                if let Some(sw) = &rec.software {
                    let lc = sw.to_ascii_lowercase();
                    if lc.contains("photoshop") || lc.contains("gimp") || lc.contains("lightroom") {
                        a.add_field("possibly_edited", "true");
                    }
                }
                out.push(a);
            }
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
            let is_sus = a
                .data
                .get("suspicious")
                .map(|v| v == "true")
                .unwrap_or(false);
            if is_sus {
                suspicious += 1;
            }
            let category = ArtifactCategory::UserActivity;
            cats.insert(category.as_str().to_string());
            let fv = match a.data.get("forensic_value").map(|s| s.as_str()) {
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
                headline: format!("Apex: {} EXIF records ({} flagged)", total, suspicious),
            },
            warnings: vec![],
        })
    }
}

fn walk_dir(dir: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
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
    fn plugin_metadata() {
        let p = ApexPlugin::new();
        assert_eq!(p.name(), "Strata Apex");
    }
}
