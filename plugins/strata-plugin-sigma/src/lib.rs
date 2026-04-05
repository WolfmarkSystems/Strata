use std::collections::{HashMap, HashSet};
use strata_plugin_sdk::{
    Artifact, ArtifactCategory, ArtifactRecord, ForensicValue, PluginCapability, PluginContext,
    PluginError, PluginOutput, PluginResult, PluginSummary, PluginType, StrataPlugin,
};

pub struct SigmaPlugin {
    name: String,
    version: String,
}

impl Default for SigmaPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl SigmaPlugin {
    pub fn new() -> Self {
        Self {
            name: "Strata Sigma".to_string(),
            version: "1.0.0".to_string(),
        }
    }

    /// Kill chain tactics in ATT&CK order.
    const KILL_CHAIN: &'static [&'static str] = &[
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "C2",
        "Exfiltration",
        "Impact",
    ];

    /// Map MITRE technique IDs to kill chain tactics.
    fn technique_to_tactic(technique: &str) -> Option<&'static str> {
        // Strip sub-technique (e.g. T1059.001 -> T1059)
        let base = if let Some(dot_idx) = technique.find('.') {
            &technique[..dot_idx]
        } else {
            technique
        };

        match base {
            "T1059" | "T1204" | "T1203" => Some("Execution"),
            "T1053" | "T1547" | "T1197" | "T1137" | "T1543" => Some("Persistence"),
            "T1055" | "T1134" => Some("Privilege Escalation"),
            "T1070" | "T1140" | "T1218" | "T1562" | "T1222" | "T1202" | "T1127" => {
                Some("Defense Evasion")
            }
            "T1555" | "T1003" => Some("Credential Access"),
            "T1016" | "T1033" | "T1049" | "T1057" | "T1082" | "T1083" => Some("Discovery"),
            "T1021" | "T1570" => Some("Lateral Movement"),
            "T1213" | "T1005" | "T1039" | "T1074" => Some("Collection"),
            "T1071" | "T1105" | "T1572" | "T1133" => Some("C2"),
            "T1567" | "T1048" => Some("Exfiltration"),
            "T1486" | "T1490" | "T1485" | "T1565" => Some("Impact"),
            "T1078" | "T1190" | "T1566" => Some("Initial Access"),
            "T1047" => Some("Execution"),
            _ => None,
        }
    }
}

impl StrataPlugin for SigmaPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn supported_inputs(&self) -> Vec<String> {
        vec!["plugin_results_json".to_string()]
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
        "Threat correlation engine \u{2014} maps artifacts to MITRE ATT&CK"
    }

    fn run(&self, ctx: PluginContext) -> PluginResult {
        let mut results = Vec::new();

        // Use prior_results from context (populated by AppState)
        if ctx.prior_results.is_empty() {
            let mut artifact = Artifact::new("SystemActivity", "sigma");
            artifact.add_field("title", "Sigma: No Input Data");
            artifact.add_field(
                "detail",
                "Run other plugins first \u{2014} Sigma correlates results from all Strata plugins",
            );
            results.push(artifact);
            return Ok(results);
        }

        // Collect all artifact records from prior plugin runs
        let all_records: Vec<&strata_plugin_sdk::ArtifactRecord> = ctx
            .prior_results
            .iter()
            .flat_map(|o| o.artifacts.iter())
            .collect();

        let total_artifacts = all_records.len();
        let suspicious_count = all_records.iter().filter(|r| r.is_suspicious).count();

        // Aggregate: count artifacts per MITRE technique
        let mut technique_counts: HashMap<String, usize> = HashMap::new();
        let mut tactics_seen: HashSet<String> = HashSet::new();

        for record in &all_records {
            if let Some(ref technique) = record.mitre_technique {
                if !technique.is_empty() {
                    *technique_counts.entry(technique.clone()).or_insert(0) += 1;
                    if let Some(tactic) = Self::technique_to_tactic(technique) {
                        tactics_seen.insert(tactic.to_string());
                    }
                }
            }
        }

        // Build kill chain coverage artifact
        let mut coverage_lines = Vec::new();
        for &tactic in Self::KILL_CHAIN {
            let covered = tactics_seen.contains(tactic);
            let marker = if covered { "[X]" } else { "[ ]" };
            coverage_lines.push(format!("{} {}", marker, tactic));
        }

        let mut kc_artifact = Artifact::new("SystemActivity", "sigma");
        kc_artifact.add_field("title", "Kill Chain Coverage");
        kc_artifact.add_field("file_type", "Kill Chain Coverage");
        kc_artifact.add_field(
            "detail",
            &format!(
                "{}/{} tactics covered | {}",
                tactics_seen.len(),
                Self::KILL_CHAIN.len(),
                coverage_lines.join(" | "),
            ),
        );
        results.push(kc_artifact);

        // Build technique breakdown string
        let mut technique_lines: Vec<String> = technique_counts
            .iter()
            .map(|(t, c)| {
                let tactic = Self::technique_to_tactic(t).unwrap_or("Unknown");
                format!("{} ({}) x{}", t, tactic, c)
            })
            .collect();
        technique_lines.sort();

        // Determine threat level
        let threat_level = if suspicious_count > 10 || tactics_seen.len() >= 6 {
            "HIGH"
        } else if suspicious_count > 3 || tactics_seen.len() >= 3 {
            "MEDIUM"
        } else {
            "LOW"
        };

        // Build summary artifact
        let headline = format!(
            "Threat Level: {} | {} artifacts, {} suspicious, {}/{} kill chain tactics covered",
            threat_level,
            total_artifacts,
            suspicious_count,
            tactics_seen.len(),
            Self::KILL_CHAIN.len(),
        );

        let detail = format!(
            "{} | Technique breakdown: {}",
            headline,
            if technique_lines.is_empty() {
                "No MITRE techniques mapped".to_string()
            } else {
                technique_lines.join(", ")
            },
        );

        let mut summary_artifact = Artifact::new("SystemActivity", "sigma");
        summary_artifact.add_field("title", "Sigma Threat Assessment");
        summary_artifact.add_field("file_type", "Sigma Threat Assessment");
        summary_artifact.add_field("detail", &detail);
        if threat_level == "HIGH" {
            summary_artifact.add_field("suspicious", "true");
        }
        results.push(summary_artifact);

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
                "Sigma Threat Assessment" => {
                    if is_suspicious {
                        ForensicValue::Critical
                    } else {
                        ForensicValue::High
                    }
                }
                "Kill Chain Coverage" => ForensicValue::High,
                "Sigma Notice" => ForensicValue::Informational,
                "Sigma Error" => ForensicValue::Low,
                _ => ForensicValue::Medium,
            };

            records.push(ArtifactRecord {
                category: ArtifactCategory::SystemActivity,
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
                mitre_technique: None,
                is_suspicious,
                raw_data: None,
            });
        }

        let suspicious_count = records.iter().filter(|r| r.is_suspicious).count();

        // Extract headline from the summary artifact
        let headline = records
            .iter()
            .find(|r| r.subcategory == "Sigma Threat Assessment")
            .map(|r| r.title.clone())
            .unwrap_or_else(|| format!("Sigma: {} records", records.len()));

        Ok(PluginOutput {
            plugin_name: self.name().to_string(),
            plugin_version: self.version().to_string(),
            executed_at: String::new(),
            duration_ms: start.elapsed().as_millis() as u64,
            artifacts: records.clone(),
            summary: PluginSummary {
                total_artifacts: records.len(),
                suspicious_count,
                categories_populated: vec!["System Activity".to_string()],
                headline,
            },
            warnings: vec![],
        })
    }
}

#[no_mangle]
pub extern "C" fn create_plugin_sigma() -> *mut std::ffi::c_void {
    let plugin: Box<dyn StrataPlugin> = Box::new(SigmaPlugin::new());
    Box::into_raw(Box::new(plugin)) as *mut std::ffi::c_void
}
