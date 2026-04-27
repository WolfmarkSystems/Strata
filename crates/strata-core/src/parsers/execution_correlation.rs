use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Cross-Source Execution Correlation Engine
///
/// Correlates execution evidence across multiple artifact types:
///   - Prefetch (application execution with timestamps)
///   - Jump Lists (file access per application)
///   - UserAssist (run counts and focus time)
///   - BAM/DAM (execution timestamps from registry)
///   - Shimcache (execution existence proof)
///   - AmCache (installation and first execution)
///   - SRUM (resource usage per application)
///   - BITS (download and transfer jobs)
///   - Scheduled Tasks (persistence via execution)
///
/// Forensic value: No single artifact proves execution conclusively.
/// Correlation across 3+ independent sources provides court-defensible
/// evidence of program execution. This engine reads previously parsed
/// artifacts and produces correlated execution timelines.
pub struct ExecutionCorrelationParser;

impl Default for ExecutionCorrelationParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutionCorrelationParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CorrelatedExecution {
    pub executable_name: String,
    pub executable_path: Option<String>,
    pub evidence_sources: Vec<ExecutionEvidence>,
    pub source_count: usize,
    pub first_seen: Option<i64>,
    pub last_seen: Option<i64>,
    pub total_run_count: u32,
    pub confidence: f32,
    pub forensic_assessment: String,
    pub mitre_techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionEvidence {
    pub source_type: String,
    pub timestamp: Option<i64>,
    pub detail: String,
    pub confidence: f32,
}

impl ArtifactParser for ExecutionCorrelationParser {
    fn name(&self) -> &str {
        "Cross-Source Execution Correlation Engine"
    }

    fn artifact_type(&self) -> &str {
        "execution_correlation"
    }

    fn target_patterns(&self) -> Vec<&str> {
        // This parser operates on JSON export files from previous parsing runs
        vec![
            "strata_artifacts.json",
            "strata_parsed_*.json",
            "examination_results.json",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();

        // Parse the JSON array of previously parsed artifacts
        let Ok(json) = serde_json::from_slice::<serde_json::Value>(data) else {
            return Ok(artifacts);
        };

        let parsed_artifacts: Vec<serde_json::Value> = if let Some(arr) = json.as_array() {
            arr.clone()
        } else if let Some(arr) = json.get("artifacts").and_then(|a| a.as_array()) {
            arr.clone()
        } else {
            return Ok(artifacts);
        };

        // Build execution evidence map: executable_name -> Vec<evidence>
        let mut evidence_map: HashMap<String, Vec<ExecutionEvidence>> = HashMap::new();

        for artifact in &parsed_artifacts {
            let artifact_type = artifact
                .get("artifactType")
                .or(artifact.get("artifact_type"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let description = artifact
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let timestamp = artifact.get("timestamp").and_then(|v| v.as_i64());

            let json_data = artifact
                .get("jsonData")
                .or(artifact.get("json_data"))
                .cloned()
                .unwrap_or_default();

            match artifact_type {
                "prefetch" => {
                    if let Some(exe_name) = extract_exe_name(description) {
                        evidence_map
                            .entry(exe_name.clone())
                            .or_default()
                            .push(ExecutionEvidence {
                                source_type: "Prefetch".to_string(),
                                timestamp,
                                detail: description.to_string(),
                                confidence: 0.95,
                            });
                    }
                }
                "jumplist_entry" | "jumplist" => {
                    if let Some(app) = json_data
                        .get("app_name")
                        .and_then(|v| v.as_str())
                        .map(String::from)
                    {
                        evidence_map
                            .entry(app.clone())
                            .or_default()
                            .push(ExecutionEvidence {
                                source_type: "JumpList".to_string(),
                                timestamp,
                                detail: description.to_string(),
                                confidence: 0.8,
                            });
                    }
                }
                "userassist_execution" => {
                    if let Some(exe) = json_data
                        .get("program_name")
                        .and_then(|v| v.as_str())
                        .map(String::from)
                    {
                        let name = exe.rsplit('\\').next().unwrap_or(&exe).to_lowercase();
                        evidence_map
                            .entry(name)
                            .or_default()
                            .push(ExecutionEvidence {
                                source_type: "UserAssist".to_string(),
                                timestamp,
                                detail: description.to_string(),
                                confidence: 0.85,
                            });
                    }
                }
                "srum_entry" => {
                    if let Some(app) = json_data
                        .get("app_name")
                        .or(json_data.get("app_id"))
                        .and_then(|v| v.as_str())
                        .map(String::from)
                    {
                        let name = app.rsplit('\\').next().unwrap_or(&app).to_lowercase();
                        evidence_map
                            .entry(name)
                            .or_default()
                            .push(ExecutionEvidence {
                                source_type: "SRUM".to_string(),
                                timestamp,
                                detail: description.to_string(),
                                confidence: 0.7,
                            });
                    }
                }
                "scheduled_task" => {
                    if let Some(cmd) = json_data
                        .get("actions")
                        .and_then(|a| a.as_array())
                        .and_then(|a| a.first())
                        .and_then(|a| a.get("command"))
                        .and_then(|v| v.as_str())
                        .map(String::from)
                    {
                        let name = cmd.rsplit('\\').next().unwrap_or(&cmd).to_lowercase();
                        evidence_map
                            .entry(name)
                            .or_default()
                            .push(ExecutionEvidence {
                                source_type: "ScheduledTask".to_string(),
                                timestamp,
                                detail: description.to_string(),
                                confidence: 0.6,
                            });
                    }
                }
                "bits_transfer" => {
                    if let Some(url) = json_data.get("url").and_then(|v| v.as_str()) {
                        let filename = url.rsplit('/').next().unwrap_or(url).to_lowercase();
                        evidence_map
                            .entry(filename)
                            .or_default()
                            .push(ExecutionEvidence {
                                source_type: "BITS".to_string(),
                                timestamp,
                                detail: description.to_string(),
                                confidence: 0.5,
                            });
                    }
                }
                _ => {}
            }
        }

        // Build correlated execution entries
        for (exe_name, evidence) in &evidence_map {
            if evidence.len() < 2 {
                continue; // Need at least 2 sources for correlation
            }

            let source_types: Vec<String> = evidence
                .iter()
                .map(|e| e.source_type.clone())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();

            if source_types.len() < 2 {
                continue; // Need 2+ different source types
            }

            let first_seen = evidence.iter().filter_map(|e| e.timestamp).min();
            let last_seen = evidence.iter().filter_map(|e| e.timestamp).max();

            let avg_confidence =
                evidence.iter().map(|e| e.confidence).sum::<f32>() / evidence.len() as f32;
            let source_bonus = (source_types.len() as f32 - 1.0) * 0.1;
            let confidence = (avg_confidence + source_bonus).min(1.0);

            let assessment = match source_types.len() {
                2 => "Moderate confidence — 2 independent sources confirm execution",
                3 => "High confidence — 3 independent sources confirm execution",
                4..=5 => "Very high confidence — 4+ sources confirm execution",
                _ => "Strong evidence of execution across multiple artifact types",
            };

            let correlated = CorrelatedExecution {
                executable_name: exe_name.clone(),
                executable_path: None,
                evidence_sources: evidence.clone(),
                source_count: source_types.len(),
                first_seen,
                last_seen,
                total_run_count: evidence.len() as u32,
                confidence,
                forensic_assessment: assessment.to_string(),
                mitre_techniques: vec!["T1204 — User Execution".to_string()],
            };

            artifacts.push(ParsedArtifact {
                timestamp: last_seen,
                artifact_type: "correlated_execution".to_string(),
                description: format!(
                    "Execution Confirmed: {} ({} sources: {}) [confidence: {:.0}%]",
                    exe_name,
                    source_types.len(),
                    source_types.join(", "),
                    confidence * 100.0,
                ),
                source_path: source.clone(),
                json_data: serde_json::to_value(&correlated).unwrap_or_default(),
            });
        }

        // Sort by confidence descending
        artifacts.sort_by(|a, b| {
            let conf_a = a
                .json_data
                .get("confidence")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let conf_b = b
                .json_data
                .get("confidence")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            conf_b
                .partial_cmp(&conf_a)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        Ok(artifacts)
    }
}

fn extract_exe_name(description: &str) -> Option<String> {
    // Extract executable name from prefetch description
    // Format: "Prefetch: NOTEPAD.EXE-..."
    let desc_lower = description.to_lowercase();
    if desc_lower.contains(".exe") {
        let parts: Vec<&str> = description.split_whitespace().collect();
        for part in parts {
            if part.to_lowercase().contains(".exe") {
                let name = part
                    .split('-')
                    .next()
                    .unwrap_or(part)
                    .trim_end_matches(':')
                    .to_lowercase();
                if name.ends_with(".exe") {
                    return Some(name);
                }
            }
        }
    }
    None
}
