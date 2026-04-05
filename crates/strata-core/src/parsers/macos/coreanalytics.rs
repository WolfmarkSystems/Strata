use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// macOS CoreAnalytics Parser
///
/// Path: /Library/Logs/DiagnosticReports/Analytics_*.core_analytics
///       /private/var/db/analyticsd/
///
/// CoreAnalytics tracks application usage telemetry including launch counts,
/// active duration, background duration, and power impact. Data persists
/// across reboots.
///
/// Forensic value: Proves application execution with frequency and duration.
/// Supplements KnowledgeC with system-level telemetry that is less likely
/// to be cleared by anti-forensic tools.
pub struct CoreAnalyticsParser;

impl Default for CoreAnalyticsParser {
    fn default() -> Self {
        Self::new()
    }
}

impl CoreAnalyticsParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CoreAnalyticsEntry {
    pub app_name: Option<String>,
    pub app_bundle_id: Option<String>,
    pub app_version: Option<String>,
    pub event_type: Option<String>,
    pub timestamp: Option<i64>,
    pub active_duration: Option<f64>,
    pub background_duration: Option<f64>,
    pub launch_count: Option<i32>,
    pub power_impact: Option<f64>,
    pub process_name: Option<String>,
}

impl ArtifactParser for CoreAnalyticsParser {
    fn name(&self) -> &str {
        "macOS CoreAnalytics"
    }

    fn artifact_type(&self) -> &str {
        "application_usage"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec![
            "*.core_analytics",
            "Analytics_*.json",
            "aggregate",
        ]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();
        let source = path.to_string_lossy().to_string();
        let text = String::from_utf8_lossy(data);

        // CoreAnalytics files contain one JSON object per line (JSONL format)
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let Ok(json) = serde_json::from_str::<serde_json::Value>(trimmed) else {
                continue;
            };

            // CoreAnalytics format has a "message" field with app usage data
            if let Some(message) = json.get("message") {
                if let Some(app_descriptions) = message.get("appDescription") {
                    // App usage record
                    let entry = CoreAnalyticsEntry {
                        app_name: app_descriptions
                            .get("processName")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        app_bundle_id: app_descriptions
                            .get("bundleIdentifier")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        app_version: app_descriptions
                            .get("bundleVersion")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        event_type: json
                            .get("name")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        timestamp: json
                            .get("timestamp")
                            .and_then(|v| v.as_str())
                            .and_then(parse_analytics_timestamp),
                        active_duration: message
                            .get("activeDuration")
                            .or(message.get("foregroundDuration"))
                            .and_then(|v| v.as_f64()),
                        background_duration: message
                            .get("backgroundDuration")
                            .and_then(|v| v.as_f64()),
                        launch_count: message
                            .get("launchCount")
                            .and_then(|v| v.as_i64())
                            .map(|v| v as i32),
                        power_impact: message
                            .get("powerImpact")
                            .and_then(|v| v.as_f64()),
                        process_name: app_descriptions
                            .get("processName")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                    };

                    let app = entry
                        .app_bundle_id
                        .as_deref()
                        .or(entry.app_name.as_deref())
                        .unwrap_or("unknown");

                    let mut desc = format!("CoreAnalytics: {}", app);
                    if let Some(launches) = entry.launch_count {
                        desc.push_str(&format!(" (launched {} times)", launches));
                    }
                    if let Some(active) = entry.active_duration {
                        if active > 0.0 {
                            desc.push_str(&format!(" [active: {:.0}s]", active));
                        }
                    }

                    artifacts.push(ParsedArtifact {
                        timestamp: entry.timestamp,
                        artifact_type: "application_usage".to_string(),
                        description: desc,
                        source_path: source.clone(),
                        json_data: serde_json::to_value(&entry).unwrap_or_default(),
                    });
                } else {
                    // Generic analytics event
                    let event_name = json
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");

                    artifacts.push(ParsedArtifact {
                        timestamp: json
                            .get("timestamp")
                            .and_then(|v| v.as_str())
                            .and_then(parse_analytics_timestamp),
                        artifact_type: "system_analytics".to_string(),
                        description: format!("CoreAnalytics Event: {}", event_name),
                        source_path: source.clone(),
                        json_data: json.clone(),
                    });
                }
            }

            if artifacts.len() >= 10000 {
                break;
            }
        }

        Ok(artifacts)
    }
}

fn parse_analytics_timestamp(ts: &str) -> Option<i64> {
    // CoreAnalytics timestamps are ISO 8601 format
    // Try simple epoch parsing first
    if let Ok(epoch) = ts.parse::<i64>() {
        return Some(epoch);
    }
    if let Ok(epoch) = ts.parse::<f64>() {
        return Some(epoch as i64);
    }
    // ISO 8601 parsing would need chrono — return None for now
    None
}
