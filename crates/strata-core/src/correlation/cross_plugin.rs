//! Cross-plugin correlation pass.
//!
//! Runs after every plugin has produced its artifacts. Walks the full
//! artifact set looking for shared indicators (IP, username, file
//! hash, domain, timestamp window) that span plugins — these become
//! the highest-value findings because they prove the story across
//! multiple evidence sources.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use strata_plugin_sdk::Artifact;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CrossPluginFinding {
    pub correlation_type: String,
    pub shared_value: String,
    pub artifact_descriptions: Vec<String>,
    pub plugins_involved: Vec<String>,
    pub earliest: Option<DateTime<Utc>>,
    pub latest: Option<DateTime<Utc>>,
    pub confidence: f64,
    pub mitre_technique: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub struct CorrelatorConfig {
    pub time_window: Duration,
    pub min_artifacts: usize,
}

impl Default for CorrelatorConfig {
    fn default() -> Self {
        Self {
            time_window: Duration::seconds(60),
            min_artifacts: 2,
        }
    }
}

const CORRELATED_KEYS: &[(&str, &str, &str)] = &[
    ("IpAddress", "dst_ip", "T1071"),
    ("IpAddress", "src_ip", "T1071"),
    ("IpAddress", "client_ip", "T1071"),
    ("IpAddress", "ip", "T1071"),
    ("Username", "username", "T1078"),
    ("Username", "user_id", "T1078"),
    ("Username", "account", "T1078"),
    ("FileHash", "sha256", "T1588.001"),
    ("FileHash", "md5", "T1588.001"),
    ("Domain", "domain", "T1071.004"),
    ("Domain", "query_name", "T1071.004"),
];

pub fn correlate(
    artifacts: &[Artifact],
    config: &CorrelatorConfig,
) -> Vec<CrossPluginFinding> {
    let mut findings = Vec::new();
    for (correlation_type, field, mitre) in CORRELATED_KEYS {
        let mut buckets: BTreeMap<String, Vec<&Artifact>> = BTreeMap::new();
        for a in artifacts {
            if let Some(v) = a.data.get(*field) {
                if !v.is_empty() {
                    buckets.entry(v.clone()).or_default().push(a);
                }
            }
        }
        for (value, arts) in buckets {
            if arts.len() < config.min_artifacts {
                continue;
            }
            let plugins: Vec<String> = unique(arts
                .iter()
                .map(|a| {
                    a.data
                        .get("plugin")
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string())
                })
                .collect());
            if plugins.len() < 2 {
                continue;
            }
            let timestamps: Vec<DateTime<Utc>> = arts
                .iter()
                .filter_map(|a| {
                    a.timestamp
                        .and_then(|s| DateTime::<Utc>::from_timestamp(s as i64, 0))
                })
                .collect();
            let (earliest, latest) = (timestamps.iter().min().copied(), timestamps.iter().max().copied());
            let window_ok = match (earliest, latest) {
                (Some(a), Some(b)) => b - a <= config.time_window,
                _ => true,
            };
            if !window_ok {
                continue;
            }
            let confidence = (0.5 + 0.1 * plugins.len() as f64).min(1.0);
            findings.push(CrossPluginFinding {
                correlation_type: (*correlation_type).to_string(),
                shared_value: value,
                artifact_descriptions: arts
                    .iter()
                    .map(|a| {
                        a.data
                            .get("title")
                            .cloned()
                            .unwrap_or_else(|| a.source.clone())
                    })
                    .collect(),
                plugins_involved: plugins,
                earliest,
                latest,
                confidence,
                mitre_technique: mitre,
            });
        }
    }
    findings
}

fn unique(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v.dedup();
    v
}

pub fn to_artifacts(findings: &[CrossPluginFinding]) -> Vec<Artifact> {
    findings
        .iter()
        .map(|f| {
            let mut a = Artifact::new("Correlation", "correlation_engine");
            a.timestamp = f.earliest.map(|d| d.timestamp() as u64);
            a.add_field(
                "title",
                &format!(
                    "{}={} across {} plugins ({} artifacts)",
                    f.correlation_type,
                    f.shared_value,
                    f.plugins_involved.len(),
                    f.artifact_descriptions.len()
                ),
            );
            a.add_field(
                "detail",
                &format!(
                    "Plugins: {} | Artifacts: {} | Window: {} -> {}",
                    f.plugins_involved.join(", "),
                    f.artifact_descriptions.len(),
                    f.earliest
                        .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    f.latest
                        .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        .unwrap_or_else(|| "-".to_string()),
                ),
            );
            a.add_field("file_type", "Correlation");
            a.add_field("correlation_type", &f.correlation_type);
            a.add_field("shared_value", &f.shared_value);
            for plugin in &f.plugins_involved {
                a.add_field("plugin_involved", plugin);
            }
            a.add_field("confidence", &format!("{:.2}", f.confidence));
            a.add_field("mitre", f.mitre_technique);
            a.add_field("forensic_value", "High");
            a.add_field("correlation_hit", "true");
            a.add_field("suspicious", "true");
            a
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn art(plugin: &str, ts: u64, fields: &[(&str, &str)]) -> Artifact {
        let mut a = Artifact::new("X", "/evidence/x");
        a.timestamp = Some(ts);
        a.add_field("title", plugin);
        a.add_field("plugin", plugin);
        for (k, v) in fields {
            a.add_field(k, v);
        }
        a
    }

    #[test]
    fn correlates_shared_ip_across_plugins() {
        let arts = vec![
            art("netflow", 100, &[("dst_ip", "10.0.0.5")]),
            art("carbon", 110, &[("dst_ip", "10.0.0.5")]),
        ];
        let findings = correlate(&arts, &CorrelatorConfig::default());
        assert!(findings
            .iter()
            .any(|f| f.correlation_type == "IpAddress" && f.shared_value == "10.0.0.5"));
    }

    #[test]
    fn single_plugin_hits_do_not_fire() {
        let arts = vec![
            art("netflow", 100, &[("dst_ip", "10.0.0.5")]),
            art("netflow", 110, &[("dst_ip", "10.0.0.5")]),
        ];
        let findings = correlate(&arts, &CorrelatorConfig::default());
        assert!(findings.is_empty());
    }

    #[test]
    fn out_of_window_events_drop_correlation() {
        let arts = vec![
            art("a", 0, &[("dst_ip", "10.0.0.5")]),
            art("b", 10_000, &[("dst_ip", "10.0.0.5")]),
        ];
        let findings = correlate(
            &arts,
            &CorrelatorConfig {
                time_window: Duration::seconds(60),
                min_artifacts: 2,
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn correlates_shared_username() {
        let arts = vec![
            art("sentinel", 100, &[("username", "alice")]),
            art("mactrace", 110, &[("username", "alice")]),
        ];
        let findings = correlate(&arts, &CorrelatorConfig::default());
        assert!(findings.iter().any(|f| f.correlation_type == "Username"));
    }

    #[test]
    fn to_artifacts_flips_correlation_hit_flag() {
        let arts = vec![
            art("a", 100, &[("dst_ip", "10.0.0.5")]),
            art("b", 110, &[("dst_ip", "10.0.0.5")]),
        ];
        let findings = correlate(&arts, &CorrelatorConfig::default());
        let converted = to_artifacts(&findings);
        assert!(converted
            .iter()
            .any(|a| a.data.get("correlation_hit").map(|s| s.as_str()) == Some("true")));
    }
}
