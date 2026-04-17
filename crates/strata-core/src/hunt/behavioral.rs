//! Behavioural detections: beaconing, credential harvesting, lateral
//! movement chains (HUNT-2).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use strata_plugin_sdk::Artifact;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BeaconingIndicator {
    pub destination: String,
    pub interval_mean_secs: f64,
    pub interval_cv: f64,
    pub connection_count: usize,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub source_artifacts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialHarvestingIndicator {
    pub indicator_type: String,
    pub confidence: String,
    pub correlated_artifacts: Vec<String>,
    pub time_window_start: DateTime<Utc>,
    pub time_window_end: DateTime<Utc>,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LateralHop {
    pub source_ip: Option<String>,
    pub target_account: String,
    pub movement_type: String,
    pub timestamp: DateTime<Utc>,
    pub artifact_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LateralMovementChain {
    pub hops: Vec<LateralHop>,
    pub total_duration_minutes: f64,
    pub chain_length: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HuntHypothesis {
    InsiderThreatExfiltration,
    RansomwarePrecursor,
    AptLateralMovement,
    CredentialTheft,
    DataStagingAndExfil,
    PersistenceMechanism,
    AntiForensicActivity,
}

/// Analyse a set of network-connection artifacts for beaconing. Each
/// artifact must expose `dst_ip` or `domain` in `a.data` and a
/// timestamp.
pub fn detect_beaconing(artifacts: &[Artifact]) -> Vec<BeaconingIndicator> {
    let mut groups: BTreeMap<String, Vec<&Artifact>> = BTreeMap::new();
    for a in artifacts {
        let key = a
            .data
            .get("dst_ip")
            .or_else(|| a.data.get("domain"))
            .or_else(|| a.data.get("query_name"))
            .cloned()
            .unwrap_or_default();
        if key.is_empty() {
            continue;
        }
        groups.entry(key).or_default().push(a);
    }
    let mut out = Vec::new();
    for (dest, group) in groups {
        if group.len() < 5 {
            continue;
        }
        let mut timestamps: Vec<DateTime<Utc>> = group
            .iter()
            .filter_map(|a| {
                a.timestamp
                    .and_then(|s| DateTime::<Utc>::from_timestamp(s as i64, 0))
            })
            .collect();
        if timestamps.len() < 5 {
            continue;
        }
        timestamps.sort();
        let intervals: Vec<f64> = timestamps
            .windows(2)
            .map(|w| (w[1] - w[0]).num_seconds() as f64)
            .collect();
        if intervals.is_empty() {
            continue;
        }
        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        if mean <= 0.0 {
            continue;
        }
        let variance = intervals
            .iter()
            .map(|v| (v - mean).powi(2))
            .sum::<f64>()
            / intervals.len() as f64;
        let std_dev = variance.sqrt();
        let cv = std_dev / mean;
        if cv >= 0.3 {
            continue;
        }
        out.push(BeaconingIndicator {
            destination: dest,
            interval_mean_secs: mean,
            interval_cv: cv,
            connection_count: group.len(),
            first_seen: *timestamps.first().unwrap_or(&Utc::now()),
            last_seen: *timestamps.last().unwrap_or(&Utc::now()),
            source_artifacts: group
                .iter()
                .map(|a| a.data.get("title").cloned().unwrap_or_else(|| a.source.clone()))
                .collect(),
        });
    }
    out
}

/// Detect credential-harvesting indicator combinations within a
/// 60-minute rolling window.
pub fn detect_credential_harvesting(
    artifacts: &[Artifact],
) -> Vec<CredentialHarvestingIndicator> {
    let mut out = Vec::new();
    let tools: &[&str] = &["mimikatz.exe", "sekurlsa", "lsass.exe", "procdump.exe"];
    let hits: Vec<&Artifact> = artifacts
        .iter()
        .filter(|a| {
            let lower = a
                .data
                .values()
                .map(|s| s.to_ascii_lowercase())
                .collect::<Vec<_>>()
                .join(" ");
            tools.iter().any(|t| lower.contains(t))
        })
        .collect();
    if hits.is_empty() {
        return out;
    }
    let new_account_times: Vec<DateTime<Utc>> = artifacts
        .iter()
        .filter(|a| {
            let mitre = a.data.get("mitre").map(|s| s.as_str()).unwrap_or("");
            mitre.starts_with("T1136")
        })
        .filter_map(|a| {
            a.timestamp
                .and_then(|s| DateTime::<Utc>::from_timestamp(s as i64, 0))
        })
        .collect();
    for hit in hits {
        let Some(ts) = hit
            .timestamp
            .and_then(|s| DateTime::<Utc>::from_timestamp(s as i64, 0))
        else {
            continue;
        };
        let window_end = ts + chrono::Duration::minutes(60);
        let mut corroborated = false;
        for t in &new_account_times {
            if *t >= ts && *t <= window_end {
                corroborated = true;
                break;
            }
        }
        let conf = if corroborated { "High" } else { "Medium" };
        out.push(CredentialHarvestingIndicator {
            indicator_type: "CredentialTool".into(),
            confidence: conf.into(),
            correlated_artifacts: vec![hit
                .data
                .get("title")
                .cloned()
                .unwrap_or_else(|| hit.source.clone())],
            time_window_start: ts,
            time_window_end: window_end,
            description: "Credential-dumping tool evidence".into(),
        });
    }
    out
}

pub fn build_chain(hops: Vec<LateralHop>) -> Option<LateralMovementChain> {
    if hops.len() < 2 {
        return None;
    }
    let mut sorted = hops;
    sorted.sort_by_key(|h| h.timestamp);
    let total = (sorted.last()?.timestamp - sorted.first()?.timestamp).num_seconds() as f64
        / 60.0;
    Some(LateralMovementChain {
        chain_length: sorted.len(),
        total_duration_minutes: total,
        hops: sorted,
    })
}

pub fn hypothesis_mitre(hypothesis: HuntHypothesis) -> Vec<&'static str> {
    match hypothesis {
        HuntHypothesis::InsiderThreatExfiltration => vec!["T1041", "T1567", "T1052", "T1005"],
        HuntHypothesis::RansomwarePrecursor => vec!["T1486", "T1490", "T1489", "T1491"],
        HuntHypothesis::AptLateralMovement => vec!["T1021", "T1550", "T1558"],
        HuntHypothesis::CredentialTheft => vec!["T1003", "T1555", "T1552", "T1110"],
        HuntHypothesis::DataStagingAndExfil => vec!["T1074", "T1560", "T1041", "T1567"],
        HuntHypothesis::PersistenceMechanism => vec!["T1547", "T1543", "T1053", "T1546"],
        HuntHypothesis::AntiForensicActivity => vec!["T1070", "T1485", "T1562", "T1561"],
    }
}

pub fn filter_for_hypothesis(
    hypothesis: HuntHypothesis,
    artifacts: &[Artifact],
) -> Vec<&Artifact> {
    let wanted = hypothesis_mitre(hypothesis);
    let mut out: Vec<&Artifact> = artifacts
        .iter()
        .filter(|a| {
            let mitre = a.data.get("mitre").map(|s| s.as_str()).unwrap_or("");
            wanted
                .iter()
                .any(|w| mitre == *w || mitre.starts_with(&format!("{}.", w)))
        })
        .collect();
    out.sort_by_key(|a| {
        let fv = match a
            .data
            .get("forensic_value")
            .map(|s| s.as_str())
            .unwrap_or("")
        {
            "Critical" => 0,
            "High" => 1,
            "Medium" => 2,
            _ => 3,
        };
        (fv, a.timestamp.unwrap_or(0))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn art(ty: &str, ts: u64, fields: &[(&str, &str)]) -> Artifact {
        let mut a = Artifact::new(ty, "/x");
        a.timestamp = Some(ts);
        a.add_field("title", ty);
        for (k, v) in fields {
            a.add_field(k, v);
        }
        a
    }

    #[test]
    fn detect_beaconing_fires_on_regular_intervals() {
        let arts: Vec<Artifact> = (0..6)
            .map(|i| art("Conn", 1000 + i * 300, &[("dst_ip", "10.0.0.5")]))
            .collect();
        let hits = detect_beaconing(&arts);
        assert_eq!(hits.len(), 1);
        assert!((hits[0].interval_mean_secs - 300.0).abs() < 1e-6);
    }

    #[test]
    fn detect_beaconing_skips_irregular_intervals() {
        let arts = vec![
            art("Conn", 100, &[("dst_ip", "10.0.0.5")]),
            art("Conn", 300, &[("dst_ip", "10.0.0.5")]),
            art("Conn", 2000, &[("dst_ip", "10.0.0.5")]),
            art("Conn", 2050, &[("dst_ip", "10.0.0.5")]),
            art("Conn", 9000, &[("dst_ip", "10.0.0.5")]),
        ];
        assert!(detect_beaconing(&arts).is_empty());
    }

    #[test]
    fn detect_credential_harvesting_flags_mimikatz() {
        let arts = vec![
            art("Prefetch", 100, &[("exe_name", "mimikatz.exe")]),
            art("SecurityEvent", 500, &[("mitre", "T1136.001")]),
        ];
        let hits = detect_credential_harvesting(&arts);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].confidence, "High");
    }

    #[test]
    fn build_chain_requires_at_least_two_hops() {
        let one = LateralHop {
            source_ip: None,
            target_account: "a".into(),
            movement_type: "SMB".into(),
            timestamp: Utc::now(),
            artifact_id: "x".into(),
        };
        assert!(build_chain(vec![one.clone()]).is_none());
        assert!(build_chain(vec![one.clone(), one]).is_some());
    }

    #[test]
    fn hypothesis_mitre_returns_nonempty_for_known_hypotheses() {
        assert!(!hypothesis_mitre(HuntHypothesis::CredentialTheft).is_empty());
        assert!(!hypothesis_mitre(HuntHypothesis::RansomwarePrecursor).is_empty());
    }

    #[test]
    fn filter_for_hypothesis_sorts_by_forensic_value() {
        let arts = vec![
            art(
                "A",
                1,
                &[("mitre", "T1021"), ("forensic_value", "Medium")],
            ),
            art(
                "B",
                2,
                &[("mitre", "T1550.002"), ("forensic_value", "High")],
            ),
        ];
        let filtered = filter_for_hypothesis(HuntHypothesis::AptLateralMovement, &arts);
        assert_eq!(filtered.len(), 2);
        assert_eq!(
            filtered[0].data.get("forensic_value").map(String::as_str),
            Some("High")
        );
    }
}
