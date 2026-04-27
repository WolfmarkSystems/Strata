//! ATT&CK kill-chain reconstruction (HUNT-1).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use strata_plugin_sdk::Artifact;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AttackTactic {
    Reconnaissance,
    ResourceDevelopment,
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
    Impact,
}

impl AttackTactic {
    pub fn tactic_id(&self) -> &'static str {
        match self {
            AttackTactic::Reconnaissance => "TA0043",
            AttackTactic::ResourceDevelopment => "TA0042",
            AttackTactic::InitialAccess => "TA0001",
            AttackTactic::Execution => "TA0002",
            AttackTactic::Persistence => "TA0003",
            AttackTactic::PrivilegeEscalation => "TA0004",
            AttackTactic::DefenseEvasion => "TA0005",
            AttackTactic::CredentialAccess => "TA0006",
            AttackTactic::Discovery => "TA0007",
            AttackTactic::LateralMovement => "TA0008",
            AttackTactic::Collection => "TA0009",
            AttackTactic::CommandAndControl => "TA0011",
            AttackTactic::Exfiltration => "TA0010",
            AttackTactic::Impact => "TA0040",
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            AttackTactic::Reconnaissance => "Reconnaissance",
            AttackTactic::ResourceDevelopment => "Resource Development",
            AttackTactic::InitialAccess => "Initial Access",
            AttackTactic::Execution => "Execution",
            AttackTactic::Persistence => "Persistence",
            AttackTactic::PrivilegeEscalation => "Privilege Escalation",
            AttackTactic::DefenseEvasion => "Defense Evasion",
            AttackTactic::CredentialAccess => "Credential Access",
            AttackTactic::Discovery => "Discovery",
            AttackTactic::LateralMovement => "Lateral Movement",
            AttackTactic::Collection => "Collection",
            AttackTactic::CommandAndControl => "Command and Control",
            AttackTactic::Exfiltration => "Exfiltration",
            AttackTactic::Impact => "Impact",
        }
    }

    pub fn all_ordered() -> &'static [AttackTactic] {
        &[
            AttackTactic::Reconnaissance,
            AttackTactic::ResourceDevelopment,
            AttackTactic::InitialAccess,
            AttackTactic::Execution,
            AttackTactic::Persistence,
            AttackTactic::PrivilegeEscalation,
            AttackTactic::DefenseEvasion,
            AttackTactic::CredentialAccess,
            AttackTactic::Discovery,
            AttackTactic::LateralMovement,
            AttackTactic::Collection,
            AttackTactic::CommandAndControl,
            AttackTactic::Exfiltration,
            AttackTactic::Impact,
        ]
    }
}

/// Map a MITRE technique (T-number) to the tactics it primarily
/// serves. A technique may participate in more than one tactic.
pub fn tactics_for_technique(technique: &str) -> Vec<AttackTactic> {
    let trimmed = technique.to_ascii_uppercase();
    let base = trimmed.split('.').next().unwrap_or("").to_string();
    match base.as_str() {
        "T1595" | "T1592" | "T1596" => vec![AttackTactic::Reconnaissance],
        "T1583" | "T1584" | "T1588" => vec![AttackTactic::ResourceDevelopment],
        "T1566" | "T1190" | "T1078" => vec![AttackTactic::InitialAccess],
        "T1059" | "T1204" | "T1203" | "T1053" => vec![AttackTactic::Execution],
        "T1547" | "T1543" | "T1546" => vec![AttackTactic::Persistence],
        "T1548" | "T1055" | "T1068" => {
            vec![
                AttackTactic::PrivilegeEscalation,
                AttackTactic::DefenseEvasion,
            ]
        }
        "T1027" => vec![AttackTactic::DefenseEvasion],
        "T1070" | "T1485" => vec![AttackTactic::DefenseEvasion, AttackTactic::Impact],
        "T1003" | "T1555" | "T1552" => vec![AttackTactic::CredentialAccess],
        "T1083" | "T1217" | "T1518" => vec![AttackTactic::Discovery],
        "T1021" | "T1550" | "T1558" | "T1534" => vec![AttackTactic::LateralMovement],
        "T1005" | "T1113" | "T1119" | "T1560" => vec![AttackTactic::Collection],
        "T1071" | "T1090" | "T1568" | "T1105" => vec![AttackTactic::CommandAndControl],
        "T1041" | "T1567" | "T1052" | "T1030" => vec![AttackTactic::Exfiltration],
        "T1486" | "T1489" | "T1561" => vec![AttackTactic::Impact],
        _ => Vec::new(),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KillChainStage {
    pub tactic: String,
    pub tactic_id: String,
    pub artifact_count: usize,
    pub artifacts: Vec<String>,
    pub earliest_timestamp: Option<DateTime<Utc>>,
    pub techniques_observed: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KillChainReconstruction {
    pub stages: Vec<KillChainStage>,
    pub attack_start: Option<DateTime<Utc>>,
    pub attack_end: Option<DateTime<Utc>>,
    pub duration_hours: Option<f64>,
    pub completeness: f64,
    pub missing_stages: Vec<String>,
}

pub fn reconstruct(artifacts: &[Artifact]) -> KillChainReconstruction {
    let mut per_tactic: BTreeMap<AttackTactic, KillChainStage> = BTreeMap::new();
    let mut global_earliest: Option<DateTime<Utc>> = None;
    let mut global_latest: Option<DateTime<Utc>> = None;
    for a in artifacts {
        let Some(mitre) = a.data.get("mitre") else {
            continue;
        };
        let tactics = tactics_for_technique(mitre);
        if tactics.is_empty() {
            continue;
        }
        let ts = a
            .timestamp
            .and_then(|s| DateTime::<Utc>::from_timestamp(s as i64, 0));
        let title = a
            .data
            .get("title")
            .cloned()
            .unwrap_or_else(|| a.source.clone());
        for tactic in tactics {
            let entry = per_tactic.entry(tactic).or_insert_with(|| KillChainStage {
                tactic: tactic.as_str().into(),
                tactic_id: tactic.tactic_id().into(),
                artifact_count: 0,
                artifacts: Vec::new(),
                earliest_timestamp: None,
                techniques_observed: Vec::new(),
            });
            entry.artifact_count += 1;
            if entry.artifacts.len() < 100 {
                entry.artifacts.push(title.clone());
            }
            if !entry.techniques_observed.contains(mitre) {
                entry.techniques_observed.push(mitre.clone());
            }
            if let Some(t) = ts {
                entry.earliest_timestamp = Some(match entry.earliest_timestamp {
                    Some(existing) => existing.min(t),
                    None => t,
                });
            }
        }
        if let Some(t) = ts {
            global_earliest = Some(match global_earliest {
                Some(e) => e.min(t),
                None => t,
            });
            global_latest = Some(match global_latest {
                Some(e) => e.max(t),
                None => t,
            });
        }
    }
    let ordered = AttackTactic::all_ordered();
    let mut stages: Vec<KillChainStage> = ordered
        .iter()
        .filter_map(|t| per_tactic.remove(t))
        .collect();
    stages.sort_by_key(|s| s.earliest_timestamp);
    let missing: Vec<String> = ordered
        .iter()
        .filter(|t| !stages.iter().any(|s| s.tactic == t.as_str()))
        .map(|t| t.as_str().to_string())
        .collect();
    let duration_hours = match (global_earliest, global_latest) {
        (Some(a), Some(b)) if b > a => Some((b - a).num_seconds() as f64 / 3600.0),
        _ => None,
    };
    let completeness = stages.len() as f64 / ordered.len() as f64;
    KillChainReconstruction {
        stages,
        attack_start: global_earliest,
        attack_end: global_latest,
        duration_hours,
        completeness,
        missing_stages: missing,
    }
}

pub fn render_html(report: &KillChainReconstruction) -> String {
    let mut out = String::from("<section><h2>ATT&CK Kill Chain Reconstruction</h2>\n");
    out.push_str(&format!(
        "<p>Completeness: {:.0}% | Duration: {}</p>\n",
        report.completeness * 100.0,
        report
            .duration_hours
            .map(|d| format!("{:.2} hours", d))
            .unwrap_or_else(|| "unknown".to_string())
    ));
    out.push_str(
        "<table><tr><th>Tactic</th><th>ID</th><th>Artifacts</th><th>Techniques</th></tr>\n",
    );
    for stage in &report.stages {
        out.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            stage.tactic,
            stage.tactic_id,
            stage.artifact_count,
            stage.techniques_observed.join(", ")
        ));
    }
    out.push_str("</table>\n");
    if !report.missing_stages.is_empty() {
        out.push_str(&format!(
            "<p>Missing stages (no evidence): {}</p>\n",
            report.missing_stages.join(", ")
        ));
    }
    out.push_str("</section>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn art(ty: &str, mitre: &str, ts: u64) -> Artifact {
        let mut a = Artifact::new(ty, "/x");
        a.timestamp = Some(ts);
        a.add_field("title", ty);
        a.add_field("mitre", mitre);
        a
    }

    #[test]
    fn tactics_for_technique_maps_known_numbers() {
        assert!(tactics_for_technique("T1059.001").contains(&AttackTactic::Execution));
        assert!(tactics_for_technique("T1070").contains(&AttackTactic::DefenseEvasion));
        assert!(tactics_for_technique("T1021").contains(&AttackTactic::LateralMovement));
        assert!(tactics_for_technique("T9999").is_empty());
    }

    #[test]
    fn reconstruct_produces_ordered_stages() {
        let arts = vec![
            art("Prefetch", "T1059", 100),
            art("SystemdUnit", "T1547", 300),
            art("Lateral", "T1021", 500),
            art("NetflowC2", "T1071", 700),
        ];
        let report = reconstruct(&arts);
        assert!(report.stages.iter().any(|s| s.tactic == "Execution"));
        assert!(report.stages.iter().any(|s| s.tactic == "Persistence"));
        assert!(report.stages.iter().any(|s| s.tactic == "Lateral Movement"));
        assert!(report
            .stages
            .iter()
            .any(|s| s.tactic == "Command and Control"));
        assert_eq!(report.attack_start.map(|d| d.timestamp()), Some(100));
        assert_eq!(report.attack_end.map(|d| d.timestamp()), Some(700));
    }

    #[test]
    fn missing_stages_reported_when_no_evidence() {
        let arts = vec![art("X", "T1059", 1)];
        let report = reconstruct(&arts);
        assert!(report
            .missing_stages
            .contains(&"Reconnaissance".to_string()));
    }

    #[test]
    fn render_html_includes_completeness() {
        let arts = vec![art("X", "T1059", 1)];
        let report = reconstruct(&arts);
        let html = render_html(&report);
        assert!(html.contains("Completeness"));
        assert!(html.contains("Execution"));
    }

    #[test]
    fn completeness_scales_with_tactic_coverage() {
        let arts = vec![
            art("A", "T1059", 1),
            art("B", "T1547", 2),
            art("C", "T1021", 3),
            art("D", "T1071", 4),
            art("E", "T1041", 5),
        ];
        let report = reconstruct(&arts);
        assert!(report.completeness > 0.2);
    }
}
