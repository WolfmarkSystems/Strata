//! Cross-artifact SIGMA correlation engine (SIGMA-2).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use strata_plugin_sdk::Artifact;

use super::rules::{rule_matches, SigmaRule};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigmaFieldMapping {
    pub product: String,
    pub category: String,
    pub sigma_field: String,
    pub artifact_type: String,
    pub artifact_field: String,
}

pub fn default_mappings() -> Vec<SigmaFieldMapping> {
    vec![
        SigmaFieldMapping {
            product: "windows".into(),
            category: "process_creation".into(),
            sigma_field: "Image".into(),
            artifact_type: "Prefetch Execution".into(),
            artifact_field: "exe_name".into(),
        },
        SigmaFieldMapping {
            product: "windows".into(),
            category: "process_creation".into(),
            sigma_field: "CommandLine".into(),
            artifact_type: "PowerShell History".into(),
            artifact_field: "command".into(),
        },
        SigmaFieldMapping {
            product: "windows".into(),
            category: "network_connection".into(),
            sigma_field: "DestinationIp".into(),
            artifact_type: "NetFlow".into(),
            artifact_field: "dst_ip".into(),
        },
        SigmaFieldMapping {
            product: "linux".into(),
            category: "process_creation".into(),
            sigma_field: "exe".into(),
            artifact_type: "Shell History".into(),
            artifact_field: "command".into(),
        },
    ]
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SigmaMatch {
    pub rule_id: String,
    pub rule_title: String,
    pub rule_level: String,
    pub mitre_techniques: Vec<String>,
    pub matched_artifacts: Vec<String>,
    pub first_match_time: Option<DateTime<Utc>>,
    pub last_match_time: Option<DateTime<Utc>>,
    pub is_correlation: bool,
}

pub fn run_rules(
    rules: &[SigmaRule],
    artifacts: &[Artifact],
    correlation_window: Duration,
) -> Vec<SigmaMatch> {
    let mut out = Vec::new();
    for rule in rules {
        let multi_selection =
            rule.selections.len() > 1 && rule.condition.as_deref() != Some("selection");
        // Map each selection block to the artifacts it matches.
        let mut selection_hits: HashMap<String, Vec<&Artifact>> = HashMap::new();
        for (name, selection) in &rule.selections {
            let hits: Vec<&Artifact> = artifacts
                .iter()
                .filter(|a| product_category_matches(rule, a))
                .filter(|a| super::rules::selection_match_helper(selection, &artifact_field_map(a)))
                .collect();
            selection_hits.insert(name.clone(), hits);
        }
        // Apply the rule's condition against the per-selection hit map.
        let condition_fires = match rule.condition.as_deref() {
            None | Some("selection") => !selection_hits
                .get("selection")
                .map(|v| v.is_empty())
                .unwrap_or(true),
            Some("all of them") => selection_hits.values().all(|v| !v.is_empty()),
            Some(c) if c.starts_with("1 of ") => {
                let prefix = c["1 of ".len()..].trim().trim_end_matches('*');
                selection_hits
                    .iter()
                    .any(|(name, hits)| !hits.is_empty() && name.starts_with(prefix))
            }
            Some(c) => selection_hits
                .get(c)
                .map(|v| !v.is_empty())
                .unwrap_or(false),
        };
        if !condition_fires {
            continue;
        }
        // Union of matching artifacts.
        let mut seen: std::collections::BTreeSet<*const Artifact> =
            std::collections::BTreeSet::new();
        let mut matched: Vec<&Artifact> = Vec::new();
        for hits in selection_hits.values() {
            for a in hits {
                let ptr = *a as *const Artifact;
                if seen.insert(ptr) {
                    matched.push(a);
                }
            }
        }
        let timestamps: Vec<DateTime<Utc>> = matched
            .iter()
            .filter_map(|a| {
                a.timestamp
                    .and_then(|s| DateTime::<Utc>::from_timestamp(s as i64, 0))
            })
            .collect();
        if multi_selection {
            if let (Some(first), Some(last)) = (timestamps.iter().min(), timestamps.iter().max()) {
                if *last - *first > correlation_window {
                    continue;
                }
            }
        }
        let first = timestamps.iter().min().copied();
        let last = timestamps.iter().max().copied();
        let matched_descriptions: Vec<String> = matched
            .iter()
            .map(|a| {
                a.data
                    .get("title")
                    .cloned()
                    .unwrap_or_else(|| a.source.clone())
            })
            .collect();
        out.push(SigmaMatch {
            rule_id: rule.id.clone(),
            rule_title: rule.title.clone(),
            rule_level: rule.level.clone().unwrap_or_else(|| "medium".to_string()),
            mitre_techniques: rule.mitre_techniques.clone(),
            matched_artifacts: matched_descriptions,
            first_match_time: first,
            last_match_time: last,
            is_correlation: multi_selection,
        });
    }
    out
}

fn product_category_matches(rule: &SigmaRule, a: &Artifact) -> bool {
    if rule.product.is_none() && rule.category.is_none() {
        return true;
    }
    // Best-effort match: compare rule.product against artifact.
    let a_platform = a.data.get("platform").cloned().unwrap_or_default();
    if let Some(product) = &rule.product {
        if !a_platform.is_empty() && !a_platform.eq_ignore_ascii_case(product) {
            return false;
        }
    }
    true
}

fn artifact_field_map(a: &Artifact) -> HashMap<String, String> {
    // Expose artifact fields under both their raw keys and SIGMA-style
    // field names so rules can match on either convention.
    let mut out: HashMap<String, String> = HashMap::new();
    for (k, v) in &a.data {
        out.insert(k.clone(), v.clone());
        out.insert(k.to_ascii_lowercase(), v.clone());
    }
    if let Some(path) = a.data.get("exe_name") {
        out.insert("Image".into(), path.clone());
    }
    if let Some(cmd) = a.data.get("command") {
        out.insert("CommandLine".into(), cmd.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::rules::parse_yaml;
    use super::*;

    fn artifact(ty: &str, title: &str, fields: &[(&str, &str)], ts: u64) -> Artifact {
        let mut a = Artifact::new(ty, "/evidence/x");
        a.timestamp = Some(ts);
        a.add_field("title", title);
        a.add_field("file_type", ty);
        for (k, v) in fields {
            a.add_field(k, v);
        }
        a
    }

    #[test]
    fn default_mappings_include_core_platforms() {
        let maps = default_mappings();
        assert!(maps.iter().any(|m| m.product == "windows"));
        assert!(maps.iter().any(|m| m.product == "linux"));
    }

    #[test]
    fn run_rules_fires_single_selection_rule() {
        let rule = parse_yaml(
            "title: Pwsh Encoded\nid: r1\nlevel: high\n\
             logsource:\n  product: windows\n  category: process_creation\n\
             tags:\n  - attack.t1059.001\n\
             detection:\n  selection:\n    CommandLine|contains: '-enc'\n  condition: selection\n",
        )
        .expect("rule");
        let a = artifact(
            "PowerShell History",
            "encoded",
            &[("command", "powershell -enc ABCDEFG")],
            1_717_243_200,
        );
        let matches = run_rules(&[rule], &[a], Duration::seconds(60));
        assert_eq!(matches.len(), 1);
        assert!(matches[0]
            .mitre_techniques
            .iter()
            .any(|t| t.contains("T1059.001")));
    }

    #[test]
    fn run_rules_applies_correlation_window() {
        let rule = parse_yaml(
            "title: Multi\nid: r2\nlevel: high\n\
             detection:\n  a:\n    Field1: a\n  b:\n    Field2: b\n  condition: all of them\n",
        )
        .expect("rule");
        let a1 = artifact("X", "one", &[("Field1", "a")], 100);
        let a2 = artifact("X", "two", &[("Field2", "b")], 500);
        let rules = [rule.clone()];
        let arts = [a1, a2];
        let matches = run_rules(&rules, &arts, Duration::seconds(60));
        assert!(matches.is_empty());
        let matches = run_rules(&rules, &arts, Duration::seconds(1000));
        assert!(!matches.is_empty());
    }

    #[test]
    fn run_rules_skips_rule_with_no_matches() {
        let rule = parse_yaml(
            "title: Nothing\nid: r3\n\
             detection:\n  selection:\n    CommandLine: 'never-present'\n  condition: selection\n",
        )
        .expect("rule");
        let a = artifact("PS", "x", &[("command", "other")], 1);
        let matches = run_rules(&[rule], &[a], Duration::seconds(60));
        assert!(matches.is_empty());
    }

    #[test]
    fn artifact_field_map_exposes_sigma_aliases() {
        let a = artifact("Prefetch", "exec", &[("exe_name", "notepad.exe")], 1);
        let map = artifact_field_map(&a);
        assert_eq!(map.get("Image").map(String::as_str), Some("notepad.exe"));
    }
}
