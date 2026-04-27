//! Artifact filtering engine (WF-3).
//!
//! Structured multi-criterion filter over `Artifact` records. Zero
//! allocation where possible — returns `Vec<&Artifact>` borrows so
//! repeated filtering doesn't copy.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use strata_plugin_sdk::{Artifact, ForensicValue};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ArtifactFilter {
    pub plugins: Option<Vec<String>>,
    pub artifact_types: Option<Vec<String>>,
    pub mitre_techniques: Option<Vec<String>>,
    pub forensic_value: Option<Vec<ForensicValue>>,
    #[serde(default)]
    pub suspicious_only: bool,
    pub date_from: Option<DateTime<Utc>>,
    pub date_to: Option<DateTime<Utc>>,
    pub text_search: Option<String>,
    #[serde(default)]
    pub has_notes: bool,
    #[serde(default)]
    pub case_critical_only: bool,
    pub min_confidence: Option<f64>,
    pub source_path_contains: Option<String>,
}

impl ArtifactFilter {
    pub fn is_empty(&self) -> bool {
        self.plugins.is_none()
            && self.artifact_types.is_none()
            && self.mitre_techniques.is_none()
            && self.forensic_value.is_none()
            && !self.suspicious_only
            && self.date_from.is_none()
            && self.date_to.is_none()
            && self.text_search.is_none()
            && !self.has_notes
            && !self.case_critical_only
            && self.min_confidence.is_none()
            && self.source_path_contains.is_none()
    }

    pub fn describe(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(p) = &self.plugins {
            parts.push(format!("plugin in [{}]", p.join(", ")));
        }
        if let Some(t) = &self.artifact_types {
            parts.push(format!("type in [{}]", t.join(", ")));
        }
        if let Some(m) = &self.mitre_techniques {
            parts.push(format!("MITRE in [{}]", m.join(", ")));
        }
        if let Some(f) = &self.forensic_value {
            let labels: Vec<String> = f.iter().map(|v| format!("{:?}", v)).collect();
            parts.push(format!("forensic_value in [{}]", labels.join(", ")));
        }
        if self.suspicious_only {
            parts.push("suspicious only".into());
        }
        if let Some(dt) = self.date_from {
            parts.push(format!("from {}", dt.format("%Y-%m-%d %H:%M:%S UTC")));
        }
        if let Some(dt) = self.date_to {
            parts.push(format!("to {}", dt.format("%Y-%m-%d %H:%M:%S UTC")));
        }
        if let Some(q) = &self.text_search {
            parts.push(format!("text contains '{}'", q));
        }
        if self.has_notes {
            parts.push("has examiner notes".into());
        }
        if self.case_critical_only {
            parts.push("case-critical only".into());
        }
        if let Some(c) = self.min_confidence {
            parts.push(format!("confidence >= {:.2}", c));
        }
        if let Some(s) = &self.source_path_contains {
            parts.push(format!("source contains '{}'", s));
        }
        if parts.is_empty() {
            "no filter".into()
        } else {
            parts.join(" AND ")
        }
    }

    pub fn apply<'a>(&self, artifacts: &'a [Artifact]) -> Vec<&'a Artifact> {
        artifacts.iter().filter(|a| self.matches(a)).collect()
    }

    pub fn count(&self, artifacts: &[Artifact]) -> usize {
        artifacts.iter().filter(|a| self.matches(a)).count()
    }

    fn matches(&self, a: &Artifact) -> bool {
        if let Some(plugins) = &self.plugins {
            let plugin = a.data.get("plugin").cloned().unwrap_or_default();
            if !plugins.iter().any(|p| p == &plugin) {
                return false;
            }
        }
        if let Some(types) = &self.artifact_types {
            let file_type = a
                .data
                .get("file_type")
                .cloned()
                .unwrap_or_else(|| a.category.clone());
            if !types.iter().any(|t| t == &file_type) {
                return false;
            }
        }
        if let Some(mitres) = &self.mitre_techniques {
            let mitre = a.data.get("mitre").cloned().unwrap_or_default();
            if !mitres
                .iter()
                .any(|needle| mitre == *needle || mitre.starts_with(&format!("{}.", needle)))
            {
                return false;
            }
        }
        if let Some(values) = &self.forensic_value {
            let fv = a
                .data
                .get("forensic_value")
                .map(|s| forensic_value_from_str(s))
                .unwrap_or(ForensicValue::Medium);
            if !values.contains(&fv) {
                return false;
            }
        }
        if self.suspicious_only && a.data.get("suspicious").map(|s| s.as_str()) != Some("true") {
            return false;
        }
        if let Some(from) = self.date_from {
            let ts = a.timestamp.unwrap_or(0);
            if ts == 0 || (ts as i64) < from.timestamp() {
                return false;
            }
        }
        if let Some(to) = self.date_to {
            let ts = a.timestamp.unwrap_or(0);
            if ts == 0 || (ts as i64) > to.timestamp() {
                return false;
            }
        }
        if let Some(q) = &self.text_search {
            let lower = q.to_ascii_lowercase();
            let mut found = false;
            for v in a.data.values() {
                if v.to_ascii_lowercase().contains(&lower) {
                    found = true;
                    break;
                }
            }
            if !found {
                return false;
            }
        }
        if self.has_notes && a.data.get("has_notes").map(|s| s.as_str()) != Some("true") {
            return false;
        }
        if self.case_critical_only
            && a.data.get("case_critical").map(|s| s.as_str()) != Some("true")
        {
            return false;
        }
        if let Some(min) = self.min_confidence {
            let c = a
                .data
                .get("confidence")
                .and_then(|s| s.parse::<f64>().ok())
                .unwrap_or(1.0);
            if c < min {
                return false;
            }
        }
        if let Some(sub) = &self.source_path_contains {
            if !a.source.contains(sub) {
                return false;
            }
        }
        true
    }
}

fn forensic_value_from_str(s: &str) -> ForensicValue {
    match s {
        "Critical" => ForensicValue::Critical,
        "High" => ForensicValue::High,
        "Low" => ForensicValue::Low,
        _ => ForensicValue::Medium,
    }
}

/// Built-in preset filters per the WF-3 spec.
pub fn preset(name: &str) -> Option<ArtifactFilter> {
    match name {
        "Suspicious Only" => Some(ArtifactFilter {
            suspicious_only: true,
            ..Default::default()
        }),
        "High Value" => Some(ArtifactFilter {
            forensic_value: Some(vec![ForensicValue::High, ForensicValue::Critical]),
            ..Default::default()
        }),
        "Execution Evidence" => Some(ArtifactFilter {
            mitre_techniques: Some(vec!["T1059".into(), "T1204".into(), "T1053".into()]),
            ..Default::default()
        }),
        "Persistence" => Some(ArtifactFilter {
            mitre_techniques: Some(vec!["T1547".into(), "T1543".into(), "T1053".into()]),
            ..Default::default()
        }),
        "Exfiltration" => Some(ArtifactFilter {
            mitre_techniques: Some(vec!["T1567".into(), "T1530".into(), "T1052".into()]),
            ..Default::default()
        }),
        "Anti-Forensic" => Some(ArtifactFilter {
            plugins: Some(vec!["Strata Vault".into()]),
            ..Default::default()
        }),
        "Case Critical" => Some(ArtifactFilter {
            case_critical_only: true,
            ..Default::default()
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(file_type: &str, mitre: &str, suspicious: bool, value: &str) -> Artifact {
        let mut a = Artifact::new(file_type, "/evidence/x");
        a.add_field("file_type", file_type);
        a.add_field("mitre", mitre);
        if suspicious {
            a.add_field("suspicious", "true");
        }
        a.add_field("forensic_value", value);
        a
    }

    #[test]
    fn empty_filter_matches_everything() {
        let f = ArtifactFilter::default();
        assert!(f.is_empty());
        let arts = vec![artifact("A", "T1059", false, "Low")];
        assert_eq!(f.apply(&arts).len(), 1);
    }

    #[test]
    fn mitre_technique_prefix_match() {
        let f = ArtifactFilter {
            mitre_techniques: Some(vec!["T1059".into()]),
            ..Default::default()
        };
        let arts = vec![
            artifact("A", "T1059.001", false, "Low"),
            artifact("B", "T1059", false, "Low"),
            artifact("C", "T1547", false, "Low"),
        ];
        let hits = f.apply(&arts);
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn suspicious_only_drops_clean_artifacts() {
        let f = ArtifactFilter {
            suspicious_only: true,
            ..Default::default()
        };
        let arts = vec![
            artifact("A", "T1", false, "High"),
            artifact("B", "T1", true, "High"),
        ];
        assert_eq!(f.count(&arts), 1);
    }

    #[test]
    fn forensic_value_filter_bucket() {
        let f = ArtifactFilter {
            forensic_value: Some(vec![ForensicValue::High, ForensicValue::Critical]),
            ..Default::default()
        };
        let arts = vec![
            artifact("A", "T1", false, "High"),
            artifact("B", "T1", false, "Low"),
            artifact("C", "T1", false, "Critical"),
        ];
        assert_eq!(f.count(&arts), 2);
    }

    #[test]
    fn text_search_is_case_insensitive() {
        let f = ArtifactFilter {
            text_search: Some("PAYLOAD".into()),
            ..Default::default()
        };
        let mut a = artifact("Pref", "T1204", false, "Medium");
        a.add_field("detail", "file named payload.exe launched");
        let arts = [a];
        let hits = f.apply(&arts);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn preset_catalogue_returns_seven_named_filters() {
        for name in [
            "Suspicious Only",
            "High Value",
            "Execution Evidence",
            "Persistence",
            "Exfiltration",
            "Anti-Forensic",
            "Case Critical",
        ] {
            assert!(preset(name).is_some(), "missing preset: {}", name);
        }
        assert!(preset("NonExistent").is_none());
    }

    #[test]
    fn describe_produces_human_readable_summary() {
        let f = ArtifactFilter {
            suspicious_only: true,
            mitre_techniques: Some(vec!["T1059".into()]),
            ..Default::default()
        };
        let s = f.describe();
        assert!(s.contains("suspicious"));
        assert!(s.contains("T1059"));
    }
}
