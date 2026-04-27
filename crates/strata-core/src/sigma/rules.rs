//! SigmaHQ rule import + lightweight YAML parser (SIGMA-1).
//!
//! Air-gapped: we accept YAML from local files / directories and
//! never fetch from the SigmaHQ repository at runtime.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SigmaError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid rule: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigmaRule {
    pub id: String,
    pub title: String,
    pub status: Option<String>,
    pub level: Option<String>,
    pub description: Option<String>,
    pub product: Option<String>,
    pub category: Option<String>,
    pub tags: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub detection_yaml: String,
    pub selections: HashMap<String, HashMap<String, Vec<String>>>,
    pub condition: Option<String>,
}

/// Minimal YAML subset parser — sufficient for SIGMA rules which use
/// a disciplined Flavor of YAML (maps + scalar lists only).
pub fn parse_yaml(body: &str) -> Result<SigmaRule, SigmaError> {
    let mut title = String::new();
    let mut id = String::new();
    let mut status: Option<String> = None;
    let mut level: Option<String> = None;
    let mut description: Option<String> = None;
    let mut product: Option<String> = None;
    let mut category: Option<String> = None;
    let mut tags: Vec<String> = Vec::new();
    let mut condition: Option<String> = None;
    let mut selections: HashMap<String, HashMap<String, Vec<String>>> = HashMap::new();
    let mut in_logsource = false;
    let mut in_tags = false;
    let mut in_detection = false;
    let mut current_selection: Option<String> = None;
    let mut current_field: Option<String> = None;
    for raw in body.lines() {
        let line = raw.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let indent = line.chars().take_while(|c| *c == ' ').count();
        let trimmed = line.trim_start();
        if indent == 0 {
            in_logsource = false;
            in_tags = false;
            in_detection = false;
            current_selection = None;
            current_field = None;
            if let Some(rest) = trimmed.strip_prefix("title:") {
                title = strip_quotes(rest.trim()).to_string();
            } else if let Some(rest) = trimmed.strip_prefix("id:") {
                id = strip_quotes(rest.trim()).to_string();
            } else if let Some(rest) = trimmed.strip_prefix("status:") {
                status = Some(rest.trim().to_string());
            } else if let Some(rest) = trimmed.strip_prefix("level:") {
                level = Some(rest.trim().to_string());
            } else if let Some(rest) = trimmed.strip_prefix("description:") {
                description = Some(strip_quotes(rest.trim()).to_string());
            } else if trimmed.starts_with("logsource:") {
                in_logsource = true;
            } else if trimmed.starts_with("tags:") {
                in_tags = true;
            } else if trimmed.starts_with("detection:") {
                in_detection = true;
            }
        } else if in_logsource {
            if let Some(rest) = trimmed.strip_prefix("product:") {
                product = Some(rest.trim().to_string());
            } else if let Some(rest) = trimmed.strip_prefix("category:") {
                category = Some(rest.trim().to_string());
            }
        } else if in_tags {
            if let Some(tag) = trimmed.strip_prefix("- ") {
                tags.push(tag.trim().to_string());
            }
        } else if in_detection {
            if trimmed.starts_with("condition:") {
                condition = Some(trimmed.trim_start_matches("condition:").trim().to_string());
                current_selection = None;
                current_field = None;
            } else if indent == 2 {
                // Section header: `<name>:`
                let name = trimmed.trim_end_matches(':').to_string();
                selections.entry(name.clone()).or_default();
                current_selection = Some(name);
                current_field = None;
            } else if indent >= 4 {
                if let Some(selection) = current_selection.clone() {
                    let entry = selections.entry(selection).or_default();
                    if let Some(rest) = trimmed.strip_prefix("- ") {
                        if let Some(field) = current_field.clone() {
                            entry
                                .entry(field)
                                .or_default()
                                .push(strip_quotes(rest.trim()).to_string());
                        }
                    } else if let Some((key, value)) = trimmed.split_once(':') {
                        let key = key.trim().to_string();
                        let value = strip_quotes(value.trim()).to_string();
                        current_field = Some(key.clone());
                        if !value.is_empty() {
                            entry.entry(key).or_default().push(value);
                        }
                    }
                }
            }
        }
    }
    if title.is_empty() {
        return Err(SigmaError::Invalid("missing title".into()));
    }
    if selections.is_empty() {
        return Err(SigmaError::Invalid("missing detection selections".into()));
    }
    let mitre_techniques: Vec<String> = tags
        .iter()
        .filter_map(|t| {
            let lower = t.to_ascii_lowercase();
            if lower.starts_with("attack.t") {
                let fragment = &t["attack.".len()..];
                Some(fragment.to_ascii_uppercase())
            } else {
                None
            }
        })
        .collect();
    Ok(SigmaRule {
        id,
        title,
        status,
        level,
        description,
        product,
        category,
        tags,
        mitre_techniques,
        detection_yaml: body.to_string(),
        selections,
        condition,
    })
}

fn strip_quotes(s: &str) -> &str {
    s.trim_matches('"').trim_matches('\'')
}

pub fn import_directory(dir: &Path) -> Vec<(PathBuf, Result<SigmaRule, SigmaError>)> {
    let mut out = Vec::new();
    walk(dir, &mut out);
    out
}

fn walk(dir: &Path, out: &mut Vec<(PathBuf, Result<SigmaRule, SigmaError>)>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out);
            continue;
        }
        if path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.eq_ignore_ascii_case("yml") || s.eq_ignore_ascii_case("yaml"))
            .unwrap_or(false)
        {
            match fs::read_to_string(&path) {
                Ok(body) => out.push((path.clone(), parse_yaml(&body))),
                Err(e) => out.push((path, Err(SigmaError::Io(e)))),
            }
        }
    }
}

/// Match a rule's selections against an artifact's fields.
///
/// Supports `|contains`, `|startswith`, `|endswith`, `|re`
/// modifiers encoded in the YAML field name. Each selection fires
/// when every field inside it matches. The rule fires when any
/// selection listed in `condition` matches — we implement the
/// simplest supported shape: `selection`, `all of them`, and
/// `1 of selection*`.
pub fn rule_matches(rule: &SigmaRule, fields: &HashMap<String, String>) -> bool {
    let mut matches: HashMap<String, bool> = HashMap::new();
    for (name, selection) in &rule.selections {
        matches.insert(name.clone(), selection_matches(selection, fields));
    }
    match rule.condition.as_deref() {
        None | Some("selection") => *matches.get("selection").unwrap_or(&false),
        Some("all of them") => matches.values().all(|v| *v),
        Some(c) if c.starts_with("1 of ") => {
            let prefix = c["1 of ".len()..].trim().trim_end_matches('*');
            matches
                .iter()
                .any(|(name, hit)| *hit && name.starts_with(prefix))
        }
        Some(c) => matches.get(c).copied().unwrap_or(false),
    }
}

pub(crate) fn selection_match_helper(
    selection: &HashMap<String, Vec<String>>,
    fields: &HashMap<String, String>,
) -> bool {
    selection_matches(selection, fields)
}

fn selection_matches(
    selection: &HashMap<String, Vec<String>>,
    fields: &HashMap<String, String>,
) -> bool {
    for (key_with_modifier, values) in selection {
        let (field_name, modifier) = match key_with_modifier.split_once('|') {
            Some((f, m)) => (f.to_string(), Some(m)),
            None => (key_with_modifier.clone(), None),
        };
        let Some(actual) = fields.get(&field_name) else {
            return false;
        };
        let matched = values.iter().any(|v| match modifier {
            Some("contains") => actual
                .to_ascii_lowercase()
                .contains(&v.to_ascii_lowercase()),
            Some("startswith") => actual
                .to_ascii_lowercase()
                .starts_with(&v.to_ascii_lowercase()),
            Some("endswith") => actual
                .to_ascii_lowercase()
                .ends_with(&v.to_ascii_lowercase()),
            Some("re") => {
                if let Ok(re) = regex::Regex::new(v) {
                    re.is_match(actual)
                } else {
                    false
                }
            }
            _ => actual.eq_ignore_ascii_case(v),
        });
        if !matched {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_yaml_captures_basics_and_tags() {
        let body = r#"title: Suspicious CommandLine
id: abc-123
status: stable
level: high
description: test
logsource:
  product: windows
  category: process_creation
tags:
  - attack.t1059.001
  - attack.execution
detection:
  selection:
    Image|endswith: "powershell.exe"
    CommandLine|contains: "-enc"
  condition: selection
"#;
        let rule = parse_yaml(body).expect("parsed");
        assert_eq!(rule.id, "abc-123");
        assert_eq!(rule.level.as_deref(), Some("high"));
        assert_eq!(rule.product.as_deref(), Some("windows"));
        assert!(rule
            .mitre_techniques
            .iter()
            .any(|t| t.contains("T1059.001")));
    }

    #[test]
    fn rule_matches_honours_contains_modifier() {
        let body = r#"title: Contains Match
id: x
detection:
  selection:
    CommandLine|contains: "evil"
  condition: selection
"#;
        let rule = parse_yaml(body).expect("parsed");
        let mut fields: HashMap<String, String> = HashMap::new();
        fields.insert("CommandLine".into(), "powershell.exe -c evil.ps1".into());
        assert!(rule_matches(&rule, &fields));
        fields.insert("CommandLine".into(), "benign".into());
        assert!(!rule_matches(&rule, &fields));
    }

    #[test]
    fn rule_matches_all_of_them_requires_every_selection() {
        let body = r#"title: All Of Them
id: x
detection:
  a:
    Field1: foo
  b:
    Field2: bar
  condition: all of them
"#;
        let rule = parse_yaml(body).expect("parsed");
        let mut fields: HashMap<String, String> = HashMap::new();
        fields.insert("Field1".into(), "foo".into());
        assert!(!rule_matches(&rule, &fields));
        fields.insert("Field2".into(), "bar".into());
        assert!(rule_matches(&rule, &fields));
    }

    #[test]
    fn parse_yaml_rejects_missing_title() {
        let body = "detection:\n  selection:\n    Field: x\n  condition: selection\n";
        assert!(parse_yaml(body).is_err());
    }

    #[test]
    fn rule_matches_supports_one_of_prefix() {
        let body = r#"title: Prefix
id: x
detection:
  selection_a:
    Field: a
  selection_b:
    Field: b
  condition: 1 of selection*
"#;
        let rule = parse_yaml(body).expect("parsed");
        let mut fields: HashMap<String, String> = HashMap::new();
        fields.insert("Field".into(), "b".into());
        assert!(rule_matches(&rule, &fields));
    }

    #[test]
    fn import_directory_walks_yaml_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rule_path = dir.path().join("rule.yml");
        fs::write(
            &rule_path,
            "title: T\nid: id1\ndetection:\n  selection:\n    F: v\n  condition: selection\n",
        )
        .expect("w");
        let results = import_directory(dir.path());
        assert_eq!(results.len(), 1);
        assert!(results[0].1.is_ok());
    }
}
