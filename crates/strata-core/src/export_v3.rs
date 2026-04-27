//! Export artifacts to CSV, JSON, and MITRE ATT&CK Navigator layers
//! (WF-5).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use strata_plugin_sdk::Artifact;

pub const STRATA_VERSION: &str = "1.5.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportMetadata {
    pub strata_version: String,
    pub export_timestamp: DateTime<Utc>,
    pub case_number: String,
    pub examiner: String,
    pub image_sha256: Option<String>,
}

pub fn to_csv(artifacts: &[Artifact]) -> String {
    let mut out = String::new();
    out.push_str(
        "artifact_type,plugin,timestamp,source_file,description,mitre_technique,forensic_value,suspicious,confidence,examiner_notes\n",
    );
    for a in artifacts {
        let file_type = a
            .data
            .get("file_type")
            .cloned()
            .unwrap_or_else(|| a.category.clone());
        let plugin = a.data.get("plugin").cloned().unwrap_or_default();
        let ts = a
            .timestamp
            .and_then(|s| DateTime::<Utc>::from_timestamp(s as i64, 0))
            .map(|d| d.to_rfc3339())
            .unwrap_or_default();
        let desc = a
            .data
            .get("title")
            .cloned()
            .or_else(|| a.data.get("detail").cloned())
            .unwrap_or_default();
        let mitre = a.data.get("mitre").cloned().unwrap_or_default();
        let fv = a.data.get("forensic_value").cloned().unwrap_or_default();
        let sus = a
            .data
            .get("suspicious")
            .cloned()
            .unwrap_or_else(|| "false".into());
        let confidence = a.data.get("confidence").cloned().unwrap_or_default();
        let notes = a.data.get("examiner_notes").cloned().unwrap_or_default();
        let row = [
            file_type,
            plugin,
            ts,
            a.source.clone(),
            desc,
            mitre,
            fv,
            sus,
            confidence,
            notes,
        ];
        for (i, cell) in row.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&csv_escape(cell));
        }
        out.push('\n');
    }
    out
}

fn csv_escape(cell: &str) -> String {
    if cell.contains(',') || cell.contains('"') || cell.contains('\n') {
        let escaped = cell.replace('"', "\"\"");
        format!("\"{}\"", escaped)
    } else {
        cell.to_string()
    }
}

pub fn to_json(meta: &ExportMetadata, artifacts: &[Artifact]) -> Result<String, serde_json::Error> {
    let arts: Vec<serde_json::Value> = artifacts.iter().map(artifact_to_json).collect();
    let doc = serde_json::json!({
        "strata_version": meta.strata_version,
        "export_timestamp": meta.export_timestamp.to_rfc3339(),
        "case_number": meta.case_number,
        "examiner": meta.examiner,
        "image_sha256": meta.image_sha256,
        "artifact_count": artifacts.len(),
        "artifacts": arts,
    });
    serde_json::to_string_pretty(&doc)
}

fn artifact_to_json(a: &Artifact) -> serde_json::Value {
    let mut fields = serde_json::Map::new();
    for (k, v) in &a.data {
        fields.insert(k.clone(), serde_json::Value::String(v.clone()));
    }
    let ts = a
        .timestamp
        .and_then(|s| DateTime::<Utc>::from_timestamp(s as i64, 0))
        .map(|d| d.to_rfc3339())
        .unwrap_or_default();
    serde_json::json!({
        "type": a.data.get("file_type").cloned().unwrap_or_else(|| a.category.clone()),
        "plugin": a.data.get("plugin").cloned().unwrap_or_default(),
        "timestamp": ts,
        "source_file": a.source,
        "description": a.data.get("title").cloned().or_else(|| a.data.get("detail").cloned()).unwrap_or_default(),
        "mitre_technique": a.data.get("mitre").cloned().unwrap_or_default(),
        "forensic_value": a.data.get("forensic_value").cloned().unwrap_or_default(),
        "suspicious": a.data.get("suspicious").map(|s| s == "true").unwrap_or(false),
        "confidence": a.data.get("confidence").and_then(|s| s.parse::<f64>().ok()),
        "fields": fields,
    })
}

pub fn to_attack_navigator(
    case_number: &str,
    artifacts: &[Artifact],
) -> Result<String, serde_json::Error> {
    let mut tally: BTreeMap<String, (u32, bool, bool)> = BTreeMap::new();
    for a in artifacts {
        let Some(technique) = a.data.get("mitre").filter(|s| !s.is_empty()) else {
            continue;
        };
        let suspicious = a
            .data
            .get("suspicious")
            .map(|s| s == "true")
            .unwrap_or(false);
        let high = matches!(
            a.data.get("forensic_value").map(|s| s.as_str()),
            Some("High") | Some("Critical")
        );
        let entry = tally.entry(technique.clone()).or_insert((0, false, false));
        entry.0 += 1;
        entry.1 = entry.1 || suspicious;
        entry.2 = entry.2 || high;
    }
    let techniques: Vec<serde_json::Value> = tally
        .iter()
        .map(|(technique, (count, suspicious, high))| {
            let score = (*count).min(100);
            let color = if *suspicious {
                "#ff6666"
            } else if *high {
                "#ffaa44"
            } else if *count > 0 {
                "#ffdd44"
            } else {
                "#ffffff"
            };
            serde_json::json!({
                "techniqueID": technique,
                "score": score,
                "color": color,
                "comment": format!("{} matching artifacts in Strata analysis", count),
            })
        })
        .collect();
    let doc = serde_json::json!({
        "name": format!("Strata Analysis — Case {}", case_number),
        "versions": { "attack": "14", "navigator": "4.9", "layer": "4.5" },
        "domain": "enterprise-attack",
        "techniques": techniques,
    });
    serde_json::to_string_pretty(&doc)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn art(ty: &str, mitre: &str, suspicious: bool, fv: &str) -> Artifact {
        let mut a = Artifact::new(ty, "/evidence/x");
        a.add_field("file_type", ty);
        a.add_field("mitre", mitre);
        a.add_field("forensic_value", fv);
        if suspicious {
            a.add_field("suspicious", "true");
        }
        a.add_field("title", &format!("{} record", ty));
        a
    }

    #[test]
    fn csv_header_and_escapes_cells_with_commas() {
        let mut a = art("Prefetch", "T1059", false, "Medium");
        a.add_field("title", "notepad, executed");
        let csv = to_csv(&[a]);
        assert!(csv.starts_with("artifact_type,plugin,"));
        assert!(csv.contains("\"notepad, executed\""));
    }

    #[test]
    fn json_round_trips_metadata_and_artifacts() {
        let meta = ExportMetadata {
            strata_version: STRATA_VERSION.into(),
            export_timestamp: Utc::now(),
            case_number: "FBI-2026-0001".into(),
            examiner: "Jane Doe".into(),
            image_sha256: Some("deadbeef".into()),
        };
        let arts = vec![art("Prefetch", "T1059", false, "Medium")];
        let json = to_json(&meta, &arts).expect("json");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed["case_number"], "FBI-2026-0001");
        assert_eq!(parsed["artifact_count"], 1);
    }

    #[test]
    fn attack_navigator_tallies_and_colours_techniques() {
        let arts = vec![
            art("A", "T1059.001", true, "High"),
            art("B", "T1059.001", false, "High"),
            art("C", "T1547", false, "Low"),
        ];
        let layer = to_attack_navigator("FBI-1", &arts).expect("layer");
        let parsed: serde_json::Value = serde_json::from_str(&layer).expect("parse");
        let techniques = parsed["techniques"].as_array().expect("arr");
        assert_eq!(techniques.len(), 2);
        let t1059 = techniques
            .iter()
            .find(|t| t["techniqueID"] == "T1059.001")
            .expect("T1059");
        assert_eq!(t1059["color"], "#ff6666");
        assert_eq!(t1059["score"], 2);
    }

    #[test]
    fn attack_navigator_colour_ladder_fallback() {
        let arts = vec![art("C", "T1547", false, "Medium")];
        let layer = to_attack_navigator("X", &arts).expect("layer");
        let parsed: serde_json::Value = serde_json::from_str(&layer).expect("parse");
        let t = &parsed["techniques"][0];
        assert_eq!(t["color"], "#ffdd44");
    }

    #[test]
    fn csv_escape_handles_quotes() {
        assert_eq!(csv_escape("he said \"hi\""), "\"he said \"\"hi\"\"\"");
        assert_eq!(csv_escape("plain"), "plain");
    }
}
