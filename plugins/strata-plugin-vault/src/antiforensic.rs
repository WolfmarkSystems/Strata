//! Anti-forensic tool detection (VAULT-4).
//!
//! Detects artifacts left by secure-deletion and evidence-wiping
//! tools. Presence is itself evidence: CCleaner / BleachBit / Eraser /
//! sdelete / Cipher.exe always touch disk in recognisable ways.
//!
//! MITRE: T1070 (indicator removal), T1027, T1485, T1561 (disk wipe).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use std::path::Path;
use strata_plugin_sdk::Artifact;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AntiForensicArtifact {
    pub tool_name: String,
    pub last_run: Option<DateTime<Utc>>,
    pub artifact_path: String,
    pub targets: Vec<String>,
    pub modules_enabled: Vec<String>,
    pub detection_source: String,
}

pub fn scan(path: &Path) -> Vec<Artifact> {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let matches: &[(&str, &str, &str)] = &[
        ("CCleaner", "registry", "software/piriform/ccleaner"),
        ("CCleaner", "config", "ccleaner64.ini"),
        ("CCleaner", "config", "ccleaner.ini"),
        ("BleachBit", "config", "bleachbit.ini"),
        ("BleachBit", "prefetch", "bleachbit.exe-"),
        ("Eraser", "task-list", "task list.ersx"),
        ("Eraser", "registry", "software/eraser/eraser 6"),
        ("sdelete", "prefetch", "sdelete.exe-"),
        ("sdelete", "prefetch", "sdelete64.exe-"),
        ("cipher.exe (/w)", "prefetch", "cipher.exe-"),
        ("PermanentEraser", "path", "permanent eraser"),
        ("ExifTool", "path", "exiftool"),
        ("MAT2", "path", "mat2"),
    ];
    let mut out = Vec::new();
    for (tool, source, needle) in matches {
        let hit = match *source {
            "registry" | "path" => lower.contains(needle),
            _ => name.contains(needle) || name == *needle,
        };
        if hit {
            let path_str = path.to_string_lossy().to_string();
            let mut a = Artifact::new("Anti-Forensic Tool", &path_str);
            a.add_field("title", &format!("Anti-forensic tool indicator: {}", tool));
            a.add_field(
                "detail",
                &format!(
                    "Tool: {} | Detection: {} | Artifact: {}",
                    tool, source, path_str
                ),
            );
            a.add_field("file_type", "Anti-Forensic Tool");
            a.add_field("tool_name", tool);
            a.add_field("detection_source", source);
            a.add_field("mitre", "T1070");
            a.add_field("mitre_secondary", "T1485");
            a.add_field("forensic_value", "High");
            a.add_field("suspicious", "true");
            out.push(a);
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_ccleaner_ini() {
        let path = Path::new("C:\\Users\\alice\\AppData\\Roaming\\CCleaner\\CCleaner64.ini");
        let out = scan(path);
        assert!(out
            .iter()
            .any(|a| a.data.get("tool_name").map(|s| s.as_str()) == Some("CCleaner")));
    }

    #[test]
    fn detects_sdelete_prefetch() {
        let path = Path::new("C:\\Windows\\Prefetch\\SDELETE.EXE-ABCDEF12.pf");
        let out = scan(path);
        assert!(out
            .iter()
            .any(|a| a.data.get("tool_name").map(|s| s.as_str()) == Some("sdelete")));
    }

    #[test]
    fn detects_eraser_task_list() {
        let path = Path::new("C:\\Users\\alice\\AppData\\Roaming\\Eraser 6\\Task List.ersx");
        let out = scan(path);
        assert!(out
            .iter()
            .any(|a| a.data.get("tool_name").map(|s| s.as_str()) == Some("Eraser")));
    }

    #[test]
    fn ignores_unrelated() {
        let path = Path::new("/Users/alice/Documents/report.pdf");
        assert!(scan(path).is_empty());
    }

    #[test]
    fn detects_bleachbit_config() {
        let path = Path::new("C:\\Users\\alice\\AppData\\Roaming\\BleachBit\\bleachbit.ini");
        let out = scan(path);
        assert!(out
            .iter()
            .any(|a| a.data.get("tool_name").map(|s| s.as_str()) == Some("BleachBit")));
    }
}
