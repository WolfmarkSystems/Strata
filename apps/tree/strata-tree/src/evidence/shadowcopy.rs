// evidence/shadowcopy.rs — Volume Shadow Copy (VSS) detection and listing.
// Phase 2, Task 2.4.
//
// On Windows: enumerates shadow copies via WMI/vssadmin or direct path probing.
// On non-Windows: returns empty list (VSS is a Windows-only feature).
//
// Forensic read-only guarantee: no shadow copies are mounted or modified.
// Shadow copies are presented as selectable evidence sources.

use anyhow::Result;
use std::path::PathBuf;

/// A discovered Volume Shadow Copy.
#[derive(Debug, Clone)]
pub struct ShadowCopy {
    /// Unique identifier, e.g. "{GUID}" or "Shadow Copy #N".
    pub id: String,
    /// Originating volume, e.g. "C:\\".
    pub volume: String,
    /// Creation time string (ISO-8601 UTC if available).
    pub created_utc: String,
    /// Accessible path on the current system (e.g. \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\).
    pub path: PathBuf,
    /// Approximate size in bytes, if reported by the OS.
    pub size_bytes: Option<u64>,
}

/// Enumerate all accessible Volume Shadow Copies.
pub fn detect_shadow_copies() -> Result<Vec<ShadowCopy>> {
    #[cfg(target_os = "windows")]
    {
        detect_shadow_copies_windows()
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(Vec::new())
    }
}

#[cfg(target_os = "windows")]
fn detect_shadow_copies_windows() -> Result<Vec<ShadowCopy>> {
    use std::process::Command;

    // Try vssadmin list shadows — available on all Windows versions including PE.
    let output = Command::new("vssadmin").args(["list", "shadows"]).output();

    match output {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            parse_vssadmin_output(&text)
        }
        _ => {
            // Fallback: probe the well-known shadow copy device paths directly.
            probe_shadow_device_paths()
        }
    }
}

/// Parse the output of `vssadmin list shadows` into ShadowCopy structs.
#[cfg(target_os = "windows")]
fn parse_vssadmin_output(text: &str) -> Result<Vec<ShadowCopy>> {
    let mut copies = Vec::new();
    let mut current_id = String::new();
    let mut current_volume = String::new();
    let mut current_created = String::new();
    let mut current_path = String::new();

    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("Shadow Copy ID:") {
            // Flush previous.
            if !current_path.is_empty() {
                copies.push(ShadowCopy {
                    id: current_id.clone(),
                    volume: current_volume.clone(),
                    created_utc: current_created.clone(),
                    path: PathBuf::from(&current_path),
                    size_bytes: None,
                });
            }
            current_id = line
                .trim_start_matches("Shadow Copy ID:")
                .trim()
                .to_string();
            current_volume.clear();
            current_created.clear();
            current_path.clear();
        } else if line.starts_with("Original Volume:") {
            current_volume = line
                .trim_start_matches("Original Volume:")
                .trim()
                .to_string();
        } else if line.starts_with("Shadow Copy Creation Time:") {
            current_created = line
                .trim_start_matches("Shadow Copy Creation Time:")
                .trim()
                .to_string();
        } else if line.starts_with("Shadow Copy Volume:") {
            current_path = line
                .trim_start_matches("Shadow Copy Volume:")
                .trim()
                .to_string();
        }
    }

    // Flush last entry.
    if !current_path.is_empty() {
        copies.push(ShadowCopy {
            id: current_id,
            volume: current_volume,
            created_utc: current_created,
            path: PathBuf::from(current_path),
            size_bytes: None,
        });
    }

    Ok(copies)
}

/// Direct probe: attempt to open HarddiskVolumeShadowCopyN paths (1–64).
#[cfg(target_os = "windows")]
fn probe_shadow_device_paths() -> Result<Vec<ShadowCopy>> {
    let mut copies = Vec::new();
    for n in 1u32..=64 {
        let path_str = format!(r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy{}\", n);
        let path = PathBuf::from(&path_str);
        if path.exists() {
            copies.push(ShadowCopy {
                id: format!("HarddiskVolumeShadowCopy{}", n),
                volume: "Unknown".to_string(),
                created_utc: "Unknown".to_string(),
                path,
                size_bytes: None,
            });
        }
    }
    Ok(copies)
}

/// Render the shadow copy picker inside an egui panel.
/// Returns the path of the shadow copy the user selected (if any).
pub fn render_shadow_picker(
    ui: &mut egui::Ui,
    copies: &[ShadowCopy],
    selected: &mut Option<String>,
) -> Option<PathBuf> {
    let mut chosen: Option<PathBuf> = None;

    ui.heading("Volume Shadow Copies");
    ui.separator();

    if copies.is_empty() {
        ui.label("No Volume Shadow Copies detected.");
        ui.label("Run as Administrator to enumerate VSS snapshots.");
        return None;
    }

    ui.label(format!(
        "{} shadow cop{} found:",
        copies.len(),
        if copies.len() == 1 { "y" } else { "ies" }
    ));
    ui.add_space(4.0);

    for copy in copies {
        let is_sel = selected.as_deref() == Some(&copy.id);
        let size = copy
            .size_bytes
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string());
        let label = format!(
            "{} — Vol: {} — Created: {} — Size: {}",
            copy.id, copy.volume, copy.created_utc, size,
        );
        if ui.selectable_label(is_sel, &label).clicked() {
            *selected = Some(copy.id.clone());
        }
    }

    ui.add_space(8.0);
    if let Some(ref sel_id) = selected.clone() {
        if let Some(copy) = copies.iter().find(|c| &c.id == sel_id) {
            if ui.button("Load Selected Shadow Copy as Evidence").clicked() {
                chosen = Some(copy.path.clone());
            }
        }
    }

    chosen
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::parse_vssadmin_output;

    #[test]
    fn parses_vssadmin_shadow_output() {
        let sample = r#"
Contents of shadow copy set ID: {12345678-1111-2222-3333-444444444444}
   Contained 1 shadow copies at creation time: 3/20/2026 5:00:00 PM
      Shadow Copy ID: {aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}
         Original Volume: (C:)\\?\Volume{123}\ [C:\]
         Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy7
         Shadow Copy Creation Time: 3/20/2026 5:00:00 PM
"#;

        let copies = parse_vssadmin_output(sample).expect("parse output");
        assert_eq!(copies.len(), 1);
        assert!(copies[0].id.contains("aaaaaaaa"));
        assert!(copies[0]
            .path
            .to_string_lossy()
            .contains("HarddiskVolumeShadowCopy7"));
    }
}
