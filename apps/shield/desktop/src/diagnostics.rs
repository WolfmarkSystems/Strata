use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::preflight::{load_latest_preflight_report, system, PreflightReport};
use crate::state::AppState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticsBundle {
    pub created_utc: String,
    pub path: String,
    pub manifest: Vec<BundleEntry>,
    pub manifest_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleEntry {
    pub filename: String,
    pub sha256: String,
    pub size_bytes: u64,
}

pub fn generate_diagnostics_bundle(
    output_dir: &str,
    app_state: &AppState,
) -> anyhow::Result<DiagnosticsBundle> {
    let output_path = PathBuf::from(output_dir);
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let bundle_dir = output_path.join(format!("diagnostics_{}", timestamp));
    std::fs::create_dir_all(&bundle_dir)?;

    let mut manifest: Vec<BundleEntry> = Vec::new();

    if let Some(preflight) = load_latest_preflight_report() {
        let path = bundle_dir.join("preflight.latest.json");
        let json = serde_json::to_string_pretty(&preflight).unwrap_or_default();
        std::fs::write(&path, &json)?;
        manifest.push(create_entry(&path, "preflight.latest.json")?);
    }

    let version_info = system::get_version_info();
    let path = bundle_dir.join("versions.json");
    let json = serde_json::to_string_pretty(&version_info).unwrap_or_default();
    std::fs::write(&path, &json)?;
    manifest.push(create_entry(&path, "versions.json")?);

    let system_info = system::get_system_info();
    let path = bundle_dir.join("system_info.json");
    let json = serde_json::to_string_pretty(&system_info).unwrap_or_default();
    std::fs::write(&path, &json)?;
    manifest.push(create_entry(&path, "system_info.json")?);

    let events = app_state.get_events(None, 500);
    let path = bundle_dir.join("recent_events.json");
    let json = serde_json::to_string_pretty(&events).unwrap_or_default();
    std::fs::write(&path, &json)?;
    manifest.push(create_entry(&path, "recent_events.json")?);

    let manifest_json = serde_json::to_string_pretty(&manifest).unwrap_or_default();
    let manifest_path = bundle_dir.join("bundle_manifest.json");
    std::fs::write(&manifest_path, &manifest_json)?;
    let manifest_hash = compute_sha256_file(&manifest_path)?;

    manifest.push(create_entry(&manifest_path, "bundle_manifest.json")?);

    Ok(DiagnosticsBundle {
        created_utc: chrono::Utc::now().to_rfc3339(),
        path: bundle_dir.to_string_lossy().to_string(),
        manifest,
        manifest_hash,
    })
}

fn create_entry(path: &PathBuf, filename: &str) -> anyhow::Result<BundleEntry> {
    let content = std::fs::read(path)?;
    let sha256 = compute_sha256(&content);
    let size_bytes = content.len() as u64;
    Ok(BundleEntry {
        filename: filename.to_string(),
        sha256,
        size_bytes,
    })
}

fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

fn compute_sha256_file(path: &PathBuf) -> anyhow::Result<String> {
    let content = std::fs::read(path)?;
    Ok(compute_sha256(&content))
}

pub mod webview2 {
    use std::process::Command;

    pub const EVERGREEN_BOOTSTRAPPER_URL: &str = "https://go.microsoft.com/fwlink/p/?LinkId=2124703";

    pub fn download_and_install_evergreen() -> anyhow::Result<String> {
        let temp_dir = std::env::temp_dir();
        let installer_path = temp_dir.join("MicrosoftEdgeWebview2Setup.exe");

        let response = reqwest::blocking::get(EVERGREEN_BOOTSTRAPPER_URL)?;
        let bytes = response.bytes()?;
        std::fs::write(&installer_path, &bytes)?;

        let output = Command::new(&installer_path)
            .args(&["/silent", "/install"])
            .output()?;

        let _ = std::fs::remove_file(&installer_path);

        if output.status.success() {
            Ok("WebView2 installation completed".to_string())
        } else {
            anyhow::bail!(
                "WebView2 installation failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bundle_structure() {
        let entry = BundleEntry {
            filename: "test.json".to_string(),
            sha256: "abc123".to_string(),
            size_bytes: 100,
        };
        
        assert_eq!(entry.filename, "test.json");
    }
}
