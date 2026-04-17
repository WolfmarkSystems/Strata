//! Photo-vault / calculator-disguise app detection (VAULT-3).
//!
//! Detects iOS bundle identifiers and Android package names belonging
//! to known photo-hiding apps, plus `.nomedia` markers in unexpected
//! locations. High signal in CSAM / SAPR / trafficking investigations —
//! presence alone is forensically meaningful.
//!
//! MITRE: T1027 (obfuscated files), T1083 (directory discovery).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use std::path::Path;
use strata_plugin_sdk::Artifact;

const IOS_VAULTS: &[(&str, &str)] = &[
    ("com.destek.recovery", "Secret Photo Vault"),
    ("com.privateapp.vault", "Private Photo Vault"),
    ("com.keepsafe.keepsafe", "Keepsafe"),
    ("com.mobilityware.calculator", "Calculator+ (vault)"),
    ("com.nqmobile.vault", "NQ Vault"),
    ("com.hideitmedia.hideitpro", "Hide It Pro"),
    ("com.secret.folder", "Secret Folder"),
    ("com.photo.safe", "Photo Safe"),
];

const ANDROID_VAULTS: &[(&str, &str)] = &[
    ("com.keepsafe.vault", "Keepsafe"),
    ("com.nqmobile.vault20", "NQ Vault"),
    ("com.calculator.vault", "Calculator Vault"),
    ("com.hide.secret.photo.video", "Hide Photos"),
    ("com.photo.vault.locker", "Photo Vault Locker"),
    ("org.privacyprotector", "Privacy Protector"),
];

const NOMEDIA_ALLOWLIST_FRAGMENTS: &[&str] = &[
    "/android/data/",
    "/android/obb/",
    "/dcim/.thumbnails/",
    "/cache/",
    "/.thumbnails/",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhotoVaultArtifact {
    pub app_name: String,
    pub bundle_id: String,
    pub platform: String,
    pub artifact_path: String,
    pub item_count: Option<u64>,
    pub database_found: bool,
    pub nomedia_present: bool,
}

pub fn scan(path: &Path) -> Vec<Artifact> {
    let mut out = Vec::new();
    let lower = path.to_string_lossy().to_ascii_lowercase();
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    for (bundle, label) in IOS_VAULTS {
        if lower.contains(bundle) {
            out.push(build_artifact(label, bundle, "iOS", path));
            return out;
        }
    }
    for (pkg, label) in ANDROID_VAULTS {
        if lower.contains(&format!("/data/data/{}/", pkg)) || lower.ends_with(pkg) {
            out.push(build_artifact(label, pkg, "Android", path));
            return out;
        }
    }
    if name == ".nomedia" && !NOMEDIA_ALLOWLIST_FRAGMENTS.iter().any(|f| lower.contains(f)) {
        let path_str = path.to_string_lossy().to_string();
        let mut a = Artifact::new("Photo Vault App", &path_str);
        a.add_field(
            "title",
            &format!(".nomedia marker in non-system location: {}", path_str),
        );
        a.add_field(
            "detail",
            "A `.nomedia` file hides the containing directory from Android Gallery — common manual concealment tactic",
        );
        a.add_field("file_type", "Photo Vault App");
        a.add_field("platform", "Android");
        a.add_field("nomedia_present", "true");
        a.add_field("mitre", "T1027");
        a.add_field("mitre_secondary", "T1083");
        a.add_field("forensic_value", "High");
        a.add_field("suspicious", "true");
        out.push(a);
    }
    out
}

fn build_artifact(label: &str, bundle: &str, platform: &str, path: &Path) -> Artifact {
    let path_str = path.to_string_lossy().to_string();
    let mut a = Artifact::new("Photo Vault App", &path_str);
    a.add_field(
        "title",
        &format!("Photo-vault app detected: {} ({})", label, bundle),
    );
    a.add_field(
        "detail",
        &format!(
            "App: {} | Bundle: {} | Platform: {} | Path: {}",
            label, bundle, platform, path_str
        ),
    );
    a.add_field("file_type", "Photo Vault App");
    a.add_field("app_name", label);
    a.add_field("bundle_id", bundle);
    a.add_field("platform", platform);
    a.add_field("artifact_path", &path_str);
    a.add_field("mitre", "T1027");
    a.add_field("mitre_secondary", "T1083");
    a.add_field("forensic_value", "High");
    a.add_field("suspicious", "true");
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_ios_bundle_id() {
        let path = Path::new(
            "/private/var/mobile/Containers/Data/Application/UUID/Library/Preferences/com.keepsafe.keepsafe.plist",
        );
        let out = scan(path);
        assert!(out
            .iter()
            .any(|a| a.data.get("app_name").map(|s| s.as_str()) == Some("Keepsafe")));
    }

    #[test]
    fn detects_android_package() {
        let path = Path::new("/data/data/com.calculator.vault/databases/vault.db");
        let out = scan(path);
        assert!(out
            .iter()
            .any(|a| a.data.get("app_name").map(|s| s.as_str()) == Some("Calculator Vault")));
    }

    #[test]
    fn flags_nomedia_outside_allowlist() {
        let path = Path::new("/sdcard/Pictures/MyStuff/.nomedia");
        let out = scan(path);
        assert!(out
            .iter()
            .any(|a| a.data.get("nomedia_present").map(|s| s.as_str()) == Some("true")));
    }

    #[test]
    fn ignores_nomedia_in_system_location() {
        let path = Path::new("/sdcard/DCIM/.thumbnails/.nomedia");
        assert!(scan(path).is_empty());
    }

    #[test]
    fn unrelated_paths_return_empty() {
        let path = Path::new("/Users/alice/Documents/report.pdf");
        assert!(scan(path).is_empty());
    }
}
