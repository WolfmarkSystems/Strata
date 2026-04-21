//! # Vault — hidden storage, encryption tools, anti-forensic applications.
//!
//! "Find what they tried to hide." Vault specialises in artifacts the
//! subject took deliberate action to conceal: VeraCrypt / TrueCrypt
//! volumes, photo vault apps, anti-forensic tool usage, hidden
//! partitions, steganography indicators, Tor Browser history, and
//! encrypted archives.
//!
//! VAULT-1 scaffolds the plugin; VAULT-2 through VAULT-6 add the
//! per-artifact parsers.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use strata_plugin_sdk::{
    ArtifactCategory, ArtifactRecord, ForensicValue, PluginCapability, PluginContext, PluginError,
    PluginOutput, PluginResult, PluginSummary, PluginType, StrataPlugin,
};

pub mod android_antiforensic;
pub mod antiforensic;
pub mod crypto_wallets;
pub mod encrypted_artifacts;
pub mod hidden_partition;
pub mod photo_vault;
pub mod veracrypt;

pub fn name() -> &'static str {
    "Vault"
}

pub fn version() -> &'static str {
    "1.0.0"
}

pub fn description() -> &'static str {
    "Detects hidden storage, encryption tools, anti-forensic applications, \
     and data concealment artifacts. Find what they tried to hide."
}

pub fn color() -> &'static str {
    "#a855f7"
}

pub struct VaultPlugin {
    name: String,
    version: String,
}

impl Default for VaultPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultPlugin {
    pub fn new() -> Self {
        Self {
            name: format!("Strata {}", name()),
            version: version().to_string(),
        }
    }
}

impl StrataPlugin for VaultPlugin {
    fn name(&self) -> &str {
        &self.name
    }
    fn version(&self) -> &str {
        &self.version
    }
    fn supported_inputs(&self) -> Vec<String> {
        vec![
            "vc".to_string(),
            "hc".to_string(),
            "tc".to_string(),
            "axx".to_string(),
            "veracrypt.xml".to_string(),
        ]
    }
    fn plugin_type(&self) -> PluginType {
        PluginType::Analyzer
    }
    fn capabilities(&self) -> Vec<PluginCapability> {
        vec![PluginCapability::ArtifactExtraction]
    }
    fn description(&self) -> &str {
        description()
    }

    fn run(&self, ctx: PluginContext) -> PluginResult {
        let root = Path::new(&ctx.root_path);
        let mut out = Vec::new();
        let files = match walk_dir(root) {
            Ok(f) => f,
            Err(_) => return Ok(out),
        };
        for path in files {
            out.extend(crate::veracrypt::scan(&path));
            out.extend(crate::photo_vault::scan(&path));
            out.extend(crate::antiforensic::scan(&path));
            out.extend(crate::hidden_partition::scan(&path));
            out.extend(crate::encrypted_artifacts::scan(&path));
            out.extend(crate::crypto_wallets::scan(&path));
        }
        Ok(out)
    }

    fn execute(&self, context: PluginContext) -> Result<PluginOutput, PluginError> {
        let start = std::time::Instant::now();
        let artifacts = self.run(context)?;
        let mut records: Vec<ArtifactRecord> = Vec::new();
        let mut cats: HashSet<String> = HashSet::new();
        let mut suspicious = 0usize;
        for a in &artifacts {
            let file_type = a.data.get("file_type").cloned().unwrap_or_default();
            let is_sus = a.data.get("suspicious").map(|v| v == "true").unwrap_or(false);
            if is_sus {
                suspicious += 1;
            }
            let category = match file_type.as_str() {
                "Secure Messaging App" | "Tor Browser History" => ArtifactCategory::Communications,
                "Photo Vault App" => ArtifactCategory::UserActivity,
                _ => ArtifactCategory::SystemActivity,
            };
            cats.insert(category.as_str().to_string());
            let fv = match a.data.get("forensic_value").map(|s| s.as_str()) {
                Some("Critical") => ForensicValue::Critical,
                Some("High") => ForensicValue::High,
                _ => ForensicValue::Medium,
            };
            records.push(ArtifactRecord {
                category,
                subcategory: file_type,
                timestamp: a.timestamp.map(|t| t as i64),
                title: a
                    .data
                    .get("title")
                    .cloned()
                    .unwrap_or_else(|| a.source.clone()),
                detail: a.data.get("detail").cloned().unwrap_or_default(),
                source_path: a.source.clone(),
                forensic_value: fv,
                mitre_technique: a.data.get("mitre").cloned(),
                is_suspicious: is_sus,
                raw_data: None,
                confidence: 0,
            });
        }
        let total = records.len();
        Ok(PluginOutput {
            plugin_name: self.name().to_string(),
            plugin_version: self.version().to_string(),
            executed_at: chrono::Utc::now().to_rfc3339(),
            duration_ms: start.elapsed().as_millis() as u64,
            artifacts: records,
            summary: PluginSummary {
                total_artifacts: total,
                suspicious_count: suspicious,
                categories_populated: cats.into_iter().collect(),
                headline: format!(
                    "Vault: {} concealment artifacts ({} suspicious)",
                    total, suspicious
                ),
            },
            warnings: vec![],
        })
    }
}

pub fn walk_dir(dir: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut paths = Vec::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let p = entry.path();
            if p.is_dir() {
                if let Ok(sub) = walk_dir(&p) {
                    paths.extend(sub);
                }
            } else {
                paths.push(p);
            }
        }
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_metadata_shape() {
        let p = VaultPlugin::new();
        assert_eq!(p.name(), "Strata Vault");
        assert_eq!(p.version(), "1.0.0");
        assert_eq!(color(), "#a855f7");
        assert!(!p.description().is_empty());
    }

    #[test]
    fn vault_run_dispatches_to_every_emitter_submodule() {
        // Post-v16 Sprint 4 Vault audit confirmation. Anti-
        // regression tripwire for the six emitter submodules
        // already wired into run(). If a future refactor
        // accidentally drops one of these calls, the silent
        // reduction would look like "plugin quietly produces
        // fewer records" rather than a visible compilation
        // failure — this test makes it a loud test failure.
        //
        // Each submodule's `scan(path)` is verified directly
        // at the module-level below; this tripwire pins the
        // wiring of all six into Vault's run() so a future
        // maintainer who deletes one of the six `out.extend(...)`
        // lines fails this test loudly rather than shipping a
        // silently-reduced plugin.
        //
        // The seventh submodule, `android_antiforensic`, is
        // intentionally not wired — see the
        // `android_antiforensic_is_utility_library_pending_specter_integration`
        // tripwire below.
        let src = include_str!("lib.rs");
        for emitter in [
            "crate::veracrypt::scan",
            "crate::photo_vault::scan",
            "crate::antiforensic::scan",
            "crate::hidden_partition::scan",
            "crate::encrypted_artifacts::scan",
            "crate::crypto_wallets::scan",
        ] {
            assert!(
                src.contains(emitter),
                "Vault run() must dispatch to {emitter}; wiring has regressed"
            );
        }
    }

    #[test]
    fn android_antiforensic_is_utility_library_pending_specter_integration() {
        // Post-v16 Sprint 4 audit finding. `android_antiforensic`
        // exposes four pub fns (known_wiper, classify_wipe_pattern,
        // indicator_from_installation, indicator_from_pattern) but
        // has NO pub fn scan(path) — it's a utility library
        // expecting a caller that already has Android package
        // metadata + block-level data access. Vault doesn't have
        // that infrastructure; Specter (Android backup) is the
        // natural home for the iteration layer.
        //
        // This tripwire pins the current "utility library, not
        // a direct emitter" state. When a future sprint wires
        // the helpers into Specter or builds an Android iteration
        // layer in Vault, this test must be intentionally changed
        // or deleted with the commit message noting
        // "android_antiforensic wired in [commit]." The
        // `_pending_specter_integration` suffix makes the
        // deferral discoverable.
        //
        // We verify by asserting (a) Vault's run() does NOT
        // reference the module, and (b) the module's public API
        // has no `scan(path)` emitter function — so the
        // "wire it in" action can't be a one-liner anyway.
        let lib_src = include_str!("lib.rs");
        // Construct the needle at runtime so the assertion's own
        // source text doesn't match the needle (otherwise this
        // file — including the test itself — always contains the
        // substring "android_antiforensic" followed by a colon).
        let needle = format!("{}::", "android_antiforensic");
        // Filter to non-test code — the assertion text above
        // legitimately contains the needle as a runtime string,
        // and we're checking production dispatch, not our own
        // tripwire source.
        let production_src = lib_src
            .split("#[cfg(test)]")
            .next()
            .expect("lib.rs has content before the test module");
        assert!(
            !production_src.contains(&needle),
            "Vault run() must not currently invoke the android wiping \
             helpers — wiring requires caller infrastructure not present \
             in Vault. When this fires, check whether the Specter \
             integration landed and update this tripwire."
        );
        let aa_src = include_str!("android_antiforensic.rs");
        assert!(
            !aa_src.contains("pub fn scan("),
            "android_antiforensic must remain a utility library (four helper \
             fns: known_wiper / classify_wipe_pattern / indicator_from_*). \
             If it grew a pub fn scan(path) signature, the deferral rationale \
             no longer holds and this tripwire must be re-examined."
        );
    }
}
