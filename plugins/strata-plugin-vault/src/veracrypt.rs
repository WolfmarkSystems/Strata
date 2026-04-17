//! VeraCrypt / TrueCrypt stubs — implementation in VAULT-2.

use std::path::Path;
use strata_plugin_sdk::Artifact;

pub fn scan(_path: &Path) -> Vec<Artifact> {
    Vec::new()
}
