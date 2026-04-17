//! antiforensic stubs — implementation in a later VAULT sprint.

use std::path::Path;
use strata_plugin_sdk::Artifact;

pub fn scan(_path: &Path) -> Vec<Artifact> {
    Vec::new()
}
